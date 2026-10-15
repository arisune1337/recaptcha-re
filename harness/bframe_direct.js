// bframe_direct.js — the BFRAME-DIRECT route for request-based reCAPTCHA v2.
//
// GOAL (map: "bframe-direct bootstrap"): boot a BFRAME realm by running the scraped
//   recaptcha.frame.Main.init("<cfg>")  (entry @byte 893462:
//      ,b)[24](74,"recaptcha.frame.Main.init",function(q,r){(r=new XZ(TP(q)),new Ac(r)).D.init(E[40](4,r,1,P))})
//   so the bframe controller Ac.D.init() AUTO-SCHEDULES the reason=fi POST /reload
//   WITHOUT any checkbox click (map: ".D.init() auto-schedules the reason=fi challenge
//   fetch on bframe load"). We wire the bframe realm to the SAME in-process loopback
//   BotGuard worker the anchor spawned, and the SAME cookie jar, then intercept the
//   /reload body and pull field16.
//
// WHY THE ANCHOR STILL RUNS HERE: the bframe has NO BotGuard worker of its own
//   (map / FINDINGS.md:62 — the worker runs in the ANCHOR frame). The bframe must relay
//   each attestation request cross-frame to the anchor's worker. So we boot:
//     (1) the ANCHOR realm  -> spawns the worker (BotGuard handshake over the loopback),
//     (2) the WORKER realm   (single instance, owned by a hub both realms attach to),
//     (3) the BFRAME realm   (parent = a relay handle into the anchor's window listeners,
//                             same worker hub, same jar, shared ___grecaptcha_cfg).
//
// bft PROVENANCE (the load-bearing input, and the riskiest unknown — see bottom):
//   bft is the anchor BotGuard's type-0d attestation token. It is NOT static and NOT
//   fetchable; in a real session only the parent/api.js sets it onto the bframe iframe
//   src AFTER the anchor goes interactive. So either:
//     - supply a live one:  BFT=<token>  (harvested from a real browser / parent-emulated run), or
//     - let this script attempt the parent-reply nudge + DOM src-capture (usually empty
//       without a full parent role — it will then abort with a clear message).
//
// RUN:  node harness/bframe_direct.js
//   env: SITEKEY, ORIGIN_HOST, VER, BFT, ENJS_SRC, TRACE=1
'use strict'
const fs = require('fs')
const vm = require('vm')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const pb = require('../poc/pb.js')
const PR = require('./page_rpc.js')   // pure: AE-capture + __onAE page-side ack patches + makeOnAE

// ----------------------------------------------------------------------------
// 0) config
// ----------------------------------------------------------------------------
const ENJS_SRC = process.env.ENJS_SRC || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
const SITEKEY = process.env.SITEKEY || '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-'
const ORIGIN_HOST = process.env.ORIGIN_HOST || 'www.google.com'
const VER = process.env.VER || 'TnA7HacJFoBWt9hnlunBlYfK'
const ORIGIN = 'https://' + ORIGIN_HOST
const CO = Buffer.from(ORIGIN + ':443').toString('base64url')
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const GOOGLE = 'https://www.google.com'
const TRACE = !!process.env.TRACE
const log = (...a) => console.log(...a)
const sleep = ms => new Promise(r => setTimeout(r, ms))

// ----------------------------------------------------------------------------
// 1) source-patch en.js (capture the Ac/WR controllers + rotating BotGuard tokens),
//    then layer page_rpc's AE-capture + __onAE page-side ack hook on top, write a temp
//    copy, and compile THAT in every realm. (My anchors are disjoint from page_rpc's.)
// ----------------------------------------------------------------------------
let CODE = fs.readFileSync(ENJS_SRC, 'utf8')
function patch(find, repl, label) {
  const i = CODE.indexOf(find)
  if (i < 0) { log('  [patch skip]', label, '(not found)'); return }
  if (CODE.indexOf(find, i + 1) >= 0) { log('  [patch skip]', label, '(non-unique)'); return }
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length); log('  [patch ok ]', label)
}
log('[bframe] patching en.js...')
patch('new Ac(r)).D.init(', '(self.__grAC=new Ac(r))).D.init(', 'Ac (bframe controller)')   // map: bframe ctrl @893462
patch('(new WR(r)).D).init()', '(self.__grWR=new WR(r)).D).init()', 'WR (anchor controller)')
patch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),', 'RPp/Qr (bg opcodes)')
patch('}],[ak,function', '}],[(__cap.ak=ak),function', 'ak (bg opcode)')
patch('d5=lZ()', 'd5=__cap.d5=lZ()', 'd5 ("recaptcha-setup")')
CODE = PR.applyPatches(CODE)   // AE=__cap.AE=... + __onAE(instance) at end of AE ctor
const PATCHED = path.join(os.tmpdir(), 'recaptcha__en.bframe.patched.js')
fs.writeFileSync(PATCHED, CODE)

// ----------------------------------------------------------------------------
// 2) by-reference loopback MessagePort (same objects cross realms; structuredClone would
//    DataCloneError on the AE's internal classes — must stay by-ref). Copied from page.js.
// ----------------------------------------------------------------------------
function makePort() {
  const p = { __isPort: true, _peer: null, _started: false, _q: [], _on: null, _lis: [],
    get onmessage() { return this._on }, set onmessage(f) { this._on = f; this._started = true; this._flush() },
    addEventListener(t, f) { if (t === 'message') { this._lis.push(f); this._started = true; this._flush() } },
    removeEventListener(t, f) { this._lis = this._lis.filter(x => x !== f) },
    start() { this._started = true; this._flush() }, close() { this._closed = true }, dispatchEvent() { return true },
    postMessage(data, transfer) { const ports = (transfer || []).filter(x => x && x.__isPort); const ev = { data, ports, type: 'message', target: this._peer }; queueMicrotask(() => this._peer && this._peer._deliver(ev)) },
    _deliver(ev) { if (this._closed) return; if (!this._started) { this._q.push(ev); return } if (this._on) try { this._on(ev) } catch (e) {} for (const f of this._lis) try { f(ev) } catch (e) {} },
    _flush() { if (!this._started) return; const q = this._q; this._q = []; for (const ev of q) this._deliver(ev) } }
  return p
}
let __portN = 0
function MessageChannelShim() { const a = makePort(), b = makePort(); a.__id = ++__portN; b.__id = ++__portN; a._peer = b; b._peer = a; this.port1 = a; this.port2 = b }

// ----------------------------------------------------------------------------
// 3) realm-realism perf (monotonic 0.1ms clock + growing heap so Xm reads U>0/x>0 hold)
// ----------------------------------------------------------------------------
function makePerf() {
  const t0 = process.hrtime.bigint(); const wall0 = Date.now(); const heap0 = process.memoryUsage().heapUsed
  const BASE = 12_000_000; let last = 0
  return {
    timeOrigin: wall0,
    now() { let ms = Number(process.hrtime.bigint() - t0) / 1e6; ms = Math.floor(ms / 0.1) * 0.1; if (ms < last) ms = last; last = ms; return ms },
    get memory() { const used = BASE + Math.max(0, process.memoryUsage().heapUsed - heap0); return { usedJSHeapSize: used, totalJSHeapSize: Math.max(used + 2_000_000, 40_000_000), jsHeapSizeLimit: 2_190_000_000 } },
    getEntriesByType: () => [], mark() {}, measure() {}, clearMarks() {}, clearMeasures() {},
  }
}

// ----------------------------------------------------------------------------
// 4) cookie jar (forward _GRECAPTCHA etc. across anchor + bframe + reload)
// ----------------------------------------------------------------------------
function makeJar() {
  const m = {}
  return {
    get cookie() { return Object.entries(m).map(([k, v]) => k + '=' + v).join('; ') },
    absorb(headers) {
      let sc = []
      try { sc = headers.getSetCookie ? headers.getSetCookie() : [] } catch {}
      if (!sc.length) { const one = headers.get && headers.get('set-cookie'); if (one) sc = [one] }
      for (const c of sc) { const kv = c.split(';')[0]; const i = kv.indexOf('='); if (i > 0) m[kv.slice(0, i).trim()] = kv.slice(i + 1).trim() }
    },
  }
}

// ----------------------------------------------------------------------------
// 5) DOM stub (no canvas). Elements capture listeners; iframe `src` is captured so a
//    parent-emulated session can harvest the server-minted bframe `bft`. (from solveloop)
// ----------------------------------------------------------------------------
function noop() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive || k === 'toString' || k === 'valueOf') return () => ''; if (k === 'length') return 0; if (k === 'nodeType') return 1; return P }, apply: () => P, construct: () => P, set: () => true, has: () => true }); return P }
function makeDom(store) {
  const ALL = store.all
  function el(tag, id) {
    const lis = {}
    function fire(type, ev) { (lis[type] || []).slice().forEach(f => { try { f(ev || mkEvent(type)) } catch (e) {} }) }
    function captureSrc(v) { const s = String(v); if (/api2\/bframe/.test(s) && /bft=/.test(s) && !store.bframeUrl) { store.bframeUrl = s.startsWith('http') ? s : GOOGLE + s; log('  [dom] captured bframe url w/ bft (', store.bframeUrl.length, 'chars)') } }
    const real = { tagName: (tag || 'div').toUpperCase(), id: id || '', nodeType: 1, value: '', checked: false,
      style: new Proxy({}, { get: () => '', set: () => true }), dataset: {}, classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
      addEventListener: (t, f) => (lis[t] = lis[t] || []).push(f), removeEventListener: (t, f) => { if (lis[t]) lis[t] = lis[t].filter(x => x !== f) },
      getAttribute: () => null, hasAttribute: () => false, removeAttribute() {}, appendChild: x => x, removeChild: x => x, insertBefore: x => x, remove() {}, contains: () => false,
      setAttribute(k, v) { if (k === 'src') captureSrc(v) },
      querySelector: () => el('div'), querySelectorAll: () => [], getElementsByTagName: () => [el('div')], getElementsByClassName: () => [el('div')],
      getBoundingClientRect: () => ({ x: 0, y: 0, width: 28, height: 28, top: 0, left: 0, right: 28, bottom: 28 }), getClientRects: () => [],
      focus() {}, blur() {}, click() { fire('click') }, cloneNode() { return el(tag, id) }, getContext: () => null, setPointerCapture() {}, releasePointerCapture() {},
      children: [], childNodes: [], firstChild: null, lastChild: null, parentNode: null, ownerDocument: null, offsetWidth: 28, offsetHeight: 28,
      innerHTML: '', outerHTML: '', textContent: '', dispatchEvent(ev) { fire(ev && ev.type, ev); return true }, _lis: lis, _fire: fire }
    const P = new Proxy(real, { get(t, k) { if (k in t) return t[k]; if (k === 'src') return t.__src || ''; if (typeof k === 'string' && /^on/.test(k)) return t['__' + k] || null; return noop() },
      set(t, k, v) { if (k === 'src') { t.__src = v; captureSrc(v) } else t[k] = v; return true }, has: () => true })
    ALL.push({ P, real, lis, fire }); return P
  }
  function mkEvent(type) { return { type, target: null, currentTarget: null, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0, key: ' ', keyCode: 32, which: 32 } }
  const ELS = {}
  const document = new Proxy({
    createElement: t => el(t), createElementNS: (ns, t) => el(t), createDocumentFragment: () => el('frag'), createTextNode: () => el('text'), createComment: () => el('cmt'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
    getElementById: id => (ELS[id] = ELS[id] || el('div', id)), querySelector: s => (ELS['q:' + s] = ELS['q:' + s] || el('div', 'q:' + s)), querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], getElementsByName: () => [],
    documentElement: el('html'), head: el('head'), body: el('body'), cookie: '', referrer: GOOGLE + '/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
  }, { get(t, k) { return k in t ? t[k] : noop() }, has: () => true })
  return { document, el, mkEvent }
}

// ----------------------------------------------------------------------------
// 6) realm builder (OWN copy, so we can control window/self/top/parent/frameElement
//    resolution — page.js/solveloop force parent===self for pageWindow which breaks the
//    bframe's framed-detection + the cross-frame relay).
//      opts.pageWindow      -> window/self/globalThis resolve to the realm global
//      opts.parentCollapse  -> top/parent also resolve to self (anchor, == driver_core)
//      else top/parent come from `extra.parent`/`extra.top` (bframe relay handle)
// ----------------------------------------------------------------------------
const INTRINSICS = ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'EvalError', 'ReferenceError', 'SyntaxError', 'URIError', 'Reflect', 'Proxy', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'parseInt', 'parseFloat', 'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape', 'isNaN', 'isFinite', 'Intl', 'structuredClone', 'Infinity', 'NaN', 'undefined', 'globalThis']
function buildRealm(role, extra, opts) {
  opts = opts || {}
  const pageWindow = !!opts.pageWindow, parentCollapse = !!opts.parentCollapse
  const base = {
    __cap: {}, importScripts: () => {}, postMessage: () => {}, addEventListener: () => {}, removeEventListener: () => {}, onmessage: null, onerror: null, close: () => {},
    MessageChannel: MessageChannelShim, MessagePort: function () {}, performance: makePerf(),
    navigator: { userAgent: UA, webdriver: false, deviceMemory: 8, hardwareConcurrency: 8, language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32', vendor: 'Google Inc.', product: 'Gecko', appName: 'Netscape', onLine: true, userAgentData: { brands: [{ brand: 'Chromium', version: '149' }], mobile: false, platform: 'Windows', getHighEntropyValues: () => Promise.resolve({}) }, sendBeacon: () => true, cookieEnabled: true, doNotTrack: null },
    location: { href: GOOGLE + '/recaptcha/api2/webworker.js', origin: GOOGLE, protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/webworker.js', search: '', hash: '' },
    atob: s => Buffer.from(s, 'base64').toString('binary'), btoa: s => Buffer.from(s, 'binary').toString('base64'),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, requestAnimationFrame: f => setTimeout(() => f(Date.now()), 16), cancelAnimationFrame: () => {}, requestIdleCallback: f => setTimeout(() => f({ timeRemaining: () => 5, didTimeout: false }), 1), cancelIdleCallback: () => {},
    TextEncoder, TextDecoder, URL, URLSearchParams, crypto: crypto.webcrypto, fetch: (...a) => fetch(...a),
    console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
  }
  Object.assign(base, extra || {})
  for (const k of INTRINSICS) if (!(k in base)) try { base[k] = globalThis[k] } catch {}
  let g
  const handler = {
    get(t, k) {
      if (typeof k === 'symbol') return t[k]
      if (k === 'self' || k === 'globalThis') return g
      if (k === 'window') return pageWindow ? g : (('window' in t) ? t.window : undefined)
      if (k === 'top' || k === 'parent') { if (parentCollapse) return g; if (k in t) return t[k]; return pageWindow ? g : undefined }
      if (k in t) return t[k]
      return undefined
    },
    has() { return true }, set(t, k, v) { t[k] = v; return true },
  }
  const sandbox = Object.assign(Object.create(null), base)
  const ctx = vm.createContext(new Proxy(sandbox, handler)); g = ctx
  let err = null
  try { vm.runInContext(CODE, ctx, { filename: `recaptcha__en.js[${role}]`, timeout: 20000 }) } catch (e) { err = e }
  return { ctx, sandbox, err }
}

// ----------------------------------------------------------------------------
// 7) WORKER HUB — a SINGLE worker realm both the anchor and the bframe attach to, so the
//    bframe is literally "wired to the SAME loopback worker". The worker's d5 bootstrap
//    (postMessage(d5,[port2])) is delivered to the FIRST attacher (the anchor), which binds
//    the page-side BotGuard AE to the transferred port. Later attachers (bframe) share the
//    same worker realm for any direct worker traffic; the bframe's PRIMARY attestation path
//    is the cross-frame relay to the anchor (see §9).
// ----------------------------------------------------------------------------
function makeWorkerHub() {
  let workerRealm = null
  const wlis = []          // worker self.addEventListener('message')
  const sinks = []         // worker -> outside fan-out (one per attached handle)
  let bootQ = []           // worker->outside before any handle attaches
  function workerPost(m, transfer) {
    const ports = Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : []
    const ev = { data: m, ports }
    if (!sinks.length) bootQ.push(ev); else for (const s of sinks) s(ev)
  }
  function ensureWorker() {
    if (workerRealm) return workerRealm
    workerRealm = buildRealm('worker', {
      performance: makePerf(),
      XMLHttpRequest: function () { return { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, getAllResponseHeaders: () => '', abort() {} } },
      postMessage: workerPost,
      addEventListener: (t, f) => { if (t === 'message') wlis.push(f) },
    }, { pageWindow: false })
    return workerRealm
  }
  function deliverToWorker(ev) { const ws = workerRealm && workerRealm.sandbox; if (ws && ws.onmessage) try { ws.onmessage(ev) } catch (e) {} for (const f of wlis) try { f(ev) } catch (e) {} }
  function attach(label) {
    ensureWorker()
    const handle = { _on: null, _lis: [], _q: [] }
    const flush = () => { if (!(handle._on || handle._lis.length)) return; while (handle._q.length) { const ev = handle._q.shift(); if (handle._on) try { handle._on(ev) } catch (e) {} for (const f of handle._lis) try { f(ev) } catch (e) {} } }
    const sink = ev => { if (TRACE) log('   [w->' + label + ']', typeof ev.data === 'string' ? 'str(' + ev.data.length + ')' : (ev.data && ev.data.constructor ? ev.data.constructor.name : typeof ev.data), 'ports=' + ev.ports.length); handle._q.push(ev); flush() }
    sinks.push(sink)
    if (bootQ.length) { const q = bootQ; bootQ = []; for (const ev of q) sink(ev) }   // d5 bootstrap -> first attacher
    handle.postMessage = (m, t) => { if (TRACE) log('   [' + label + '->w]'); deliverToWorker({ data: m, ports: (t || []).filter(x => x && x.__isPort) }) }
    handle.addEventListener = (t, f) => { if (t === 'message') { handle._lis.push(f); flush() } }
    handle.removeEventListener = (t, f) => { handle._lis = handle._lis.filter(x => x !== f) }
    handle.terminate = () => {}
    Object.defineProperty(handle, 'onmessage', { get() { return handle._on }, set(f) { handle._on = f; flush() } })
    return handle
  }
  return { attach, getWorkerRealm: () => workerRealm }
}

// ----------------------------------------------------------------------------
// 8) instrumented XHR: capture /reload body verbatim (field16), forward raw bytes over the
//    shared jar so the session advances; surface rresp/uvresp via onResp.
// ----------------------------------------------------------------------------
function toBuf(body) {
  if (body == null) return Buffer.alloc(0)
  if (Buffer.isBuffer(body)) return body
  if (typeof body === 'string') return Buffer.from(body, 'latin1')
  if (body instanceof ArrayBuffer) return Buffer.from(body)
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength)
  try { return Buffer.from(body) } catch { return Buffer.alloc(0) }
}
function extractField16(buf) {
  let fields; try { fields = pb.decode(buf) } catch (e) { return { error: 'decode failed: ' + e.message } }
  const map = {}
  for (const f of fields) map['f' + f.field] = (f.type === 'string') ? `"${f.preview.slice(0, 18)}"(${f.len})` : (f.wire === 2 ? `<${f.len}b>` : f.value)
  const f16 = fields.find(f => f.field === 16 && f.wire === 2)
  if (!f16) return { fields, map, present: false }
  const text = f16.raw.toString('latin1')
  return { fields, map, present: true, len: f16.len, raw: f16.raw, text, urlSafeB64: /^[A-Za-z0-9_-]+$/.test(text) }
}
function makeXHR(jar, refererDefault, RELOADS, resolveReload, onResp, tag) {
  return class XHR {
    constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = '' }
    open(m, u) { this._m = m; this._u = u }
    setRequestHeader(k, v) { this._h[k] = v }
    addEventListener(t, f) { this['on' + t] = f }
    getAllResponseHeaders() { return Object.entries(this._rh || {}).map(([k, v]) => k + ': ' + v).join('\r\n') }
    getResponseHeader(k) { return (this._rh || {})[String(k).toLowerCase()] || null }
    abort() {}
    send(body) {
      const self = this, url = String(this._u), pth = url.split('?')[0].replace(/^https?:\/\/[^/]+/, '')
      const buf = toBuf(body), isReload = /recaptcha\/api2\/reload/.test(url)
      if (/recaptcha\/api2\/(reload|userverify|replaceimage|anchor|bframe|payload)/.test(url)) log(`  [${tag} XHR]`, this._m, pth, 'bodyLen=' + buf.length)
      if (isReload) {
        const info = extractField16(buf); RELOADS.push({ buf, info, tag })
        log(`  *** /reload INTERCEPTED (${tag}):`, buf.length, 'B | fields:', JSON.stringify(info.map))
        if (info.present) log('      field16:', info.len, 'B | urlSafeB64=' + info.urlSafeB64 + ' | head=' + info.text.slice(0, 40))
        else log('      field16: ABSENT/EMPTY (expected on reload#1 — populated only from reload#2, built from the prior rresp field18 attestation)')
        try { fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/bframe_reload_' + RELOADS.length + '.bin', buf) } catch {}
        try { resolveReload({ buf, info }) } catch {}
      }
      const headers = { 'User-Agent': UA, 'Origin': GOOGLE, ...this._h }
      if (jar.cookie) headers['Cookie'] = jar.cookie
      if (!headers['Referer']) headers['Referer'] = refererDefault
      fetch(url, { method: this._m || 'GET', headers, body: (this._m === 'POST' || this._m === 'PUT') ? buf : undefined })
        .then(async r => {
          self.status = r.status; self._rh = Object.fromEntries(r.headers); jar.absorb(r.headers)
          const rb = Buffer.from(await r.arrayBuffer())
          self.responseText = rb.toString('latin1'); self.response = self.responseText; self.readyState = 4
          if (isReload) log(`      /reload response:`, r.status, rb.length, 'B |', self.responseText.slice(0, 48).replace(/\n/g, ' '))
          try { onResp && onResp({ url, path: pth, status: r.status, text: self.responseText, buf: rb }) } catch (e) {}
          if (self.onreadystatechange) self.onreadystatechange(); if (self.onload) self.onload()
        })
        .catch(e => { self.status = 0; self.readyState = 4; if (self.onerror) self.onerror(e); if (self.onreadystatechange) self.onreadystatechange() })
    }
  }
}

// ----------------------------------------------------------------------------
// 9) cross-realm window relay. The bframe's window.parent.postMessage(...) must reach the
//    ANCHOR realm's window 'message' listeners with a stable source identity + by-ref ports,
//    so the bframe's "recaptcha-setup"+port handshake is adopted by the anchor's d5 intake
//    (map @byte 246348 / LINE 455: accepts when data==d5 && originOk && ports>0; the anchor
//    does NOT check source). Once adopted, attestation RPC rides the by-ref MessagePort.
// ----------------------------------------------------------------------------
function deliverWinMsg(listeners, data, origin, source, ports) {
  const ev = { data, origin, source, ports: (ports || []).filter(p => p && p.__isPort), type: 'message', lastEventId: '', preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {} }
  for (const fn of (listeners['message'] || []).slice()) { try { fn(ev) } catch (e) { if (TRACE) log('   [relay] listener threw', e.message) } }
}

// ----------------------------------------------------------------------------
// 10) scrape recaptcha.frame.Main.init("...") / recaptcha.anchor.Main.init("...") literals.
// ----------------------------------------------------------------------------
function extractInitCall(html, sym) {
  const key = sym + '('; const i = html.indexOf(key); if (i < 0) return null
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) { const c = html[p]
    if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
    if (c === '"' || c === "'") { inStr = true; q = c; continue }
    if (c === '(') depth++; else if (c === ')') { if (--depth === 0) { p++; break } } }
  return html.slice(i, p)
}
function locFrom(u) { const url = new URL(u); return { href: u, origin: url.origin, protocol: url.protocol, host: url.host, hostname: url.hostname, pathname: url.pathname, search: url.search, hash: '', replace() {}, assign() {}, reload() {} } }

// ----------------------------------------------------------------------------
// 11) MAIN
// ----------------------------------------------------------------------------
async function main() {
  process.on('unhandledRejection', () => {})
  log('[bframe] sitekey=%s co=%s (%s) ver=%s', SITEKEY, CO, ORIGIN, VER)

  const jar = makeJar()
  const hub = makeWorkerHub()
  const RELOADS = []
  let resolveReload; const firstReload = new Promise(r => { resolveReload = r })

  // -- ANCHOR realm (parentCollapse: identical to driver_core's proven boot) -----------
  const anchorStore = { all: [], bframeUrl: null }
  const aDom = makeDom(anchorStore)
  const ANCHOR_WIN_LIS = {}, ANCHOR_WIN_POSTS = []
  const anchorExtra = {
    __cap: {},
    Worker: function () { return hub.attach('anchor') },
    __onAE: PR.makeOnAE({ log: (...a) => { if (TRACE) log('  [page-rpc]', ...a) } }),   // page-side worker-channel ack
    document: aDom.document,
    XMLHttpRequest: makeXHR(jar, GOOGLE + `/recaptcha/api2/anchor?k=${SITEKEY}`, RELOADS, resolveReload, null, 'anchor'),
    addEventListener: (t, f) => { (ANCHOR_WIN_LIS[t] = ANCHOR_WIN_LIS[t] || []).push(f) },
    removeEventListener: (t, f) => { if (ANCHOR_WIN_LIS[t]) ANCHOR_WIN_LIS[t] = ANCHOR_WIN_LIS[t].filter(x => x !== f) },
    postMessage: (m, targetOrigin, transfer) => { const ports = Array.isArray(transfer) ? transfer : (Array.isArray(targetOrigin) ? targetOrigin : []); ANCHOR_WIN_POSTS.push({ m, targetOrigin, ports }) },
    performance: makePerf(),
    location: locFrom(`${GOOGLE}/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=${CO}&hl=en&v=${VER}&size=normal`),
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1080, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), frameElement: null, scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, Event: function () { return noop() }, CustomEvent: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
    // window.botguard intentionally undefined -> the worker-attestation path (map note).
  }
  log('[bframe] booting ANCHOR realm...')
  const anchor = buildRealm('anchor', anchorExtra, { pageWindow: true, parentCollapse: true })
  if (anchor.err) { log('[bframe] anchor load THREW:', anchor.err.message) }
  if (!anchor.sandbox.recaptcha || !anchor.sandbox.recaptcha.anchor) { log('[bframe] no recaptcha.anchor api — abort'); process.exit(1) }

  // fetch fresh anchor cfg + run init (this spawns the worker + runs the BotGuard handshake)
  const aurl = anchorExtra.location.href + '&cb=' + Math.random().toString(36).slice(2, 14)
  log('[bframe] GET anchor...')
  let ahtml
  try { const r = await fetch(aurl, { headers: { 'User-Agent': UA } }); jar.absorb(r.headers); ahtml = await r.text() }
  catch (e) { log('[bframe] anchor fetch failed:', e.message); process.exit(1) }
  const ainit = extractInitCall(ahtml, 'recaptcha.anchor.Main.init')
  if (!ainit) { log('[bframe] no anchor.Main.init literal (sitekey/origin not provisioned?) — abort'); process.exit(1) }
  log('[bframe] anchor init literal:', ainit.length, 'chars')
  try { vm.runInContext(ainit, anchor.ctx, { timeout: 20000 }) } catch (e) { log('[bframe] anchor init threw:', e.message) }

  for (let s = 0; s < 12 && !hub.getWorkerRealm(); s++) await sleep(400)
  log('[bframe] worker spawned:', !!hub.getWorkerRealm(), '| anchor __cap:', Object.keys(anchor.sandbox.__cap || {}).join(',') || '-')
  await sleep(1500)

  // -- (best-effort) parent-reply nudge so a real parent role MIGHT set the bframe iframe src
  //    -> captureSrc harvests bft. Documented insufficient on its own (the anchor needs the REAL
  //    api.js command responses), but it records the comm frames and is harmless. --------------
  await tryHarvestBft(anchor, ANCHOR_WIN_LIS, ANCHOR_WIN_POSTS, anchorStore)

  // -- resolve bft -----------------------------------------------------------------------------
  let BFT = process.env.BFT || null
  if (!BFT && anchorStore.bframeUrl) { const m = anchorStore.bframeUrl.match(/[?&]bft=([^&]+)/); if (m) BFT = decodeURIComponent(m[1]) }
  if (!BFT) {
    log('\n[bframe] NO bft available. bft is the anchor BotGuard type-0d attestation token; it is')
    log('         minted in-session and only the parent/api.js sets it onto the bframe iframe src')
    log('         AFTER the anchor goes interactive (the documented circular blocker). Supply one')
    log('         via  BFT=<token>  (from a real browser / parent-emulated run) and re-run.')
    process.exit(2)
  }
  log('[bframe] using bft (', BFT.length, 'chars ):', BFT.slice(0, 18) + '...')

  // -- fetch the bframe HTML with bft + scrape recaptcha.frame.Main.init("...") ----------------
  const burl = `${GOOGLE}/recaptcha/api2/bframe?hl=en&v=${VER}&k=${SITEKEY}&bft=${encodeURIComponent(BFT)}`
  log('[bframe] GET bframe (with bft)...')
  let bhtml
  try { const r = await fetch(burl, { headers: { 'User-Agent': UA, Referer: burl, Cookie: jar.cookie } }); jar.absorb(r.headers); bhtml = await r.text() }
  catch (e) { log('[bframe] bframe fetch failed:', e.message); process.exit(1) }
  const binit = extractInitCall(bhtml, 'recaptcha.frame.Main.init')
  if (!binit) { log('[bframe] no recaptcha.frame.Main.init literal in bframe html (bft invalid/expired or sitekey not provisioned) — abort'); process.exit(2) }
  log('[bframe] frame.Main.init literal:', binit.length, 'chars')

  // -- BFRAME realm: parent = relay handle into the anchor's window listeners; SAME worker hub,
  //    SAME jar, shared ___grecaptcha_cfg. window===self, but window.parent===relay (framed). --
  const bStore = { all: [], bframeUrl: null }
  const bDom = makeDom(bStore)
  const BFRAME_WIN_LIS = {}
  // a stable identity for the anchor's source-check (anchor d5 intake ignores source, but the
  // api.js named-channel path checks source===K(); we present a consistent object either way):
  const bframeContentWindow = { __isWindow: true, postMessage: (m, o, t) => deliverWinMsg(BFRAME_WIN_LIS, m, o || GOOGLE, anchorParentRef, t) }
  // bframe.window.parent: posting on it relays to the ANCHOR realm's window listeners, source =
  // the bframe contentWindow proxy (so the anchor can adopt the bframe's transferred port).
  const anchorParentRef = { __isWindow: true, postMessage: (m, targetOrigin, transfer) => {
    if (TRACE) log('   [bframe->anchor win]', typeof m === 'string' ? 'str:' + String(m).slice(0, 30) : typeof m, 'ports=' + ((transfer || []).filter(x => x && x.__isPort).length))
    deliverWinMsg(ANCHOR_WIN_LIS, m, GOOGLE, bframeContentWindow, transfer)
  } }
  // the bframe controller opens its sibling channel to the anchor via `parent.frames[<anchorName>]`.
  // Any frame name resolves to a window handle that relays bframe->anchor (source = bframe cw), so
  // the anchor's named-channel intake can adopt it. Without this, `parent.frames[N]` is undefined
  // and frame.Main.init throws before /reload is ever scheduled.
  const siblingAnchorRef = { __isWindow: true, addEventListener() {}, removeEventListener() {}, focus() {}, blur() {}, closed: false, location: { origin: GOOGLE },
    postMessage: (m, targetOrigin, transfer) => {
      if (TRACE) log('   [bframe->sibling(anchor) win]', typeof m === 'string' ? 'str:' + String(m).slice(0, 30) : typeof m, 'ports=' + ((transfer || []).filter(x => x && x.__isPort).length))
      deliverWinMsg(ANCHOR_WIN_LIS, m, GOOGLE, bframeContentWindow, transfer)
    } }
  anchorParentRef.frames = new Proxy({ length: 1 }, { get(t, k) { if (k === 'length') return 1; if (k === Symbol.iterator || typeof k === 'symbol') return t[k]; return siblingAnchorRef }, has: () => true })
  anchorParentRef.length = 1
  const bExtra = {
    __cap: {},
    Worker: function () { return hub.attach('bframe') },   // share the SAME worker realm
    document: bDom.document,
    XMLHttpRequest: makeXHR(jar, burl, RELOADS, resolveReload, null, 'bframe'),
    addEventListener: (t, f) => { (BFRAME_WIN_LIS[t] = BFRAME_WIN_LIS[t] || []).push(f) },
    removeEventListener: (t, f) => { if (BFRAME_WIN_LIS[t]) BFRAME_WIN_LIS[t] = BFRAME_WIN_LIS[t].filter(x => x !== f) },
    postMessage: (m, o, t) => deliverWinMsg(BFRAME_WIN_LIS, m, o || GOOGLE, bframeContentWindow, t),   // self-posts
    performance: makePerf(),
    location: locFrom(burl),
    parent: anchorParentRef, top: anchorParentRef, frameElement: bDom.el('div'),   // window.parent!=window => framed (gate @190196)
    window: undefined,   // resolved to global by the proxy (pageWindow)
    ___grecaptcha_cfg: anchor.sandbox.___grecaptcha_cfg,   // SHARE the registry with the anchor
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 400, innerHeight: 580, outerWidth: 400, outerHeight: 580, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, Event: function () { return noop() }, CustomEvent: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    botguard: undefined,
  }
  log('[bframe] booting BFRAME realm...')
  const bframe = buildRealm('bframe', bExtra, { pageWindow: true, parentCollapse: false })
  if (bframe.err) log('[bframe] bframe load THREW:', bframe.err.message)
  if (!bframe.sandbox.recaptcha || !bframe.sandbox.recaptcha.frame) { log('[bframe] no recaptcha.frame api in bframe realm — abort'); process.exit(1) }

  // run the scraped frame.Main.init verbatim -> Ac controller -> .D.init() auto-schedules /reload
  log('[bframe] recaptcha.frame.Main.init(cfg)...')
  try { vm.runInContext(binit, bframe.ctx, { timeout: 20000 }) } catch (e) { log('[bframe] frame init threw:', e.message, '\n', (e.stack || '').split('\n').slice(1, 4).join('\n')) }

  log('[bframe] bframe controller captured (__grAC):', !!bframe.sandbox.__grAC,
    '| bframe win listeners:', Object.keys(BFRAME_WIN_LIS).map(k => k + '(' + BFRAME_WIN_LIS[k].length + ')').join(',') || 'none',
    '| anchor win listeners:', Object.keys(ANCHOR_WIN_LIS).map(k => k + '(' + ANCHOR_WIN_LIS[k].length + ')').join(',') || 'none')

  // wait for the bframe-emitted reason=fi POST /reload (race with a timeout)
  log('[bframe] waiting for bframe /reload ...')
  const winner = await Promise.race([firstReload, sleep(15000).then(() => null)])

  log('\n[bframe] ===== RESULT =====')
  log('reloads intercepted:', RELOADS.length)
  RELOADS.forEach((R, i) => log(`  reload#${i + 1} [${R.tag}]: ${R.buf.length}B | field16 ${R.info.present ? R.info.len + 'B urlSafeB64=' + R.info.urlSafeB64 : 'EMPTY'} | fields ${JSON.stringify(R.info.map)}`))
  if (!winner) {
    log('NO bframe /reload fired. Most likely the bframe controller is awaiting the cross-frame')
    log('attestation relay to the anchor worker (or the bft did not bind the session). See the')
    log('riskiest-unknown note in this file: bframe-direct removes the CHECKBOX, not the anchor')
    log('BotGuard handshake + the bframe<->anchor attestation relay.')
  } else if (winner.info.present && winner.info.len > 0) {
    log('FIELD16 PRESENT (', winner.info.len, 'B ). Wrote bframe_reload_*.bin.')
  } else {
    log('FIELD16 EMPTY on this reload — expected for the FIRST /reload; a populated field16 appears')
    log('only from reload#2 onward (built from the prior rresp field18 attestation).')
  }
  process.exit(0)
}

// best-effort: replay the synthetic parent "recaptcha-setup" reply (driver_core step4b) so a real
// parent role MIGHT advance the anchor and set the bframe iframe src -> captureSrc harvests bft.
async function tryHarvestBft(anchor, ANCHOR_WIN_LIS, ANCHOR_WIN_POSTS, store) {
  try {
    const anchorPost = ANCHOR_WIN_POSTS.find(p => p.ports && p.ports.length)
    if (!ANCHOR_WIN_LIS['message'] || !ANCHOR_WIN_LIS['message'].length) return
    const hostOrigin = (anchorPost && typeof anchorPost.targetOrigin === 'string') ? anchorPost.targetOrigin.replace(/:443$/, '') : ORIGIN
    const ch = new MessageChannelShim()
    for (const v of [
      { data: 'recaptcha-setup', origin: hostOrigin, source: anchor.ctx, ports: [ch.port2] },
      { data: 'recaptcha-setup', origin: GOOGLE, source: anchor.ctx, ports: [ch.port2] },
    ]) {
      for (const fn of ANCHOR_WIN_LIS['message'].slice()) { try { fn({ ...v, type: 'message', preventDefault() {}, stopPropagation() {} }) } catch (e) {} }
      await sleep(800)
      if (store.bframeUrl) break
    }
  } catch (e) { if (TRACE) log('  [harvest] threw', e.message) }
}

if (require.main === module) main()
module.exports = { buildRealm, makeWorkerHub, makeXHR, extractField16, extractInitCall,
  makeJar, makePerf, makeDom, MessageChannelShim, makePort, locFrom, noop }

// =====================================================================================
// RISKIEST UNKNOWN (load-bearing, highest first)
// -------------------------------------------------------------------------------------
// 1) bft IS CIRCULAR. The only non-circular source of a valid bft is the parent/api.js role
//    setting the bframe iframe src AFTER the anchor goes interactive — the exact blocker
//    bframe-direct was hoped to skip. This route removes the CHECKBOX CLICK, not the anchor
//    BotGuard handshake nor the parent-emulation that mints bft. With a stale/synthesized
//    bframe?k=SITEKEY (no live bft) the returned HTML's frame.Main.init cfg lacks the session
//    binding and /reload is rejected (FINDINGS.md:51-55 refuted the bft-in-Referer shortcut).
//    => Supply BFT from a real/parent-emulated session; tryHarvestBft() is best-effort only.
//
// 2) THE bframe<->anchor ATTESTATION RELAY. The bframe has no worker; its /reload field16 must
//    come from the anchor's worker via a cross-frame channel. This file wires the bframe ->
//    anchor "recaptcha-setup"+port handshake (so the anchor's d5 intake @246348 adopts the
//    bframe's by-ref port and attestation RPC can flow), but the anchor only opens its SIBLING
//    channel to the bframe after IT is interactive — again gated on the parent handshake. If the
//    relay is not live, the bframe either never emits /reload (awaits the token) or emits one with
//    empty/invalid field16 -> low-trust/soft-block. field16 is empty on reload#1 regardless.
//
// 3) WINDOW IDENTITY. The anchor's named-channel path hard-checks source===K() && origin allowed;
//    the relay presents bframeContentWindow as source and GOOGLE as origin. A mismatch is dropped
//    SILENTLY (no throw) — same failure signature as a stall. The d5 path ignores source, so the
//    handshake adoption is robust, but any api.js-style named channel the bframe opens is not.
//
// 4) Ac CONTROLLER IS DISPATCH-ENCODED (Ac -> E[36] selector 49) and ROTATES per release. Even
//    once /reload fires, the tile-select/Verify methods on ctrl.D cannot be hardcoded; they must
//    be runtime-traced each VER. This file only needs Ac to schedule the first /reload, which
//    .D.init() does on load — no method poke — so it is robust to that rotation for THIS goal.
//
// 5) TRUST CEILING. A node-minted field16 may still score low even when structurally valid; the
//    own-key /api/siteverify oracle (solveloop.finish) is the only thing that falsifies trust.
