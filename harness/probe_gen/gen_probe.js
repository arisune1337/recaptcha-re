// gen_probe.js — PROVE where reCAPTCHA v2's ~288KB per-session BotGuard "bgprogram" is minted.
//
// HYPOTHESIS (from RE + the existing harness facts):
//   The ~288KB program is generated INSIDE the api.js-HOST (TOP) realm's OWN BotGuard WEB WORKER
//   (webworker.js runs the same recaptcha__en.js in worker role). The host boots BotGuard, spawns
//   the worker, and drives it to build the challenge program; the worker serializes its VM state
//   via E_.prototype.CE (== aq.Z().get().CE()) and posts the ~288KB result back to the host, which
//   then relays it to the anchor as the type-"x" channel frame.  driver_emulate_parent's PARENT
//   realm stubs Worker() to a NO-OP, so that generation never happens there (CE only ever fires as
//   the anchor's inline ~812B bootstrap). This probe gives the HOST a REAL in-process worker realm,
//   instruments E_.prototype.CE + every cross-boundary message, drives grecaptcha render/execute,
//   and MEASURES the largest BotGuard buffer produced.  SUCCESS = a 250-350KB buffer, no browser.
//
// Run:  node harness/probe_gen/gen_probe.js         (env: TRACE=1 for verbose, NONET=1 to block XHR)
'use strict'
const fs = require('fs')
const vm = require('vm')
const os = require('os')
const path = require('path')

const ENJS_SRC = process.env.ENJS_SRC || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
const SITEKEY = process.env.SITEKEY || '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-'
const VER = process.env.VER || 'TnA7HacJFoBWt9hnlunBlYfK'
const HOST_ORIGIN = 'https://' + (process.env.ORIGIN_HOST || 'www.google.com')
const ORIGIN_HOST = process.env.ORIGIN_HOST || 'www.google.com'
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const TRACE = !!process.env.TRACE
const log = (...a) => console.log(...a)

// ---------------------------------------------------------------------------
// 0) Patch a temp copy of en.js: instrument E_.prototype.CE (the BotGuard state serializer) and
//    AE.prototype.send (channel opcode+payload). Tolerant: skip a patch if its anchor is missing.
// ---------------------------------------------------------------------------
let CODE = fs.readFileSync(ENJS_SRC, 'utf8')
function patch(find, repl, label) {
  const i = CODE.indexOf(find)
  if (i < 0) { log('  [patch SKIP]', label, '(anchor missing)'); return false }
  if (CODE.indexOf(find, i + 1) >= 0) { log('  [patch SKIP]', label, '(non-unique)'); return false }
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length); log('  [patch ok ]', label); return true
}
log('[gen] patching en.js (CE + send probes)...')
// CE serializer: capture the serialized-state string it returns, tagged by realm role.
patch('E_.prototype.CE=function(q){return Rl(t[1](42,this,q))}',
      'E_.prototype.CE=function(q){var __c=Rl(t[1](42,this,q));try{if(typeof self.__CE==="function")self.__CE(__c,this)}catch(e){}return __c}',
      'E_.prototype.CE')
// AE channel send: opcode q + structured message r, BEFORE serialization.
patch('AE).prototype.send=function(q,r,w,D,d,A){return F[48](65,',
      'AE).prototype.send=function(q,r,w,D,d,A){try{if(typeof self.__SEND==="function")self.__SEND(String(q),r)}catch(e){}return F[48](65,',
      'AE.prototype.send')
// PR-equivalent: expose AE ctor + fire __onAE at ctor end (so we can watch AE instances).
patch('AE=function(q,r,w,D,d,A){return b[32]', 'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]', 'AE ctor expose')
patch('this.D.start()),q^6)>>3', 'this.D.start(),typeof __onAE==="function"&&__onAE(x)),q^6)>>3', '__onAE hook')

const PATCHED = path.join(os.tmpdir(), 'recaptcha__en.genprobe.js')
fs.writeFileSync(PATCHED, CODE)
process.env.ENJS = PATCHED           // page.js reads ENJS at require-time; it re-applies PR patches
// page.js's applyPatches would DOUBLE-apply the two PR anchors we just consumed -> not found ->
// it throws. Guard: set a flag page.js honours? It doesn't. So bypass page.js's applyPatches by
// pre-satisfying it: we already applied them, so remove page.js from the equation and build our
// realm here. We still reuse page.js's makePort/MessageChannelShim/makeXHR via require but supply
// our OWN CODE to vm. (require page.js AFTER pointing ENJS at the ORIGINAL so its applyPatches ok.)
process.env.ENJS = ENJS_SRC
const PJ = require('../page.js')   // makePort, MessageChannelShim, makeXHR, XHR_REQS, buildRealm
const { makePort, MessageChannelShim } = PJ

// ---------------------------------------------------------------------------
// 1) Our own realm builder that runs the PATCHED CODE (page.js.buildRealm runs the unpatched-by-us
//    file). Mirrors page.js.buildRealm's global surface so the bundle boots identically.
// ---------------------------------------------------------------------------
const INTRINSICS = ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'EvalError', 'ReferenceError', 'SyntaxError', 'URIError', 'Reflect', 'Proxy', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'parseInt', 'parseFloat', 'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape', 'isNaN', 'isFinite', 'Intl', 'structuredClone', 'Infinity', 'NaN', 'undefined', 'globalThis']

function makePerf() {
  const t0 = process.hrtime.bigint(); let last = 0; const heap0 = process.memoryUsage().heapUsed; const BASE = 12_000_000
  return { timeOrigin: Date.now(),
    now() { let ms = Number(process.hrtime.bigint() - t0) / 1e6; ms = Math.floor(ms / 0.1) * 0.1; if (ms < last) ms = last; last = ms; return ms },
    get memory() { const u = BASE + Math.max(0, process.memoryUsage().heapUsed - heap0); return { usedJSHeapSize: u, totalJSHeapSize: Math.max(u + 2e6, 4e7), jsHeapSizeLimit: 2.19e9 } },
    getEntriesByType: () => [], mark() {}, measure() {}, clearMarks() {}, clearMeasures() {} }
}
function makeXHR(tag) {
  return class XHR {
    constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = '' }
    open(m, u) { this._m = m; this._u = u }
    setRequestHeader(k, v) { this._h[k] = v }
    addEventListener(t, f) { this['on' + t] = f }
    getAllResponseHeaders() { return Object.entries(this._rh || {}).map(([k, v]) => k + ': ' + v).join('\r\n') }
    abort() {}
    send(body) {
      const self = this, url = String(this._u), p = url.split('?')[0].replace(/^https?:\/\/[^/]+/, '')
      if (/recaptcha\/api2\/(reload|userverify|anchor|bframe|payload|bg|jsn)/.test(url)) log('  [' + tag + ' XHR]', this._m, p, 'bodyLen=' + (body ? (body.byteLength || body.length || 0) : 0))
      if (process.env.NONET) { self.status = 200; self.responseText = ''; self.response = ''; self.readyState = 4; if (self.onload) self.onload(); if (self.onreadystatechange) self.onreadystatechange(); return }
      fetch(url, { method: this._m || 'GET', headers: { 'User-Agent': UA, ...this._h }, body: body || undefined })
        .then(async r => { self.status = r.status; self._rh = Object.fromEntries(r.headers); const b = Buffer.from(await r.arrayBuffer()); self.responseText = b.toString('latin1'); self.response = self.responseText; self.readyState = 4; if (self.onreadystatechange) self.onreadystatechange(); if (self.onload) self.onload() })
        .catch(e => { self.status = 0; self.readyState = 4; if (self.onerror) self.onerror(e); if (self.onreadystatechange) self.onreadystatechange() })
    }
  }
}

function buildRealm(role, extra, opts) {
  const pageWindow = !!(opts && opts.pageWindow)
  const missing = new Set(); let hotCanvas = 0
  const base = {
    __cap: {}, __ROLE: role,
    importScripts: () => {}, postMessage: () => {}, addEventListener: () => {}, removeEventListener: () => {}, onmessage: null, onerror: null, close: () => {},
    MessageChannel: MessageChannelShim, MessagePort: function () {},
    performance: makePerf(),
    navigator: { userAgent: UA, webdriver: false, deviceMemory: 8, hardwareConcurrency: 8, language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32', vendor: 'Google Inc.', product: 'Gecko', appName: 'Netscape', onLine: true, userAgentData: { brands: [{ brand: 'Chromium', version: '149' }], mobile: false, platform: 'Windows', getHighEntropyValues: () => Promise.resolve({}) }, sendBeacon: () => true, cookieEnabled: true, doNotTrack: null },
    XMLHttpRequest: makeXHR(role),
    location: { href: 'https://www.google.com/recaptcha/api2/webworker.js', origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/webworker.js', search: '', hash: '' },
    atob: s => Buffer.from(s, 'base64').toString('binary'), btoa: s => Buffer.from(s, 'binary').toString('base64'),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, requestAnimationFrame: f => setTimeout(() => f(Date.now()), 16), cancelAnimationFrame: () => {}, requestIdleCallback: f => setTimeout(() => f({ timeRemaining: () => 5, didTimeout: false }), 1), cancelIdleCallback: () => {},
    TextEncoder, TextDecoder, URL, URLSearchParams, crypto: require('crypto').webcrypto, fetch: (...a) => fetch(...a),
    console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
  }
  Object.assign(base, extra || {})
  for (const k of INTRINSICS) if (!(k in base)) try { base[k] = globalThis[k] } catch {}
  let globalRef
  const handler = { get(t, k) { if (typeof k === 'symbol') return t[k]; if (k === 'self' || k === 'globalThis') return globalRef; if (k === 'window') return pageWindow ? globalRef : undefined; if (k === 'top' || k === 'parent') return pageWindow ? globalRef : undefined; if (k === 'getContext' || k === 'toDataURL') hotCanvas++; if (k in t) return t[k]; missing.add(k); return undefined }, has() { return true }, set(t, k, v) { t[k] = v; return true } }
  const sandbox = Object.assign(Object.create(null), base)
  const ctx = vm.createContext(new Proxy(sandbox, handler)); globalRef = ctx
  let err = null
  try { vm.runInContext(CODE, ctx, { filename: 'recaptcha__en.js[' + role + ']', timeout: 20000 }) } catch (e) { err = e }
  return { ctx, sandbox, missing, err, get hotCanvas() { return hotCanvas } }
}

// ---------------------------------------------------------------------------
// 2) Measurement bus: record every large buffer crossing any boundary + all CE outputs.
// ---------------------------------------------------------------------------
const BIG = []                 // {where, role, len, head}
const BIG_FULL = new Map()     // rec -> full string (for >200KB artifacts)
let MAX = { len: 0 }
function note(where, role, val) {
  let len = 0, head = '', full = null
  try {
    if (typeof val === 'string') { len = val.length; head = val.slice(0, 46); full = val }
    else if (val && val.byteLength != null) { len = val.byteLength; head = Buffer.from(val.buffer || val).slice(0, 24).toString('latin1') }
    else if (Array.isArray(val)) { const j = JSON.stringify(val); len = j.length; head = j.slice(0, 46); full = j }
    else if (val && typeof val === 'object') { const j = JSON.stringify(val); len = j.length; head = j.slice(0, 46); full = j }
  } catch {}
  if (len >= 4096) { const rec = { where, role, len, head }; BIG.push(rec); if (full && len > 200000) BIG_FULL.set(rec, full); if (len > MAX.len) MAX = rec
    log('  [BIG @' + where + ' role=' + role + '] len=' + len + ' head=' + JSON.stringify(head)) }
  return val
}
const CE_CAP = []              // {role, len}
const SENDS = []               // {role, op, msgLen}

// ---------------------------------------------------------------------------
// 3) FakeWorker: spawn a worker realm (same bundle, worker role) over by-ref loopback.
//    Wire __CE/__SEND capture into the worker realm's globals.
// ---------------------------------------------------------------------------
let WORKER_REALM = null, WORKER_URLS = []
function makeFakeWorker() {
  return function FakeWorker(url) {
    WORKER_URLS.push(String(url))
    log('  [host] new Worker(', String(url).slice(0, 72), ')')
    const self_ = this; self_._lis = []; self_._on = null
    const wmsg = [], toPageQ = []
    function flush() { if (!(self_._on || self_._lis.length)) return; while (toPageQ.length) { const ev = toPageQ.shift(); if (self_._on) try { self_._on(ev) } catch (e) { if (TRACE) log('   worker->page onmessage threw', e.message) } for (const f of self_._lis) try { f(ev) } catch {} } }
    WORKER_REALM = buildRealm('worker', {
      __cap: {}, performance: makePerf(),
      __CE: (c) => { CE_CAP.push({ role: 'worker', len: (c && c.length) || 0 }); note('worker.CE', 'worker', c) },
      __SEND: (op, msg) => { const l = (() => { try { return JSON.stringify(msg).length } catch { return -1 } })(); SENDS.push({ role: 'worker', op, msgLen: l }); if (l >= 4096) note('worker.AE.send(' + op + ')', 'worker', msg) },
      postMessage: (m, transfer) => { note('worker->host.postMessage', 'worker', m); const tp = Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : []; toPageQ.push({ data: m, ports: tp }); flush() },
      addEventListener: (t, f) => { if (t === 'message') wmsg.push(f) },
    })
    function toWorker(ev) { const ws = WORKER_REALM.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch (e) { if (TRACE) log('   worker onmessage threw', e.message) } for (const f of wmsg) try { f(ev) } catch {} }
    self_.postMessage = (m, t) => { note('host->worker.postMessage', 'host', m); toWorker({ data: m, ports: (t || []).filter(x => x && x.__isPort) }) }
    self_.addEventListener = (t, f) => { if (t === 'message') { self_._lis.push(f); flush() } }
    self_.removeEventListener = (t, f) => { self_._lis = self_._lis.filter(x => x !== f) }
    self_.terminate = () => {}
    Object.defineProperty(self_, 'onmessage', { get() { return self_._on }, set(f) { self_._on = f; flush() } })
  }
}

// ---------------------------------------------------------------------------
// 4) Minimal HOST DOM (no canvas). Provides a g-recaptcha container so grecaptcha auto-renders.
// ---------------------------------------------------------------------------
function noop() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive || k === 'toString' || k === 'valueOf') return () => ''; if (k === 'length') return 0; if (k === 'nodeType') return 1; return P }, apply() { return P }, construct() { return P }, set() { return true }, has() { return true } }); return P }
const ALL_ELS = []
let anchorSrc = null
function makeEl(tag, id) {
  const lis = {}
  function fire(type, ev) { (lis[type] || []).slice().forEach(f => { try { f(ev || { type, target: P, currentTarget: P, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0 }) } catch {} }) }
  let _src = ''
  const real = { tagName: (tag || 'div').toUpperCase(), id: id || '', nodeType: 1, style: new Proxy({}, { get: () => '', set: () => true }), dataset: {}, classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
    addEventListener: (t, f) => { (lis[t] = lis[t] || []).push(f) }, removeEventListener: (t, f) => { if (lis[t]) lis[t] = lis[t].filter(x => x !== f) },
    setAttribute(k, v) { if (k === 'src') { _src = String(v); if (/api2\/anchor/.test(_src) && !anchorSrc) { anchorSrc = _src; log('  [host] anchor iframe src set') } } }, getAttribute: () => null, hasAttribute: () => false, removeAttribute() {}, appendChild: x => x, removeChild: x => x, insertBefore: x => x, replaceChild: x => x, remove() {}, contains: () => false,
    querySelector: () => makeEl('div'), querySelectorAll: () => [], getElementsByTagName: () => [makeEl('div')], getElementsByClassName: () => [makeEl('div')],
    getBoundingClientRect: () => ({ x: 0, y: 0, width: 28, height: 28, top: 0, left: 0, right: 28, bottom: 28 }), getClientRects: () => [],
    focus() {}, blur() {}, click() { fire('click') }, cloneNode() { return makeEl(tag, id) }, getContext: () => null, setPointerCapture() {}, releasePointerCapture() {},
    children: [], childNodes: [], firstChild: null, lastChild: null, parentNode: null, nextSibling: null, previousSibling: null, ownerDocument: null,
    innerHTML: '', outerHTML: '', textContent: '', value: '', checked: false, disabled: false, offsetWidth: 28, offsetHeight: 28, offsetParent: null,
    dispatchEvent(ev) { fire(ev && ev.type, ev); return true }, _lis: lis, _fire: fire }
  Object.defineProperty(real, 'src', { get() { return _src }, set(v) { real.setAttribute('src', v) }, configurable: true })
  if ((tag || '').toLowerCase() === 'iframe') {
    Object.defineProperty(real, 'contentWindow', { configurable: true, get() { return { JSON, Array, Object, postMessage() {}, addEventListener() {}, removeEventListener() {}, location: { href: 'about:blank', origin: 'null' }, document: { createElement: () => makeEl('div') } } } })
    Object.defineProperty(real, 'contentDocument', { configurable: true, get: () => ({ createElement: () => makeEl('div'), documentElement: makeEl('html'), body: makeEl('body') }) })
  }
  const P = new Proxy(real, { get(t, k) { if (k in t) return t[k]; if (typeof k === 'string' && /^on/.test(k)) return t['__' + k] || null; return noop() }, set(t, k, v) { t[k] = v; return true }, has() { return true } })
  ALL_ELS.push(real); return P
}
const container = makeEl('div', 'cap'); container.className = 'g-recaptcha'; container.dataset.sitekey = SITEKEY
container.getAttribute = k => (k === 'data-sitekey' ? SITEKEY : (k === 'data-size' ? 'normal' : null)); container.hasChildNodes = () => false
const ELS = { cap: container }
const document = new Proxy({
  createElement: t => makeEl(t), createElementNS: (ns, t) => makeEl(t), createDocumentFragment: () => makeEl('fragment'), createTextNode: () => makeEl('text'), createComment: () => makeEl('comment'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
  getElementById: id => (ELS[id] = ELS[id] || makeEl('div', id)),
  querySelector: s => (/g-recaptcha/.test(s) ? container : (ELS['q:' + s] = ELS['q:' + s] || makeEl('div', 'q:' + s))),
  querySelectorAll: s => (/g-recaptcha/.test(s) ? [container] : []),
  getElementsByTagName: () => [], getElementsByClassName: s => (/g-recaptcha/.test(s) ? [container] : []), getElementsByName: () => [],
  documentElement: makeEl('html'), head: makeEl('head'), body: makeEl('body'), cookie: '', referrer: HOST_ORIGIN + '/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
}, { get(t, k) { if (k in t) return t[k]; return noop() }, has() { return true } })

// host window.postMessage: this is how the host would ship the program to the anchor (transfer a
// port + the "x" frame). Capture the data (and any transferred ports we can later tap).
const WIN_POSTS = []
function hostPostMessage(data, targetOrigin, transfer) { WIN_POSTS.push({ data, targetOrigin }); note('host.window.postMessage', 'host', data) }

// ---------------------------------------------------------------------------
// 5) Boot the HOST realm exactly like api.js, WITH a real worker, and drive it.
// ---------------------------------------------------------------------------
const HOST_AES = []
const hostLis = {}
;(async () => {
  process.on('unhandledRejection', e => { if (TRACE) log('  [unhandledRejection]', e && e.message) })
  log('[gen] sitekey=%s host=%s ver=%s', SITEKEY, HOST_ORIGIN, VER)

  const extra = {
    __cap: {},
    __CE: (c) => { CE_CAP.push({ role: 'host', len: (c && c.length) || 0 }); note('host.CE', 'host', c) },
    __SEND: (op, msg) => { const l = (() => { try { return JSON.stringify(msg).length } catch { return -1 } })(); SENDS.push({ role: 'host', op, msgLen: l }); if (l >= 4096) note('host.AE.send(' + op + ')', 'host', msg) },
    __onAE: (ae) => { HOST_AES.push(ae); if (TRACE) log('  [host __onAE] AE instance #' + HOST_AES.length); return ae },
    Worker: makeFakeWorker(),
    document,
    addEventListener: (t, f) => { /* host window listeners (message intake) */ (hostLis[t] = hostLis[t] || []).push(f) },
    removeEventListener: () => {},
    postMessage: hostPostMessage,
    performance: makePerf(),
    XMLHttpRequest: makeXHR('host'),
    location: { href: HOST_ORIGIN + '/', origin: HOST_ORIGIN, protocol: 'https:', host: ORIGIN_HOST, hostname: ORIGIN_HOST, pathname: '/', search: '', hash: '', replace() {}, assign() {}, reload() {} },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 1280, innerHeight: 800, outerWidth: 1280, outerHeight: 880, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    __recaptcha_api: 'https://www.google.com/recaptcha/api2/', __google_recaptcha_client: true,
    ___grecaptcha_cfg: { fns: [], render: ['onload'], 'anchor-ms': [20000], 'execute-ms': [30000] },
  }
  extra.grecaptcha = { ready: function (f) { extra.___grecaptcha_cfg.fns.push(f) } }

  log('[gen] booting HOST (api.js) realm with a REAL worker...')
  const host = buildRealm('host', extra, { pageWindow: true })
  log('[gen] host load:', host.err ? 'THREW ' + host.err.message : 'OK')
  const gr = host.sandbox.grecaptcha
  log('[gen] grecaptcha api:', gr ? Object.keys(gr).join(',') : '(none)')
  log('[gen] cfg.clients at load:', Object.keys(host.sandbox.___grecaptcha_cfg.clients || {}).length)

  await new Promise(r => setTimeout(r, 200))
  log('[gen] anchor iframe created:', !!anchorSrc, anchorSrc ? anchorSrc.slice(0, 90) : '')

  // Explicit render (in case auto-render didn't fire) + execute to force the challenge/bgRequest.
  try { if (gr && typeof gr.render === 'function' && !anchorSrc) { const id = gr.render('cap', { sitekey: SITEKEY }); log('[gen] grecaptcha.render ->', id) } } catch (e) { log('[gen] render threw:', e.message) }
  await new Promise(r => setTimeout(r, 300))

  // fire the checkbox click (whatever element registered a click listener) to trigger verify.
  function clickAll(tag) { const cl = ALL_ELS.filter(el => el._lis && (el._lis.click || el._lis.mousedown || el._lis.pointerdown)); log('[gen] ' + tag + ' clickable els:', cl.length); for (const el of cl) { try { el._fire('pointerdown'); el._fire('mousedown'); el._fire('click'); el._fire('mouseup'); el._fire('pointerup') } catch {} } }

  // wait for the worker to spawn
  for (let s = 0; s < 24 && !WORKER_REALM; s++) await new Promise(r => setTimeout(r, 250))
  log('[gen] worker spawned:', !!WORKER_REALM, '| worker load:', WORKER_REALM ? (WORKER_REALM.err ? 'THREW ' + WORKER_REALM.err.message : 'OK') : 'n/a')

  await new Promise(r => setTimeout(r, 1500))
  clickAll('host')
  try { if (gr && typeof gr.execute === 'function') { log('[gen] calling grecaptcha.execute()...'); gr.execute() } } catch (e) { log('[gen] execute threw:', e.message) }
  await new Promise(r => setTimeout(r, 2500))
  clickAll('host')
  await new Promise(r => setTimeout(r, 1500))

  log('\n[gen] ---- PHASE 1 (render/execute only) done. host window "message" listeners:', (hostLis.message || []).length, '----')

  // =========================================================================
  // PHASE 2: establish the TOP<->ANCHOR channel by delivering a synthetic
  // "recaptcha-setup" + a loopback port to the host, capture the host-side AE,
  // then (a) REPLAY the real captured anchor->top frames (tests session-keying),
  // and (b) enumerate + directly invoke the host AE's opcode handlers (bypasses
  // the codec) to try to fire the "D" generator.  The anchor's request that mints
  // the 288KB program is messageType "D" (comm_full.json: anchor.out#4 -> in#4).
  // =========================================================================
  let REPLAY_DECODED = 0, REPLAY_FRAMES = 0, DIRECT_RESULTS = []
  try {
    const ch = new MessageChannelShim(); const aPort = ch.port1, bPort = ch.port2  // b -> host, a -> me
    const meIn = []
    aPort.onmessage = (ev) => { const d = ev && ev.data; meIn.push(d); note('host->me(port)', 'host', d); if (TRACE) log('   [me<-host port] ' + (typeof d === 'string' ? 'str(' + d.length + ')' : (d && d.constructor && d.constructor.name)) ) }
    const fakeAnchorWin = { __isWindow: true, postMessage: (d) => { note('host->anchorWin', 'host', d) }, addEventListener() {}, removeEventListener() {}, location: { origin: 'https://www.google.com' } }
    const setupEv = { data: 'recaptcha-setup', origin: 'https://www.google.com', source: fakeAnchorWin, ports: [bPort], type: 'message', preventDefault() {}, stopPropagation() {} }
    const nAEbefore = HOST_AES.length
    log('[gen] delivering synthetic "recaptcha-setup"+port to host (' + (hostLis.message || []).length + ' listeners)...')
    for (const f of (hostLis.message || []).slice()) { try { f(setupEv) } catch (e) { log('   setup listener threw:', e.message) } }
    await new Promise(r => setTimeout(r, 400))
    log('[gen] host AEs after setup:', HOST_AES.length, '(was', nAEbefore + ')')
    HOST_AES.forEach((ae, i) => { let keys = '?'; try { const inner = ae.P && (ae.P._inner || ae.P); keys = inner && inner.keys ? [...inner.keys()].map(String).join(',') : (ae.P && ae.P.size != null ? 'size=' + ae.P.size : '?') } catch {} let pid = '?'; try { pid = ae.D && ae.D.__id } catch {} log('   AE#' + i + ' port=' + pid + ' handlerOpcodes=[' + keys + ']') })

    // Print the D/E handler source (locate the generator in the file by its minified body).
    for (const ae of HOST_AES) { const inner = ae.P && (ae.P._inner || ae.P); if (!inner || !inner.get) continue
      for (const K of ['D', 'E']) { try { const h = inner.get(K); if (typeof h === 'function') { const src = h.toString(); log('[gen] handler "' + K + '" src(' + src.length + '): ' + src.slice(0, 220).replace(/\n/g, ' ')) } } catch {} } }

    // (a) REPLAY the real captured anchor->top frames onto the PEER of the host AE's bound port
    // (so the host decodes them on its own port). Tests whether the codec is session-keyed.
    let real = null
    try { const cf = JSON.parse(fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/comm_full.json', 'utf8')); real = cf.anchor && cf.anchor.out } catch {}
    const hostAE = HOST_AES[0]
    const hostPort = hostAE && hostAE.D
    const peer = hostPort && hostPort._peer
    log('[gen] host AE bound port id=' + (hostPort && hostPort.__id) + ' peer id=' + (peer && peer.__id))
    if (real && real.length && peer && peer.postMessage) {
      // capture whatever the host emits back on its port
      try { const op = hostPort.postMessage.bind(hostPort); hostPort.postMessage = (d, t) => { note('hostAE.port.out', 'host', d); return op(d, t) } } catch {}
      // DONLY=1 -> replay ONLY the "D" frame (index 4) to test if the preamble is required.
      const frames = process.env.DONLY ? real.slice(4, 5) : real.slice(0, 6)
      log('[gen] replaying ' + frames.length + ' real anchor->top frames onto host AE peer port' + (process.env.DONLY ? ' [DONLY]' : '') + '...')
      let fi = process.env.DONLY ? 4 : 0
      for (const frame of frames) { REPLAY_FRAMES++
        let mt = '?'; try { mt = JSON.parse(frame)[1] } catch {}
        const beforeMax = MAX.len
        try { peer.postMessage(frame) } catch (e) {}
        await new Promise(r => setTimeout(r, 300))
        log('   replayed frame#' + fi + ' mt=' + JSON.stringify(mt) + ' len=' + frame.length + (MAX.len > beforeMax ? '  ==> host emitted ' + MAX.len + 'B' : ''))
        fi++
      }
      await new Promise(r => setTimeout(r, 1200))
      log('[gen] after replay: host AE.send count=' + SENDS.length + ' | CE calls=' + CE_CAP.length + ' | BIG=' + BIG.length)
      // save the generated program artifact + compare to the real captured one
      const gen = BIG.filter(b => b.len > 200000).sort((a, b) => b.len - a.len)[0]
      if (gen) {
        try {
          const full = BIG_FULL.get(gen) || ''
          fs.writeFileSync(path.join(__dirname, 'generated_bgprogram.txt'), full)
          const realProg = (JSON.parse(fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/comm_full.json', 'utf8')).anchor.in.find(m => m.length > 200000)) || ''
          let cp = 0; while (cp < full.length && cp < realProg.length && full[cp] === realProg[cp]) cp++
          log('[gen] generated program: ' + full.length + 'B | real captured: ' + realProg.length + 'B | commonPrefix=' + cp + ' chars')
          log('[gen]   gen head : ' + JSON.stringify(full.slice(0, 60)))
          log('[gen]   real head: ' + JSON.stringify(realProg.slice(0, 60)))
        } catch (e) { log('[gen] artifact save err', e.message) }
      }
    } else log('[gen] replay skipped (real frames=' + (real ? real.length : 0) + ' peer=' + !!peer + ')')

    // (b) DIRECT handler invocation with a permissive Proxy payload (bypasses codec). The "D"
    // handler reads payload.Oo() etc.; a self-returning proxy lets it proceed to see if the
    // program is built from TOP-side state/entropy (size), independent of payload content.
    function permissive() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive) return () => 1; if (k === 'length') return 0; if (typeof k === 'symbol') return undefined; return P }, apply() { return P }, construct() { return P }, has() { return true } }); return P }
    const candidates = [undefined, {}, [], permissive()]
    for (const ae of HOST_AES) {
      const inner = ae.P && (ae.P._inner || ae.P)
      let opcodes = []; try { opcodes = inner && inner.keys ? [...inner.keys()] : [] } catch {}
      for (const K of opcodes) {
        let h; try { h = (inner.get ? inner.get(K) : null) } catch {}
        if (typeof h !== 'function') continue
        for (const pay of candidates) {
          const beforeMax = MAX.len
          const label = pay === undefined ? 'undef' : (pay && pay.__proto__ === undefined ? 'proxy' : (typeof pay === 'object' ? JSON.stringify(pay) : String(pay)))
          try { const r = h.call(ae.C, pay, K); await Promise.resolve(r).catch(() => {}) }
          catch (e) { DIRECT_RESULTS.push({ op: String(K), pay: label, err: (e && e.message || '').slice(0, 70) }); continue }
          await new Promise(r => setTimeout(r, 10))
          DIRECT_RESULTS.push({ op: String(K), pay: label, produced: MAX.len > beforeMax ? MAX.len : 0, ok: true })
        }
      }
    }
    log('[gen] direct-invocation results:', DIRECT_RESULTS.length)
    DIRECT_RESULTS.slice(0, 30).forEach(r => log('   op=' + JSON.stringify(r.op) + ' pay=' + r.pay + (r.ok ? (r.produced ? ' -> PRODUCED ' + r.produced + 'B' : ' -> ran, no big buffer') : ' -> throw: ' + r.err)))
  } catch (e) { log('[gen] phase2 threw:', e && e.stack || e) }
  await new Promise(r => setTimeout(r, 1500))

  // ---- REPORT ----
  log('\n[gen] ================= RESULT =================')
  log('worker spawned         :', !!WORKER_REALM, '| worker URL(s):', WORKER_URLS.map(u => u.slice(0, 70)).join(' , ') || '(none)')
  log('HOST canvas/webgl reads:', host.hotCanvas, '| WORKER canvas/webgl reads:', WORKER_REALM ? WORKER_REALM.hotCanvas : 'n/a')
  log('CE serializer calls    :', CE_CAP.length, JSON.stringify(CE_CAP))
  log('AE.send calls          :', SENDS.length, '| by op:', JSON.stringify(SENDS.reduce((a, s) => { a[s.role + ':' + s.op] = (a[s.role + ':' + s.op] || 0) + 1; return a }, {})))
  log('host window.postMessage:', WIN_POSTS.length)
  log('BIG buffers (>=4KB)    :', BIG.length)
  BIG.sort((a, b) => b.len - a.len).slice(0, 12).forEach(b => log('   ' + String(b.len).padStart(7) + 'B  ' + b.where.padEnd(28) + ' role=' + b.role + ' head=' + JSON.stringify(b.head)))
  log('\n>>> LARGEST BotGuard-related buffer: ' + MAX.len + 'B  (' + (MAX.where || '-') + ' role=' + (MAX.role || '-') + ')')
  const ok = MAX.len >= 250000 && MAX.len <= 360000
  log('>>> VERDICT: ' + (ok ? 'SUCCESS — produced a 250-350KB program from a fresh node-vm run (no browser).' : 'PARTIAL — largest buffer ' + MAX.len + 'B; see gap analysis in the report.'))
  try { fs.writeFileSync(path.join(__dirname, 'gen_probe_result.json'), JSON.stringify({ ts: Date.now(), ver: VER, workerSpawned: !!WORKER_REALM, workerUrls: WORKER_URLS, ceCap: CE_CAP, sends: SENDS.slice(0, 40), big: BIG.sort((a, b) => b.len - a.len).slice(0, 20), max: MAX, verdict: ok ? 'SUCCESS' : 'PARTIAL' }, null, 1)) } catch {}
  process.exit(0)
})()
