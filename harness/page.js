// Two-realm self-driving harness: run recaptcha__en.js in PAGE mode (minimal document
// stub — no canvas, per the GO finding) AND in WORKER mode, wired by an in-process loopback,
// so Google's own client code drives the BotGuard handshake itself (program -> attestation),
// instead of us reverse-engineering the bidirectional RPC. Goal milestone: page boots, spawns
// the worker, completes the handshake (worker receives the program), and a page-side bg client
// appears. XHR is routed to real network (node fetch suffices for fetch/reload).
'use strict'
const fs = require('fs')
const vm = require('vm')
const ENJS = process.env.ENJS || (__dirname + '/../recaptcha__en.js')
const PR = require('./page_rpc.js')
// expose the AE class via __cap and fire __onAE(instance) at the end of every AE ctor, so the
// page-side BotGuard client AE gets a catch-all handler set (no worker "x" request can stall it).
let CODE = PR.applyPatches(fs.readFileSync(ENJS, 'utf8'))
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const log = (...a) => console.log(...a)

const INTRINSICS = ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'EvalError', 'ReferenceError', 'SyntaxError', 'URIError', 'Reflect', 'Proxy', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'parseInt', 'parseFloat', 'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape', 'isNaN', 'isFinite', 'Intl', 'structuredClone', 'Infinity', 'NaN', 'undefined', 'globalThis']

// ---- shared loopback MessagePort (by reference; same objects cross both realms) ----
function makePort() {
  const p = { __isPort: true, _peer: null, _started: false, _q: [], _on: null, _lis: [],
    get onmessage() { return this._on }, set onmessage(f) { this._on = f; this._started = true; this._flush() },
    addEventListener(t, f) { if (t === 'message') { this._lis.push(f); this._started = true; this._flush() } },
    removeEventListener(t, f) { this._lis = this._lis.filter(x => x !== f) },
    start() { this._started = true; this._flush() }, close() { this._closed = true }, dispatchEvent() { return true },
    postMessage(data, transfer) { const ports = (transfer || []).filter(x => x && x.__isPort); const ev = { data, ports, type: 'message', target: this._peer }; if (process.env.TRACE) { try { console.log('   [port', this.__id, '->', this._peer && this._peer.__id, ']', typeof data === 'string' ? 'str(' + data.length + '):' + data.slice(0, 30) : (data && data.constructor ? data.constructor.name : typeof data)) } catch {} } queueMicrotask(() => this._peer && this._peer._deliver(ev)) },
    _deliver(ev) { if (this._closed) return; if (!this._started) { this._q.push(ev); return } if (this._on) try { this._on(ev) } catch (e) { if (process.env.DECTRACE || process.env.TRACE) console.log('   [port', this.__id, 'onmessage THREW]', e && (e.stack || e.message)) } for (const f of this._lis) try { f(ev) } catch (e) { if (process.env.DECTRACE || process.env.TRACE) console.log('   [port', this.__id, 'listener THREW]', e && (e.stack || e.message)) } },
    _flush() { if (!this._started) return; const q = this._q; this._q = []; for (const ev of q) this._deliver(ev) } }
  return p
}
let __portN = 0
function MessageChannelShim() { const a = makePort(), b = makePort(); a.__id = ++__portN; b.__id = ++__portN; a._peer = b; b._peer = a; this.port1 = a; this.port2 = b }

// ---- network: route the VM's XHR to node fetch (fetch/reload work over plain TLS) ----
const XHR_REQS = []   // {m,u,body} of every request the VM issues
function makeXHR() {
  return class XHR {
    constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = '' }
    open(m, u) { this._m = m; this._u = u }
    setRequestHeader(k, v) { this._h[k] = v }
    addEventListener(t, f) { this['on' + t] = f }
    getAllResponseHeaders() { return Object.entries(this._rh || {}).map(([k, v]) => k + ': ' + v).join('\r\n') }
    abort() {}
    send(body) {
      const self = this
      const path = String(this._u).split('?')[0].replace(/^https?:\/\/[^/]+/, '')
      XHR_REQS.push({ m: this._m, u: this._u, path, bodyLen: body ? (body.byteLength || body.length || 0) : 0, body })
      if (/recaptcha\/api2\/(reload|userverify|replaceimage|anchor|bframe)/.test(this._u)) console.log('  [XHR]', this._m, path, 'bodyLen=' + (body ? (body.byteLength || body.length || 0) : 0))
      fetch(this._u, { method: this._m || 'GET', headers: { 'User-Agent': UA, ...this._h }, body: body || undefined })
        .then(async r => { self.status = r.status; self._rh = Object.fromEntries(r.headers); const buf = Buffer.from(await r.arrayBuffer()); self.responseText = buf.toString('latin1'); self.response = self.responseText; self.readyState = 4; if (self.onreadystatechange) self.onreadystatechange(); if (self.onload) self.onload(); })
        .catch(e => { self.status = 0; self.readyState = 4; if (self.onerror) self.onerror(e); if (self.onreadystatechange) self.onreadystatechange() })
    }
  }
}

// ---- shared browser-env realism (field16 / BotGuard env attestation) ----------------------
// Real Edge/Chrome 149 on Windows: UA-CH high-entropy that RESOLVES (empty -> "UACH unavailable"
// hard bot tell), non-empty plugins/mimeTypes, window.chrome with an h2 loadTimes(), Notification.
// These are the specific, statically-visible surfaces the BotGuard bytecode + gU/Xm builders probe.
const EDGE_BRANDS = [{ brand: 'Chromium', version: '149' }, { brand: 'Microsoft Edge', version: '149' }, { brand: 'Not.A/Brand', version: '24' }]
const EDGE_FULLVER = [{ brand: 'Chromium', version: '149.0.0.0' }, { brand: 'Microsoft Edge', version: '149.0.0.0' }, { brand: 'Not.A/Brand', version: '24.0.0.0' }]
function makePlugins() {
  const defs = [
    ['PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
    ['Chrome PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
    ['Chromium PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
    ['Microsoft Edge PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
    ['WebKit built-in PDF', 'internal-pdf-viewer', 'Portable Document Format'],
  ]
  const mt1 = { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' }
  const mt2 = { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format' }
  const arr = defs.map(([name, filename, description]) => {
    const p = { name, filename, description, length: 2, 0: mt1, 1: mt2, item: i => [mt1, mt2][i] || null, namedItem: t => (t === mt1.type ? mt1 : t === mt2.type ? mt2 : null) }
    return p
  })
  arr.item = i => arr[i] || null
  arr.namedItem = n => arr.find(p => p.name === n) || null
  arr.refresh = () => {}
  try { Object.defineProperty(arr, 'length', { value: defs.length, enumerable: false }) } catch {}
  return arr
}
function makeMimeTypes() {
  const mt1 = { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: null }
  const mt2 = { type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: null }
  const arr = [mt1, mt2]
  arr.item = i => arr[i] || null
  arr.namedItem = n => arr.find(m => m.type === n) || null
  return arr
}
function makeChrome() {
  const s = () => Date.now() / 1000
  return {
    app: { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }, getDetails: () => null, getIsInstalled: () => false, runningState: () => 'cannot_run' },
    runtime: { OnInstalledReason: {}, OnRestartRequiredReason: {}, PlatformArch: {}, PlatformNaclArch: {}, PlatformOs: {}, RequestUpdateCheckStatus: {}, connect: () => ({}), sendMessage: () => {}, id: undefined },
    csi: () => ({ onloadT: Date.now(), startE: Date.now() - 480, pageT: 320 + Math.random() * 900, tran: 15 }),
    loadTimes: () => ({ requestTime: s() - 1.2, startLoadTime: s() - 1.15, commitLoadTime: s() - 1.0, finishDocumentLoadTime: s() - 0.6, finishLoadTime: s() - 0.4, firstPaintTime: s() - 0.5, firstPaintAfterLoadTime: 0, navigationType: 'Other', wasFetchedViaSpdy: true, wasNpnNegotiated: true, npnNegotiatedProtocol: 'h2', wasAlternateProtocolAvailable: false, connectionInfo: 'h2' }),
  }
}
function makeNavigator() {
  return {
    userAgent: UA, appVersion: UA.replace('Mozilla/', ''), appName: 'Netscape', appCodeName: 'Mozilla',
    webdriver: false, deviceMemory: 8, hardwareConcurrency: 8, maxTouchPoints: 0,
    language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32', oscpu: undefined,
    vendor: 'Google Inc.', vendorSub: '', product: 'Gecko', productSub: '20030107',
    onLine: true, cookieEnabled: true, doNotTrack: null, pdfViewerEnabled: true,
    userAgentData: {
      brands: EDGE_BRANDS.slice(), mobile: false, platform: 'Windows',
      getHighEntropyValues: (hints) => Promise.resolve({
        architecture: 'x86', bitness: '64', brands: EDGE_BRANDS.slice(), fullVersionList: EDGE_FULLVER.slice(),
        mobile: false, model: '', platform: 'Windows', platformVersion: '15.0.0', uaFullVersion: '149.0.0.0', wow64: false,
      }),
      toJSON() { return { brands: this.brands, mobile: this.mobile, platform: this.platform } },
    },
    plugins: makePlugins(), mimeTypes: makeMimeTypes(),
    permissions: { query: () => Promise.resolve({ state: 'prompt', onchange: null }) },
    sendBeacon: () => true, javaEnabled: () => false, vibrate: () => false, getBattery: () => Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1 }),
  }
}

// ---- build a realm running recaptcha__en.js; role decided by presence of `document` ----
function buildRealm(role, extra, opts) {
  const pageWindow = !!(opts && opts.pageWindow)
  const accessed = new Map(); const missing = new Set(); const HOT = ['canvas', 'getContext', 'toDataURL', 'webgl', 'getParameter']
  const hot = []
  const note = k => { accessed.set(k, (accessed.get(k) || 0) + 1); if (HOT.includes(k)) hot.push(k) }
  let T0 = Date.now(); let heap = 12_000_000
  // Chrome-realistic fallback perf (the driver realms override this with realism.makePerf, but a
  // realm that doesn't must NOT expose the old Math.random now()/2.2e9-limit/empty-getEntriesByType
  // tells the ak/Xm attestation + @43227 HTTP/2 check read). timeOrigin real, heap quantized,
  // getEntriesByType('navigation') -> nextHopProtocol h2.
  let perf
  try {
    const R = require('./realism.js')
    perf = R.makePerf({ resourceHost: (extra && extra.location && (extra.location.hostname || (extra.location.host))) || 'lucille.sh' })
    perf.memory.jsHeapSizeLimit = 2172649472
  } catch (e) {
    perf = { now: () => Date.now() - T0, memory: { get usedJSHeapSize() { return heap }, totalJSHeapSize: 42_000_000, jsHeapSizeLimit: 2172649472 }, timeOrigin: Date.now(), getEntriesByType: t => (t === 'navigation' ? [{ entryType: 'navigation', nextHopProtocol: 'h2', startTime: 0, type: 'navigate', responseStatus: 200 }] : []), mark() {}, measure() {}, clearMarks() {}, clearMeasures() {} }
  }
  const base = {
    __cap: {},   // patched `AE=__cap.AE=...` writes here; present in BOTH realms so the assign can't throw
    importScripts: () => {}, postMessage: () => {}, addEventListener: () => {}, removeEventListener: () => {}, onmessage: null, onerror: null, close: () => {},
    MessageChannel: MessageChannelShim, MessagePort: function () {},
    performance: perf,
    navigator: makeNavigator(),
    chrome: makeChrome(),
    Notification: Object.assign(function Notification() {}, { permission: 'default', requestPermission: () => Promise.resolve('default'), maxActions: 2 }),
    XMLHttpRequest: makeXHR(),
    location: { href: 'https://www.google.com/recaptcha/api2/webworker.js', origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/webworker.js', search: '', hash: '' },
    atob: s => Buffer.from(s, 'base64').toString('binary'), btoa: s => Buffer.from(s, 'binary').toString('base64'),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, requestAnimationFrame: f => setTimeout(() => f(Date.now()), 16), cancelAnimationFrame: () => {}, requestIdleCallback: f => setTimeout(() => f({ timeRemaining: () => 5, didTimeout: false }), 1), cancelIdleCallback: () => {},
    TextEncoder, TextDecoder, URL, URLSearchParams, crypto: require('crypto').webcrypto, fetch: (...a) => fetch(...a),
    console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
  }
  Object.assign(base, extra || {})
  for (const k of INTRINSICS) if (!(k in base)) try { base[k] = globalThis[k] } catch {}
  let globalRef
  // opts.parentRef: when set, window.parent / window.top resolve to it (a framed page whose
  // parent is a DISTINCT window object, e.g. the bframe: window===self but parent===host). When
  // absent, behaviour is unchanged (pageWindow -> self; else undefined).
  const parentRef = opts && opts.parentRef
  const handler = { get(t, k) { if (typeof k === 'symbol') return t[k]; if (k === 'self' || k === 'globalThis') return globalRef; if (k === 'window') return pageWindow ? globalRef : undefined; if (k === 'top' || k === 'parent') return parentRef ? parentRef : (pageWindow ? globalRef : undefined); if (k in t) { note(k); return t[k] } note(k); missing.add(k); return undefined }, has() { return true }, set(t, k, v) { t[k] = v; return true } }
  const sandbox = Object.assign(Object.create(null), base)
  const ctx = vm.createContext(new Proxy(sandbox, handler)); globalRef = ctx
  let err = null
  try { vm.runInContext(CODE, ctx, { filename: `recaptcha__en.js[${role}]`, timeout: 20000 }) } catch (e) { err = e }
  // Function.prototype.toString native-code spoof: the BotGuard bytecode probes String(fn) for
  // "[native code]" on env stubs (perf.now, navigator.*, XHR, observers, ...). Install AFTER the
  // bundle loads and BEFORE init/ak is driven, so hand-stubbed funcs read native but the bundle's
  // own functions still print real source. Gated by NOSPOOF=1; never fatal.
  if (!(opts && opts.noRealism) && !process.env.NOSPOOF) {
    try { const R = require('./realism.js'); const mark = R.installNativeToString(ctx, vm); R.markRealmNatives(sandbox, mark) } catch (e) { if (process.env.TRACE) console.log('  [realism spoof skip]', role, e && e.message) }
  }
  return { ctx, sandbox, accessed, missing, hot, err, setHeap: v => { heap = v } }
}

module.exports = { makePort, MessageChannelShim, buildRealm, makeXHR, XHR_REQS }

if (require.main === module) {
  process.on('unhandledRejection', () => {})
  // WORKER realm: spawned lazily when the page does new Worker(url)
  let workerRealm = null, workerOut = null, pageWorkerPort = null
  function FakeWorker(url) {
    log('[page] new Worker(', String(url).slice(0, 70), ')')
    const self_ = this
    self_._lis = []; self_._on = null
    const wmsgListeners = []     // worker self.addEventListener('message') handlers
    const toPageQ = []           // worker -> page messages, queued until page sets a handler
    const TR = process.env.TRACE
    const d = m => { try { return typeof m === 'string' ? 'str(' + m.length + '):' + m.slice(0, 24) : (m && m.constructor ? m.constructor.name : typeof m) } catch { return '?' } }
    function flushToPage() { if (!(self_._on || self_._lis.length)) return; while (toPageQ.length) { const ev = toPageQ.shift(); if (TR) log('   [w->p] deliver', d(ev.data), 'ports=' + (ev.ports || []).length); if (self_._on) try { self_._on(ev) } catch (e) { if (TR) log('   page onmessage threw', e.message) } for (const f of self_._lis) try { f(ev) } catch (e) {} } }
    // build the worker realm; its bootstrap posts "recaptcha-setup" SYNCHRONOUSLY during this call,
    // so the postMessage stub queues it (toPageQ) until the page registers worker.onmessage.
    workerRealm = buildRealm('worker', {
      postMessage: (m, transfer) => { const tp = Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : []; if (tp.length && !pageWorkerPort) { pageWorkerPort = tp[0]; log('[page] captured worker-transferred port (d5 handshake) -> page-side AE handler set will bind here') } toPageQ.push({ data: m, ports: tp }); flushToPage() },
      addEventListener: (t, f) => { if (t === 'message') wmsgListeners.push(f) },
    })
    function deliverToWorker(ev) { if (TR) log('   [p->w] deliver', d(ev.data), 'ports=' + (ev.ports || []).length); const ws = workerRealm.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch (e) { if (TR) log('   worker onmessage threw', e.message) } for (const f of wmsgListeners) try { f(ev) } catch (e) {} }
    self_.postMessage = (m, t) => deliverToWorker({ data: m, ports: (t || []).filter(x => x && x.__isPort) })
    self_.addEventListener = (t, f) => { if (t === 'message') { if (TR) log('   [page] worker.addEventListener(message)'); self_._lis.push(f); flushToPage() } }
    self_.removeEventListener = (t, f) => { self_._lis = self_._lis.filter(x => x !== f) }
    self_.terminate = () => {}
    Object.defineProperty(self_, 'onmessage', { get() { return self_._on }, set(f) { if (TR) log('   [page] set worker.onmessage'); self_._on = f; flushToPage() } })
  }

  // DOM stub (page mode; no canvas). Elements capture event listeners so we can fire the
  // checkbox 'click' that triggers the verify -> /reload flow.
  function noop() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive || k === 'toString' || k === 'valueOf') return () => ''; if (k === 'length') return 0; if (k === 'nodeType') return 1; if (k === 'parentNode' || k === 'ownerDocument' || k === 'style' || k === 'dataset' || k === 'classList') return P; return P }, apply() { return P }, construct() { return P }, set() { return true }, has() { return true } }); return P }
  const ELS = {}
  const ALL_ELS = []
  function makeEl(tag, id) {
    const lis = {}
    function fire(type, ev) { (lis[type] || []).slice().forEach(f => { try { f(ev || { type, target: P, currentTarget: P, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0 }) } catch (e) {} }) }
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
    ALL_ELS.push(real)
    return P
  }
  const docEl = makeEl('html')
  const document = new Proxy({
    createElement: (t) => makeEl(t), createElementNS: (ns, t) => makeEl(t), createDocumentFragment: () => makeEl('fragment'), createTextNode: () => makeEl('text'), createComment: () => makeEl('comment'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
    getElementById: (id) => (ELS[id] = ELS[id] || makeEl('div', id)), querySelector: (s) => (ELS['q:' + s] = ELS['q:' + s] || makeEl('div', 'q:' + s)), querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], getElementsByName: () => [],
    documentElement: docEl, head: makeEl('head'), body: makeEl('body'), cookie: '', referrer: 'https://www.google.com/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat', _els: ELS,
  }, { get(t, k) { if (k in t) return t[k]; return noop() }, has() { return true } })

  const windowExtra = {
    Worker: FakeWorker,
    // page-side AE handler set: install a catch-all `.P` on every page-realm AE (merge-preserving,
    // so any real handlers survive) so the worker's inbound "x" requests get a same-callid MZ ack
    // within the 15s watchdog instead of a V3 / timeout. Logs each inbound opcode+payload so the
    // ack set can later be specialised by diffing against a real-browser worker->page capture.
    __onAE: PR.makeOnAE({
      getPort: () => pageWorkerPort,
      log: (...a) => log('  [page-rpc]', ...a),
      onRequest: (K, payload) => { /* diff hook: real worker->page request opcode + payload */ },
    }),
    document,
    location: { href: 'https://www.google.com/recaptcha/api2/anchor?k=6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-&co=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDM&hl=en&v=TnA7HacJFoBWt9hnlunBlYfK&size=normal', origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/anchor', search: '?k=6Le-wvkS', hash: '', replace() {}, assign() {}, reload() {} },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1080, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), parent: null, top: null, frameElement: null, scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, Event: function () { return noop() }, CustomEvent: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
  }
  // page mode: window/top/parent resolve to the global (handled in buildRealm get-trap)

  const SITEKEY = '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-', VER = 'TnA7HacJFoBWt9hnlunBlYfK'
  function extractInitCall(html) {
    const key = 'recaptcha.anchor.Main.init('
    const i = html.indexOf(key); if (i < 0) return null
    let p = i + key.length, depth = 1, inStr = false, q = ''
    for (; p < html.length; p++) { const c = html[p]
      if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
      if (c === '"' || c === "'") { inStr = true; q = c; continue }
      if (c === '(') depth++; else if (c === ')') { depth--; if (depth === 0) { p++; break } } }
    return html.slice(i, p)
  }

  ;(async () => {
    log('[page] booting page realm...')
    const page = buildRealm('page', windowExtra, { pageWindow: true })
    log('[page] load:', page.err ? 'THREW: ' + page.err.message : 'OK (no throw)')
    log('[page] recaptcha api:', page.sandbox.recaptcha ? Object.keys(page.sandbox.recaptcha).join(',') : '-')
    if (!page.sandbox.recaptcha || !page.sandbox.recaptcha.anchor) { log('no anchor api; abort'); return }

    // fetch a fresh anchor cfg (carries bgdata) for the demo sitekey and run its init call
    const aurl = `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDM&hl=en&v=${VER}&size=normal&cb=p`
    log('[page] fetching anchor cfg...')
    const html = await (await fetch(aurl, { headers: { 'User-Agent': UA } })).text()
    const initCall = extractInitCall(html)
    log('[page] init call found:', !!initCall, initCall ? '(' + initCall.length + ' chars)' : '')
    if (!initCall) { log('no init call in anchor html'); return }

    log('[page] calling recaptcha.anchor.Main.init(cfg)...')
    try { vm.runInContext(initCall, page.ctx, { timeout: 20000 }) }
    catch (e) { log('[page] init threw:', e.message); log((e.stack || '').split('\n').slice(1, 5).join('\n')) }

    // let the async bootstrap run (worker handshake, BotGuard)
    for (let s = 0; s < 10; s++) { await new Promise(r => setTimeout(r, 800)); if (workerRealm) break }
    await new Promise(r => setTimeout(r, 2500))

    // TRIGGER: fire 'click' on every element that registered a click listener (the checkbox),
    // which should start the verify -> /reload(field16) flow.
    const clickable = ALL_ELS.filter(el => el._lis && (el._lis.click || el._lis.mousedown || el._lis.pointerdown || el._lis.keydown))
    log(`[page] total elements: ${ALL_ELS.length} | with click/key listeners: ${clickable.length} (${clickable.map(el => el.id || el.tagName).slice(0, 8).join(',')})`)
    for (const el of clickable) {
      try { el._fire('pointerdown'); el._fire('mousedown'); el._fire('focus'); el._fire('keydown', { type: 'keydown', key: ' ', keyCode: 32, which: 32, target: el, preventDefault() {}, stopPropagation() {}, isTrusted: true }); el._fire('click'); el._fire('mouseup'); el._fire('pointerup') } catch (e) {}
    }
    await new Promise(r => setTimeout(r, 4000))

    log('\n[page] === result ===')
    log('worker spawned:', !!workerRealm, workerRealm ? '| worker load: ' + (workerRealm.err ? 'THREW ' + workerRealm.err.message : 'OK') : '')
    log('HOT canvas/webgl (page):', page.hot.length ? [...new Set(page.hot)].join(' ') : 'NONE')
    log('XHR requests issued:', XHR_REQS.length)
    for (const r of XHR_REQS) log('   ', r.m, r.path, 'bodyLen=' + r.bodyLen)
    const reload = XHR_REQS.find(r => /api2\/reload/.test(r.u))
    if (reload && reload.body) {
      const buf = Buffer.from(reload.body.buffer || reload.body, reload.body.buffer ? undefined : 'latin1')
      log('\n*** /reload body captured:', buf.length, 'bytes — checking for field16 ***')
      fs.writeFileSync(__dirname + '/selfdriven_reload.bin', buf)
    }
    // introspect what's reachable post-init: the grecaptcha cfg, clients, botguard client
    const sb = page.sandbox
    try {
      const cfg = sb.___grecaptcha_cfg
      log('\n[introspect] ___grecaptcha_cfg keys:', cfg ? Object.keys(cfg).join(',') : 'none')
      if (cfg && cfg.clients) { const ids = Object.keys(cfg.clients); log('  clients:', ids.length, ids.slice(0, 3).join(',')); if (ids.length) { const c0 = cfg.clients[ids[0]]; log('  client0 keys:', c0 && typeof c0 === 'object' ? Object.keys(c0).slice(0, 30).join(',') : typeof c0) } }
      if (cfg && cfg.fns) log('  fns:', cfg.fns.length)
    } catch (e) { log('[introspect] cfg err', e.message) }
    log('[introspect] botguard:', typeof sb.botguard, '| __google_recaptcha_client:', typeof sb.__google_recaptcha_client)
    // scan globals for a bg client (has a function-valued prop that sends ak / invoke / execute)
    const cand = []
    for (const k of Object.keys(sb)) { try { const v = sb[k]; if (v && typeof v === 'object') { const fns = Object.keys(v).filter(kk => typeof v[kk] === 'function'); if (fns.length && /^[A-Za-z]{1,3}$/.test(k) === false && (k.includes('recaptcha') || k.includes('grecaptcha'))) cand.push(k + ':{' + fns.slice(0, 8).join(',') + '}') } } catch {} }
    log('[introspect] grecaptcha-ish objects:', cand.slice(0, 6).join('  ') || '(none)')
    if (sb.grecaptcha) log('[introspect] grecaptcha methods:', Object.keys(sb.grecaptcha).join(','))
    log('[page] missing globals:', [...page.missing].slice(0, 30).join(' '))
    process.exit(0)
  })()
}
