// solveloop.js — full request-based reCAPTCHA v2 SOLVE LOOP on top of the two-realm
// node-vm harness (page.js / worker.js). Design (per recaptcha-jsvm map):
//
//   boot anchor PAGE realm + BotGuard WORKER realm (loopback MessagePort)
//     -> recaptcha.anchor.Main.init(cfg)              [client mints field16 in-VM]
//     -> fire checkbox  -> client self-emits POST /reload (field16 rides the body)
//     -> intercept rresp: { c, type, payloadToken(arr[9]), pmeta(arr[4]) }
//     -> GET /payload  -> ONNX classify the grid (cf-bypasss/lib/recaptchaModel)
//     -> get the answer INTO the live client so IT builds replaceimage/userverify
//        (keeping the BotGuard worker session attesting on every interaction)
//     -> intercept uvresp[1] = g-recaptcha-response  (or grecaptcha.getResponse)
//     -> POST /api/siteverify on the OWN key (own_key.json) = GO/NO-GO oracle.
//
// Two answer-delivery modes:
//   CLIENT_DRIVEN=1  -> solveViaClient(): boot the bframe realm from the captured
//                       bft, reach the bframe challenge controller, inject the tile
//                       selection at the client's selection layer, fire Verify, and
//                       let recaptcha__en.js build /replaceimage + /userverify itself
//                       (continuous in-VM attestation = the only path with a chance).
//   (default)        -> solveViaHybrid(): runnable TODAY — classify loop + hand-built
//                       /replaceimage + /userverify (urlencoded, no field16, FINDINGS-
//                       confirmed 200) reusing the live c-token; gives a real siteverify
//                       verdict but does NOT re-attest -> expect the documented soft-block.
'use strict'
const fs = require('fs')
const vm = require('vm')
const crypto = require('crypto')
const { makePort, MessageChannelShim } = require('C:/Users/user/Desktop/a/recaptcha-re/harness/page.js')
const { decode, encode } = require('C:/Users/user/Desktop/a/recaptcha-re/poc/pb.js')
const model = require('C:/Users/user/Desktop/a/cf-bypass/cf-bypasss/lib/recaptchaModel')
const OWN = require('C:/Users/user/Desktop/a/recaptcha-re/poc/own_key.json')

// ---------------------------------------------------------------- config
const ENJS = process.env.ENJS || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
const VER = process.env.VER || 'TnA7HacJFoBWt9hnlunBlYfK'        // release token (rotates)
const SITEKEY = process.env.SITEKEY || OWN.sitekey               // 6LeKLz4t... (own easy key)
const ORIGIN = 'https://' + OWN.domain                          // https://lucille.sh
const CO = Buffer.from(ORIGIN + ':443').toString('base64').replace(/=+$/, '') // co= param
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const CLIENT_DRIVEN = process.env.CLIENT_DRIVEN === '1'
const log = (...a) => console.log(...a)
const sleep = ms => new Promise(r => setTimeout(r, ms))
const dejson = t => JSON.parse(String(t).replace(/^\)\]\}'\n?/, ''))

// challenge keyword resolution (from poc/solve.js, byte-for-byte)
const MID = { '/m/0199g': 'bicycle', '/m/01bjv': 'bus', '/m/0k4j': 'car', '/m/015qff': 'traffic light', '/m/01pns0': 'fire hydrant', '/m/04_sv': 'motorcycle', '/m/01lynh': 'stairs', '/m/079cl': 'crosswalk', '/m/014j1m': 'mountain', '/m/0cdl1': 'palm tree', '/m/06bt6': 'chimney', '/m/013xlm': 'tractor', '/m/0c9ph5': 'bridge', '/m/0pg52': 'taxi', '/m/01_5g': 'parking meter', '/m/0d4v4': 'window' }
const HUMAN = { bike: 'bicycle', bicycle: 'bicycle', bus: 'bus', car: 'car', 'pedestrian crossing': 'crosswalk', crosswalk: 'crosswalk', 'fire hydrant': 'fire hydrant', hydrant: 'fire hydrant', 'traffic light': 'traffic light', stairs: 'stairs', motorcycle: 'motorcycle', chimney: 'chimney', bridge: 'bridge', mountain: 'mountain', tractor: 'tractor', 'palm tree': 'palm tree', taxi: 'car' }
const kwOf = (mid, human) => MID[mid] || HUMAN[String(human || '').toLowerCase()] || human || mid
const pickTiles = confs => confs.filter(x => x.conf > 0.5).map(x => x.i).sort((a, b) => a - b)

// ---------------------------------------------------------------- en.js + source patches
// We OWN the realm build (vs importing page.js buildRealm) so we can source-patch the
// minified controllers into the realm global — the only way to reach the verify/select
// methods that make the client emit replaceimage/userverify (map: anchor ctrl @810567,
// bframe ctrl @893462; capture pattern from harness/worker.js).
let CODE = fs.readFileSync(ENJS, 'utf8')
function patch(find, repl, optional) {
  const i = CODE.indexOf(find)
  if (i < 0) { if (optional) { log('  [patch] (optional) anchor not found:', find.slice(0, 40)); return false } throw new Error('patch anchor NOT FOUND: ' + find) }
  if (CODE.indexOf(find, i + 1) >= 0 && !optional) throw new Error('patch anchor NON-UNIQUE: ' + find)
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length); return true
}
// capture anchor controller WR.D and bframe controller Ac, plus worker RPC tokens
patch('(new WR(r)).D).init()', '(self.__grWR=new WR(r)).D).init()', true)
patch('new Ac(r)).D.init(', '(self.__grAC=new Ac(r))).D.init(', true)  // extra ) closes the wrapper; outer (r=new XZ(TP(q)),...) stays balanced
patch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),', true)
patch('}],[ak,function', '}],[(__cap.ak=ak),function', true)
patch('AE=function(q,r,w,D,d,A){return b[32]', 'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]', true)

const INTRINSICS = ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'EvalError', 'ReferenceError', 'SyntaxError', 'URIError', 'Reflect', 'Proxy', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'parseInt', 'parseFloat', 'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape', 'isNaN', 'isFinite', 'Intl', 'structuredClone', 'Infinity', 'NaN', 'undefined', 'globalThis']

// ---------------------------------------------------------------- realm builder
// perf stub upgraded for Xm realism (integrity map driver_step): monotonic 0.1ms-coarse
// clock + REAL growing heap so the ak attestation's heapDelta U>0 and execMs x>0.
function makePerf() {
  const T0 = Date.now(), hr0 = process.hrtime.bigint(), HEAP0 = process.memoryUsage().heapUsed
  const BASE = 13_000_000; let last = 0
  const now = () => { let ms = Number(process.hrtime.bigint() - hr0) / 1e6; ms = Math.floor(ms / 0.1) * 0.1; if (ms < last) ms = last; last = ms; return ms }
  return { now, timeOrigin: T0, getEntriesByType: () => [], mark() {}, measure() {}, clearMarks() {}, clearMeasures() {},
    memory: { get usedJSHeapSize() { return BASE + Math.max(0, process.memoryUsage().heapUsed - HEAP0) }, get totalJSHeapSize() { return Math.max(this.usedJSHeapSize + 2_000_000, 40_000_000) }, jsHeapSizeLimit: 2_190_000_000 } }
}

// response-hooking XHR: routes the VM's XHR to node fetch AND fires onResp(meta) so the
// orchestrator can read rresp/uvresp/dresp the moment the client receives them.
function makeXHR(onResp, jar) {
  return class XHR {
    constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = '' }
    open(m, u) { this._m = m; this._u = u }
    setRequestHeader(k, v) { this._h[k] = v }
    addEventListener(t, f) { this['on' + t] = f }
    getAllResponseHeaders() { return Object.entries(this._rh || {}).map(([k, v]) => k + ': ' + v).join('\r\n') }
    getResponseHeader(k) { return (this._rh || {})[String(k).toLowerCase()] || null }
    abort() {}
    send(body) {
      const self = this, url = String(this._u), path = url.split('?')[0].replace(/^https?:\/\/[^/]+/, '')
      const reqBody = body && body.byteLength != null ? Buffer.from(body.buffer || body, body.buffer ? undefined : 'latin1') : (typeof body === 'string' ? Buffer.from(body, 'latin1') : null)
      if (/api2\/(reload|userverify|replaceimage|anchor|bframe|payload)/.test(url)) log('  [XHR]', this._m, path, 'bodyLen=' + (reqBody ? reqBody.length : 0))
      const headers = { 'User-Agent': UA, ...this._h }; if (jar && jar.cookie) headers.cookie = jar.cookie
      fetch(url, { method: this._m || 'GET', headers, body: body || undefined }).then(async r => {
        self.status = r.status; self._rh = Object.fromEntries(r.headers)
        const sc = r.headers.get('set-cookie'); if (sc && jar) jar.absorb(sc)
        const buf = Buffer.from(await r.arrayBuffer())
        self.responseText = buf.toString('latin1'); self.response = self.responseText; self.readyState = 4
        try { onResp && onResp({ url, path, status: r.status, text: self.responseText, buf, reqBody }) } catch (e) { log('  onResp err', e.message) }
        if (self.onreadystatechange) self.onreadystatechange(); if (self.onload) self.onload()
      }).catch(e => { self.status = 0; self.readyState = 4; if (self.onerror) self.onerror(e); if (self.onreadystatechange) self.onreadystatechange() })
    }
  }
}

// compact DOM stub (page-mode, NO canvas — map: field16 needs no renderer). Elements
// capture listeners so we can fire the checkbox click; iframe src is captured so we can
// harvest the server-minted bframe `bft` token (its provenance — see riskiest unknown).
function makeDom(state) {
  const lisFor = new WeakMap()
  function el(tag, id) {
    const lis = {}; const real = {
      tagName: (tag || 'div').toUpperCase(), id: id || '', nodeType: 1, value: '', checked: false,
      style: new Proxy({}, { get: () => '', set: () => true }), dataset: {}, classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
      addEventListener: (t, f) => (lis[t] = lis[t] || []).push(f), removeEventListener: (t, f) => { if (lis[t]) lis[t] = lis[t].filter(x => x !== f) },
      getAttribute: () => null, hasAttribute: () => false, removeAttribute() {}, appendChild: x => x, removeChild: x => x, insertBefore: x => x, remove() {}, contains: () => false,
      setAttribute(k, v) { if (k === 'src') captureSrc(v) },
      querySelector: () => el('div'), querySelectorAll: () => [], getElementsByTagName: () => [el('div')], getElementsByClassName: () => [el('div')],
      getBoundingClientRect: () => ({ x: 0, y: 0, width: 28, height: 28, top: 0, left: 0, right: 28, bottom: 28 }), getClientRects: () => [],
      focus() {}, blur() {}, click() { fire('click') }, cloneNode() { return el(tag, id) }, getContext: () => null, setPointerCapture() {}, releasePointerCapture() {},
      children: [], childNodes: [], firstChild: null, lastChild: null, parentNode: null, ownerDocument: null, offsetWidth: 28, offsetHeight: 28,
      innerHTML: '', outerHTML: '', textContent: '', dispatchEvent(ev) { fire(ev && ev.type, ev); return true } }
    function fire(type, ev) { (lis[type] || []).slice().forEach(f => { try { f(ev || mkEvent(type)) } catch (e) {} }) }
    const P = new Proxy(real, { get(t, k) { if (k in t) return t[k]; if (typeof k === 'string' && k === 'src') return t.__src || ''; return noop() },
      set(t, k, v) { if (k === 'src') { t.__src = v; captureSrc(v) } else t[k] = v; return true }, has: () => true })
    lisFor.set(P, { real, lis, fire }); state.all.push({ P, real, lis, fire }); return P
  }
  function captureSrc(v) { const s = String(v); if (/api2\/bframe/.test(s) && /bft=/.test(s) && !state.bframeUrl) { state.bframeUrl = s.startsWith('http') ? s : 'https://www.google.com' + s; log('  [dom] captured bframe url w/ bft (', state.bframeUrl.length, 'chars)') } }
  function mkEvent(type) { return { type, target: null, currentTarget: null, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0, key: ' ', keyCode: 32, which: 32 } }
  function noop() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive || k === 'toString' || k === 'valueOf') return () => ''; if (k === 'nodeType') return 1; return P }, apply: () => P, construct: () => P, set: () => true, has: () => true }); return P }
  const ELS = {}
  const document = new Proxy({
    createElement: t => el(t), createElementNS: (ns, t) => el(t), createDocumentFragment: () => el('frag'), createTextNode: () => el('text'), createComment: () => el('cmt'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
    getElementById: id => (ELS[id] = ELS[id] || el('div', id)), querySelector: s => (ELS['q:' + s] = ELS['q:' + s] || el('div', 'q:' + s)), querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], getElementsByName: () => [],
    documentElement: el('html'), head: el('head'), body: el('body'), cookie: '', referrer: ORIGIN + '/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
  }, { get(t, k) { return k in t ? t[k] : noop() }, has: () => true })
  return { document, el, ELS, mkEvent, noop }
}

function buildRealm(role, extra, opts) {
  const pageWindow = !!(opts && opts.pageWindow)
  const base = {
    importScripts: () => {}, postMessage: () => {}, addEventListener: () => {}, removeEventListener: () => {}, onmessage: null, onerror: null, close: () => {},
    MessageChannel: MessageChannelShim, MessagePort: function () {}, performance: makePerf(),
    navigator: { userAgent: UA, webdriver: false, deviceMemory: 8, hardwareConcurrency: 8, language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32', vendor: 'Google Inc.', product: 'Gecko', appName: 'Netscape', onLine: true, userAgentData: { brands: [{ brand: 'Chromium', version: '149' }], mobile: false, platform: 'Windows', getHighEntropyValues: () => Promise.resolve({}) }, sendBeacon: () => true, cookieEnabled: true, doNotTrack: null },
    location: { href: 'https://www.google.com/recaptcha/api2/webworker.js', origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/webworker.js', search: '', hash: '' },
    atob: s => Buffer.from(s, 'base64').toString('binary'), btoa: s => Buffer.from(s, 'binary').toString('base64'),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, requestAnimationFrame: f => setTimeout(() => f(Date.now()), 16), cancelAnimationFrame: () => {}, requestIdleCallback: f => setTimeout(() => f({ timeRemaining: () => 5, didTimeout: false }), 1), cancelIdleCallback: () => {},
    TextEncoder, TextDecoder, URL, URLSearchParams, crypto: crypto.webcrypto, fetch: (...a) => fetch(...a),
    console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} }, __cap: {},
  }
  Object.assign(base, extra || {})
  for (const k of INTRINSICS) if (!(k in base)) try { base[k] = globalThis[k] } catch {}
  let g
  const handler = { get(t, k) { if (typeof k === 'symbol') return t[k]; if (k === 'self' || k === 'globalThis') return g; if (k === 'window' || k === 'top' || k === 'parent') return pageWindow ? g : undefined; return t[k] }, has: () => true, set(t, k, v) { t[k] = v; return true } }
  const sandbox = Object.assign(Object.create(null), base)
  const ctx = vm.createContext(new Proxy(sandbox, handler)); g = ctx
  let err = null
  try { vm.runInContext(CODE, ctx, { filename: `recaptcha__en.js[${role}]`, timeout: 20000 }) } catch (e) { err = e }
  return { ctx, sandbox, err }
}

// FakeWorker: lazily builds the worker realm; bootstrap posts "recaptcha-setup" + the
// transferred port. By-reference loopback (structuredClone would DataCloneError on Bp/Lf).
function makeFakeWorker(store) {
  return function FakeWorker(url) {
    log('  [worker] new Worker(', String(url).slice(0, 64), ')')
    const self_ = this, lisP = [], toPage = []
    self_._on = null
    function flush() { if (!(self_._on || lisP.length)) return; while (toPage.length) { const ev = toPage.shift(); if (self_._on) try { self_._on(ev) } catch (e) {} for (const f of lisP) try { f(ev) } catch (e) {} } }
    const wlis = []
    store.worker = buildRealm('worker', {
      postMessage: (m, tr) => { toPage.push({ data: m, ports: Array.isArray(tr) ? tr.filter(x => x && x.__isPort) : [], type: 'message' }); flush() },
      addEventListener: (t, f) => { if (t === 'message') wlis.push(f) },
    })
    self_.postMessage = (m, tr) => { const ev = { data: m, ports: (tr || []).filter(x => x && x.__isPort), type: 'message' }; const ws = store.worker.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch (e) {} for (const f of wlis) try { f(ev) } catch (e) {} }
    self_.addEventListener = (t, f) => { if (t === 'message') { lisP.push(f); flush() } }
    self_.removeEventListener = (t, f) => { } ; self_.terminate = () => {}
    Object.defineProperty(self_, 'onmessage', { get: () => self_._on, set(f) { self_._on = f; flush() } })
  }
}

function extractInitCall(html, sym) {
  const key = sym + '('; const i = html.indexOf(key); if (i < 0) return null
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) { const c = html[p]
    if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
    if (c === '"' || c === "'") { inStr = true; q = c; continue }
    if (c === '(') depth++; else if (c === ')') { if (--depth === 0) { p++; break } } }
  return html.slice(i, p)
}

// simple cookie jar (forward _GRECAPTCHA across the session)
function makeJar() { const m = {}; return { get cookie() { return Object.entries(m).map(([k, v]) => k + '=' + v).join('; ') }, absorb(sc) { String(sc).split(/,(?=[^;]+=)/).forEach(c => { const [kv] = c.split(';'); const i = kv.indexOf('='); if (i > 0) m[kv.slice(0, i).trim()] = kv.slice(i + 1).trim() }) } } }

// ============================================================ ORCHESTRATION
async function main() {
  process.on('unhandledRejection', () => {})
  log('[solveloop] sitekey', SITEKEY, '| origin', ORIGIN, '| co', CO, '| clientDriven', CLIENT_DRIVEN)

  const jar = makeJar()
  const store = { worker: null, all: [], bframeUrl: null }
  const sess = { reload: null, dresp: null, token: null, ttl: 0, reloadBody: null }

  function onResp(m) {
    try {
      if (/api2\/reload/.test(m.url)) {
        if (m.reqBody) { sess.reloadBody = m.reqBody; fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/selfdriven_reload.bin', m.reqBody)
          const f16 = decode(m.reqBody).find(f => f.field === 16); log('  [reload] body', m.reqBody.length, 'B | field16', f16 ? f16.len + 'B' : 'EMPTY') }
        const a = dejson(m.text); if (a[0] === 'rresp') { sess.reload = { c: a[1], type: a[5], payloadToken: a[9], pmeta: a[4] }; log('  [rresp] type', a[5], '| payloadTok', String(a[9]).slice(0, 14) + '…') }
      } else if (/api2\/replaceimage/.test(m.url)) { const a = dejson(m.text); if (a[0] === 'dresp') { sess.dresp = { c: a[1], payloadToken: a[5] }; log('  [dresp] newC len', String(a[1]).length, '| payload', a[5] ? 'yes' : 'none') } }
      else if (/api2\/userverify/.test(m.url)) { const a = dejson(m.text); if (a[0] === 'uvresp' && a[1]) { sess.token = a[1]; sess.ttl = a[2]; log('  [uvresp] *** TOKEN', String(a[1]).slice(0, 24) + '… ttl', a[2]) } }
    } catch (e) {}
  }

  const dom = makeDom(store)
  const windowExtra = {
    Worker: makeFakeWorker(store), document: dom.document, XMLHttpRequest: makeXHR(onResp, jar),
    location: { href: `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=${CO}&hl=en&v=${VER}&size=normal&cb=p`, origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/anchor', search: `?k=${SITEKEY}`, hash: '', replace() {}, assign() {}, reload() {} },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1080, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => dom.noop(), parent: null, top: null, frameElement: null, scrollTo() {}, focus() {}, blur() {},
    Image: function () { return dom.noop() }, Event: function () { return dom.noop() }, CustomEvent: function () { return dom.noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] }, botguard: undefined,
  }

  // 1) boot anchor PAGE realm
  log('[1] boot anchor page realm')
  const page = buildRealm('page', windowExtra, { pageWindow: true })
  if (page.err) log('  load THREW:', page.err.message); else log('  load OK | recaptcha api:', page.sandbox.recaptcha ? Object.keys(page.sandbox.recaptcha).join(',') : 'NONE')
  if (!page.sandbox.recaptcha || !page.sandbox.recaptcha.anchor) return fail('no recaptcha.anchor api')

  // 2) fetch fresh anchor cfg (carries bgdata BotGuard program) + run init verbatim
  log('[2] fetch anchor cfg + init')
  const aurl = windowExtra.location.href
  const html = await (await fetch(aurl, { headers: { 'User-Agent': UA } })).text()
  const initCall = extractInitCall(html, 'recaptcha.anchor.Main.init')
  if (!initCall) return fail('no anchor.Main.init in anchor html (sitekey/origin not provisioned?)')
  log('  init call', initCall.length, 'chars')
  try { vm.runInContext(initCall, page.ctx, { timeout: 20000 }) } catch (e) { log('  init threw:', e.message) }

  for (let s = 0; s < 8 && !store.worker; s++) await sleep(400)
  log('  worker spawned:', !!store.worker, store.worker && store.worker.err ? '(worker THREW ' + store.worker.err.message + ')' : '')

  // 3) fire the checkbox -> client self-emits /reload (field16). map: init is NOT the trigger.
  log('[3] fire checkbox -> /reload')
  const clickable = store.all.filter(e => e.lis && (e.lis.click || e.lis.mousedown || e.lis.pointerdown || e.lis.keydown))
  log('  elements', store.all.length, '| clickable', clickable.length)
  for (const e of clickable) { for (const t of ['pointerdown', 'mousedown', 'focus', 'keydown', 'click', 'mouseup', 'pointerup']) e.fire(t, dom.mkEvent(t)) }

  // 4) wait for rresp OR a frictionless uvresp
  for (let s = 0; s < 25 && !sess.reload && !sess.token; s++) await sleep(300)
  if (sess.token) { log('[4] frictionless auto-pass'); return finish(page) }
  if (!sess.reload) return fail('no /reload emitted by client (checkbox trigger did not fire verify — see riskiest unknown)')

  // 5) frictionless?  if no image payload, the client may go straight to userverify
  if (!sess.reload.payloadToken || sess.reload.type === 'no-frame') {
    log('[5] no image challenge — awaiting userverify')
    for (let s = 0; s < 20 && !sess.token; s++) await sleep(300)
    return finish(page)
  }

  // 6) IMAGE CHALLENGE
  log('[6] image challenge:', sess.reload.type)
  if (CLIENT_DRIVEN) await solveViaClient(page, store, sess, jar)
  else await solveViaHybrid(sess, jar)

  for (let s = 0; s < 20 && !sess.token; s++) await sleep(300)
  return finish(page)

  function fail(msg) { log('\n[RESULT] ABORT:', msg); printXhr(); process.exit(2) }
  async function finish(pageRealm) {
    // read token: prefer captured uvresp, else grecaptcha.getResponse
    let tok = sess.token
    if (!tok) { try { const gr = pageRealm.sandbox.grecaptcha; if (gr && gr.getResponse) tok = gr.getResponse() } catch (e) {} }
    if (!tok) { log('\n[RESULT] NO TOKEN minted'); printXhr(); process.exit(3) }
    log('\n[7] siteverify token', tok.slice(0, 28) + '…')
    const v = await siteverify(tok)
    log('[RESULT] siteverify:', JSON.stringify(v))
    log(v && v.success ? '*** ACCEPTED ***' : '*** REJECTED (soft-block / low-trust) ***')
    process.exit(v && v.success ? 0 : 1)
  }
  function printXhr() { log('  (the in-VM client did not reach a token; inspect selfdriven_reload.bin for field16)') }
}

// ---- design-faithful: let the in-VM client build replaceimage/userverify ----
// Boots the bframe realm from the captured bft, reaches the bframe controller, injects
// the model's tile selection at the client's selection layer, and fires Verify so
// recaptcha__en.js itself emits /replaceimage + /userverify (with live attestation).
async function solveViaClient(page, store, sess, jar) {
  log('  [client] bframe url captured:', !!store.bframeUrl)
  if (!store.bframeUrl) { log('  [client] NO bft captured -> cannot boot bframe; falling back to hybrid'); return solveViaHybrid(sess, jar) }

  // boot bframe realm sharing the same worker loopback + cookie jar
  const onResp2 = m => {}      // bframe XHR responses are also caught by the shared session via fetch
  const bframeWindow = Object.assign({}, { /* reuse a fresh dom */ })
  const bdom = makeDom(store)
  const bExtra = {
    Worker: store.worker ? function () { return mirrorWorker(store) } : makeFakeWorker(store),
    document: bdom.document, XMLHttpRequest: makeXHR(rerouteToSession(sess), jar),
    location: locFrom(store.bframeUrl), parent: page.ctx, top: page.ctx, ___grecaptcha_cfg: page.sandbox.___grecaptcha_cfg,
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 }, devicePixelRatio: 1, innerWidth: 400, innerHeight: 580,
    matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {} }), getComputedStyle: () => bdom.noop(),
  }
  const bhtml = await (await fetch(store.bframeUrl, { headers: { 'User-Agent': UA, Referer: store.bframeUrl, cookie: jar.cookie } })).text()
  const binit = extractInitCall(bhtml, 'recaptcha.frame.Main.init')
  if (!binit) { log('  [client] no frame.Main.init in bframe html -> hybrid'); return solveViaHybrid(sess, jar) }
  const bframe = buildRealm('bframe', bExtra, { pageWindow: true })
  try { vm.runInContext(binit, bframe.ctx, { timeout: 20000 }) } catch (e) { log('  [client] bframe init threw:', e.message) }
  await sleep(1500)

  const ctrl = bframe.sandbox.__grAC          // bframe controller (Ac); .D is the challenge controller
  log('  [client] bframe controller captured:', !!ctrl)

  // classify the current payload, then drive the client's selection layer.
  let round = 0
  while (round < 10 && !sess.token) {
    const sel = await classifyCurrent(sess, jar)
    log(`  [client] round ${round} model selection = ${JSON.stringify(sel)}`)
    if (!sel) break
    // ----------------------------------------------------------------------------
    // SEAM (riskiest unknown): poke the selected tiles + fire Verify on ctrl.D so the
    // client builds /replaceimage (3x3 dynamic) or /userverify (4x4). The selection
    // method name is minified + dispatch-encoded and ROTATES per release; it must be
    // traced at runtime, NOT hardcoded. Trace recipe: enumerate ctrl.D own function
    // props, call each with (tileIndex) under a try/catch while watching store.all for
    // a tile element whose `checked`/class flips, then find the method that triggers a
    // /replaceimage XHR. Until traced for THIS release, we cannot complete client-built.
    if (!await driveSelection(ctrl, bframe, store, sel, sess)) {
      log('  [client] selection method not yet traced for this release -> hybrid for remainder')
      return solveViaHybrid(sess, jar)
    }
    for (let s = 0; s < 20 && !sess.dresp && !sess.token; s++) await sleep(300)
    if (sess.token) break
    if (!sess.dresp || !sess.dresp.payloadToken) break
    sess.reload.c = sess.dresp.c; sess.reload.payloadToken = sess.dresp.payloadToken; sess.dresp = null
    round++
  }
}

// driveSelection — use the bframe challenge controller to select tiles and fire Verify.
// Per CHALLENGE_PLAYBOOK.md:
//   dynamic 3x3: challenge.Dr(challenge.P.VI.I$.e_[i])  -> /replaceimage per tile
//   static 3x3/4x4: challenge.Dr(e_[i]) toggles, then H[31](17,!1,challenge) submits
//
// ctrl   = __grAC  (bframe coordinator Ac)
// ctrl.D = challenge controller (tS)
// tS.H   = current challenge object (mr subclass: GG=dynamic, B5=static, oS=multicaptcha)
//
// The actual selector method rotates per release — we try the direct path first,
// then fall back to runtime enumeration if needed.
async function driveSelection(ctrl, bframe, store, sel, sess) {
  if (!ctrl || !ctrl.D) return false

  const challenge = ctrl.D     // tS / challenge controller
  const store_before = store.all.length

  // --- direct path per playbook ---
  // challenge.P.VI.I$ is the tile model array {e_, selected, PG}
  try {
    const model = challenge.P && challenge.P.VI && challenge.P.VI.I$
    if (model && model.e_ && typeof challenge.Dr === 'function') {
      for (const i of sel) {
        const tile = model.e_[i]
        if (tile) challenge.Dr(tile)
      }
      await sleep(200)
      // Check if /replaceimage or /userverify was triggered (sess.dresp/sess.token will update)
      return true
    }
  } catch (e) {}

  // --- runtime enumeration fallback ---
  // Enumerate ctrl.D own function props, call each with (tileObj) while watching for
  // a tile element state flip or a new XHR.  Only works if challenge.P.VI.I$ is accessible.
  try {
    const model = challenge.P && challenge.P.VI && challenge.P.VI.I$
    if (!model || !model.e_) return false
    const fns = Object.getOwnPropertyNames(Object.getPrototypeOf(challenge)).filter(k => typeof challenge[k] === 'function' && k.length <= 3 && k !== 'constructor')
    for (const fn of fns) {
      const tile0 = model.e_[sel[0]]
      if (!tile0) continue
      const wasSel = tile0.selected
      try { challenge[fn](tile0) } catch {}
      await sleep(50)
      if (tile0.selected !== wasSel || store.all.length > store_before) {
        // This fn toggled tile state — it's the Dr equivalent. Apply to remaining tiles.
        for (const i of sel.slice(1)) { try { challenge[fn](model.e_[i]) } catch {} }
        return true
      }
    }
  } catch (e) {}

  return false
}

function mirrorWorker(store) { return {} }
function rerouteToSession(sess) {
  return m => {
    try {
      if (/api2\/replaceimage/.test(m.url)) { const a = JSON.parse(m.text.replace(/^\)\]\}'\n?/, '')); if (a[0] === 'dresp') sess.dresp = { c: a[1], payloadToken: a[5] } }
      else if (/api2\/userverify/.test(m.url)) { const a = JSON.parse(m.text.replace(/^\)\]\}'\n?/, '')); if (a[0] === 'uvresp' && a[1]) { sess.token = a[1]; sess.ttl = a[2] } }
    } catch (e) {}
  }
}
function locFrom(u) { const url = new URL(u); return { href: u, origin: url.origin, protocol: url.protocol, host: url.host, hostname: url.hostname, pathname: url.pathname, search: url.search, hash: '', replace() {}, assign() {}, reload() {} } }

// ---- runnable-today fallback: hand-built loop (FINDINGS-confirmed 200; expect soft-block) ----
async function solveViaHybrid(sess, jar) {
  const REF = `https://www.google.com/recaptcha/api2/bframe?hl=en&v=${VER}&k=${SITEKEY}`
  const form = { 'User-Agent': UA, 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', Referer: REF, Origin: 'https://www.google.com', cookie: jar.cookie }
  let round = 0
  while (round < 10 && !sess.token) {
    const sel = await classifyCurrent(sess, jar)
    if (!sel) { // no matches -> commit
      log('  [hybrid] no matches -> userverify')
      const r = await fetch(`https://www.google.com/recaptcha/api2/userverify?k=${SITEKEY}`, { method: 'POST', headers: form, body: `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(sess.reload.c)}` })
      try { const a = dejson(await r.text()); if (a[0] === 'uvresp' && a[1]) { sess.token = a[1]; sess.ttl = a[2]; log('  [hybrid] uvresp token!') } else log('  [hybrid] userverify:', JSON.stringify(a).slice(0, 120)) } catch (e) {}
      break
    }
    const body = `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(sess.reload.c)}&ds=${encodeURIComponent(JSON.stringify([sel]))}`
    const r = await fetch(`https://www.google.com/recaptcha/api2/replaceimage?k=${SITEKEY}`, { method: 'POST', headers: form, body })
    let a; try { a = dejson(await r.text()) } catch (e) { log('  [hybrid] replaceimage non-json', r.status); break }
    if (a[0] !== 'dresp') { log('  [hybrid] replaceimage:', JSON.stringify(a).slice(0, 120)); break }
    sess.reload.c = a[1]; sess.reload.payloadToken = a[5]
    log(`  [hybrid] round ${round} dresp newC | payload ${a[5] ? 'yes' : 'none'}`)
    if (!a[5]) { // committed: dynamic finished
      const r2 = await fetch(`https://www.google.com/recaptcha/api2/userverify?k=${SITEKEY}`, { method: 'POST', headers: form, body: `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(sess.reload.c)}` })
      try { const u = dejson(await r2.text()); if (u[0] === 'uvresp' && u[1]) { sess.token = u[1]; sess.ttl = u[2] } else log('  [hybrid] userverify:', JSON.stringify(u).slice(0, 120)) } catch (e) {}
      break
    }
    round++
  }
}

// classify the current payload grid; returns selected tile indices, [] for "none left", null on error
async function classifyCurrent(sess, jar) {
  const tok = sess.reload.payloadToken
  const r = await fetch(`https://www.google.com/recaptcha/api2/payload?p=${encodeURIComponent(tok)}&k=${SITEKEY}`, { headers: { 'User-Agent': UA, Referer: `https://www.google.com/recaptcha/api2/bframe?hl=en&v=${VER}&k=${SITEKEY}`, cookie: jar.cookie } })
  if (!r.ok || !/image/.test(r.headers.get('content-type') || '')) { log('  [classify] payload not an image'); return null }
  const img = Buffer.from(await r.arrayBuffer())
  const pm = sess.reload.pmeta || []
  let kw = 'bus', rows = 3, cols = 3
  if (sess.reload.type === 'dynamic' && pm[1]) { kw = kwOf(pm[1][0], pm[1][6]); rows = pm[1][2] || 3; cols = pm[1][3] || 3 }
  else if (pm[5] && pm[5][0] && pm[5][0][0]) { const t = pm[5][0][0]; kw = MID[t[0]] || t[0]; rows = t[3] || 4; cols = t[4] || 4 }
  const count = rows * cols
  const res = await model.classifyGrid(img.toString('base64'), kw, count)
  if (!res) { log('  [classify] keyword', kw, 'not a model class -> need vision fallback'); return null }
  const sel = pickTiles(res.confs)
  log(`  [classify] "${kw}" ${rows}x${cols} -> sel=${JSON.stringify(sel)} top=${res.confs.slice(0, 3).map(x => x.i + ':' + x.conf.toFixed(2)).join(',')}`)
  return sel
}

async function siteverify(token) {
  const body = new URLSearchParams({ secret: OWN.secret, response: token })
  const r = await fetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body })
  try { return await r.json() } catch (e) { return { success: false, error: 'parse', status: r.status } }
}

if (require.main === module) main().catch(e => { console.log('FATAL', e.stack || e); process.exit(9) })
module.exports = { buildRealm, makeXHR, classifyCurrent, siteverify, solveViaHybrid }
