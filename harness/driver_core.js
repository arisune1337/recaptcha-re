// driver_core.js — request-based reCAPTCHA v2 driver core.
//
// Extends harness/page.js: reuses its buildRealm() / loopback-port primitives, but
//   (1) loads a SOURCE-PATCHED recaptcha__en.js (captures rotating tokens + the WR
//       anchor controller) by pointing page.js's ENJS at a patched copy *before* require,
//   (2) supplies its own instrumented XMLHttpRequest that captures the EXACT /reload
//       protobuf body as raw bytes (no UTF-8 mangling) and extracts field16, while still
//       forwarding the request to the real network as raw bytes (so the session advances),
//   (3) upgrades performance.now()/performance.memory to a monotonic clock + growing heap
//       so the Xm attestation reads (heapDelta>0, timing>0) are non-degenerate.
//
// Flow: GET /anchor -> extract recaptcha.anchor.Main.init("<cfg>") literal -> run it in the
// page realm -> FakeWorker bootstraps the BotGuard worker over the by-ref loopback -> fire the
// checkbox trigger -> Google's own code emits POST /reload -> we intercept it and pull field16.
//
// Run:  node harness/driver_core.js
//   env: SITEKEY, ORIGIN_HOST (for co=), VER, ENJS_SRC, TRACE=1
'use strict'
const fs = require('fs')
const vm = require('vm')
const os = require('os')
const path = require('path')
const pb = require('../poc/pb.js')

// ----------------------------------------------------------------------------
// 0) Source-patch en.js, write a temp copy, point page.js at it BEFORE requiring it.
//    page.js reads process.env.ENJS at require-time, so this must happen first.
// ----------------------------------------------------------------------------
const ENJS_SRC = process.env.ENJS_SRC || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
let CODE = fs.readFileSync(ENJS_SRC, 'utf8')
function tryPatch(find, repl, label) {
  const i = CODE.indexOf(find)
  if (i < 0) { console.log('  [patch skip]', label, '(anchor not found)'); return }
  if (CODE.indexOf(find, i + 1) >= 0) { console.log('  [patch skip]', label, '(non-unique)'); return }
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length)
  console.log('  [patch ok ]', label)
}
console.log('[driver] patching en.js for token + controller capture...')
// rotating BotGuard tokens (same anchors worker.js uses) -> realm-global __cap
tryPatch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),', 'RPp/Qr')
tryPatch('}],[ak,function', '}],[(__cap.ak=ak),function', 'ak')
tryPatch('AE=function(q,r,w,D,d,A){return b[32]', 'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]', 'AE')
tryPatch('d5=lZ()', 'd5=__cap.d5=lZ()', 'd5')
// capture the anchor "Main" controller instance for the direct-trigger fallback
tryPatch('(new WR(r)).D).init()', '(self.__grWR=new WR(r)).D).init()', 'WR controller')
const PATCHED = path.join(os.tmpdir(), 'recaptcha__en.patched.js')
fs.writeFileSync(PATCHED, CODE)
process.env.ENJS = PATCHED

// now load page.js — its buildRealm() will compile our patched code in every realm
const { buildRealm } = require('./page.js')

// ----------------------------------------------------------------------------
// 1) Config (demo key by default; swap to own key via env for the siteverify oracle).
// ----------------------------------------------------------------------------
const SITEKEY = process.env.SITEKEY || '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-'
const ORIGIN_HOST = process.env.ORIGIN_HOST || 'www.google.com'
const VER = process.env.VER || 'TnA7HacJFoBWt9hnlunBlYfK'
const ORIGIN = 'https://' + ORIGIN_HOST
const CO = Buffer.from(ORIGIN + ':443').toString('base64url')
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const TRACE = !!process.env.TRACE
const log = (...a) => console.log(...a)

// ----------------------------------------------------------------------------
// 2) Shared state: cookie jar, captured reloads, results promise.
// ----------------------------------------------------------------------------
let COOKIE = ''                       // _GRECAPTCHA etc., harvested from Set-Cookie
const RELOADS = []                    // every /reload we intercepted: {buf, field16, fields}
let resolveFirstReload
const firstReload = new Promise(r => { resolveFirstReload = r })

function mergeSetCookie(headers) {
  // node fetch Headers: getSetCookie() (node>=19.7) or raw 'set-cookie'
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

// pull field16 (+ a context field-map) out of a /reload protobuf body
function extractField16(buf) {
  let fields
  try { fields = pb.decode(buf) } catch (e) { return { error: 'decode failed: ' + e.message } }
  const map = {}
  for (const f of fields) {
    const v = (f.type === 'string' || f.type === 'bytes') ? (f.len) : f.value
    map['f' + f.field] = (f.type === 'string') ? `"${f.preview.slice(0, 24)}"(${f.len})` : (f.wire === 2 ? `<${f.len}b>` : v)
  }
  const f16 = fields.find(f => f.field === 16 && f.wire === 2)
  if (!f16) return { fields, map, present: false }
  const text = f16.raw.toString('latin1')
  const urlSafeB64 = /^[A-Za-z0-9_-]+$/.test(text)
  return { fields, map, present: true, len: f16.len, raw: f16.raw, text, urlSafeB64 }
}

// ----------------------------------------------------------------------------
// 3) Instrumented XMLHttpRequest: capture /reload body verbatim, then forward raw bytes.
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
      const self = this
      const url = String(this._u)
      const path_ = url.split('?')[0].replace(/^https?:\/\/[^/]+/, '')
      const buf = toBuf(body)
      const isReload = /recaptcha\/api2\/reload/.test(url)

      if (/recaptcha\/api2\/(reload|userverify|replaceimage|anchor|bframe)/.test(url))
        log('  [XHR]', this._m, path_, 'bodyLen=' + buf.length)

      if (isReload) {
        const info = extractField16(buf)
        RELOADS.push({ buf, info })
        log('  *** /reload INTERCEPTED:', buf.length, 'bytes | fields:', JSON.stringify(info.map))
        if (info.present) {
          log('      field16:', info.len, 'bytes | urlSafeB64=' + info.urlSafeB64 + ' | head=' + info.text.slice(0, 40))
        } else {
          log('      field16: ABSENT/EMPTY (expected on the FIRST reload — non-empty only from the 2nd onward)')
        }
        try { resolveFirstReload({ buf, info }) } catch {}
        const out = 'C:/Users/user/Desktop/a/recaptcha-re/harness/selfdriven_reload_' + RELOADS.length + '.bin'
        try { fs.writeFileSync(out, buf) } catch {}
      }

      // forward to real network as RAW BYTES (Buffer) so the protobuf isn't UTF-8 mangled
      const headers = { 'User-Agent': UA, 'Origin': ORIGIN, ...this._h }
      if (COOKIE) headers['Cookie'] = COOKIE
      if (!headers['Referer']) headers['Referer'] = 'https://www.google.com/recaptcha/api2/bframe?hl=en&v=' + VER + '&k=' + SITEKEY
      fetch(url, { method: this._m || 'GET', headers, body: (this._m === 'POST' || this._m === 'PUT') ? buf : undefined })
        .then(async r => {
          self.status = r.status; self._rh = Object.fromEntries(r.headers); mergeSetCookie(r.headers)
          const rb = Buffer.from(await r.arrayBuffer())
          self.responseText = rb.toString('latin1'); self.response = self.responseText; self.readyState = 4
          if (isReload) log('      /reload response:', r.status, rb.length, 'bytes |', self.responseText.slice(0, 48).replace(/\n/g, ' '))
          if (self.onreadystatechange) self.onreadystatechange()
          if (self.onload) self.onload()
        })
        .catch(e => { self.status = 0; self.readyState = 4; if (self.onerror) self.onerror(e); if (self.onreadystatechange) self.onreadystatechange() })
    }
  }
}

// ----------------------------------------------------------------------------
// 4) Realm-realism: monotonic 0.1ms clock + growing heap so Xm reads (U>0, x>0) are valid.
//    (Static heap -> U=0 and now()+random -> non-monotonic x are degenerate giveaways.)
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
// 5) FakeWorker: spawns the WORKER realm in-process and wires it to the page via the
//    by-reference loopback (worker-bootstrap postMessage(d5,[port2]) is delivered intact).
// ----------------------------------------------------------------------------
let workerRealm = null
const ALL_ELS = []
function FakeWorker(url) {
  log('[page] new Worker(', String(url).slice(0, 72), ')')
  const self_ = this; self_._lis = []; self_._on = null
  const wmsgListeners = [], toPageQ = []
  const d = m => { try { return typeof m === 'string' ? 'str(' + m.length + ')' : (m && m.constructor ? m.constructor.name : typeof m) } catch { return '?' } }
  function flushToPage() { if (!(self_._on || self_._lis.length)) return; while (toPageQ.length) { const ev = toPageQ.shift(); if (TRACE) log('   [w->p]', d(ev.data), 'ports=' + ev.ports.length); if (self_._on) try { self_._on(ev) } catch {} for (const f of self_._lis) try { f(ev) } catch {} } }
  workerRealm = buildRealm('worker', {
    __cap: {},
    performance: makePerf(),
    XMLHttpRequest: function () { return { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, getAllResponseHeaders: () => '', abort() {} } },
    postMessage: (m, transfer) => { toPageQ.push({ data: m, ports: Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : [] }); flushToPage() },
    addEventListener: (t, f) => { if (t === 'message') wmsgListeners.push(f) },
  })
  function deliverToWorker(ev) { if (TRACE) log('   [p->w]', d(ev.data), 'ports=' + ev.ports.length); const ws = workerRealm.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch {} for (const f of wmsgListeners) try { f(ev) } catch {} }
  self_.postMessage = (m, t) => deliverToWorker({ data: m, ports: (t || []).filter(x => x && x.__isPort) })
  self_.addEventListener = (t, f) => { if (t === 'message') { self_._lis.push(f); flushToPage() } }
  self_.removeEventListener = (t, f) => { self_._lis = self_._lis.filter(x => x !== f) }
  self_.terminate = () => {}
  Object.defineProperty(self_, 'onmessage', { get() { return self_._on }, set(f) { self_._on = f; flushToPage() } })
}

// ----------------------------------------------------------------------------
// 6) Page DOM stub (no canvas). Elements capture listeners so we can fire the checkbox.
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
  ALL_ELS.push(real)
  return P
}
const docEl = makeEl('html')
const document = new Proxy({
  createElement: t => makeEl(t), createElementNS: (ns, t) => makeEl(t), createDocumentFragment: () => makeEl('fragment'), createTextNode: () => makeEl('text'), createComment: () => makeEl('comment'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
  getElementById: id => (ELS[id] = ELS[id] || makeEl('div', id)), querySelector: s => (ELS['q:' + s] = ELS['q:' + s] || makeEl('div', 'q:' + s)), querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], getElementsByName: () => [],
  documentElement: docEl, head: makeEl('head'), body: makeEl('body'), cookie: '', referrer: 'https://www.google.com/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
}, { get(t, k) { if (k in t) return t[k]; return noop() }, has() { return true } })

const WIN_LIS = {}        // window-level event listeners (the anchor's parent 'message' intake)
const WIN_POSTS = []      // what the anchor posts to its parent (api.js handshake)
function winDesc(m) { try { if (typeof m === 'string') return 'str(' + m.length + '):' + m.slice(0, 70); if (Array.isArray(m)) return 'arr[' + m.length + ']:' + JSON.stringify(m).slice(0, 90); return (m && m.constructor && m.constructor.name || typeof m) + ':' + JSON.stringify(m).slice(0, 90) } catch { return typeof m } }
const windowExtra = {
  __cap: {},
  Worker: FakeWorker,
  document,
  addEventListener: (t, f) => { (WIN_LIS[t] = WIN_LIS[t] || []).push(f) },
  removeEventListener: (t, f) => { if (WIN_LIS[t]) WIN_LIS[t] = WIN_LIS[t].filter(x => x !== f) },
  postMessage: (m, targetOrigin, transfer) => { const ports = Array.isArray(transfer) ? transfer : (Array.isArray(targetOrigin) ? targetOrigin : []); WIN_POSTS.push({ m, targetOrigin, ports }); if (process.env.TRACE) log('   [anchor->parent post]', winDesc(m), 'to=' + targetOrigin, 'ports=' + ports.length) },
  performance: makePerf(),
  XMLHttpRequest: makeDriverXHR(),               // <-- our instrumented XHR wins via Object.assign
  location: { href: `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=${CO}&hl=en&v=${VER}&size=normal`, origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/anchor', search: `?k=${SITEKEY}`, hash: '', replace() {}, assign() {}, reload() {} },
  screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
  history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
  sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
  devicePixelRatio: 1, innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1080, name: '', closed: false,
  matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
  getComputedStyle: () => noop(), parent: null, top: null, frameElement: null, scrollTo() {}, focus() {}, blur() {},
  Image: function () { return noop() }, Event: function () { return noop() }, CustomEvent: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
  ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
  // NOTE: window.botguard intentionally LEFT UNDEFINED. With ew.D==null the anchor verify
  // method takes Promise.resolve().then(this.U) (the worker-attestation path that builds the
  // /reload), instead of this.D.C.execute() (page-side BotGuard we cannot run in node).
}

// ----------------------------------------------------------------------------
// 7) extract the exact recaptcha.anchor.Main.init("...") literal from anchor HTML.
// ----------------------------------------------------------------------------
function extractInitCall(html) {
  const key = 'recaptcha.anchor.Main.init('
  const i = html.indexOf(key); if (i < 0) return null
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) {
    const c = html[p]
    if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
    if (c === '"' || c === "'") { inStr = true; q = c; continue }
    if (c === '(') depth++; else if (c === ')') { depth--; if (depth === 0) { p++; break } }
  }
  return html.slice(i, p)
}

// ----------------------------------------------------------------------------
// 8) Main: boot page realm -> fetch anchor -> init -> trigger -> intercept /reload.
// ----------------------------------------------------------------------------
async function main() {
  process.on('unhandledRejection', () => {})
  log('[driver] sitekey=%s  co=%s (%s)  ver=%s', SITEKEY, CO, ORIGIN, VER)

  log('[driver] booting page realm...')
  const page = buildRealm('page', windowExtra, { pageWindow: true })
  log('[driver] page load:', page.err ? 'THREW ' + page.err.message : 'OK')
  if (!page.sandbox.recaptcha || !page.sandbox.recaptcha.anchor) { log('[driver] no recaptcha.anchor api — abort'); process.exit(1) }
  log('[driver] recaptcha api:', Object.keys(page.sandbox.recaptcha).join(','))

  // fetch a FRESH anchor (cfg is server-/session-bound — must not be cached/synthesized)
  const aurl = `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=${CO}&hl=en&v=${VER}&size=normal&cb=${Math.random().toString(36).slice(2, 14)}`
  log('[driver] GET anchor...')
  let html
  try { const r = await fetch(aurl, { headers: { 'User-Agent': UA } }); mergeSetCookie(r.headers); html = await r.text() }
  catch (e) { log('[driver] anchor fetch failed:', e.message); process.exit(1) }
  const initCall = extractInitCall(html)
  if (!initCall) { log('[driver] no init() literal in anchor html (len=' + html.length + ') — cfg not present'); process.exit(1) }
  log('[driver] init literal extracted:', initCall.length, 'chars | cookie:', COOKIE ? COOKIE.split(';')[0] : '(none)')

  log('[driver] recaptcha.anchor.Main.init(cfg)...')
  try { vm.runInContext(initCall, page.ctx, { timeout: 20000 }) }
  catch (e) { log('[driver] init threw:', e.message, '\n', (e.stack || '').split('\n').slice(1, 4).join('\n')) }

  // let the worker spawn + the BotGuard handshake run over the loopback
  for (let s = 0; s < 12 && !workerRealm; s++) await new Promise(r => setTimeout(r, 500))
  log('[driver] worker spawned:', !!workerRealm, workerRealm ? '| load ' + (workerRealm.err ? 'THREW ' + workerRealm.err.message : 'OK') : '')
  const pcap = page.sandbox.__cap || {}, wcap = workerRealm ? (workerRealm.sandbox.__cap || {}) : {}
  log('[driver] page __cap:', Object.keys(pcap).join(',') || '-', '| worker __cap:', Object.keys(wcap).join(',') || '-', '| RPp opcodes:', wcap.RPp ? wcap.RPp.size : '-')
  await new Promise(r => setTimeout(r, 1500))

  // Step 4a diagnostic: the cross-frame parent<->anchor handshake the anchor is waiting on.
  log('[driver] window listeners:', Object.keys(WIN_LIS).map(k => k + '(' + WIN_LIS[k].length + ')').join(',') || 'none')
  log('[driver] anchor->parent posts:', WIN_POSTS.length)
  WIN_POSTS.slice(0, 6).forEach((p, i) => log('   post#' + i + ':', winDesc(p.m), 'to=' + p.targetOrigin, 'ports=' + p.ports.length))

  // Step 4b: EMULATE THE PARENT (api.js). The anchor posted "recaptcha-setup"+port to its
  // parent and is waiting for the parent's reply to establish the comm channel + go interactive.
  log('[driver] entering step4b parent-handshake block...')
  try {
  const anchorPost = WIN_POSTS.find(p => p.ports && p.ports.length)
  const anchorPort = anchorPost && anchorPost.ports[0]
  log('[driver] anchorPort=' + !!anchorPort + ' msgListeners=' + (WIN_LIS['message'] || []).length)
  const mkPort = () => ({ __isPort: true, _peer: null, _on: null, _q: [], get onmessage() { return this._on }, set onmessage(f) { this._on = f; const q = this._q.splice(0); for (const e of q) try { f(e) } catch {} }, addEventListener(t, f) { if (t === 'message') this.onmessage = f }, removeEventListener() {}, start() {}, close() {}, postMessage(dd, tr) { const ev = { data: dd, ports: (tr || []).filter(x => x && x.__isPort), type: 'message' }; const p = this._peer; queueMicrotask(() => { if (!p) return; if (p._on) try { p._on(ev) } catch {} else p._q.push(ev) }) } })
  const mkChannel = () => { const a = mkPort(), b = mkPort(); a._peer = b; b._peer = a; return { port1: a, port2: b } }
  if (WIN_LIS['message'] && WIN_LIS['message'].length) {
    const parentCh = mkChannel()
    const hostOrigin = (anchorPost && anchorPost.targetOrigin && typeof anchorPost.targetOrigin === 'string') ? anchorPost.targetOrigin.replace(/:443$/, '') : 'https://lucille.sh'
    // RECORD the raw anchor<->parent comm frames (both channel directions) so agents can
    // decode the api.js command protocol. Each frame = ["B"+b64(ciphertext), tag, callid].
    const FRAMES = []
    parentCh.port1.onmessage = (ev) => { FRAMES.push({ dir: 'anchor->parent', t: Date.now(), data: ev && ev.data }); if (process.env.TRACE) log('   [a->p frame]', winDesc(ev && ev.data)) }
    if (anchorPort) anchorPort.onmessage = (ev) => { FRAMES.push({ dir: 'anchor->parent(altport)', t: Date.now(), data: ev && ev.data }); if (process.env.TRACE) log('   [a->p alt]', winDesc(ev && ev.data)) }
    global.__FRAMES = FRAMES; global.__WIN_POSTS = WIN_POSTS
    const variants = [
      { data: 'recaptcha-setup', origin: hostOrigin, source: page.ctx, ports: [parentCh.port2] },
      { data: 'recaptcha-setup', origin: 'https://www.google.com', source: page.ctx, ports: [parentCh.port2] },
    ]
    for (const v of variants) {
      log('[driver] -> posting parent reply (origin=' + v.origin + ')')
      for (const fn of WIN_LIS['message']) { try { fn({ ...v, type: 'message', preventDefault() {}, stopPropagation() {} }); log('[driver]    reply delivered to anchor handler') } catch (e) { log('   [parent-reply] handler threw:', e.message) } }
      await new Promise(r => setTimeout(r, 1200))
      if (RELOADS.length || ALL_ELS.some(el => el._lis && el._lis.click)) break
    }
    await new Promise(r => setTimeout(r, 1500))
    log('[driver] after parent handshake: reloads=' + RELOADS.length + ' | clickListeners=' + ALL_ELS.filter(el => el._lis && el._lis.click).length + ' | win listeners now=' + Object.keys(WIN_LIS).map(k => k + '(' + WIN_LIS[k].length + ')').join(','))
    log('[driver] comm frames captured:', FRAMES.length, '| anchor->parent window posts:', WIN_POSTS.length)
    try {
      const dump = { winPosts: WIN_POSTS.map(p => ({ data: typeof p.m === 'string' ? p.m : JSON.stringify(p.m).slice(0, 200), to: String(p.targetOrigin).slice(0, 60), ports: p.ports.length })), frames: FRAMES.map(f => ({ dir: f.dir, data: typeof f.data === 'string' ? f.data : JSON.stringify(f.data).slice(0, 4000) })) }
      fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/comm_frames.json', JSON.stringify(dump, null, 1))
      log('[driver] saved comm_frames.json (' + FRAMES.length + ' frames)')
    } catch (e) { log('save frames err', e.message) }
  }
  } catch (e) { log('[driver] step4b THREW:', e.message, '\n', (e.stack || '').split('\n').slice(1, 4).join('\n')) }

  // TRIGGER: bare init does NOT emit /reload — fire the checkbox interaction. Synthesize a
  // small pointer path first so field20 telemetry is non-empty, then click/space the checkbox.
  const clickable = ALL_ELS.filter(el => el._lis && (el._lis.click || el._lis.mousedown || el._lis.pointerdown || el._lis.keydown))
  log('[driver] DOM elements:', ALL_ELS.length, '| with click/key listeners:', clickable.length, '(' + clickable.map(el => el.id || el.tagName).slice(0, 8).join(',') + ')')
  for (const el of clickable) {
    try {
      for (let k = 0; k < 4; k++) el._fire('pointermove', { type: 'pointermove', clientX: 8 + k * 3, clientY: 9 + k * 2, isTrusted: true, target: el, preventDefault() {}, stopPropagation() {} })
      el._fire('pointerdown'); el._fire('mousedown'); el._fire('focus')
      el._fire('keydown', { type: 'keydown', key: ' ', keyCode: 32, which: 32, isTrusted: true, target: el, preventDefault() {}, stopPropagation() {} })
      el._fire('click'); el._fire('mouseup'); el._fire('pointerup')
    } catch {}
  }
  // fallback: if the controller was captured and exposed a public execute, nudge it
  try { if (page.sandbox.grecaptcha && typeof page.sandbox.grecaptcha.execute === 'function') page.sandbox.grecaptcha.execute() } catch {}
  if (page.sandbox.__grWR) log('[driver] WR controller captured (__grWR); .D keys:', page.sandbox.__grWR.D ? Object.keys(page.sandbox.__grWR.D).slice(0, 20).join(',') : '-')

  // wait for the /reload (race with a timeout)
  log('[driver] waiting for /reload ...')
  const winner = await Promise.race([firstReload, new Promise(r => setTimeout(() => r(null), 12000))])

  log('\n[driver] ===== RESULT =====')
  log('reloads intercepted:', RELOADS.length)
  RELOADS.forEach((R, i) => log(`  reload#${i + 1}: ${R.buf.length}B | field16 ${R.info.present ? R.info.len + 'B urlSafeB64=' + R.info.urlSafeB64 : 'EMPTY'} | fields ${JSON.stringify(R.info.map)}`))
  if (!winner) {
    log('NO /reload fired. The trigger did not reach the verify->reload path in-VM.')
    log('Most likely: the page-side AE is not bound to the worker\'s transferred port, so Qr/ak')
    log('never complete and the controller never schedules the reload. (See riskiest-unknown note.)')
  } else if (winner.info.present && winner.info.len > 0) {
    log('FIELD16 PRESENT (', winner.info.len, 'bytes ). Wrote selfdriven_reload_*.bin.')
    log('Next: keep the session alive across the rresp (field18 -> ak -> 2nd reload non-empty field16),')
    log('then POST the resulting g-recaptcha-response to siteverify on the own key as the GO/NO-GO oracle.')
  } else {
    log('FIELD16 EMPTY on this reload — expected for the FIRST /reload; a populated field16 appears')
    log('only from the 2nd reload onward (built from the prior response\'s field18 attestation).')
  }
  process.exit(0)
}

if (require.main === module) main()
module.exports = { extractField16, extractInitCall, makeDriverXHR, makePerf, RELOADS }
