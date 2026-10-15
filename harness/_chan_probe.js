// Offline probe: run recaptcha.anchor.Main.init(<captured cfg>) and capture the
// cross-frame channel configs (BY=name N, x0=token f), the EQ/zG property keys, and
// what the anchor posts to its parent. No network: init runs on the captured cfg literal.
'use strict'
const fs = require('fs')
const vm = require('vm')
process.env.ENJS = 'C:/Users/user/Desktop/a/recaptcha-re/harness/_en_chancap.js'
const { buildRealm } = require('./page.js')

const SITEKEY = '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-'
const VER = 'TnA7HacJFoBWt9hnlunBlYfK'
const HOST = 'https://2captcha.com'           // co decoded from the captured cfg[4]
const CO = Buffer.from(HOST + ':443').toString('base64url')
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/149.0.0.0'
const log = (...a) => console.log(...a)

// ---- minimal worker shim ----
let workerRealm = null
function FakeWorker(url) {
  const self_ = this; self_._lis = []; self_._on = null
  const wmsg = [], toPageQ = []
  function flush() { if (!(self_._on || self_._lis.length)) return; while (toPageQ.length) { const ev = toPageQ.shift(); if (self_._on) try { self_._on(ev) } catch {} for (const f of self_._lis) try { f(ev) } catch {} } }
  workerRealm = buildRealm('worker', {
    __cap: {}, postMessage: (m, t) => { toPageQ.push({ data: m, ports: Array.isArray(t) ? t.filter(x => x && x.__isPort) : [] }); flush() },
    addEventListener: (t, f) => { if (t === 'message') wmsg.push(f) },
  })
  self_.postMessage = (m, t) => { const ev = { data: m, ports: (t || []).filter(x => x && x.__isPort) }; const ws = workerRealm.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch {} for (const f of wmsg) try { f(ev) } catch {} }
  self_.addEventListener = (t, f) => { if (t === 'message') { self_._lis.push(f); flush() } }
  self_.removeEventListener = () => {}; self_.terminate = () => {}
  Object.defineProperty(self_, 'onmessage', { get() { return self_._on }, set(f) { self_._on = f; flush() } })
}

// ---- DOM stub (no canvas) ----
function noop() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive || k === 'toString' || k === 'valueOf') return () => ''; if (k === 'length') return 0; if (k === 'nodeType') return 1; return P }, apply() { return P }, construct() { return P }, set() { return true }, has() { return true } }); return P }
const ELS = {}, ALL_ELS = []
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
const docEl = makeEl('html')
const document = new Proxy({
  createElement: t => makeEl(t), createElementNS: (ns, t) => makeEl(t), createDocumentFragment: () => makeEl('fragment'), createTextNode: () => makeEl('text'), createComment: () => makeEl('comment'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
  getElementById: id => (ELS[id] = ELS[id] || makeEl('div', id)), querySelector: s => (ELS['q:' + s] = ELS['q:' + s] || makeEl('div', 'q:' + s)), querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], getElementsByName: () => [],
  documentElement: docEl, head: makeEl('head'), body: makeEl('body'), cookie: '', referrer: HOST + '/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
}, { get(t, k) { if (k in t) return t[k]; return noop() }, has() { return true } })

const WIN_LIS = {}, WIN_POSTS = []
function winDesc(m) { try { if (typeof m === 'string') return 'str(' + m.length + '):' + m.slice(0, 80); if (Array.isArray(m)) return 'arr[' + m.length + ']:' + JSON.stringify(m).slice(0, 120); return (m && m.constructor && m.constructor.name || typeof m) + ':' + JSON.stringify(m).slice(0, 120) } catch { return typeof m } }
const windowExtra = {
  __cap: {}, Worker: FakeWorker, document,
  addEventListener: (t, f) => { (WIN_LIS[t] = WIN_LIS[t] || []).push(f); if (t === 'message') (windowExtra.__mlStacks = windowExtra.__mlStacks || []).push(new Error().stack) },
  removeEventListener: (t, f) => { if (WIN_LIS[t]) WIN_LIS[t] = WIN_LIS[t].filter(x => x !== f) },
  postMessage: (m, targetOrigin, transfer) => { const ports = Array.isArray(transfer) ? transfer : (Array.isArray(targetOrigin) ? targetOrigin : []); const stack = new Error().stack; WIN_POSTS.push({ m, targetOrigin, ports, stack }); log('   [anchor->parent post]', winDesc(m), 'to=' + targetOrigin, 'ports=' + ports.length) },
  location: { href: `${HOST}/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=${CO}&hl=en&v=${VER}&size=normal&cb=probecbval`, origin: HOST, protocol: 'https:', host: '2captcha.com', hostname: '2captcha.com', pathname: '/recaptcha/api2/anchor', search: `?k=${SITEKEY}&cb=probecbval`, hash: '', replace() {}, assign() {}, reload() {} },
  screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
  history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
  devicePixelRatio: 1, innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1080, name: '', closed: false,
  matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
  getComputedStyle: () => noop(), parent: null, top: null, frameElement: null, scrollTo() {}, focus() {}, blur() {},
  Image: function () { return noop() }, Event: function () { return noop() }, CustomEvent: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
  ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
}

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

async function main() {
  process.on('unhandledRejection', e => log('  [unhandled]', e && e.message))
  const page = buildRealm('page', windowExtra, { pageWindow: true })
  log('[probe] page load:', page.err ? 'THREW ' + page.err.message : 'OK')
  log('[probe] recaptcha api:', page.sandbox.recaptcha ? Object.keys(page.sandbox.recaptcha).join(',') : '-')

  const html = fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/poc/anchor_html.txt', 'utf8')
  const initCall = extractInitCall(html)
  log('[probe] init literal:', initCall ? initCall.length + ' chars' : 'MISSING')

  try { vm.runInContext(initCall, page.ctx, { timeout: 20000 }) }
  catch (e) { log('[probe] init threw:', e.message, '\n', (e.stack || '').split('\n').slice(1, 4).join('\n')) }

  for (let s = 0; s < 8 && !workerRealm; s++) await new Promise(r => setTimeout(r, 300))
  await new Promise(r => setTimeout(r, 800))

  const sb = page.sandbox
  log('\n[probe] ===== EQ / zG property keys =====')
  log('  EQ (name key)  =', JSON.stringify(sb.__EQ2))
  log('  zG (token key) =', JSON.stringify(sb.__zG2))

  log('\n[probe] ===== channels established (line 405) =====')
  const CH = sb.__CHAN || []
  log('  count:', CH.length)
  CH.forEach((c, i) => log(`  chan#${i}: BY(name N)=${JSON.stringify(c.BY)}  x0(token f)=${JSON.stringify(c.x0)}  destType=${c.destType}`))

  log('\n[probe] ===== anchor -> parent window.postMessage =====')
  log('  count:', WIN_POSTS.length)
  WIN_POSTS.forEach((p, i) => log(`  post#${i}: ${winDesc(p.m)}  to=${p.targetOrigin}  ports=${p.ports.length}`))

  log('\n[probe] window listeners now:', Object.keys(WIN_LIS).map(k => k + '(' + WIN_LIS[k].length + ')').join(',') || 'none')
  log('[probe] worker spawned:', !!workerRealm)

  log('\n[probe] ===== postMessage call stacks (locate setup code) =====')
  WIN_POSTS.forEach((p, i) => { log(`  post#${i} stack:`); (p.stack || '').split('\n').slice(1, 6).forEach(l => log('    ' + l.trim())) })

  log('\n[probe] ===== window message-listener install stacks =====')
  ;(windowExtra.__mlStacks || []).forEach((s, i) => { log(`  mlisten#${i}:`); s.split('\n').slice(1, 14).forEach(l => log('    ' + l.trim())) })

  log('\n[probe] ===== setup-receiver source (window message listener[0]) =====')
  const ml = (WIN_LIS['message'] || [])
  ml.forEach((fn, i) => { try { const s = fn.toString(); log(`  listener#${i} (${s.length} chars):\n`, s.slice(0, 1600)) } catch (e) { log('  toString err', e.message) } })

  // Reproduce driver_core's acceptance: deliver the parent reply and watch (a) the anchor's
  // transferred port for outbound AE frames, (b) any NEW nj channel (carries name/token), (c)
  // a 2nd window 'message' listener.
  log('\n[probe] ===== replaying parent reply (driver_core form) =====')
  const before = { posts: WIN_POSTS.length, mlis: (WIN_LIS['message'] || []).length, chan: (sb.__CHAN || []).length }
  const anchorPost = WIN_POSTS.find(p => p.ports && p.ports.length)   // post#1 to host origin
  const anchorPort = anchorPost && anchorPost.ports[0]                // the port WE (parent) received
  const AE_FRAMES = []
  if (anchorPort) { try { anchorPort.onmessage = (ev) => { AE_FRAMES.push(ev && ev.data); log('   [AE frame over port]', winDesc(ev && ev.data)) } } catch (e) { log('   set onmessage err', e.message) } }
  const EQ = sb.__EQ2, zG = sb.__zG2
  // a loopback reply port the "parent" hands back
  const mkPort = () => ({ __isPort: true, _peer: null, _on: null, _q: [], get onmessage() { return this._on }, set onmessage(f) { this._on = f }, addEventListener(t, f) { if (t === 'message') this._on = f }, removeEventListener() {}, start() {}, close() {}, postMessage(dd, tr) { const ev = { data: dd, ports: (tr || []).filter(x => x && x.__isPort), type: 'message' }; const p = this._peer; queueMicrotask(() => { if (p && p._on) try { p._on(ev) } catch {} }) } })
  const a = mkPort(), b = mkPort(); a._peer = b; b._peer = a
  function deliver(data, origin, source, ports) {
    const ev = { data, origin, source, ports, type: 'message', lastEventId: '', currentTarget: page.ctx, target: page.ctx, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {} }
    for (const fn of (WIN_LIS['message'] || []).slice()) { try { fn(ev) } catch (e) { log('   reply handler threw:', e.message) } }
  }
  // exact driver_core form: plain string, source = page global, host origin, our reply port
  deliver('recaptcha-setup', 'https://2captcha.com', page.ctx, [b])
  await new Promise(r => setTimeout(r, 600))
  // try alternate source refs in case K() expects a different object
  deliver('recaptcha-setup', 'https://2captcha.com', page.sandbox, [b])
  deliver('recaptcha-setup', 'https://2captcha.com', undefined, [b])
  await new Promise(r => setTimeout(r, 600))
  log('  EQ(name key)=' + JSON.stringify(EQ) + '  zG(token key)=' + JSON.stringify(zG))
  log('  AE frames captured over anchor port:', AE_FRAMES.length)
  log('  delta: posts ' + before.posts + '->' + WIN_POSTS.length + ' | mlis ' + before.mlis + '->' + (WIN_LIS['message'] || []).length + ' | nj-chan ' + before.chan + '->' + (sb.__CHAN || []).length)
  ;(sb.__CHAN || []).forEach((c, i) => log(`  nj-chan#${i}: BY(name N)=${JSON.stringify(c.BY)} x0(token f)=${JSON.stringify(c.x0)} destType=${c.destType}`))
  WIN_POSTS.slice(before.posts).forEach((p) => log(`  +post: ${winDesc(p.m)} to=${p.targetOrigin} ports=${p.ports.length}`))
  process.exit(0)
}
main()
