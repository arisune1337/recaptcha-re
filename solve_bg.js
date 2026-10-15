/**
 * solve_bg.js — BotGuard field16 token via synthetic parent-message handshake
 * Usage: node solve_bg.js <anchor_url>
 * Output: JSON { "bg": "<field16_b64url>" } on stdout, or { "error": "..." }
 *
 * Strategy (WF_INTEGRATE.md Step 4b):
 *   1. Boot anchor PAGE realm + WORKER realm (loopback) — en.js loads, worker spawns
 *   2. Capture window.addEventListener('message') handlers (winListeners)
 *   3. Run recaptcha.anchor.Main.init(cfg) — extract cfg[24] (name) + cfg[30] (token)
 *   4. After init, inject a synthetic parent MessageEvent with:
 *        { data: [name, token, portFromApiJs], source: pageCtx, origin: 'https://www.google.com' }
 *      This emulates what api.js would post to unlock the checkbox
 *   5. Fire checkbox click events → /reload fires (field16 in body)
 *   6. Return field16 as the bg token
 */
'use strict'

const fs  = require('fs')
const vm  = require('vm')
const crypto = require('crypto')
const { decode } = require(__dirname + '/poc/pb.js')
const PR  = require(__dirname + '/harness/page_rpc.js')
const { makePort, MessageChannelShim } = require(__dirname + '/harness/page.js')

const ENJS = process.env.ENJS || (__dirname + '/recaptcha__en.js')
const UA   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const TIMEOUT = parseInt(process.env.BG_TIMEOUT || '35000', 10)
const sleep = ms => new Promise(r => setTimeout(r, ms))

// ---- proxy support (HTTPS_PROXY env var or process.argv[3]) ----------------
const PROXY_URL = process.argv[3] || process.env.HTTPS_PROXY || process.env.HTTP_PROXY || ''
let fetchFn = global.fetch
let fetchAgent = undefined

if (PROXY_URL) {
  try {
    const fetch = require('node-fetch')
    const { HttpsProxyAgent } = require('https-proxy-agent')
    fetchFn = fetch
    fetchAgent = new HttpsProxyAgent(PROXY_URL)
  } catch (e) {
    // node-fetch or proxy-agent not available
  }
}


const anchor_url = process.argv[2]
if (!anchor_url) {
  process.stdout.write(JSON.stringify({ error: 'Usage: node solve_bg.js <anchor_url>' }) + '\n')
  process.exit(1)
}

// ---- patch en.js (same as page_rpc.js + solveloop.js) ----------------------
let CODE = PR.applyPatches(fs.readFileSync(ENJS, 'utf8'))
function patch(find, repl, optional) {
  const i = CODE.indexOf(find)
  if (i < 0) { if (optional) return false; throw new Error('patch NOT FOUND: ' + find) }
  if (CODE.indexOf(find, i + 1) >= 0 && !optional) throw new Error('patch NON-UNIQUE: ' + find)
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length); return true
}
patch('(new WR(r)).D).init()', '(self.__grWR=new WR(r)).D).init()', true)
patch('RPp=new Map([[Qr,',    'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),', true)
patch('}],[ak,function',      '}],[(__cap.ak=ak),function', true)
patch('AE=function(q,r,w,D,d,A){return b[32]', 'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]', true)

const INTRINSICS = ['Object','Array','Function','String','Number','Boolean','Symbol','BigInt',
  'Math','JSON','Date','RegExp','Error','TypeError','RangeError','EvalError','ReferenceError',
  'SyntaxError','URIError','Reflect','Proxy','Promise','Map','Set','WeakMap','WeakSet','WeakRef',
  'ArrayBuffer','SharedArrayBuffer','DataView','Uint8Array','Int8Array','Uint8ClampedArray',
  'Uint16Array','Int16Array','Uint32Array','Int32Array','Float32Array','Float64Array',
  'BigInt64Array','BigUint64Array','parseInt','parseFloat','decodeURIComponent',
  'encodeURIComponent','decodeURI','encodeURI','escape','unescape','isNaN','isFinite',
  'Intl','structuredClone','Infinity','NaN','undefined','globalThis']

// ---- perf stub (Xm attestation needs heapDelta>0, execMs>0) ----------------
function makePerf(resourceHost) {
  const T0 = Date.now(), hr0 = process.hrtime.bigint(), HEAP0 = process.memoryUsage().heapUsed
  const BASE = 13_000_000; let last = 0
  const now = () => { let ms = Number(process.hrtime.bigint() - hr0) / 1e6; ms = Math.floor(ms / 0.1) * 0.1; if (ms < last) ms = last; last = ms; return ms }
  const host = resourceHost || 'www.google.com'
  const entries = [
    { entryType: 'navigation', name: `https://${host}/recaptcha/api2/anchor`, startTime: 0, duration: 320, nextHopProtocol: 'h2', responseStatus: 200, type: 'navigate' },
    { entryType: 'resource', name: `https://${host}/recaptcha/api2/webworker.js`, startTime: 80, duration: 120, nextHopProtocol: 'h2', responseStatus: 200 },
    { entryType: 'resource', name: 'https://www.gstatic.com/recaptcha/releases/TnA7HacJFoBWt9hnlunBlYfK/recaptcha__en.js', startTime: 10, duration: 280, nextHopProtocol: 'h2', responseStatus: 200 },
  ]
  return {
    now, timeOrigin: T0, mark() {}, measure() {}, clearMarks() {}, clearMeasures() {},
    getEntriesByType: t => t === 'navigation' ? entries.slice(0, 1) : t === 'resource' ? entries.slice(1) : [],
    memory: {
      get usedJSHeapSize() { return BASE + Math.max(0, process.memoryUsage().heapUsed - HEAP0) },
      get totalJSHeapSize() { return Math.max(this.usedJSHeapSize + 2_000_000, 40_000_000) },
      jsHeapSizeLimit: 2_190_000_000
    }
  }
}

// ---- XHR: route to fetch, capture /reload bodies ----------------------------
const ALL_REQS = []
function makeXHR(jar) {
  return class XHR {
    constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = '' }
    open(m, u) { this._m = m; this._u = u }
    setRequestHeader(k, v) { this._h[k] = v }
    addEventListener(t, f) { this['on' + t] = f }
    getAllResponseHeaders() { return Object.entries(this._rh || {}).map(([k, v]) => k + ': ' + v).join('\r\n') }
    getResponseHeader(k) { return (this._rh || {})[String(k).toLowerCase()] || null }
    abort() {}
    send(body) {
      const self = this, url = String(this._u)
      const reqBody = body && body.byteLength != null
        ? Buffer.from(body.buffer || body, body.buffer ? undefined : 'latin1')
        : (typeof body === 'string' ? Buffer.from(body, 'latin1') : null)
      ALL_REQS.push({ u: url, body: reqBody })
      const headers = { 'User-Agent': UA, ...this._h }
      if (jar && jar.cookie) headers.cookie = jar.cookie
      fetch(url, { method: this._m || 'GET', headers, body: body || undefined }).then(async r => {
        self.status = r.status; self._rh = Object.fromEntries(r.headers)
        const sc = r.headers.get('set-cookie'); if (sc && jar) jar.absorb(sc)
        const buf = Buffer.from(await r.arrayBuffer())
        self.responseText = buf.toString('latin1'); self.response = self.responseText; self.readyState = 4
        if (self.onreadystatechange) self.onreadystatechange()
        if (self.onload) self.onload()
      }).catch(e => {
        self.status = 0; self.readyState = 4
        if (self.onerror) self.onerror(e)
        if (self.onreadystatechange) self.onreadystatechange()
      })
    }
  }
}

function makeJar() {
  const m = {}
  return { get cookie() { return Object.entries(m).map(([k, v]) => k + '=' + v).join('; ') },
    absorb(sc) { String(sc).split(/,(?=[^;]+=)/).forEach(c => { const [kv] = c.split(';'); const i = kv.indexOf('='); if (i > 0) m[kv.slice(0, i).trim()] = kv.slice(i + 1).trim() }) } }
}

// ---- DOM stub with listener capture (mirrors page.js makeEl) ----------------
const ALL_ELS = [], ELS = {}
const DOC_LIS = {}  // document-level event listeners (event delegation)

function noop() {
  const f = function() { return P }
  const P = new Proxy(f, {
    get(t, k) {
      if (k === Symbol.toPrimitive) return (hint) => hint === 'number' ? 0 : ''
      if (k === Symbol.iterator) return function*() {}
      if (k === 'valueOf') return () => 0
      if (k === 'toString' || k === 'toJSON') return () => ''
      if (k === 'nodeType') return 1
      if (k === 'length') return 0
      if (k === 'then') return undefined  // not a Promise
      return P
    },
    apply: () => P, construct: () => P, set: () => true, has: () => true
  })
  return P
}
function makeEl(tag, id) {
  const lis = {}
  function mkEv(t) { return { type: t, isTrusted: true, bubbles: true, cancelable: true, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, target: P, currentTarget: P, clientX: 14, clientY: 14, button: 0, key: ' ', keyCode: 32, which: 32 } }
  function fire(type, ev) { (lis[type] || []).slice().forEach(f => { try { f(ev || mkEv(type)) } catch {} }) }
  const real = {
    tagName: (tag || 'div').toUpperCase(), id: id || '', nodeType: 1, value: '', checked: false, disabled: false,
    style: new Proxy({}, { get: () => '', set: () => true }), dataset: {},
    classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
    addEventListener(t, f) {
      if (process.env.BG_DEBUG) process.stderr.write(`[EL.addEventListener] tag=${real.tagName} id=${real.id} type=${t}\n`)
      ;(lis[t] = lis[t] || []).push(f)
    },
    attachEvent(type, fn) {
      // IE-style event registration — capture same as addEventListener
      const t = type.replace(/^on/, '')
      if (process.env.BG_DEBUG) process.stderr.write(`[EL.attachEvent] tag=${real.tagName} id=${real.id} type=${t}\n`)
      ;(lis[t] = lis[t] || []).push(fn)
    },
    detachEvent(type, fn) { const t = type.replace(/^on/, ''); if (lis[t]) lis[t] = lis[t].filter(x => x !== fn) },
    removeEventListener(t, f) { if (lis[t]) lis[t] = lis[t].filter(x => x !== f) },
    setAttribute(k, v) { real[k] = v }, getAttribute: k => real[k] !== undefined ? String(real[k]) : null, hasAttribute: k => k in real, removeAttribute(k) { delete real[k] },
    appendChild: x => x, removeChild: x => x, insertBefore: x => x, replaceChild: x => x,
    remove() {}, contains: () => false, focus() {}, blur() {}, click() { fire('click') },
    cloneNode() { return makeEl(tag, id) }, getContext: () => null,
    setPointerCapture() {}, releasePointerCapture() {},
    querySelector: () => makeEl('div'), querySelectorAll: () => [],
    getElementsByTagName: () => [makeEl('div')], getElementsByClassName: () => [makeEl('div')],
    getBoundingClientRect: () => ({ x: 0, y: 0, width: 28, height: 28, top: 0, left: 0, right: 28, bottom: 28 }),
    getClientRects: () => [], children: [], childNodes: [], firstChild: null, lastChild: null,
    nextSibling: null, previousSibling: null, parentNode: null, ownerDocument: null,
    innerHTML: '', outerHTML: '', textContent: '',
    offsetWidth: 28, offsetHeight: 28, offsetParent: null,
    dispatchEvent(ev) { fire(ev && ev.type, ev); return true },
    _lis: lis, _fire: fire
  }
  const P = new Proxy(real, {
    get(t, k) {
      if (k === Symbol.toPrimitive) return (hint) => hint === 'number' ? 0 : (t.tagName || '')
      if (k === 'valueOf') return () => 0
      if (k === 'then') return undefined  // not thenable/Promise
      if (k in t) return t[k]
      // on* property getter — return actual stored handler (not __prefix)
      if (typeof k === 'string' && /^on/.test(k)) return t[k] || null
      return noop()
    },
    set(t, k, v) {
      if (process.env.BG_DEBUG && typeof k === 'string' && /^on/.test(k) && typeof v === 'function') {
        process.stderr.write(`[EL.on*] tag=${real.tagName} id=${real.id} prop=${k}\n`)
      }
      t[k] = v; return true
    },
    has: () => true
  })
  ALL_ELS.push(real)
  return P
}

const document = new Proxy({
  createElement: t => makeEl(t), createElementNS: (ns, t) => makeEl(t),
  createDocumentFragment: () => makeEl('frag'), createTextNode: () => makeEl('text'),
  createComment: () => makeEl('cmt'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
  getElementById: id => (ELS[id] = ELS[id] || makeEl('div', id)),
  querySelector: s => (ELS['q:' + s] = ELS['q:' + s] || makeEl('div', 'q:' + s)),
  querySelectorAll: () => [], getElementsByTagName: () => [], getElementsByClassName: () => [], getElementsByName: () => [],
  documentElement: makeEl('html'), head: makeEl('head'), body: makeEl('body'),
  cookie: '', referrer: 'https://www.google.com/',
  addEventListener(t, f) { (DOC_LIS[t] = DOC_LIS[t] || []).push(f) },
  removeEventListener(t, f) { if (DOC_LIS[t]) DOC_LIS[t] = DOC_LIS[t].filter(x => x !== f) },
  dispatchEvent: () => true,
  readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null,
  scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat', _els: ELS,
}, { get(t, k) { if (k in t) return t[k]; return noop() }, has: () => true })

// ---- realm builder ----------------------------------------------------------
function buildRealm(role, extra) {
  const winListeners = {}   // capture window.addEventListener calls
  const jar = extra && extra._jar
  const base = {
    __cap: {},
    importScripts: () => {}, postMessage: () => {}, close: () => {},
    addEventListener: (t, f) => { (winListeners[t] = winListeners[t] || []).push(f) },
    removeEventListener: (t, f) => { if (winListeners[t]) winListeners[t] = winListeners[t].filter(x => x !== f) },
    onmessage: null, onerror: null,
    MessageChannel: MessageChannelShim, MessagePort: function() {},
    performance: makePerf(),
    navigator: {
      userAgent: UA, webdriver: false, deviceMemory: 8, hardwareConcurrency: 8,
      language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32',
      vendor: 'Google Inc.', product: 'Gecko', appName: 'Netscape', onLine: true,
      userAgentData: { brands: [{ brand: 'Chromium', version: '149' }, { brand: 'Microsoft Edge', version: '149' }, { brand: 'Not.A/Brand', version: '24' }], mobile: false, platform: 'Windows', getHighEntropyValues: () => Promise.resolve({ architecture: 'x86', bitness: '64', mobile: false, platform: 'Windows', platformVersion: '15.0.0' }) },
      sendBeacon: () => true, cookieEnabled: true, doNotTrack: null, pdfViewerEnabled: true,
      plugins: [], mimeTypes: [],
      permissions: { query: () => Promise.resolve({ state: 'prompt' }) },
    },
    location: {
      href: anchor_url, origin: 'https://www.google.com', protocol: 'https:',
      host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/anchor',
      search: '', hash: '', replace() {}, assign() {}, reload() {}
    },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    atob: s => Buffer.from(s, 'base64').toString('binary'),
    btoa: s => Buffer.from(s, 'binary').toString('base64'),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
    requestAnimationFrame: f => setTimeout(() => f(Date.now()), 16), cancelAnimationFrame: () => {},
    requestIdleCallback: f => setTimeout(() => f({ timeRemaining: () => 5, didTimeout: false }), 1), cancelIdleCallback: () => {},
    TextEncoder, TextDecoder, URL, URLSearchParams, crypto: crypto.webcrypto, fetch: (...a) => fetch(...a),
    console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 1920, innerHeight: 1040, outerWidth: 1920, outerHeight: 1080,
    name: '', closed: false, frameElement: null, scrollTo() {}, focus() {}, blur() {},
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), parent: null, top: null,
    Image: function() { return noop() }, Event: function(t, o) { return { type: t, isTrusted: true, bubbles: !!(o && o.bubbles), cancelable: !!(o && o.cancelable), preventDefault() {}, stopPropagation() {} } },
    CustomEvent: function(t, o) { return { type: t, detail: o && o.detail, isTrusted: true, preventDefault() {}, stopPropagation() {} } },
    MutationObserver: function() { return { observe() {}, disconnect() {}, takeRecords: () => [] } },
    IntersectionObserver: function() { return { observe() {}, disconnect() {} } },
    ResizeObserver: function() { return { observe() {}, disconnect() {} } },
    Notification: Object.assign(function() {}, { permission: 'default', requestPermission: () => Promise.resolve('default'), maxActions: 2 }),
    ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
    botguard: undefined,
    chrome: {
      app: { isInstalled: false }, runtime: {},
      loadTimes: () => ({ requestTime: Date.now()/1000 - 1, firstPaintTime: 0, wasNpnNegotiated: true, npnNegotiatedProtocol: 'h2', wasFetchedViaSpdy: true }),
      csi: () => ({ onloadT: Date.now(), startE: Date.now() - 480, pageT: 320, tran: 15 }),
    },
    XMLHttpRequest: makeXHR(jar),
  }
  Object.assign(base, extra || {})
  for (const k of INTRINSICS) if (!(k in base)) try { base[k] = globalThis[k] } catch {}

  let g
  const captureFn = (t, f) => {
    if (process.env.BG_DEBUG) process.stderr.write(`[BG][${role}] addEventListener(${t})\n`)
    ;(winListeners[t] = winListeners[t] || []).push(f)
  }
  // Keep handlers - don't let CODE remove them from winListeners
  const removeFn = (t, f) => { /* intentional no-op: keep captured handlers */ }
  const pageWindow = !!(extra && extra._pageWindow)
  const parentSpy = extra && extra._parentSpy
  const handler = {
    get(t, k) {
      if (typeof k === 'symbol') return t[k]
      if (k === 'self' || k === 'globalThis') return g
      if (k === 'window') return pageWindow ? g : undefined
      // parent/top: return parentSpy if provided so anchor detects iframe mode
      if (k === 'parent' || k === 'top') return parentSpy || (pageWindow ? g : undefined)
      // Always return our capture fn for addEventListener so en.js can't replace it
      if (k === 'addEventListener') {
        if (process.env.BG_DEBUG) process.stderr.write(`[BG][${role}] getTrap: addEventListener\n`)
        return captureFn
      }
      // Intercept removeEventListener — keep our winListeners intact for replay
      if (k === 'removeEventListener') return removeFn
      return t[k]
    },
    has: () => true, set(t, k, v) { t[k] = v; return true }
  }
  const sandbox = Object.assign(Object.create(null), base)
  const ctx = vm.createContext(new Proxy(sandbox, handler)); g = ctx
  let err = null
  try { vm.runInContext(CODE, ctx, { filename: `recaptcha__en.js[${role}]`, timeout: 20000 }) } catch (e) {
    err = e
    if (process.env.BG_DEBUG) process.stderr.write(`[BG][${role}] CODE err: ${e.message}\n`)
  }
  if (process.env.BG_DEBUG) {
    const wlSummary = Object.entries(winListeners).map(([t, a]) => `${t}×${a.length}`).join(',')
    process.stderr.write(`[BG][${role}] CODE done, winListeners: ${wlSummary || '(none)'}, recaptcha: ${sandbox.recaptcha ? Object.keys(sandbox.recaptcha).join(',') : 'NONE'}\n`)
  }
  return { ctx, sandbox, err, winListeners }
}

// ---- FakeWorker: loopback between page + worker realms ----------------------
let workerRealm = null, pageWorkerPort = null
function FakeWorker(url) {
  const self_ = this; self_._lis = []; self_._on = null
  const wmsgListeners = [], toPageQ = []
  function flushToPage() {
    if (!(self_._on || self_._lis.length)) return
    while (toPageQ.length) { const ev = toPageQ.shift(); if (self_._on) try { self_._on(ev) } catch {} for (const f of self_._lis) try { f(ev) } catch {} }
  }
  workerRealm = buildRealm('worker', {
    postMessage: (m, transfer) => {
      const tp = Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : []
      if (tp.length && !pageWorkerPort) pageWorkerPort = tp[0]
      toPageQ.push({ data: m, ports: tp }); flushToPage()
    },
    addEventListener: (t, f) => { if (t === 'message') wmsgListeners.push(f) },
  })
  function deliverToWorker(ev) { const ws = workerRealm.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch {} for (const f of wmsgListeners) try { f(ev) } catch {} }
  self_.postMessage = (m, t) => deliverToWorker({ data: m, ports: (t || []).filter(x => x && x.__isPort) })
  self_.addEventListener = (t, f) => { if (t === 'message') { self_._lis.push(f); flushToPage() } }
  self_.removeEventListener = (t, f) => { self_._lis = self_._lis.filter(x => x !== f) }
  self_.terminate = () => {}
  Object.defineProperty(self_, 'onmessage', { get() { return self_._on }, set(f) { self_._on = f; flushToPage() } })
}

// ---- init call extractor ----------------------------------------------------
function extractInitCall(html, sym) {
  const key = (sym || 'recaptcha.anchor.Main.init') + '('
  const i = html.indexOf(key); if (i < 0) return { call: null, cfg: null }
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) { const c = html[p]
    if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
    if (c === '"' || c === "'") { inStr = true; q = c; continue }
    if (c === '(') depth++; else if (c === ')') { if (--depth === 0) { p++; break } } }
  const call = html.slice(i, p)
  // Extract cfg array: the arg is a JS string literal containing JSON
  let cfg = null
  try { const strArg = call.slice(key.length, -1); const cfgStr = Function('return ' + strArg)(); cfg = JSON.parse(cfgStr) } catch {}
  return { call, cfg }
}

// ---- field16 extractor -------------------------------------------------------
function extractField16(body) {
  if (!body) return ''
  try {
    let buf = body
    if (typeof body === 'string') buf = Buffer.from(body, 'latin1')
    else if (body.buffer && !(body instanceof Buffer)) buf = Buffer.from(body.buffer)
    const fields = decode(buf)
    const f16 = fields.find(f => f.field === 16)
    if (f16 && f16.raw && f16.len > 100) {
      const s = f16.raw.toString('latin1')
      if (/^[A-Za-z0-9_\-]+$/.test(s)) return s
    }
  } catch {}
  return ''
}

// ---- main -------------------------------------------------------------------
async function main() {
  process.on('unhandledRejection', () => {})

  const jar = makeJar()

  // Spy parent window: when anchor calls parent.postMessage(data, origin),
  // we capture it. Also keeps parent !== window so anchor detects iframe mode.
  const parentMsgs = []
  const hostOrigin = (() => { try { return atob(new URL(anchor_url).searchParams.get('co') || '').replace(/:\d+$/, '') } catch { return 'https://2captcha.com' } })()
  const parentSpy = {
    postMessage: (data, origin, transfer) => {
      if (process.env.BG_DEBUG) process.stderr.write(`[parent.postMessage] data=${JSON.stringify(data).slice(0,60)} ports=${Array.isArray(transfer)?transfer.length:0}\n`)
      parentMsgs.push({ data, origin, transfer: Array.isArray(transfer) ? transfer : [] })
    },
    origin: hostOrigin,
    closed: false,
    location: { href: hostOrigin + '/', origin: hostOrigin },
  }

  // 2. Fetch anchor HTML FIRST so we have cfg before building realm
  let html
  try {
    html = await (await fetchFn(anchor_url, { agent: fetchAgent, headers: { 'User-Agent': UA } })).text()
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: 'anchor fetch: ' + e.message }) + '\n'); process.exit(1)
  }
  const { call: initCall, cfg } = extractInitCall(html)
  if (!initCall) {
    process.stdout.write(JSON.stringify({ error: 'no anchor.Main.init in anchor html' }) + '\n'); process.exit(1)
  }

  // 3. Boot anchor PAGE realm — parent=parentSpy so anchor detects iframe mode
  const page = buildRealm('page', {
    _pageWindow: true,
    _jar: jar,
    _parentSpy: parentSpy,
    Worker: FakeWorker,
    document,
    __onAE: PR.makeOnAE({ getPort: () => pageWorkerPort,
      log: (msg) => { if (process.env.BG_DEBUG) process.stderr.write(`[AE] ${msg}\n`) },
      onRequest: (K, payload, ae) => {
        if (process.env.BG_DEBUG) process.stderr.write(`[AE.req] K=${typeof K === 'symbol' ? String(K) : JSON.stringify(String(K)).slice(0,60)} payload=${PR.describe(payload)}\n`)
      }
    }),

    location: {
      href: anchor_url, origin: 'https://www.google.com', protocol: 'https:',
      host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/anchor',
      search: new URL(anchor_url).search, hash: '', replace() {}, assign() {}, reload() {}
    },
  })

  if (!page.sandbox.recaptcha || !page.sandbox.recaptcha.anchor) {
    process.stdout.write(JSON.stringify({ error: 'no recaptcha.anchor api in realm' }) + '\n'); process.exit(1)
  }

  // 4. IMMEDIATELY save test handlers — NO await between buildRealm and here!
  //    VM setTimeout callbacks remove these listeners asynchronously so we must
  //    capture them synchronously before any event loop turn.
  const savedTestHandlers    = [...(page.winListeners['test']    || [])]
  const savedMsgHandlers     = [...(page.winListeners['message'] || [])]
  const savedStorageHandlers = [...(page.winListeners['storage'] || [])]

  // 5. Inject synthetic parent 'test' event BEFORE initCall
  //    In real browser: api.js posts test message after iframe load, before Main.init
  //    Keep apiToAnchor in scope so we can send RPC via port1 later
  let apiToAnchor = null
  if (cfg && savedTestHandlers.length > 0) {
    const name = cfg[24] || ''   // RC-handle (frame name)
    const cb   = new URL(anchor_url).searchParams.get('cb') || 'p'
    apiToAnchor = new MessageChannelShim()
    // Try multiple data formats: name (RC-handle), cb ('p'), [name, cb]
    for (const dataVal of [name, cb, [name, cb]]) {
      const testMsg = {
        data: dataVal,
        origin: hostOrigin, source: parentSpy,
        ports: [apiToAnchor.port2],
        type: 'test', isTrusted: true, preventDefault() {}, stopPropagation() {}
      }
      for (const fn of savedTestHandlers) {
        try { fn(testMsg) }
        catch(e) { if (process.env.BG_DEBUG) process.stderr.write(`[BG] testFire err (data=${JSON.stringify(dataVal).slice(0,40)}): ${e.message}\n`) }
      }
    }
    if (process.env.BG_DEBUG) process.stderr.write(`[BG] test fired, parentMsgs: ${parentMsgs.length}\n`)
    await sleep(300)
  }

  // 6. Run initCall
  const preInitKeys = new Set(Object.keys(page.sandbox))
  let initErr = null
  try { vm.runInContext(initCall, page.ctx, { timeout: 20000 }) } catch(e) { initErr = e }
  if (process.env.BG_DEBUG) {
    const newKeys = Object.keys(page.sandbox).filter(k => !preInitKeys.has(k))
    process.stderr.write(`[BG] new sandbox keys after init: [${newKeys.slice(0,30).join(', ')}]\n`)
    // Find any objects with render method
    for (const k of newKeys) {
      try {
        const v = page.sandbox[k]
        if (v && typeof v === 'object') {
          const methods = Object.keys(v).filter(m => typeof v[m] === 'function')
          if (methods.length > 0) process.stderr.write(`  ${k}: {${methods.slice(0,10).join(',')}  }\n`)
        }
      } catch {}
    }
  }
  if (process.env.BG_DEBUG) {
    const nClients = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.clients ? Object.keys(page.sandbox.___grecaptcha_cfg.clients).length : 0
    process.stderr.write(`[BG] initCall done. err: ${initErr ? initErr.message : 'none'} | clients: ${nClients} | parentMsgs: ${parentMsgs.length}\n`)
    if (parentMsgs.length) process.stderr.write(`[BG] parentMsgs[0].data: ${JSON.stringify(parentMsgs[0] && parentMsgs[0].data).slice(0, 120)}\n`)
  }

  // 7. Wait for worker to spawn + BotGuard handshake
  for (let s = 0; s < 12 && !workerRealm; s++) await sleep(400)
  await sleep(2500)
  if (process.env.BG_DEBUG) {
    const nCl2 = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.clients ? Object.keys(page.sandbox.___grecaptcha_cfg.clients).length : 0
    const fnsLen = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.fns ? page.sandbox.___grecaptcha_cfg.fns.length : 0
    process.stderr.write(`[BG] after BG wait. parentMsgs: ${parentMsgs.length} | clients: ${nCl2} | allEls: ${ALL_ELS.length} | fns: ${fnsLen}\n`)
    for (const m of parentMsgs) process.stderr.write(`  parentMsg: ${JSON.stringify(m.data).slice(0,100)}\n`)
    // Log recaptcha.frame.Main methods
    try {
      const fm = page.sandbox.recaptcha && page.sandbox.recaptcha.frame && page.sandbox.recaptcha.frame.Main
      process.stderr.write(`[BG] recaptcha.frame.Main methods: ${fm ? Object.keys(fm).join(', ') : 'NONE'}\n`)
    } catch(e) { process.stderr.write(`[BG] frame.Main err: ${e.message}\n`) }
    try {
      const am = page.sandbox.recaptcha && page.sandbox.recaptcha.anchor && page.sandbox.recaptcha.anchor.Main
      process.stderr.write(`[BG] recaptcha.anchor.Main methods: ${am ? Object.keys(am).join(', ') : 'NONE'}\n`)
    } catch(e) {}
    // Try calling any render/show methods
    try {
      const fm = page.sandbox.recaptcha && page.sandbox.recaptcha.frame && page.sandbox.recaptcha.frame.Main
      if (fm) {
        for (const method of ['render', 'show', 'init', 'start', 'enable', 'activate']) {
          if (typeof fm[method] === 'function') {
            process.stderr.write(`[BG] Calling recaptcha.frame.Main.${method}()\n`)
            try { fm[method]() } catch(e) { process.stderr.write(`[BG] ${method}() err: ${e.message}\n`) }
          }
        }
      }
    } catch(e) {}
    // Inspect __grWR and its .D widget controller
    const grWR = page.sandbox['__grWR']
    if (grWR) {
      try {
        const wrKeys = Object.keys(grWR).filter(k => typeof grWR[k] === 'function')
        process.stderr.write(`[BG] __grWR methods: [${wrKeys.slice(0,15).join(', ')}]\n`)
        const widgetD = grWR.D
        if (widgetD && typeof widgetD === 'object') {
          const dKeys = Object.keys(widgetD).filter(k => typeof widgetD[k] === 'function')
          process.stderr.write(`[BG] __grWR.D methods: [${dKeys.slice(0,20).join(', ')}]\n`)
          // Try calling render-sounding methods
          for (const m of dKeys) {
            if (/render|show|display|init|start|activate|widget|draw|create/.test(m)) {
              try {
                process.stderr.write(`[BG] Trying __grWR.D.${m}()...\n`)
                widgetD[m](makeEl('div'))
                process.stderr.write(`[BG]   -> OK\n`)
              } catch(e) { process.stderr.write(`[BG]   -> err: ${e.message}\n`) }
            }
          }
        } else if (widgetD) {
          process.stderr.write(`[BG] __grWR.D type: ${typeof widgetD}\n`)
        }
      } catch(e) { process.stderr.write(`[BG] __grWR inspect err: ${e.message}\n`) }
    }
    // Check if grecaptcha global exists
    const gr = page.sandbox.grecaptcha
    if (gr) {
      process.stderr.write(`[BG] grecaptcha methods: [${Object.keys(gr).filter(k=>typeof gr[k]==='function').slice(0,10).join(', ')}]\n`)
    }
    // Process any pending fns
    const fns = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.fns
    if (fns && fns.length > 0) {
      process.stderr.write(`[BG] Processing ${fns.length} ___grecaptcha_cfg.fns\n`)
      for (const fn of fns) { try { fn() } catch {} }
    }
    // Inspect sandbox closure_lm value (safe - avoid circular JSON)
    const lmKey2 = Object.keys(page.sandbox).find(k => /^closure_lm_/.test(k))
    if (lmKey2) {
      const lmVal = page.sandbox[lmKey2]
      process.stderr.write(`[BG] sandbox.${lmKey2} type: ${typeof lmVal} constructor: ${lmVal && lmVal.constructor && lmVal.constructor.name}\n`)
      // Try to read GCL ListenerMap's Df field (event type map)
      if (lmVal && typeof lmVal === 'object') {
        try {
          const keys = Object.keys(lmVal)
          process.stderr.write(`[BG] sandbox.${lmKey2} keys: [${keys.join(', ')}]\n`)
          // Df is the event type→listener map in GCL ListenerMap
          for (const dk of keys) {
            const dv = lmVal[dk]
            if (dv && typeof dv === 'object' && !Array.isArray(dv)) {
              const evTypes = Object.keys(dv)
              process.stderr.write(`  Df.${dk} types: [${evTypes.join(', ')}]\n`)
            }
          }
        } catch(e) { process.stderr.write(`[BG] lm inspect err: ${e.message}\n`) }
      }
    }
    try { process.stderr.write(`[BG] sandbox.__grWR: ${String(page.sandbox['__grWR']).slice(0,100)}\n`) } catch {}
    // Print ALL elements with ALL own props (to find iframes, src, onload, etc.)
    const lmKeyE = Object.keys(page.sandbox).find(k => /^closure_lm_/.test(k))
    for (let i = 0; i < ALL_ELS.length; i++) {
      const el = ALL_ELS[i]
      const allKeys = Object.keys(el).filter(k => k !== '_lis' && k !== '_fire')
      const nonDefault = allKeys.filter(k => {
        const v = el[k]; return v !== null && v !== '' && v !== false && v !== 0 && v !== undefined && typeof v !== 'function' && !k.startsWith('_')
      })
      process.stderr.write(`  el[${i}] tag=${el.tagName} id=${el.id} keys=[${nonDefault.slice(0,8).join(',')}]\n`)
      if (el.src) process.stderr.write(`    src=${String(el.src).slice(0,80)}\n`)
      const fnKeys = allKeys.filter(k => typeof el[k] === 'function')
      if (fnKeys.length) process.stderr.write(`    fn-props=[${fnKeys.slice(0,10).join(',')}]\n`)
      // Check GCL listener tree on this element
      if (lmKeyE && el[lmKeyE]) {
        try {
          const etypes = Object.keys(el[lmKeyE])
          process.stderr.write(`    gcl-lm event types: [${etypes.join(',')}]\n`)
        } catch {}
      }
    }
  }

  // Auto-fire 'load' event for any element with onload set (bframe iframe)
  // The anchor creates a bframe iframe and waits for its onload before adding click handlers
  for (const el of ALL_ELS) {
    if (el.onload && typeof el.onload === 'function') {
      if (process.env.BG_DEBUG) process.stderr.write(`[BG] Auto-firing onload on el tag=${el.tagName} id=${el.id}\n`)
      try { el.onload({ type: 'load', target: el }) } catch {}
    }
    const loadLis = (el._lis && el._lis.load) || []
    for (const fn of loadLis) {
      if (process.env.BG_DEBUG) process.stderr.write(`[BG] Auto-firing load listener on el tag=${el.tagName}\n`)
      try { fn({ type: 'load', target: el }) } catch {}
    }
    // GCL load listeners
    if (page.sandbox) {
      const lmK = Object.keys(page.sandbox).find(k => /^closure_lm_/.test(k))
      if (lmK) {
        const tree = el[lmK]
        if (tree && tree.load) {
          for (const k2 of Object.keys(tree.load)) {
            const entry = tree.load[k2]
            const fn = entry && (entry.listener || (typeof entry === 'function' ? entry : null))
            if (typeof fn === 'function') {
              if (process.env.BG_DEBUG) process.stderr.write(`[BG] Auto-firing GCL load on el tag=${el.tagName}\n`)
              try { fn({ type: 'load', target: el }) } catch {}
            }
          }
        }
      }
    }
  }
  await sleep(800)




  // 8. STEP 4b — fire 'message' window handler + port RPC
  //    anchor sends "recaptcha-setup" + port2 to parent via postMessage.
  //    api.js sends render command via port2 → anchor's AE(x.port1) receives it.
  //    Also try window 'message' handler with various formats.
  const winMsgHandlers  = page.winListeners['message'] || savedMsgHandlers
  if (process.env.BG_DEBUG && winMsgHandlers.length > 0) {
    const src = winMsgHandlers[0].toString()
    process.stderr.write(`[BG] msgHandler[0] src (first 400): ${src.slice(0, 400)}\n`)
    if (apiToAnchor) {
      process.stderr.write(`[BG] port2.onmessage type: ${typeof apiToAnchor.port2.onmessage} | port2._listeners: ${apiToAnchor.port2._listeners ? apiToAnchor.port2._listeners.length : 0}\n`)
    }
  }

  // Use captured port from parent.postMessage (anchor→api.js port)
  const anchorApiPort2 = parentMsgs.length > 0 && parentMsgs[0].transfer && parentMsgs[0].transfer[0]
  if (process.env.BG_DEBUG) {
    process.stderr.write(`[BG] anchorApiPort2: ${anchorApiPort2 ? 'FOUND (type='+typeof anchorApiPort2+')' : 'NOT FOUND'}\n`)
    if (anchorApiPort2) {
      process.stderr.write(`[BG] anchorApiPort2.onmessage: ${typeof anchorApiPort2.onmessage} _listeners: ${anchorApiPort2._listeners ? anchorApiPort2._listeners.length : 'n/a'}\n`)
      // CRITICAL: dump queued messages from anchor to api.js
      const q = anchorApiPort2._q || []
      process.stderr.write(`[BG] anchorApiPort2._q (anchor→api.js): ${q.length} queued\n`)
      for (let qi = 0; qi < q.length; qi++) {
        const qmsg = q[qi]
        let dataSummary
        try {
          dataSummary = typeof qmsg.data === 'string' ? `str(${qmsg.data.length}):` + qmsg.data.slice(0,60)
            : qmsg.data instanceof Uint8Array ? `Uint8Array(${qmsg.data.length}): ${Buffer.from(qmsg.data).toString('hex').slice(0,60)}`
            : qmsg.data && typeof qmsg.data === 'object' ? `obj{${Object.keys(qmsg.data).slice(0,6).join(',')}}`
            : String(qmsg.data).slice(0,80)
        } catch { dataSummary = '?' }
        process.stderr.write(`  q[${qi}]: ports=${qmsg.ports ? qmsg.ports.length : 0} data=${dataSummary}\n`)
      }
    }
  }
  // Install a listener on anchorApiPort2 to capture future anchor→api.js messages
  const anchorToApiMsgs = []
  if (anchorApiPort2) {
    anchorApiPort2.onmessage = (ev) => {
      anchorToApiMsgs.push(ev)
      let ds
      try {
        ds = typeof ev.data === 'string' ? `str(${ev.data.length}):${ev.data.slice(0,60)}`
          : ev.data instanceof Uint8Array ? `Uint8Array(${ev.data.length}):${Buffer.from(ev.data).toString('hex').slice(0,60)}`
          : ev.data && typeof ev.data === 'object' ? `obj{${Object.keys(ev.data).slice(0,6).join(',')}}`
          : String(ev.data).slice(0,80)
      } catch { ds = '?' }
    }
  }



  if (cfg && (winMsgHandlers.length > 0 || anchorApiPort2 || apiToAnchor)) {
    const name  = cfg[24] || ''
    const token = cfg[30] || ''

    // Spy on event.data property access to detect expected format
    if (process.env.BG_DEBUG && winMsgHandlers.length > 0) {
      const accessed = []
      const dataSpy = new Proxy({}, {
        get(t, k) { accessed.push(String(k)); return undefined },
        has(t, k) { accessed.push('has:'+k); return false }
      })
      const spyEv = { data: dataSpy, origin: hostOrigin, source: parentSpy, ports: [], type: 'message', isTrusted: true, preventDefault(){}, stopPropagation(){} }
      try { winMsgHandlers[0](spyEv) } catch {}
      process.stderr.write(`[BG] spy event.data accesses: [${accessed.join(', ')}]\n`)
    }

    // Try window message handler with various data formats that api.js sends back:
    const toTry = [
      'recaptcha-setup',
      [name, token],
      name,
      cfg,
    ]
    for (const dataVal of toTry) {
      const msgEv = { data: dataVal, origin: hostOrigin, source: parentSpy, ports: [], type: 'message', isTrusted: true, preventDefault() {}, stopPropagation() {} }
      for (const fn of winMsgHandlers) {
        try { fn(msgEv) }
        catch(e) { if (process.env.BG_DEBUG) process.stderr.write(`[BG] msgFire err (data=${JSON.stringify(dataVal).slice(0,30)}): ${e.message}\n`) }
      }
      await sleep(200)
      const nCl = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.clients ? Object.keys(page.sandbox.___grecaptcha_cfg.clients).length : 0
      if (process.env.BG_DEBUG) process.stderr.write(`[BG] after msg(${JSON.stringify(dataVal).slice(0,30)}): clients=${nCl} clickable=${ALL_ELS.filter(e=>e._lis&&(e._lis.click||e._lis.mousedown)).length}\n`)
      if (nCl > 0 || ALL_ELS.some(e=>e._lis&&(e._lis.click||e._lis.mousedown))) break
    }

    // Try posting via anchorApiPort2 (the port anchor transferred to api.js)
    // This goes to anchor's AE(x.port1) which processes api.js render commands
    if (anchorApiPort2) {
      if (process.env.BG_DEBUG) process.stderr.write(`[BG] trying anchorApiPort2 postMessage\n`)
      for (const dataVal of ['recaptcha-setup', name, [name, token], cfg]) {
        try {
          anchorApiPort2.postMessage(dataVal)
          await sleep(200)
          const nCl = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.clients ? Object.keys(page.sandbox.___grecaptcha_cfg.clients).length : 0
          const cl = ALL_ELS.filter(e=>e._lis&&(e._lis.click||e._lis.mousedown)).length
          if (process.env.BG_DEBUG) process.stderr.write(`[BG] anchorPort2.post(${JSON.stringify(dataVal).slice(0,25)}): clients=${nCl} cl=${cl}\n`)
          if (nCl > 0 || cl > 0) break
        } catch(e) { if (process.env.BG_DEBUG) process.stderr.write(`[BG] anchorPort2 err: ${e.message}\n`) }
      }
    }

    // Also try via apiToAnchor port (from test event)
    if (apiToAnchor && apiToAnchor.port1) {
      for (const dataVal of ['recaptcha-setup', [name, token], name]) {
        try { apiToAnchor.port1.postMessage(dataVal) } catch {}
      }
    }

    await sleep(600)
  }




  // 9. Fire checkbox click on any element with click/touch/key listeners
  await sleep(300)
  // Find GCL listener map key (closure_lm_XXXXX key added to sandbox by GCL event system)
  const gclLmKey = Object.keys(page.sandbox).find(k => /^closure_lm_/.test(k))
  if (process.env.BG_DEBUG) process.stderr.write(`[BG] GCL listener map key: ${gclLmKey || 'NOT FOUND'}\n`)

  // Helper: extract all click/mouse/key/pointer handlers from a GCL listener tree on an element
  function getGCLHandlers(elReal, lmKey) {
    if (!lmKey) return []
    const tree = elReal[lmKey]  // { click: { '2': { listener: fn, key: N }, ... }, ... }
    if (!tree || typeof tree !== 'object') return []
    const handlers = []
    const targetTypes = ['click', 'mousedown', 'pointerdown', 'keydown', 'touchstart', 'focus']
    for (const type of targetTypes) {
      const typeMap = tree[type]
      if (!typeMap || typeof typeMap !== 'object') continue
      for (const k of Object.keys(typeMap)) {
        const entry = typeMap[k]
        if (!entry) continue
        // GCL Listener has .listener (the actual callback) or itself is a function
        const fn = entry.listener || (typeof entry === 'function' ? entry : null)
        if (typeof fn === 'function') handlers.push({ type, fn })
      }
    }
    return handlers
  }

  if (process.env.BG_DEBUG && gclLmKey) {
    const docLisKeys = Object.keys(DOC_LIS).filter(k => (DOC_LIS[k]||[]).length > 0)
    process.stderr.write(`[BG] ALL_ELS count: ${ALL_ELS.length} | DOC_LIS: [${docLisKeys.join(',')}]\n`)
    for (let i = 0; i < ALL_ELS.length; i++) {
      const el = ALL_ELS[i]
      const lisKeys = Object.keys(el._lis || {}).filter(k => (el._lis[k]||[]).length > 0)
      const propKeys = Object.keys(el).filter(k => /^on/.test(k) && typeof el[k] === 'function')
      const gclH = getGCLHandlers(el, gclLmKey)
      if (lisKeys.length > 0 || propKeys.length > 0 || gclH.length > 0) {
        process.stderr.write(`  el[${i}] tag=${el.tagName} id=${el.id} lis=[${lisKeys}] props=[${propKeys}] gcl=[${gclH.map(h=>h.type).join(',')}]\n`)
      }
    }
  } else if (process.env.BG_DEBUG) {
    const docLisKeys = Object.keys(DOC_LIS).filter(k => (DOC_LIS[k]||[]).length > 0)
    process.stderr.write(`[BG] ALL_ELS count: ${ALL_ELS.length} | DOC_LIS: [${docLisKeys.join(',')}]\n`)
  }

  // Detect clickable: via addEventListener (_lis), on* property, OR GCL listener tree
  const clickable = ALL_ELS.filter(el => {
    const lis = el._lis || {}
    const hasLis = !!(lis.click || lis.mousedown || lis.pointerdown || lis.keydown || lis.touchstart)
    const hasProp = Object.keys(el).some(k => /^on(click|mousedown|pointerdown|keydown|touchstart)$/.test(k) && typeof el[k] === 'function')
    const hasGCL = getGCLHandlers(el, gclLmKey).length > 0
    return hasLis || hasProp || hasGCL
  })
  if (process.env.BG_DEBUG) process.stderr.write(`[BG] clickable count (incl GCL): ${clickable.length}\n`)

  for (const el of clickable) {
    try {
      const fire = (type, extra) => {
        const ev = { type, isTrusted: true, bubbles: true, cancelable: true, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, target: el, currentTarget: el, clientX: 14, clientY: 14, button: 0, key: ' ', keyCode: 32, which: 32, ...extra }
        el._fire && el._fire(type, ev)
        if (el['on' + type] && typeof el['on' + type] === 'function') try { el['on' + type](ev) } catch {}
        // Also fire GCL handlers directly
        if (gclLmKey) {
          const gclH = getGCLHandlers(el, gclLmKey).filter(h => h.type === type)
          for (const { fn } of gclH) try { fn(ev) } catch {}
        }
      }
      fire('pointerdown'); fire('mousedown'); fire('focus')
      fire('keydown', { key: ' ', keyCode: 32, which: 32 })
      fire('click'); fire('mouseup'); fire('pointerup')
    } catch {}
  }



  // Also fire document-level delegated click handlers (event delegation pattern)
  // The anchor may use document.addEventListener('click', fn) to handle checkbox clicks
  const docClickHandlers = (DOC_LIS.click || []).concat(DOC_LIS.pointerdown || []).concat(DOC_LIS.mousedown || [])
  if (docClickHandlers.length > 0) {
    if (process.env.BG_DEBUG) process.stderr.write(`[BG] Firing ${docClickHandlers.length} document-level click handlers\n`)
    // Target the most likely checkbox element (small div, not html/head/body/frag/text/cmt)
    const checkboxEl = ALL_ELS.find(el => !['HTML','HEAD','BODY','FRAG','TEXT','CMT'].includes(el.tagName)) || ALL_ELS[0]
    for (const fn of docClickHandlers) {
      try {
        const ev = { type: 'click', isTrusted: true, bubbles: true, cancelable: true, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, target: checkboxEl, currentTarget: document, clientX: 14, clientY: 14, button: 0 }
        fn(ev)
      } catch {}
    }
    await sleep(500)
  }




  // 7a. FAST PATH: extract BG token directly from anchor→api.js AE messages
  //     Anchor sends BG attestation as JSON ["<base64url_token>"] to api.js after BG worker completes.
  //     This IS field16 — no checkbox click needed.
  await sleep(500) // let queuedMicrotasks flush any pending anchorApiPort2 deliveries
  let bgFromAE = ''
  for (const ev of anchorToApiMsgs) {
    try {
      if (typeof ev.data !== 'string') continue
      const arr = JSON.parse(ev.data)
      if (!Array.isArray(arr) || arr.length < 1) continue
      const tok = arr[0]
      if (typeof tok === 'string' && tok.length > 100 && /^[A-Za-z0-9_\-]+$/.test(tok.slice(0, 60))) {
        bgFromAE = tok
        if (process.env.BG_DEBUG) process.stderr.write(`[BG] bgFromAE: len=${tok.length} head=${tok.slice(0,50)}\n`)
        break
      }
    } catch {}
  }
  if (bgFromAE) {
    const clients = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.clients ? Object.keys(page.sandbox.___grecaptcha_cfg.clients).length : 0
    process.stdout.write(JSON.stringify({ bg: bgFromAE, reloads: ALL_REQS.filter(r => /reload/.test(r.u)).length, clickable: clickable.length, testHandlers: savedTestHandlers.length, msgHandlers: winMsgHandlers.length, parentMsgs: parentMsgs.length, clients }) + '\n')
    process.exit(0)
  }

  // 7b. SLOW PATH: wait for /reload XHR triggered by click-based flow
  const deadline = Date.now() + TIMEOUT
  let field16 = ''
  while (Date.now() < deadline && !field16) {
    await sleep(500)
    for (const req of ALL_REQS) {
      if (!/api2\/reload/.test(req.u)) continue
      const f16 = extractField16(req.body)
      if (f16) { field16 = f16; break }
    }
  }

  const clients = page.sandbox.___grecaptcha_cfg && page.sandbox.___grecaptcha_cfg.clients ? Object.keys(page.sandbox.___grecaptcha_cfg.clients).length : 0
  process.stdout.write(JSON.stringify({ bg: field16, reloads: ALL_REQS.filter(r => /reload/.test(r.u)).length, clickable: clickable.length, testHandlers: savedTestHandlers.length, msgHandlers: winMsgHandlers.length, parentMsgs: parentMsgs.length, clients }) + '\n')
  process.exit(0)

}

main().catch(e => {
  process.stdout.write(JSON.stringify({ error: String(e && e.message || e) }) + '\n')
  process.exit(1)
})

