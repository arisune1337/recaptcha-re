// Request-based reCAPTCHA v2 — JS-VM worker harness (Step 2).
// Runs Google's real recaptcha__en.js in node `vm` worker-mode, source-instruments it to
// capture the rotating internal tokens (RPp opcode map, Qr=init, ak=run, AE=rpc, d5=handshake),
// installs a REAL by-reference loopback MessagePort so we can talk to the in-VM BotGuard RPC
// server, and exposes a driver to run Qr(program) -> ak(input) -> read the Xm attestation.
// A recursive logging Proxy records every env property the VM + bg-program touch (so we can
// see whether the attestation needs canvas/webgl/dom -> the GO/NO-GO gate).
'use strict'
const fs = require('fs')
const vm = require('vm')
const path = require('path')
const ENJS = process.env.ENJS || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
let CODE = fs.readFileSync(ENJS, 'utf8')

// ---- source instrumentation: capture rotating tokens into global __cap -----
function patch(find, repl) {
  const i = CODE.indexOf(find)
  if (i < 0) throw new Error('anchor NOT FOUND: ' + find)
  if (CODE.indexOf(find, i + 1) >= 0) throw new Error('anchor NON-UNIQUE: ' + find)
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length)
}
patch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),')
patch('}],[ak,function', '}],[(__cap.ak=ak),function')
patch('AE=function(q,r,w,D,d,A){return b[32]', 'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]')
patch('d5=lZ()', 'd5=__cap.d5=lZ()')

// ---- env (worker-mode); ES intrinsics injected because the Proxy global shadows realm ----
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const accessed = new Map(); const missing = new Set()
const HOT = new Set(['canvas', 'getContext', 'toDataURL', 'getImageData', 'webgl', 'WebGLRenderingContext', 'WebGL2RenderingContext', 'getParameter', 'document', 'OffscreenCanvas', 'AudioContext', 'OfflineAudioContext', 'createElement'])
const hotHits = []
function note(k) { accessed.set(k, (accessed.get(k) || 0) + 1); if (HOT.has(k)) hotHits.push(k) }

let T0 = Date.now()
let heap = 12_000_000
const perf = { now: () => Date.now() - T0 + Math.random(), memory: { get usedJSHeapSize() { return heap }, totalJSHeapSize: 30_000_000, jsHeapSizeLimit: 2_200_000_000 }, timeOrigin: 0, getEntriesByType: () => [], mark: () => {}, measure: () => {} }

// real by-reference loopback MessagePort (worker_threads/structuredClone would DataCloneError)
function makePort() {
  const p = {
    __isPort: true, _peer: null, _started: false, _q: [], _on: null, _lis: [],
    get onmessage() { return this._on }, set onmessage(f) { this._on = f; this._started = true; this._flush() },
    addEventListener(t, f) { if (t === 'message') { this._lis.push(f); this._started = true; this._flush() } },
    removeEventListener(t, f) { this._lis = this._lis.filter(x => x !== f) },
    start() { this._started = true; this._flush() }, close() { this._closed = true },
    dispatchEvent() { return true },
    postMessage(data, transfer) {
      const ports = (transfer || []).filter(x => x && x.__isPort)
      const ev = { data, ports, type: 'message', target: this._peer, source: null }
      queueMicrotask(() => this._peer && this._peer._deliver(ev))
    },
    _deliver(ev) { if (this._closed) return; if (!this._started) { this._q.push(ev); return } if (this._on) try { this._on(ev) } catch (e) {} for (const f of this._lis) try { f(ev) } catch (e) {} },
    _flush() { if (!this._started) return; const q = this._q; this._q = []; for (const ev of q) this._deliver(ev) },
  }
  return p
}
function MessageChannelShim() { const a = makePort(), b = makePort(); a._peer = b; b._peer = a; this.port1 = a; this.port2 = b }

let WORKER_PORT = null            // port2, transferred by the worker bootstrap postMessage
const outMsgs = []

const base = {
  __cap: {},
  importScripts: () => {},
  postMessage: (msg, transfer) => { outMsgs.push(typeof msg === 'string' ? msg : '<obj>'); const t = transfer || (msg && msg.length ? msg : null); const arr = Array.isArray(transfer) ? transfer : (Array.isArray(msg) ? null : null); if (Array.isArray(transfer)) { for (const x of transfer) if (x && x.__isPort) WORKER_PORT = x } },
  addEventListener: () => {}, removeEventListener: () => {}, onmessage: null, onerror: null, close: () => {},
  MessageChannel: MessageChannelShim, MessagePort: function () {},
  performance: perf,
  navigator: { userAgent: UA, webdriver: false, deviceMemory: 8, hardwareConcurrency: 8, language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32', vendor: 'Google Inc.', product: 'Gecko', appName: 'Netscape', onLine: true, userAgentData: { brands: [{ brand: 'Chromium', version: '149' }], mobile: false, platform: 'Windows' }, sendBeacon: () => true },
  location: { href: 'https://www.google.com/recaptcha/api2/webworker.js', origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/webworker.js', search: '', hash: '' },
  XMLHttpRequest: function () { return { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, getAllResponseHeaders: () => '', abort() {} } },
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  btoa: s => Buffer.from(s, 'binary').toString('base64'),
  setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
  TextEncoder, TextDecoder, URL, URLSearchParams, crypto: require('crypto').webcrypto,
  console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {} },
}
for (const k of ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'EvalError', 'ReferenceError', 'SyntaxError', 'URIError', 'Reflect', 'Proxy', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'parseInt', 'parseFloat', 'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape', 'isNaN', 'isFinite', 'Intl', 'structuredClone', 'Infinity', 'NaN', 'undefined', 'globalThis'])
  if (!(k in base)) try { base[k] = globalThis[k] } catch {}

let globalRef
const handler = {
  get(t, k) { if (typeof k === 'symbol') return t[k]; if (k === 'self' || k === 'globalThis') return globalRef; if (k in t) { note(k); return t[k] } note(k); missing.add(k); return undefined },
  has() { return true }, set(t, k, v) { t[k] = v; return true },
}
const sandbox = Object.assign(Object.create(null), base)
const ctx = vm.createContext(new Proxy(sandbox, handler)); globalRef = ctx

let err = null
try { vm.runInContext(CODE, ctx, { filename: 'recaptcha__en.js', timeout: 20000 }) } catch (e) { err = e }
const cap = sandbox.__cap

console.log('=== load ===', err ? 'THREW: ' + err.message : 'OK (no throw)')
console.log('captured tokens:', ['RPp', 'Qr', 'ak', 'AE', 'd5'].map(k => `${k}=${cap[k] !== undefined ? (typeof cap[k]) : 'MISSING'}`).join('  '))
console.log('worker handshake out:', outMsgs.join(','), '| WORKER_PORT captured:', !!WORKER_PORT)
console.log('RPp opcodes:', cap.RPp ? [...cap.RPp.keys()].length : 'n/a')

// Phase A success criteria: tokens + port captured. Phase B (drive) happens in driver.js.
module.exports = { ctx, sandbox, cap, WORKER_PORT, accessed, missing, hotHits, note,
  setHeap: v => { heap = v }, makePort, MessageChannelShim }

if (require.main === module) {
  console.log('\nhot env hits during load (canvas/webgl/dom/audio):', hotHits.length ? [...new Set(hotHits)].join(' ') : 'NONE')
  console.log('top env reads:', [...accessed.entries()].sort((a, b) => b[1] - a[1]).slice(0, 18).map(([k, n]) => `${k}:${n}`).join('  '))
}
