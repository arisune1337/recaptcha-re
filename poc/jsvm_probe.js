// Foundational JS-VM probe: run Google's real recaptcha__en.js in node `vm` worker-mode
// under a recursive LOGGING global, to empirically enumerate which browser/worker globals
// BotGuard reads and where it first breaks — turning "how hard to stub" into a checklist.
const fs = require('fs')
const vm = require('vm')
const CODE = fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js', 'utf8')

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const accessed = new Map()   // key -> count
const missing = new Set()
function note(k) { accessed.set(k, (accessed.get(k) || 0) + 1) }

let T0 = Date.now()
const perf = { now: () => Date.now() - T0, memory: { usedJSHeapSize: 12_000_000, totalJSHeapSize: 30_000_000, jsHeapSizeLimit: 2_200_000_000 }, timeOrigin: 0, getEntriesByType: () => [], mark: () => {}, measure: () => {} }

function portShim(name) {
  const p = { onmessage: null, postMessage: (...a) => recordMsg('port:' + name, a), addEventListener: (t, f) => { if (t === 'message') p.onmessage = f }, removeEventListener: () => {}, start: () => {}, close: () => {} }
  return p
}
function MessageChannelShim() { this.port1 = portShim('1'); this.port2 = portShim('2') }

class XHRStub {
  constructor() { this.headers = {}; this.readyState = 0; this.status = 0; this.responseText = '' }
  open(m, u) { this._m = m; this._u = u; note('XHR.open:' + String(u).split('?')[0].replace(/^https?:\/\/[^/]+/, '')) }
  setRequestHeader(k, v) { this.headers[k] = v; note('XHR.setRequestHeader:' + k) }
  send(b) { note('XHR.send'); this._body = b; /* no real network in the probe */ if (this.onerror) {} }
  addEventListener(t, f) { this['on' + t] = f }
  getAllResponseHeaders() { return '' }
  abort() {}
  get [Symbol.toStringTag]() { return 'XMLHttpRequest' }
}

const outMsgs = []           // postMessage(...) the worker sends to the main thread
const listeners = {}         // event -> [fn]
function recordMsg(where, args) { try { outMsgs.push({ where, msg: JSON.parse(JSON.stringify(args[0])) }) } catch { outMsgs.push({ where, msg: '<' + typeof args[0] + (args[0] && args[0].constructor && args[0].constructor.name ? ':' + args[0].constructor.name : '') + '>' }) } }

// concrete worker-ish stubs; unknowns fall through to the proxy get-trap (logged)
const base = {
  importScripts: () => {},
  postMessage: (...a) => recordMsg('self', a),
  addEventListener: (t, f) => { (listeners[t] = listeners[t] || []).push(f); note('addEventListener:' + t) },
  removeEventListener: () => {},
  onmessage: null, onerror: null, close: () => {},
  MessageChannel: MessageChannelShim,
  MessagePort: function () {}, Worker: function () {},
  performance: perf,
  navigator: { userAgent: UA, webdriver: false, deviceMemory: 8, hardwareConcurrency: 8, language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32', vendor: 'Google Inc.', product: 'Gecko', appName: 'Netscape', onLine: true, plugins: { length: 0 }, mimeTypes: { length: 0 }, userAgentData: { brands: [{ brand: 'Chromium', version: '149' }], mobile: false, platform: 'Windows' }, sendBeacon: () => true },
  location: { href: 'https://www.google.com/recaptcha/api2/webworker.js', origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/webworker.js', search: '', hash: '' },
  XMLHttpRequest: XHRStub,
  atob: s => Buffer.from(s, 'base64').toString('binary'),
  btoa: s => Buffer.from(s, 'binary').toString('base64'),
  setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
  TextEncoder, TextDecoder, URL, URLSearchParams, crypto: require('crypto').webcrypto,
  console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {} },
  Date, Math, JSON, parseInt, parseFloat, isNaN, isFinite, encodeURIComponent, decodeURIComponent,
}

// intrinsics: the Proxy global shadows the realm built-ins, so inject them explicitly.
for (const k of ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'EvalError', 'ReferenceError', 'SyntaxError', 'URIError', 'Reflect', 'Proxy', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURIComponent', 'decodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape', 'Intl', 'Function', 'structuredClone', 'Infinity', 'NaN', 'undefined', 'globalThis'])
  if (!(k in base)) try { base[k] = globalThis[k] } catch {}

// the global is a Proxy: real value if present, else log + return undefined.
let globalRef
const handler = {
  get(t, k) {
    if (typeof k === 'symbol') return t[k]
    if (k === 'self' || k === 'globalThis' || k === 'window' && false) return globalRef
    if (k === 'self' || k === 'globalThis') return globalRef
    if (k in t) { note(k); return t[k] }
    note(k); missing.add(k)
    return undefined
  },
  has(t, k) { return true },            // make `x in self` / typeof checks resolve
  set(t, k, v) { t[k] = v; return true },
}
const sandbox = Object.assign(Object.create(null), base)
const ctx = vm.createContext(new Proxy(sandbox, handler))
globalRef = ctx

let err = null
try {
  vm.runInContext(CODE, ctx, { filename: 'recaptcha__en.js', timeout: 15000 })
} catch (e) { err = e }

const top = [...accessed.entries()].sort((a, b) => b[1] - a[1])
console.log('=== accessed globals/props (top 60 by count) ===')
console.log(top.slice(0, 60).map(([k, n]) => `${k}:${n}`).join('  '))
console.log('\n=== MISSING (returned undefined) — likely stub targets ===')
console.log([...missing].slice(0, 80).join('  '))
console.log('\n=== outcome ===')
console.log(err ? 'THREW: ' + (err && err.message || err) : 'ran to completion (no throw)')
console.log('XHR activity:', top.filter(([k]) => k.startsWith('XHR.')).map(([k, n]) => `${k}(${n})`).join(' ') || 'none')
console.log('\n=== worker handshake — outgoing postMessage(s) ===')
console.log(outMsgs.length ? outMsgs.map(m => `${m.where}: ${JSON.stringify(m.msg).slice(0, 200)}`).join('\n') : '(none posted)')
console.log('\n=== message listeners registered ===', Object.keys(listeners).map(k => `${k}(${listeners[k].length})`).join(' ') || '(none)')
// try to nudge the worker: deliver a bare init message and see if it reacts (posts/XHR)
if (listeners.message && listeners.message.length) {
  const before = outMsgs.length
  try { for (const fn of listeners.message) fn({ data: ['', null] }); } catch (e) { console.log('onmessage({data:[]}) ->', e.message) }
  console.log('after poking onmessage: +' + (outMsgs.length - before) + ' outgoing, last:', JSON.stringify(outMsgs[outMsgs.length - 1] || null).slice(0, 160))
}
// introspect the `recaptcha` API object the worker installed (the BotGuard surface)
function shape(o, d = 0) {
  if (!o || d > 2) return typeof o
  if (typeof o === 'function') return 'fn(' + o.length + ')'
  if (typeof o !== 'object') return typeof o
  const out = {}
  for (const k of Object.keys(o).slice(0, 30)) { try { out[k] = shape(o[k], d + 1) } catch { out[k] = '?' } }
  return out
}
console.log('\n=== installed `recaptcha` API shape ===')
console.log(JSON.stringify(shape(sandbox.recaptcha), null, 1).slice(0, 1500))
console.log('\nany global fn props added by script:', Object.keys(sandbox).filter(k => typeof sandbox[k] === 'function' && !(k in base)).join(' ') || '(none)')
console.log('all script-set globals:', Object.keys(sandbox).filter(k => !(k in base)).join(' '))
