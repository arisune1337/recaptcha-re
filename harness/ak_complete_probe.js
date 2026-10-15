// ak_complete_probe.js — STANDALONE feasibility probe (does NOT touch the default driver run).
//
// DECISIVE QUESTION: when the node-vm BotGuard worker runs a real ~336KB program and emits its own
// "x" REQUESTS back to the page, do SYNTHETIC MZ-acks (page_rpc catch-all) let it COMPLETE
// (=> FULLY FIXABLE, node-vm can mint a native token), or does it STALL on an "x" that demands a
// real browser value (canvas/render/DOM/hardware/timing) it can't fabricate (=> FUNDAMENTAL)?
//
// Method: run the worker realm (worker.js env), feed it the captured anchor->worker frames
// (prog_capture.json — real ~336KB program; codec-level question is program-agnostic), CAPTURE the
// worker's OUTBOUND sends (AE.send, pre-encode = readable) to see exactly what each "x" asks for,
// ANSWER every worker "x" with a synthetic MZ-ack, and watch aq.Z().get().CE() advance past ["conf"].
'use strict'
const fs = require('fs')
const vm = require('vm')
const PR = require('./page_rpc.js')
const ENJS = process.env.ENJS || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
let CODE = fs.readFileSync(ENJS, 'utf8')
const log = (...a) => console.log(...a)

function patch(find, repl, label) {
  const i = CODE.indexOf(find)
  if (i < 0) { log('  [patch skip]', label); return false }
  if (CODE.indexOf(find, i + 1) >= 0) { log('  [patch dup ]', label); return false }
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length); log('  [patch ok  ]', label); return true
}
log('[probe] patching en.js...')
patch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),', 'RPp/Qr expose')
patch('}],[ak,function', '}],[(__cap.ak=ak),function', 'ak expose')
patch(',aq).Z().init(', ',(self.__cap.aq=aq)).Z().init(', 'aq expose')
// capture EVERY AE.send(opcode, structuredMsg) BEFORE serialization — the worker's outbound requests
patch('AE).prototype.send=function(q,r,w,D,d,A){return F[48](65,',
      'AE).prototype.send=function(q,r,w,D,d,A){try{(self.__cap.sends=self.__cap.sends||[]).push({op:String(q),msg:r,t:Date.now()})}catch(e){}return F[48](65,', 'AE.send capture')
// parsed-inbound-message ctor hook + dispatch hook (see which opcodes flow)
patch('this.message=r,this.messageType=w,this.D=D',
      'this.message=r,this.messageType=w,this.D=D,(typeof self.__msgHook==="function"&&self.__msgHook(w,r))', 'msg-ctor hook')
CODE = PR.applyPatches(CODE)   // __onAE(instance) at AE ctor end

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const INTRINSICS = ['Object', 'Array', 'Function', 'String', 'Number', 'Boolean', 'Symbol', 'BigInt', 'Math', 'JSON', 'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'EvalError', 'ReferenceError', 'SyntaxError', 'URIError', 'Reflect', 'Proxy', 'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'WeakRef', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Uint8Array', 'Int8Array', 'Uint8ClampedArray', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'parseInt', 'parseFloat', 'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape', 'isNaN', 'isFinite', 'Intl', 'structuredClone', 'Infinity', 'NaN', 'undefined', 'globalThis']

// by-ref loopback MessagePort (same objects across the shim)
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

// Chrome-realistic perf (hardened env, like the driver)
function makePerf() {
  const hr0 = process.hrtime.bigint(); const wall0 = Date.now(); const heap0 = process.memoryUsage().heapUsed
  const BASE = 12_600_000, BUCKET = 100000; let lastNow = 0, lastUsed = BASE
  const q = n => Math.floor(n / BUCKET) * BUCKET
  const used = () => { let u = q(BASE + Math.max(0, process.memoryUsage().heapUsed - heap0)); if (u < lastUsed) u = lastUsed; lastUsed = u; return u }
  const memory = {}
  Object.defineProperty(memory, 'usedJSHeapSize', { get: used, enumerable: true }); Object.defineProperty(memory, 'totalJSHeapSize', { get: () => q(Math.max(used() + 2_000_000, 40_000_000)), enumerable: true }); memory.jsHeapSizeLimit = 2172649472
  return { timeOrigin: wall0, now() { let ms = Number(process.hrtime.bigint() - hr0) / 1e6; ms = Math.floor(ms / 0.1) * 0.1; if (ms < lastNow) ms = lastNow; lastNow = ms; return ms }, memory, getEntriesByType: t => (t === 'navigation' ? [{ entryType: 'navigation', nextHopProtocol: 'h2', startTime: 0, type: 'navigate', responseStatus: 200 }] : []), mark() {}, measure() {}, clearMarks() {}, clearMeasures() {} }
}

const captured = { sends: [], inbound: [] }
let WORKER_PORT = null

function buildWorker(withDocument) {
  const perf = makePerf()
  const base = {
    __cap: {},
    __onAE: PR.makeOnAE({ getPort: () => WORKER_PORT, log: () => {} }),   // catch-all: any inbound request -> MZ ack
    __msgHook: (w, r) => { try { captured.inbound.push({ mt: String(w) }) } catch {} },
    importScripts: () => {}, close: () => {}, onmessage: null, onerror: null,
    postMessage: (m, transfer) => { const tp = Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : []; if (tp.length && !WORKER_PORT) WORKER_PORT = tp[0]; if (process.env.PLOG) log('  [W->page]', typeof m === 'string' ? 'str(' + m.length + '):' + m.slice(0, 34) : (m && m.constructor && m.constructor.name)) },
    addEventListener: () => {}, removeEventListener: () => {},
    MessageChannel: MessageChannelShim, MessagePort: function () {},
    performance: perf,
    navigator: { userAgent: UA, webdriver: false, deviceMemory: 8, hardwareConcurrency: 8, maxTouchPoints: 0, language: 'en-US', languages: ['en-US', 'en'], platform: 'Win32', vendor: 'Google Inc.', product: 'Gecko', appName: 'Netscape', onLine: true, cookieEnabled: true, userAgentData: { brands: [{ brand: 'Chromium', version: '149' }, { brand: 'Microsoft Edge', version: '149' }, { brand: 'Not.A/Brand', version: '24' }], mobile: false, platform: 'Windows', getHighEntropyValues: () => Promise.resolve({ architecture: 'x86', bitness: '64', platform: 'Windows', platformVersion: '15.0.0', uaFullVersion: '149.0.0.0', model: '', wow64: false, brands: [{ brand: 'Chromium', version: '149' }], fullVersionList: [{ brand: 'Chromium', version: '149.0.0.0' }] }) }, sendBeacon: () => true, plugins: { length: 5 }, mimeTypes: { length: 2 } },
    chrome: { loadTimes: () => ({ connectionInfo: 'h2', wasFetchedViaSpdy: true, npnNegotiatedProtocol: 'h2' }), csi: () => ({ tran: 15 }), app: { isInstalled: false }, runtime: {} },
    XMLHttpRequest: function () { return { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, getAllResponseHeaders: () => '', abort() {} } },
    location: { href: 'https://www.google.com/recaptcha/api2/webworker.js', origin: 'https://www.google.com', protocol: 'https:', host: 'www.google.com', hostname: 'www.google.com', pathname: '/recaptcha/api2/webworker.js', search: '', hash: '' },
    atob: s => Buffer.from(s, 'base64').toString('binary'), btoa: s => Buffer.from(s, 'binary').toString('base64'),
    setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, requestAnimationFrame: f => setTimeout(() => f(Date.now()), 16), cancelAnimationFrame: () => {}, requestIdleCallback: f => setTimeout(() => f({ timeRemaining: () => 5, didTimeout: false }), 1), cancelIdleCallback: () => {},
    TextEncoder, TextDecoder, URL, URLSearchParams, crypto: require('crypto').webcrypto, fetch: (...a) => fetch(...a),
    console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
  }
  if (withDocument) {
    const el = () => ({ style: {}, setAttribute() {}, getAttribute: () => null, appendChild: x => x, addEventListener() {}, getContext: () => ({ fillRect() {}, getImageData: () => ({ data: new Uint8ClampedArray(4) }), measureText: () => ({ width: 10 }), getParameter: () => 'ANGLE (Intel)', getExtension: () => ({ UNMASKED_RENDERER_WEBGL: 37446 }) }), toDataURL: () => 'data:image/png;base64,iVBORw0KGgo=', getBoundingClientRect: () => ({ width: 300, height: 150, top: 0, left: 0 }), offsetWidth: 300, offsetHeight: 150 })
    base.document = { createElement: () => el(), getElementById: () => el(), querySelector: () => el(), documentElement: el(), body: el(), head: el(), addEventListener() {}, cookie: '', readyState: 'complete', hidden: false, visibilityState: 'visible' }
  }
  Object.assign(base, {})
  for (const k of INTRINSICS) if (!(k in base)) try { base[k] = globalThis[k] } catch {}
  let globalRef
  const handler = { get(t, k) { if (typeof k === 'symbol') return t[k]; if (k === 'self' || k === 'globalThis') return globalRef; if (k in t) return t[k]; return undefined }, has() { return true }, set(t, k, v) { t[k] = v; return true } }
  const sandbox = Object.assign(Object.create(null), base)
  const ctx = vm.createContext(new Proxy(sandbox, handler)); globalRef = ctx
  let err = null
  try { vm.runInContext(CODE, ctx, { filename: 'recaptcha__en.js[worker]', timeout: 20000 }) } catch (e) { err = e }
  return { ctx, sandbox, err }
}

function ceSize(sandbox) {
  try { const aq = sandbox.__cap && sandbox.__cap.aq; if (!aq || !aq.Z) return null; const ce = aq.Z().get().CE(); const b = Buffer.isBuffer(ce) ? ce : Buffer.from(String(ce), 'latin1'); return { len: b.length, head: b.slice(0, 40).toString('latin1') } } catch (e) { return { err: e.message } }
}

;(async () => {
  const withDoc = !!process.env.WITHDOC
  log('[probe] building worker realm (withDocument=%s)...', withDoc)
  const W = buildWorker(withDoc)
  log('[probe] worker load:', W.err ? 'THREW ' + W.err.message : 'OK')
  const cap = W.sandbox.__cap
  log('[probe] captured tokens: RPp=%s Qr=%s ak=%s aq(after Qr)=pending | WORKER_PORT=%s', typeof cap.RPp, typeof cap.Qr, typeof cap.ak, WORKER_PORT ? WORKER_PORT.__id : 'none')
  if (!WORKER_PORT) { log('[probe] no WORKER_PORT — worker did not transfer its channel; abort'); process.exit(1) }

  // load the captured anchor->worker frames (real ~336KB program) and feed them, ANSWERING worker "x".
  const cf = JSON.parse(fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/poc/prog_capture.json', 'utf8'))
  const msgs = ((cf.anchor && cf.anchor.portMsgs) || []).map(m => m.full).filter(Boolean)
  log('[probe] feeding %d captured frames; will ANSWER every worker "x" with a synthetic MZ-ack (catch-all).', msgs.length)

  // capture the worker's OUTBOUND replies/requests on WORKER_PORT
  const outFrames = []
  WORKER_PORT.onmessage = (ev) => { const d = ev && ev.data; let op = '?'; try { op = JSON.parse(d)[1] } catch {}; outFrames.push({ op, len: typeof d === 'string' ? d.length : 0, raw: d })
    // NOTE: the catch-all __onAE already auto-answers inbound *requests* to the worker's own client-AE;
    // the worker's outbound requests are answered by the page-side AE the catch-all installs (getPort=WORKER_PORT).
  }

  const tick = () => new Promise(r => setImmediate(r))
  const ceLog = []
  for (let i = 0; i < msgs.length; i++) {
    const before = outFrames.length
    try { WORKER_PORT.postMessage(msgs[i]) } catch (e) { log('  frame%d post threw: %s', i, e.message) }
    await tick(); await tick(); await new Promise(r => setTimeout(r, 40)); await tick()
    const ce = ceSize(W.sandbox)
    const newOut = outFrames.slice(before)
    if (newOut.length || (ce && ce.len && ce.len !== 8) || i < 10) {
      log('  frame%d op=%s (%dB) -> worker sent %d frame(s) [%s] | CE=%s', i, (() => { try { return JSON.parse(msgs[i])[1] } catch { return '?' } })(), msgs[i].length, newOut.length, newOut.map(f => f.op + ':' + f.len).join(','), ce ? (ce.len + 'B ' + JSON.stringify(ce.head.slice(0, 24))) : 'n/a')
    }
    if (ce && ce.len) ceLog.push(ce.len)
  }
  await new Promise(r => setTimeout(r, 500))

  log('\n[probe] ===== VERDICT DATA =====')
  const finalCE = ceSize(W.sandbox)
  log('[probe] final aq.Z().get().CE(): %s', finalCE ? (finalCE.len + 'B head=' + JSON.stringify(finalCE.head)) : 'n/a')
  log('[probe] CE progression (bytes): %s', ceLog.length ? [...new Set(ceLog)].join(' -> ') : '(never grew / stayed ["conf"]=8B)')
  const sends = cap.sends || []
  log('[probe] worker OUTBOUND sends (AE.send): %d total; opcodes: %s', sends.length, sends.map(s => s.op).join(','))
  // dump the worker's "x" REQUESTS (what it asks the page for) — the decisive content
  const xs = sends.filter(s => s.op === 'x' || s.op === 'ak' || s.op === 'D')
  log('[probe] worker request-like sends: %d', xs.length)
  xs.slice(0, 12).forEach((s, i) => {
    let desc = '?'
    try { desc = JSON.stringify(s.msg, (k, v) => (typeof v === 'string' && v.length > 120 ? v.slice(0, 60) + '…(' + v.length + ')' : (v && v.length > 200 ? '<arr' + v.length + '>' : v))).slice(0, 300) } catch (e) { desc = '(' + (s.msg && s.msg.constructor && s.msg.constructor.name) + ' keys=' + (s.msg && typeof s.msg === 'object' ? Object.keys(s.msg).slice(0, 10).join(',') : typeof s.msg) + ')' }
    log('   send#%d op=%s msg=%s', i, s.op, desc)
  })
  log('[probe] inbound decoded messageTypes at worker: [%s]', [...new Set(captured.inbound.map(m => m.mt))].join(','))
  const advanced = finalCE && finalCE.len > 100
  log('\n[probe] >>> VERDICT: %s', advanced ? 'CE ADVANCED past ["conf"] (' + finalCE.len + 'B) — synthetic acks let the program progress => leaning FIXABLE' : 'CE STAYED at ["conf"] (' + (finalCE ? finalCE.len : '?') + 'B) — the program did NOT complete with synthetic acks; inspect the worker request-sends above for the exact unanswered/blocking exchange')
  process.exit(0)
})().catch(e => { log('[probe] fatal:', e && e.stack || e); process.exit(1) })
