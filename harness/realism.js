// realism.js — the integrity/realism layer for the node-vm reCAPTCHA harness.
// Three concerns, all grounded in the byte-map of recaptcha__en.js:
//   (1) Function.prototype.toString native-code spoof for our hand-stubbed env funcs,
//       so the BotGuard bytecode's `String(fn)==="function name() { [native code] }"`
//       probes pass (the file itself never contains "[native code]" — the probe lives in
//       the server-delivered bC-VM program, ak handler @886328).
//   (2) performance.memory + monotonic timing realism, so the ak attestation reads
//       (usedJSHeapSize delta U, performance.now delta x, navigator.deviceMemory d) are
//       Chrome-plausible: U>0, x>0 integer ms, timeOrigin+now()≈Date.now().
//   (3) field20 non-degenerate inputs: a realistic getEntriesByType('resource') set (el3)
//       and a synthetic pointer path (el0/el2), plus a read-only validator over pb.js.
//
// Wire into page.js/worker.js by (a) replacing the inline `perf` object with makePerf(),
// (b) calling installNativeToString(ctx) + markRealmNatives(...) right AFTER
// vm.runInContext(CODE,ctx) and BEFORE driving init/ak, (c) using makeResourceEntries()
// for perf.getEntriesByType, and (d) synthPointerPath(ALL_ELS) before the verify click.
'use strict'

const pb = require('../poc/pb.js')

// ----------------------------------------------------------------------------
// (2) TIMING + HEAP REALISM  -> feeds the ak/Xm attestation (deviceMemory,U,x)
// ----------------------------------------------------------------------------
// Chrome MemoryInfo is quantized to 100KB buckets; jsHeapSizeLimit ~2.19e9 on desktop.
const HEAP_BUCKET = 100000
const JS_HEAP_LIMIT = 2190000000

function quantize(n, bucket) { return Math.floor(n / bucket) * bucket }

// One realism perf object per realm. Uses the REAL node clock + REAL process heap so the
// values move organically when the bC VM runs the 336KB program inside this realm:
//   - now(): monotonic non-decreasing, 0.1ms-coarse (Chrome granularity), starts ~0.
//   - timeOrigin: real epoch ms captured at realm construction (NOT 0).
//   - memory.usedJSHeapSize: BASE + real heapUsed delta, ratcheted (never decreases) and
//     bucketed to 100KB, so the BEFORE/AFTER reads bracketing one ak run give U=N-K>0.
function makePerf(opts) {
  opts = opts || {}
  const wallStart = Date.now()                 // timeOrigin
  const hr0 = process.hrtime.bigint()          // monotonic base
  const heap0 = process.memoryUsage().heapUsed
  const BASE = opts.baseHeap || 12_600_000     // plausible idle Chrome renderer used-heap
  let lastNow = 0
  let lastUsed = BASE

  function now() {
    let ms = Number(process.hrtime.bigint() - hr0) / 1e6
    ms = Math.floor(ms / 0.1) * 0.1            // coarse to 100us
    if (ms < lastNow) ms = lastNow             // strictly monotonic
    lastNow = ms
    return ms
  }
  function usedJSHeapSize() {
    const delta = Math.max(0, process.memoryUsage().heapUsed - heap0)
    let used = quantize(BASE + delta, HEAP_BUCKET)
    if (used < lastUsed) used = lastUsed       // ratchet: never shrink between ak reads
    lastUsed = used
    return used
  }

  const memory = {}
  Object.defineProperty(memory, 'usedJSHeapSize', { get: usedJSHeapSize, enumerable: true, configurable: true })
  Object.defineProperty(memory, 'totalJSHeapSize', {
    get() { return quantize(Math.max(usedJSHeapSize() + 2_000_000, 40_000_000), HEAP_BUCKET) },
    enumerable: true, configurable: true,
  })
  memory.jsHeapSizeLimit = JS_HEAP_LIMIT

  const perf = {
    now, timeOrigin: wallStart, memory,
    getEntriesByType: makeResourceEntries(opts.resourceHost, opts.resourceEntries),
    getEntries: () => [], getEntriesByName: () => [],
    mark() {}, measure() {}, clearMarks() {}, clearMeasures() {}, clearResourceTimings() {},
    setResourceTimingBufferSize() {}, toJSON() { return { timeOrigin: wallStart } },
  }
  // name the functions so the toString spoof prints the right identifier.
  defName(now, 'now'); defName(usedJSHeapSize, 'get usedJSHeapSize')
  defName(perf.getEntriesByType, 'getEntriesByType'); defName(perf.mark, 'mark'); defName(perf.measure, 'measure')
  return perf
}

// ----------------------------------------------------------------------------
// (3) field20  -> getEntriesByType('resource') feeds el3; synthPointerPath feeds el0/el2
// ----------------------------------------------------------------------------
// Each entry MUST carry name(full URL -> client takes new URL(name).hostname), duration,
// startTime, responseStatus (>=400 takes a side branch), initiatorType. Mirror the real
// 8-origin graph shape (capture.json el3) but anchored to the host site.
function defaultResourceUrls(host) {
  host = host || 'lucille.sh'
  return [
    'https://' + host + '/',
    'https://www.gstatic.com/recaptcha/releases/TnA7HacJFoBWt9hnlunBlYfK/recaptcha__en.js',
    'https://www.google.com/recaptcha/api2/anchor',
    'https://www.googletagmanager.com/gtag/js',
    'https://static.cloudflareinsights.com/beacon.min.js',
    'https://fonts.gstatic.com/s/roboto/v30/font.woff2',
    'https://www.google-analytics.com/analytics.js',
    'https://ssl.gstatic.com/ui/v1/icons/mail/images/2/x.png',
  ]
}

// Returns a getEntriesByType(type) function. For 'resource' returns plausible entries with
// monotonic startTimes and small positive durations; other types -> [].
function makeResourceEntries(host, customUrls) {
  const urls = customUrls || defaultResourceUrls(host)
  let t = 38.0
  const entries = urls.map((name, i) => {
    const startTime = +(t).toFixed(4); const duration = +(8 + Math.random() * 60).toFixed(4)
    t += 11 + Math.random() * 40
    return {
      name, entryType: 'resource', initiatorType: i === 0 ? 'navigation' : (/\.js/.test(name) ? 'script' : (/\.css/.test(name) ? 'link' : (/\.(png|jpg|woff2?)/.test(name) ? 'img' : 'fetch'))),
      startTime, duration, responseStatus: 200,
      responseEnd: +(startTime + duration).toFixed(4), responseStart: +(startTime + duration * 0.6).toFixed(4),
      fetchStart: startTime, domainLookupStart: startTime, domainLookupEnd: startTime,
      connectStart: startTime, connectEnd: startTime, requestStart: +(startTime + 1).toFixed(4),
      secureConnectionStart: startTime, transferSize: 1024 + ((i * 733) % 40000), encodedBodySize: 800 + ((i * 511) % 30000),
      decodedBodySize: 1000 + ((i * 911) % 60000), nextHopProtocol: 'h2', workerStart: 0, redirectStart: 0, redirectEnd: 0, toJSON() { return this },
    }
  })
  const fn = function getEntriesByType(type) {
    if (type === 'resource') return entries.slice()
    if (type === 'navigation') return [{ name: 'https://' + (host || 'lucille.sh') + '/', entryType: 'navigation', startTime: 0, duration: 480, nextHopProtocol: 'h2', type: 'navigate', responseStatus: 200, toJSON() { return this } }]
    if (type === 'paint') return [{ name: 'first-paint', entryType: 'paint', startTime: 120.5, duration: 0 }, { name: 'first-contentful-paint', entryType: 'paint', startTime: 140.2, duration: 0 }]
    return []
  }
  return fn
}

// Synthesize a human-ish pointer path so el0 (events) and el2 (per-type timing stats with
// count>1 + nonzero variance) are non-degenerate. `elements` = the harness ALL_ELS array of
// raw element records (each has _lis + _fire from page.js makeEl). We drive the elements that
// registered pointer/mouse listeners. timeStamps increase; clientX/clientY jitter.
function synthPointerPath(elements, opts) {
  opts = opts || {}
  const targets = (elements || []).filter(el => el && el._lis && (el._lis.pointermove || el._lis.mousemove || el._lis.pointerdown || el._lis.mousedown || el._lis.click))
  if (!targets.length) return { fired: 0, targets: 0 }
  let ts = (opts.t0 || 1000) + Math.random() * 50
  let x = 240 + Math.random() * 40, y = 300 + Math.random() * 40
  let fired = 0
  const ev = (type, ox, oy, t) => ({
    type, clientX: Math.round(ox), clientY: Math.round(oy), screenX: Math.round(ox) + 0, screenY: Math.round(oy) + 84,
    pageX: Math.round(ox), pageY: Math.round(oy), movementX: 0, movementY: 0, button: 0, buttons: type === 'pointerdown' || type === 'mousedown' ? 1 : 0,
    pointerType: 'mouse', pointerId: 1, isPrimary: true, isTrusted: true, timeStamp: +t.toFixed(1), bubbles: true,
    preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, getModifierState: () => false,
  })
  const dispatch = (type, e) => { for (const el of targets) if (el._lis && el._lis[type]) { el._fire(type, e); fired++ } }
  const steps = opts.steps || 18
  for (let i = 0; i < steps; i++) {
    // ease toward the widget center (≈ 28x28 checkbox) with decaying jitter
    const targetX = 28, targetY = 28, k = (i + 1) / steps
    x += (targetX - x) * 0.18 + (Math.random() - 0.5) * 14 * (1 - k)
    y += (targetY - y) * 0.18 + (Math.random() - 0.5) * 14 * (1 - k)
    ts += 8 + Math.random() * 22                 // non-uniform inter-event gaps -> nonzero variance
    dispatch('pointermove', ev('pointermove', x, y, ts)); dispatch('mousemove', ev('mousemove', x, y, ts))
  }
  ts += 30 + Math.random() * 40
  dispatch('pointerdown', ev('pointerdown', x, y, ts)); dispatch('mousedown', ev('mousedown', x, y, ts))
  ts += 40 + Math.random() * 60
  dispatch('pointerup', ev('pointerup', x, y, ts)); dispatch('mouseup', ev('mouseup', x, y, ts)); dispatch('click', ev('click', x, y, ts))
  return { fired, targets: targets.length }
}

// Read-only validator: decode a /reload body and assert field20 is structurally non-degenerate.
// Returns {present, valid, reason, struct, head}. Use before spending a siteverify attempt.
function validateField20(reloadBodyBuf) {
  const buf = Buffer.isBuffer(reloadBodyBuf) ? reloadBodyBuf : Buffer.from(reloadBodyBuf.buffer || reloadBodyBuf, reloadBodyBuf.buffer ? undefined : 'latin1')
  let fields; try { fields = pb.decode(buf) } catch (e) { return { present: false, valid: false, reason: 'protobuf decode failed: ' + e.message } }
  const f = fields.find(x => x.field === 20)
  if (!f) return { present: false, valid: false, reason: 'no field20 on the wire' }
  const s = f.raw.toString('latin1')
  let struct
  try { struct = JSON.parse(Buffer.from('W1' + s, 'base64').toString('latin1')) } catch (e) { return { present: true, valid: false, reason: 'base64/JSON decode failed: ' + e.message, head: s.slice(0, 16) } }
  if (!Array.isArray(struct) || struct.length !== 5) return { present: true, valid: false, reason: 'arity != 5 (got ' + (Array.isArray(struct) ? struct.length : typeof struct) + ')', struct }
  const el0 = struct[0], el2 = struct[2], el3 = struct[3]
  const reasons = []
  if (!Array.isArray(el0) || el0.length < 2) reasons.push('el0 events < 2 (mouse path degenerate)')
  if (!Array.isArray(el3) || el3.length < 1) reasons.push('el3 origins empty (no resource graph)')
  // el2 inner per-type stats: [typeCode, mean, variance, count]; want some count>1 & variance>0
  let okStat = false
  if (Array.isArray(el2)) for (const e of el2) if (Array.isArray(e) && e.length >= 4 && e[3] > 1 && e[2] > 0) okStat = true
  if (!okStat) reasons.push('el2 has no per-type stat with count>1 & variance>0')
  return { present: true, valid: reasons.length === 0, reason: reasons.join('; ') || 'ok', struct, head: s.slice(0, 16) }
}

// ----------------------------------------------------------------------------
// (1) NATIVE toString SPOOF  -> defeats `String(fn)` integrity probes in the bC-VM program
// ----------------------------------------------------------------------------
function defName(fn, name) { try { Object.defineProperty(fn, 'name', { value: name, configurable: true }) } catch (e) {} return fn }

// Install inside the realm: override the realm's Function.prototype.toString so that any
// function we tag as native prints `function <name>() { [native code] }`, while everything
// else (the real bundle code, genuine intrinsics) delegates to the original toString. The
// override itself, the original, and the spoof set are all made native-looking, and method
// identity ( (fn).toString === Function.prototype.toString ) is preserved.
//
// Returns a host-callable marker `markNative(fn[,name])`. Functions are tagged by object
// identity in a realm-resident WeakSet, so host-created stubs put on the sandbox are tagged
// correctly even though they were authored host-side (same object identity across the vm
// boundary because vm shares the host's Function intrinsic here).
function installNativeToString(ctx, vmRef) {
  const vm = vmRef || require('vm')
  // NOTE: a vm context has TWO %Function.prototype%s — the context-internal one (inherited by
  // in-context function literals: the bundle + the bC-VM bytecode) and the host one bound to
  // the global `Function` because the harness injects base.Function = globalThis.Function
  // (inherited by our host-authored stubs: perf.now, atob, ...). We patch BOTH with the SAME
  // override + WeakSet, else `String(hostStub)` or `String(bundleFn)` leaks down whichever FP
  // we missed. `Function.prototype.toString` is generic, so one `orig` works cross-FP.
  const SNIPPET = `(function(){
    var fnFP = Object.getPrototypeOf(function(){});      // context-internal FP (bundle/bytecode)
    var gFP  = (typeof Function !== 'undefined' && Function.prototype) || fnFP; // global-binding FP (host stubs)
    var orig = fnFP.toString;
    var spoof = new WeakSet();
    function nativeToString(){
      if (spoof.has(this)) { return 'function ' + (this.name || '') + '() { [native code] }'; }
      return orig.apply(this, arguments);
    }
    try { Object.defineProperty(nativeToString, 'name', { value: 'toString', configurable: true }); } catch(e){}
    try { Object.defineProperty(nativeToString, 'length', { value: 0, configurable: true }); } catch(e){}
    spoof.add(nativeToString);     // toString.toString() -> native
    spoof.add(orig);               // original (context FP) is native too
    spoof.add(gFP.toString);       // original (host FP) is native too
    fnFP.toString = nativeToString;
    if (gFP !== fnFP) gFP.toString = nativeToString;
    // also spoof the common probe surface .call / .apply / .bind on both FPs
    try { spoof.add(fnFP.toString.call); spoof.add(fnFP.toString.apply); spoof.add(fnFP.toString.bind); } catch(e){}
    try { spoof.add(gFP.call); spoof.add(gFP.apply); spoof.add(gFP.bind); } catch(e){}
    globalThis.__realismMark = function(fn, name){
      if (typeof fn !== 'function') return fn;
      if (name) { try { Object.defineProperty(fn, 'name', { value: name, configurable: true }); } catch(e){} }
      spoof.add(fn); return fn;
    };
    globalThis.__realismIsNative = function(fn){ try { return /\\[native code\\]/.test(Function.prototype.toString.call(fn)); } catch(e){ return false; } };
    return true;
  })()`
  vm.runInContext(SNIPPET, ctx, { filename: 'realism-tostring.js' })
  const mark = ctx.__realismMark
  return function markNative(fn, name) { try { return mark(fn, name) } catch (e) { return fn } }
}

// Walk the known hand-stub surface in a realm's sandbox and tag every non-native function.
// Call AFTER installNativeToString(ctx). Covers worker AND page realms (missing paths are
// skipped silently). The list mirrors exactly the stubs page.js/worker.js author by hand.
function markRealmNatives(sandbox, markNative) {
  const tag = (obj, key, name) => { try { if (obj && typeof obj[key] === 'function') markNative(obj[key], name || key) } catch (e) {} }
  const S = sandbox
  // global env funcs
  for (const k of ['importScripts', 'postMessage', 'addEventListener', 'removeEventListener', 'close', 'atob', 'btoa',
    'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'queueMicrotask', 'requestAnimationFrame',
    'cancelAnimationFrame', 'requestIdleCallback', 'cancelIdleCallback', 'fetch', 'getComputedStyle', 'matchMedia',
    'scrollTo', 'focus', 'blur', 'reportError', 'structuredClone']) tag(S, k)
  // performance
  if (S.performance) { tag(S.performance, 'now'); tag(S.performance, 'getEntriesByType'); tag(S.performance, 'getEntries'); tag(S.performance, 'getEntriesByName'); tag(S.performance, 'mark'); tag(S.performance, 'measure'); tag(S.performance, 'clearMarks'); tag(S.performance, 'clearMeasures')
    const md = S.performance.memory && Object.getOwnPropertyDescriptor(S.performance.memory, 'usedJSHeapSize'); if (md && md.get) markNative(md.get, 'get usedJSHeapSize')
    const td = S.performance.memory && Object.getOwnPropertyDescriptor(S.performance.memory, 'totalJSHeapSize'); if (td && td.get) markNative(td.get, 'get totalJSHeapSize') }
  // navigator
  if (S.navigator) { tag(S.navigator, 'sendBeacon'); tag(S.navigator, 'javaEnabled'); tag(S.navigator, 'vibrate')
    if (S.navigator.userAgentData) tag(S.navigator.userAgentData, 'getHighEntropyValues') }
  // crypto (webcrypto.getRandomValues is host-native already, but tag defensively if stubbed)
  if (S.crypto && typeof S.crypto.getRandomValues === 'function') tag(S.crypto, 'getRandomValues')
  // XHR prototype methods
  const X = S.XMLHttpRequest
  if (typeof X === 'function' && X.prototype) for (const m of ['open', 'send', 'setRequestHeader', 'getAllResponseHeaders', 'getResponseHeader', 'addEventListener', 'removeEventListener', 'abort', 'overrideMimeType']) tag(X.prototype, m)
  // constructors that observers/text codecs expose
  for (const k of ['MessageChannel', 'MessagePort', 'Worker', 'TextEncoder', 'TextDecoder', 'URL', 'URLSearchParams',
    'MutationObserver', 'IntersectionObserver', 'ResizeObserver', 'Image', 'Event', 'CustomEvent', 'Worker']) tag(S, k)
  // localStorage / sessionStorage
  for (const store of ['localStorage', 'sessionStorage']) if (S[store]) for (const m of ['getItem', 'setItem', 'removeItem', 'clear', 'key']) tag(S[store], m)
  return markNative
}

module.exports = {
  makePerf, makeResourceEntries, defaultResourceUrls, synthPointerPath, validateField20,
  installNativeToString, markRealmNatives, defName, HEAP_BUCKET, JS_HEAP_LIMIT,
}

// --------------------------- self-test ---------------------------
if (require.main === module) {
  const vm = require('vm')
  // (2) perf realism
  const perf = makePerf({ resourceHost: 'lucille.sh' })
  const t1 = perf.now(); const u1 = perf.memory.usedJSHeapSize
  const junk = []; for (let i = 0; i < 200000; i++) junk.push({ i, s: 'x'.repeat(8) }) // force heap growth
  const t2 = perf.now(); const u2 = perf.memory.usedJSHeapSize
  console.log('[perf] timeOrigin=', perf.timeOrigin, '| now monotonic:', t2 >= t1, '| x(ms)=', Math.round(t2 - t1))
  console.log('[perf] heap U=', u2 - u1, '(want >0)  used=', u2, 'limit=', perf.memory.jsHeapSizeLimit)
  console.log('[perf] coherence timeOrigin+now≈Date.now:', Math.abs(perf.timeOrigin + perf.now() - Date.now()) < 5, '| resources:', perf.getEntriesByType('resource').length, 'el3 hosts e.g.', new URL(perf.getEntriesByType('resource')[1].name).hostname)
  console.log('junk len', junk.length > 0)

  // (1) native toString spoof inside a realm
  const ctx = vm.createContext({})
  ctx.Function = Function; ctx.Object = Object; ctx.WeakSet = WeakSet; ctx.RegExp = RegExp; ctx.String = String
  const stub = function () {}; // a non-native fn we will pass into the realm
  ctx.stub = stub; ctx.perfNow = perf.now
  const mark = installNativeToString(ctx)
  mark(stub, 'now'); mark(perf.now, 'now')
  const r = vm.runInContext(`[
    String(stub),
    String(Function.prototype.toString),
    Function.prototype.toString.call(Function.prototype.toString),
    String(perfNow),
    String(function realBundleFn(){var x=1;return x}),
    String(Object)
  ]`, ctx)
  console.log('[toString] stub        ->', r[0])
  console.log('[toString] FT.toString ->', r[1])
  console.log('[toString] FT.ts.call  ->', r[2])
  console.log('[toString] perf.now    ->', r[3])
  console.log('[toString] realBundleFn->', r[4], '(must show source, NOT native)')
  console.log('[toString] Object      ->', r[5], '(genuine native, delegated)')

  // (3) field20 validator over a real capture
  try {
    const CAP = require('../poc/capture.json')
    const v = validateField20(Buffer.from(CAP.items[0].bodyB64, 'base64'))
    console.log('[field20] capture.json ->', v.valid ? 'VALID' : 'INVALID', '|', v.reason, '| el0len', v.struct && v.struct[0].length, '| el3len', v.struct && v.struct[3].length)
  } catch (e) { console.log('[field20] capture decode err', e.message) }
}
