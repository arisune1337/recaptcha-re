// page_rpc.js — the PAGE-side AE handler set for the BotGuard worker channel.
//
// WHY THIS EXISTS (grounded in the AE dispatch @byte 212085 of recaptcha__en.js):
//
//   ...else if(d.P["has"](K)) A=d.P.get(K),
//        (new Promise(function(h){h(A.call(d.C, x||void 0, K))}))
//          .then(function(h){ b[5](10,0,d, h||w, MZ, N) },          // resolve -> MZ ack (callid N)
//                function(h){ b[5]( 9,0,d, h.name||h||w, V3, N) }); // reject  -> V3 error
//   else b[5](8,0,d, w, V3, N);                                       // UNKNOWN opcode -> V3 error
//
//   K = inbound messageType (opcode for a request, or MZ/V3 for a reply)
//   N = 12-char callid           x = decoded payload (jspb message)   d.C = handler `this`
//
// The worker's AE.send() (@794881) registers a deferred in this.L keyed by callid and arms a
// 15000ms watchdog that rejects with `reCAPTCHA Timeout (<opcode>)`. So a worker->page request
// stalls/soft-blocks iff the page does NOT reply MZ with the same callid inside 15s. There are
// exactly two ways the page fails to reply: (a) the opcode is unknown -> `else` branch emits V3
// (an *error* the worker's deferred rejects on), or (b) the page handler THROWS / returns a
// rejected promise -> V3. This module removes both failure modes.
//
// CONSTRUCTOR FACT (@byte ~254860): `new AE(port, opcodeMap, ctxThis, origin, channel)` does
//   this.P = new Map; opcodeMap.forEach(... this.P.set(opcode, handler) ...)
// i.e. it COPIES arg2 into a fresh plain Map. Passing a clever Map as arg2 is therefore useless
// for a catch-all — the catch-all MUST be installed by overwriting the instance's `.P` AFTER
// construction. The dispatch reads `d.P.has(K)` / `d.P.get(K)` live off the instance, so an
// overwrite takes effect. That is exactly what installOn() / the __onAE hook below do.
//
// The real Google page builds this client AE with an EMPTY map (page mirror @446226 defaults
// `d = d===void 0 ? new Map : d`), and the measured field16 phase shows the worker only RESPONDS
// (the 215KB "x" frame is the worker's reply to the page's ak call, same callid) — so an empty
// map "works" only because the worker happens not to request anything in that window. This
// module makes the page robust regardless: every inbound opcode (known or not) gets a same-callid
// MZ ack, real handlers (if Google seeded any) are preserved, and a handler can never stall.
'use strict'

// ---- source patches: capture the AE class + fire a per-instance hook at end of ctor ----
// Apply these to the recaptcha__en.js source string before vm.runInContext (see integration note
// at the bottom of this file). Each anchor was verified UNIQUE against the local 895421-byte file.
const PATCHES = [
  // expose the AE constructor (so the harness can assert/inspect; same object Google uses)
  ['AE=function(q,r,w,D,d,A){return b[32]',
   'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]'],
  // fire __onAE(instance) at the very end of the AE constructor body. `x` === `this` (set by the
  // ctor as `x=this`). Guarded by typeof so it is a no-op in the worker realm (no __onAE there).
  ['this.D.start()),q^6)>>3',
   'this.D.start(),typeof __onAE==="function"&&__onAE(x)),q^6)>>3'],
]

function applyPatches(code) {
  for (const [find, repl] of PATCHES) {
    const i = code.indexOf(find)
    if (i < 0) throw new Error('page_rpc: anchor NOT FOUND: ' + find)
    if (code.indexOf(find, i + 1) >= 0) throw new Error('page_rpc: anchor NON-UNIQUE: ' + find)
    code = code.slice(0, i) + repl + code.slice(i + find.length)
  }
  return code
}

// ---- small payload describer for inbound-request logging (diff target vs a real browser) ----
function describe(v) {
  try {
    if (v == null) return String(v)
    if (typeof v === 'string') return 'str(' + v.length + '):' + v.slice(0, 24)
    if (typeof v !== 'object') return typeof v + ':' + String(v).slice(0, 24)
    const ctor = v.constructor && v.constructor.name
    // jspb messages keep their backing array on a small set of fields; surface a shallow hint
    const keys = Object.keys(v).slice(0, 6)
    return (ctor || 'obj') + '{' + keys.join(',') + '}'
  } catch { return '?' }
}

// ---- the handler SET: a live has()/get() facade over an inner Map of specific handlers ----
//
// Contract enforced:
//   has(K) -> ALWAYS true  => dispatch never takes the `else` (V3-unknown) branch.
//   get(K) -> the specific handler if Google/we seeded one, else the ACK handler.
//   ACK handler returns undefined and NEVER throws => dispatch replies MZ with the default `w`
//     ack payload (the same 4-byte "y" ack the real page emits for liveness/echo polls), same
//     callid => the worker's deferred resolves, the BotGuard run continues.
//
// `specific` is normally the AE instance's existing `this.P` (so any real handlers survive).
function makePageHandlerMap(specific, opts) {
  opts = opts || {}
  const inner = specific instanceof Map ? specific : new Map()
  const log = opts.log || (() => {})
  const onRequest = opts.onRequest || null         // (opcodeKey, payload, instance) => void
  const stats = opts.stats || new Map()            // opcodeKey -> count (worker->page requests)

  // optional extra handlers to seed (e.g. discovered later by diffing a real-browser capture)
  if (opts.handlers) for (const [k, fn] of (opts.handlers instanceof Map ? opts.handlers : Object.entries(opts.handlers))) inner.set(k, fn)

  // The universal ACK. `this` === d.C (page global). Args: (decodedPayload, opcodeKey).
  function ack(payload, K) {
    try {
      stats.set(K, (stats.get(K) || 0) + 1)
      log('inbound worker->page request opcode=' + String(K) + ' payload=' + describe(payload) + ' #' + stats.get(K))
      if (onRequest) onRequest(K, payload, opts.instance)
    } catch (_) { /* logging must never turn an ack into a V3 */ }
    return undefined   // -> b[5](10,0,d, undefined||w, MZ, N): a same-callid MZ ack, no throw
  }

  const facade = {
    __isPageHandlerSet: true,
    _inner: inner,
    _stats: stats,
    has(_K) { return true },                                   // never let dispatch hit the V3-unknown branch
    get(K) { return inner.has(K) ? inner.get(K) : ack },       // real handler wins; else ACK
    // keep Map-ish surface in case anything else introspects .P
    set(K, v) { inner.set(K, v); return this },
    delete(K) { return inner.delete(K) },
    forEach(cb, t) { return inner.forEach(cb, t) },
    keys() { return inner.keys() },
    get size() { return inner.size },
  }
  return facade
}

// ---- installer: swap a constructed AE instance's `.P` for the catch-all (merge-preserving) ----
function installOn(ae, opts) {
  if (!ae || ae.P == null || (ae.P && ae.P.__isPageHandlerSet)) return ae   // idempotent
  const existing = ae.P instanceof Map ? ae.P : new Map()
  ae.P = makePageHandlerMap(existing, Object.assign({ instance: ae }, opts || {}))
  return ae
}

// ---- the __onAE hook factory for page.js's windowExtra -----------------------------------
//
// Install on EVERY page-realm AE (merge-preserving, so the anchor<->bframe AE and the @446226
// mirror AE keep their real handlers and only GAIN a default-ACK for unknown opcodes). Set
// opts.onlyPort to a port object to restrict the swap to the AE bound to that exact worker port
// (matched by `ae.D === port`) if you want to leave the anchor<->bframe channel untouched.
function makeOnAE(opts) {
  opts = opts || {}
  const seen = []
  const stats = new Map()
  return function onAE(ae) {
    try {
      seen.push(ae)
      const port = typeof opts.getPort === 'function' ? opts.getPort() : opts.onlyPort
      if (port && ae && ae.D !== port) {
        // a non-worker AE (anchor<->bframe / mirror); install only if not port-restricted
        if (opts.allPageAEs === false) return ae
      }
      installOn(ae, { log: opts.log, onRequest: opts.onRequest, handlers: opts.handlers, stats })
      if (opts.log) opts.log('installed page-side handler set on AE (port-match=' + (port ? (ae.D === port) : 'n/a') + ', total AEs=' + seen.length + ')')
    } catch (e) { if (opts.log) opts.log('onAE install failed: ' + e.message) }
    return ae
  }
}

module.exports = { PATCHES, applyPatches, makePageHandlerMap, installOn, makeOnAE, describe }
