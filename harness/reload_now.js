// reload_now.js — the SHORTEST path to a CAPTURED /reload body (bframe-direct, reload#1).
//
// DECISION — why this is the shortest of the three routes (vs parent-emulation / full relay):
//   * The /reload POST is ALWAYS emitted by the BFRAME, never by the anchor (poc/flow.json:
//     the /reload Referer is the bframe url). So a /reload requires getting a bframe to run.
//   * recaptcha.frame.Main.init("<cfg>")  ->  (r=new XZ(TP(q)),new Ac(r)).D.init(E[40](4,r,1,P))
//     (bundle @byte 893462, confirmed). Ac.D.init() AUTO-SCHEDULES the reason=fi POST /reload on
//     bframe LOAD — no checkbox, no parent render-config MZ, no AE codec, ZERO frames to send.
//   * reload#1's field16 is EMPTY (attestation only matters from reload#2), so reload#1 needs
//     NOTHING from the anchor BotGuard worker. The single load-bearing input is a valid,
//     in-session, non-expired bft (the anchor's type-0d attestation token).
//
//   This bypasses the per-session AE crypto wall that blocks driver_emulate_parent.js (the
//   cross-frame AE keystream is derived per-session; a second realm derives a different seed and
//   cannot encode the render-config MZ the anchor needs to go interactive). Here we never encode
//   an AE frame: we just hand the server-minted bft back and let Ac.D.init() fire the timer.
//
// RELATION TO driver_core.js: this reuses driver_core's exact primitives via bframe_direct.js
//   (instrumented XHR that captures the /reload body as raw bytes + extractField16 + the
//   monotonic-clock/growing-heap perf), and the bundle is patched identically (Ac/WR capture).
//
// RUN:  BFT=<fresh token> SITEKEY=<key> ORIGIN_HOST=<embedder host> VER=<ver> node harness/reload_now.js
//   GRECAPTCHA cookie optional — reload#1 returns 200 + ["rresp",...] even cookieless
//   (poc/FINDINGS.md: "POST /reload ... 200 every time", field16 ignored at reload).
//
// FALLBACK if NO /reload fires (the bframe init turns out to be gated on a real parent setup,
//   not just the auto-timer):  node harness/bframe_direct.js  (same BFT) — it additionally boots
//   the anchor + worker + the bframe<->anchor attestation relay.
'use strict'
const vm = require('vm')
// bframe_direct.js (required, not run): module-load patches recaptcha__en.js (Ac/WR/RPp/ak/d5
// capture + page_rpc AE hooks) and exposes the realm/XHR/codec helpers. buildRealm compiles the
// PATCHED bundle in every realm, so __grAC (the bframe controller) is captured for free.
const BD = require('./bframe_direct.js')
const { buildRealm, makeXHR, makeJar, extractInitCall, extractField16, MessageChannelShim, locFrom, noop } = BD

const SITEKEY = process.env.SITEKEY || '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-'
const ORIGIN_HOST = process.env.ORIGIN_HOST || 'www.google.com'
const VER = process.env.VER || 'TnA7HacJFoBWt9hnlunBlYfK'
const GOOGLE = 'https://www.google.com'
const HOST_ORIGIN = 'https://' + ORIGIN_HOST          // the embedder origin = the bframe's expected parent origin
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const BFT = process.env.BFT || ''
const log = (...a) => console.log(...a)
const sleep = ms => new Promise(r => setTimeout(r, ms))

async function main() {
  process.on('unhandledRejection', () => {})
  if (!BFT) {
    log('FATAL: no BFT supplied.')
    log('  bft = the anchor BotGuard type-0d attestation token, minted in-session and set onto the')
    log('  bframe iframe src by api.js AFTER the anchor goes interactive. Capture a FRESH one:')
    log('   - real browser DevTools: read the <iframe src=".../api2/bframe?...&bft=<TOKEN>">, or')
    log('   - a parent-emulated run (driver_emulate_parent.js) decodes it off the create-bframe RPC.')
    log('  Then:  BFT=<token> node harness/reload_now.js   (bft is time/session-bound -> use it promptly)')
    process.exit(2)
  }

  const jar = makeJar()
  const RELOADS = []
  let resolveReload; const firstReload = new Promise(r => { resolveReload = r })

  // 1) GET /bframe with the live bft. The server binds the session to bft and returns HTML carrying
  //    recaptcha.frame.Main.init("<cfg>"). A missing init literal == bft invalid/expired.
  const burl = `${GOOGLE}/recaptcha/api2/bframe?hl=en&v=${VER}&k=${SITEKEY}&bft=${encodeURIComponent(BFT)}`
  log('[reload_now] GET', burl.slice(0, 96) + '...')
  let bhtml
  try { const r = await fetch(burl, { headers: { 'User-Agent': UA, Referer: burl } }); jar.absorb(r.headers); bhtml = await r.text() }
  catch (e) { log('[reload_now] bframe fetch failed:', e.message); process.exit(1) }
  const binit = extractInitCall(bhtml, 'recaptcha.frame.Main.init')
  if (!binit) { log('[reload_now] NO recaptcha.frame.Main.init literal in bframe HTML (', bhtml.length, 'B) -> bft invalid/expired or sitekey not provisioned. ABORT.'); process.exit(2) }
  log('[reload_now] frame.Main.init literal:', binit.length, 'chars | cookie:', jar.cookie ? jar.cookie.split(';')[0] : '(none)')

  // 2) MINIMAL parent stub. The bframe posts "recaptcha-setup"+MessagePort to window.parent during
  //    init; we capture it and reply ONCE so its setup path does not throw. We send NO command
  //    frames (reload#1 is an auto-scheduled timer, not gated on a parent render-config). Whatever
  //    the bframe sends over the adopted port we swallow — a same-callid ack is unnecessary for
  //    reload#1 (and would need the per-session codec, which we deliberately avoid here).
  const BFRAME_WIN_LIS = {}
  const ch = new MessageChannelShim()
  ch.port1.onmessage = () => {}                         // swallow bframe->parent frames
  const parentStub = { __isWindow: true, postMessage: (m, targetOrigin, transfer) => {
    const ports = (transfer || []).filter(x => x && x.__isPort)
    if (process.env.TRACE) log('   [bframe->parent post]', typeof m === 'string' ? 'str:' + String(m).slice(0, 28) : typeof m, 'ports=' + ports.length)
    if (typeof m === 'string' && ports.length) {        // the bframe's "recaptcha-setup" handshake
      const ev = { data: m, origin: HOST_ORIGIN, source: parentStub, ports: [ch.port2],
        type: 'message', preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {} }
      for (const fn of (BFRAME_WIN_LIS['message'] || []).slice()) { try { fn(ev) } catch (e) {} }
    }
  } }
  // the bframe controller builds a channel to its sibling ANCHOR via parent.frames[name];
  // give it a swallow-stub window for any frame name (reload#1 needs no real anchor relay).
  const siblingStub = { __isWindow: true, postMessage() {}, addEventListener() {}, removeEventListener() {}, focus() {}, blur() {}, location: { origin: HOST_ORIGIN } }
  parentStub.frames = new Proxy({ length: 1 }, { get(t, k) { if (k === 'length') return 1; return siblingStub }, has() { return true } })

  // 3) Boot the BFRAME realm. window===self (pageWindow) BUT window.parent===parentStub (!==window),
  //    so the "am I framed?" gate (@190196) passes and the controller takes the bframe code path.
  // minimal DOM stub for the bframe realm (no canvas; just non-throwing getElementById/createElement)
  const els = {}
  const bdoc = new Proxy({
    getElementById: (id) => (els[id] = els[id] || noop()), createElement: () => noop(), createElementNS: () => noop(), createDocumentFragment: () => noop(),
    querySelector: () => noop(), querySelectorAll: () => [], getElementsByTagName: () => [noop()], getElementsByClassName: () => [noop()], getElementsByName: () => [], createTextNode: () => noop(), createComment: () => noop(), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
    documentElement: noop(), head: noop(), body: noop(), cookie: '', referrer: HOST_ORIGIN + '/', addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
  }, { get(t, k) { if (k in t) return t[k]; return noop() }, has() { return true } })
  const bExtra = {
    document: bdoc,
    Worker: function () { return { postMessage() {}, addEventListener() {}, removeEventListener() {}, terminate() {} } }, // bframe has no own worker
    XMLHttpRequest: makeXHR(jar, burl, RELOADS, resolveReload, null, 'bframe'),                                            // captures /reload verbatim + field16
    addEventListener: (t, f) => { (BFRAME_WIN_LIS[t] = BFRAME_WIN_LIS[t] || []).push(f) },
    removeEventListener: (t, f) => { if (BFRAME_WIN_LIS[t]) BFRAME_WIN_LIS[t] = BFRAME_WIN_LIS[t].filter(x => x !== f) },
    postMessage: () => {},                               // self-posts: ignore
    location: locFrom(burl),                             // origin www.google.com, pathname /recaptcha/api2/bframe
    parent: parentStub, top: parentStub, frameElement: {}, // window.parent != window -> framed
    innerWidth: 400, innerHeight: 580, outerWidth: 400, outerHeight: 580, devicePixelRatio: 1, name: '', closed: false,
    botguard: undefined,                                 // force worker-attestation path (irrelevant to reload#1)
    ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, Event: function () { return noop() }, CustomEvent: function () { return noop() },
    MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } },
    IntersectionObserver: function () { return { observe() {}, disconnect() {} } },
    ResizeObserver: function () { return { observe() {}, disconnect() {} } },
  }
  log('[reload_now] booting BFRAME realm...')
  const bframe = buildRealm('bframe', bExtra, { pageWindow: true, parentCollapse: false })
  if (bframe.err) log('[reload_now] bframe load THREW:', bframe.err.message)
  if (!bframe.sandbox.recaptcha || !bframe.sandbox.recaptcha.frame) { log('[reload_now] no recaptcha.frame api -> abort'); process.exit(1) }

  // 4) TRIGGER = NONE. Running the scraped frame.Main.init verbatim makes Ac.D.init() auto-schedule
  //    the reason=fi POST /reload. (Contrast with the anchor route, which needs a checkbox click.)
  log('[reload_now] recaptcha.frame.Main.init(cfg)...')
  try { vm.runInContext(binit, bframe.ctx, { timeout: 20000 }) }
  catch (e) { log('[reload_now] frame init threw:', e.message, '\n', (e.stack || '').split('\n').slice(1, 4).join('\n')) }
  log('[reload_now] Ac controller captured (__grAC):', !!bframe.sandbox.__grAC,
    '| bframe win listeners:', Object.keys(BFRAME_WIN_LIS).map(k => k + '(' + BFRAME_WIN_LIS[k].length + ')').join(',') || 'none')

  // 5) wait for the auto-fired /reload, then CAPTURE + VALIDATE field16.
  log('[reload_now] waiting for bframe /reload (auto reason=fi) ...')
  const winner = await Promise.race([firstReload, sleep(15000).then(() => null)])

  log('\n[reload_now] ===== RESULT =====')
  log('reloads intercepted:', RELOADS.length)
  RELOADS.forEach((R, i) => log(`  reload#${i + 1} [${R.tag}]: ${R.buf.length}B | field16 ${R.info.present ? R.info.len + 'B urlSafeB64=' + R.info.urlSafeB64 : 'EMPTY (correct for reload#1)'} | fields ${JSON.stringify(R.info.map)}`))
  if (!winner) {
    log('NO /reload fired in 15s. The bframe init is likely gated on a real parent setup (not just the')
    log('auto-timer). FALLBACK: node harness/bframe_direct.js (boots anchor+worker+relay), same BFT.')
    process.exit(3)
  }
  // VALIDATION: the body must protobuf-decode and look like a reload (f1=VER, f2=c / f14=sitekey).
  // field16 ABSENT/EMPTY is the EXPECTED, correct state for reload#1 (populated only from reload#2,
  // which is built from this rresp's field18 attestation — that step needs the anchor-worker relay).
  const info = winner.info, decoded = info && !info.error
  const looksLikeReload = decoded && (('f1' in info.map) || ('f2' in info.map) || ('f14' in info.map))
  if (!decoded) { log('FAIL: /reload body did not protobuf-decode:', info && info.error); process.exit(4) }
  log('PASS: captured a real /reload protobuf body (wrote bframe_reload_1.bin).',
    looksLikeReload ? '(f1/f2/f14 present)' : '(WARN: expected reload fields f1/f2/f14 not seen — verify VER/sitekey)')
  log('field16:', info.present ? info.len + 'B urlSafeB64=' + info.urlSafeB64 + ' (UNEXPECTED on reload#1 — bonus)'
    : 'EMPTY — correct for reload#1. For a populated field16 run reload#2 via bframe_direct.js (anchor-worker relay).')
  process.exit(0)
}

if (require.main === module) main()
module.exports = { main }
