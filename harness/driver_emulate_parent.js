// driver_emulate_parent.js — emulate the api.js PARENT by booting a SECOND en.js realm.
//
// WHY (grounded in MEMORY map "apijs-loader" / "render-register" / "anchor-intake-sm"):
//   A bare MZ-ack to the anchor's first AE "C" frame is proven INSUFFICIENT — the anchor only
//   wires its checkbox 'click' listener (and later fires POST /reload) after it receives the
//   GENUINE api.js render/register response, which is AE-sealed (the "B"+b64(XOR12(json)) wire
//   codec) with a per-session key. We cannot hand-craft that. But the api.js/parent ROLE lives
//   in the SAME universal recaptcha__en.js bundle. So we boot a top-level HOST realm, seed it
//   exactly like api.js, let its grecaptcha auto-render create the anchor <iframe> + the parent
//   cross-frame intake, and BRIDGE the two realms' window.postMessage + (by-ref) MessagePorts.
//   Google's own parent code then decodes the anchor's "C"/"z" frames and emits the real MZ
//   responses + the render/create-bframe/register commands — flipping the anchor interactive.
//
// VALIDATED HERE (scratchpad/smoke_parent.js):
//   * loader seeds -> grecaptcha = {ready,render,reset,getResponse,execute,getPageId}
//   * auto-render (cfg.render=['onload']) registers a client (cfg.count=1) AND creates the anchor
//     <iframe src=".../api2/anchor?...&co=b64(HOST_ORIGIN:443)...">  AND installs 1 window
//     'message' intake listener — all at realm-load time. co is derived from the parent realm's
//     location.origin (no hand-built co).
//
// Run:  node harness/driver_emulate_parent.js
//   env: SITEKEY, ORIGIN_HOST (host/embedder origin -> co), VER, TRACE=1
'use strict'
const fs = require('fs')
const vm = require('vm')
const os = require('os')
const path = require('path')
const pb = require('../poc/pb.js')
const REAL = require('./realism.js')
const crypto = require('crypto')

// ----------------------------------------------------------------------------
// 0) Source-patch en.js (same family as driver_core): capture AE/d5/WR + the parent-realm
//    render path, write a temp copy, point page.js at it BEFORE requiring page.js.
// ----------------------------------------------------------------------------
const ENJS_SRC = process.env.ENJS_SRC || 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
let CODE = fs.readFileSync(ENJS_SRC, 'utf8')
// per-realm captured channel AES keys (Cy bytes); INJECT shares anchor->parent.
const ANCHOR_KEYS = [], PARENT_KEYS = [], WORKER_KEYS = []
const INJECT = process.env.INJECT === '1'
const keyHex = b => Buffer.from(b).toString('hex')
// XOR keystream capture: per realm, grouped into runs (a new run when N resets to 0 = new frame).
const ANCHOR_KS = [], PARENT_KS = []
function mkKsHook(store) { let cur = null; return (b, n) => { if (n === 0) { cur = []; store.push(cur) } if (cur) cur.push(b & 0xff); return b } }
// parsed-inbound-message capture (post-decode): proves whether decode succeeded per realm.
const ANCHOR_MSGS = [], PARENT_MSGS = [], PARENT_DISP = [], PARENT_PARSE = [], ANCHOR_PARSE = []
function mkMsgHook(store) { return (mt, msg) => { try { store.push({ mt: String(mt), prev: (() => { try { return JSON.stringify(msg).slice(0, 60) } catch { return (msg && msg.constructor && msg.constructor.name) || typeof msg } })() }) } catch {} } }
// NDUMP: dump a fully-decoded inbound message (post-decrypt/parse) to a scratch file, so we can
// see whether the injected foreign "n" activate literally CONTAINS the reload's f16/f2/f5 values
// (proving COPY) vs the bframe computing them. Byte arrays are rendered as length markers.
function dumpDecoded(realm, mt, msg) {
  try {
    const seen = new WeakSet()
    const s = JSON.stringify(msg, (k, v) => {
      if (v && typeof v === 'object') { if (seen.has(v)) return '<circ>'; seen.add(v); if (v.buffer instanceof ArrayBuffer && typeof v.length === 'number') return '<bytes:' + v.length + '>'; }
      if (typeof v === 'function') return undefined
      if (typeof v === 'string' && v.length > 400) return v.slice(0, 60) + '…(' + v.length + ')'
      return v
    })
    fs.appendFileSync(process.env.NDUMP, '\n=== ' + realm + ' decoded mt=' + JSON.stringify(String(mt)) + ' jsonLen=' + (s ? s.length : 0) + ' ===\n' + (s || '').slice(0, 40000) + '\n')
  } catch (e) { try { fs.appendFileSync(process.env.NDUMP, '\n=== ' + realm + ' mt=' + mt + ' DUMP-ERR ' + (e && e.message) + ' ===\n') } catch {} }
}
function tryPatch(find, repl, label) {
  const i = CODE.indexOf(find)
  if (i < 0) { console.log('  [patch skip]', label, '(anchor not found)'); return }
  if (CODE.indexOf(find, i + 1) >= 0) { console.log('  [patch skip]', label, '(non-unique)'); return }
  CODE = CODE.slice(0, i) + repl + CODE.slice(i + find.length); console.log('  [patch ok ]', label)
}
console.log('[emp] patching en.js (AE/d5/WR capture)...')
tryPatch('AE=function(q,r,w,D,d,A){return b[32]', 'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]', 'AE ctor')
tryPatch('d5=lZ()', 'd5=__cap.d5=lZ()', 'd5 (recaptcha-setup)')
tryPatch('(new WR(r)).D).init()', '(self.__grWR=new WR(r)).D).init()', 'WR anchor controller')
// capture every AE.send {opcode, structured-message} BEFORE serialization (map entry 3 anchor)
tryPatch('AE).prototype.send=function(q,r,w,D,d,A){return F[48](65,',
         'AE).prototype.send=function(q,r,w,D,d,A){try{(self.__cap.sends=self.__cap.sends||[]).push({opS:String(q),msg:r})}catch(e){};return F[48](65,', 'AE.send capture')
// CHANNEL AES-GCM KEY hook: capture the raw key bytes (Cy) and allow injecting a shared key,
// so the emulated-parent realm can share the anchor realm's per-channel key and decrypt conf.
tryPatch('M.importKey(hd(),Cy,{name:Gg(),length:Cy.length}',
         'M.importKey(hd(),(Cy=(self.__keyHook?self.__keyHook(Cy):Cy)),{name:Gg(),length:Cy.length}', 'Cy AES key hook')
// per-char XOR keystream hook (the ACTUAL cross-frame codec): capture each keystream byte so we
// can compare the anchor's conf-encode keystream vs the parent's conf-decode keystream.
tryPatch('String.fromCharCode(d.charCodeAt(N)^A())',
         'String.fromCharCode(d.charCodeAt(N)^(self.__ksHook?self.__ksHook(A(),N):A()))', 'XOR keystream hook')
// parsed-inbound-message ctor: fires AFTER a frame's payload was successfully decoded+parsed.
// If the parent reaches this with messageType "C", the decode WORKED (blocker = routing/map);
// if it never fires for inbound "C", the parse/decrypt threw first (blocker = keystream).
tryPatch('this.message=r,this.messageType=w,this.D=D',
         'this.message=r,this.messageType=w,this.D=D,(typeof self.__msgHook==="function"&&self.__msgHook(w,r))', 'msg-ctor hook')
// AE inbound dispatch decision: log the messageType K the dispatch actually sees (and whether
// it routes to the MZ/V3 pending-resolve branch or the d.P.has(K) handler branch).
tryPatch('p.message),K==MZ)',
         'p.message),(typeof self.__dispHook==="function"&&self.__dispHook(K,d)),K==MZ)', 'dispatch K hook')
// the conf-body parser resolve: f is the parser for type r; capture r when f is undefined.
tryPatch('function(f){return f.parse(d)}',
         'function(f){return (typeof self.__pHook==="function"&&self.__pHook(f,d,r)),(f?f.parse(d):(typeof self.__pFB==="function"?self.__pFB(r,d):d))}', 'parser-resolve hook+fallback')
// null-safe document resolver: the headless DOM stub sometimes yields a null node in the
// checkbox-render path; default to `document` instead of crashing on null.nodeType.
tryPatch('w.nodeType==r?w:w.ownerDocument||w.document',
         '(w&&w.nodeType)==r?w:(w&&(w.ownerDocument||w.document))||document', 'null-safe doc-resolver')
// null-safe currentStyle: same checkbox-render path reads style off a possibly-null node.
tryPatch('w.currentStyle?w.currentStyle[r]:null',
         '(w&&w.currentStyle)?w.currentStyle[r]:null', 'null-safe currentStyle')
// null-safe inline style fallback on the same getStyle helper (w may be null).
tryPatch(')||w.style&&w.style[r]',
         ')||(w&&w.style&&w.style[r])', 'null-safe inline-style')
// null-safe element-size helper: when the measured node r is null, substitute a zero-size
// stub inline (comma-expr) so the remaining offsetHeight/getBoundingClientRect reads are safe.
tryPatch('D=r.offsetWidth,r.offsetHeight',
         'D=(r=r||{offsetWidth:0,offsetHeight:0,getBoundingClientRect:function(){return{left:0,top:0,right:0,bottom:0,width:0,height:0}}}).offsetWidth,r.offsetHeight', 'null-safe size-helper')
// GR bgprogram-serialization probe: log the size of the anchor's aq.Z().get().CE() (the ~336KB
// BotGuard program the anchor should relay to the bframe as opcode Ck). If small/empty, the
// anchor's BotGuard lacks the challenge program.
tryPatch('w.get().CE()',
         '(typeof self.__ceHook==="function"?self.__ceHook(w.get().CE()):w.get().CE())', 'CE bgprogram probe')
// Expose Pa (program-message wrapper @565966) so we can construct vy's arg from a captured program.
tryPatch('Pa=function(q){return E[15].call(this,11,q)}',
         'Pa=__cap.Pa=function(q){return E[15].call(this,11,q)}', 'Pa expose')
// Capture Rl + the vy call inputs at @382690 (N=Rl-decoded program, A=raw field18 bC) whenever a
// field18-bearing message is processed, AND expose Rl unconditionally so we can decode a captured
// program ourselves. `N=Rl(A)` -> `N=(self.__cap.Rl=Rl)(A)` sets __cap.Rl the first time it runs;
// but to have Rl BEFORE any field18 msg, we also expose it via the vy wrap capturing Rl by ref.
tryPatch('N=Rl(A),w.C=w.D.D.vy(new Pa(N),3E4)',
         'N=(self.__cap.Rl=Rl)(A),w.C=w.D.D.vy((typeof self.__vyHook==="function"?self.__vyHook(new Pa(N),N,A):new Pa(N)),3E4)', 'Rl expose + vy capture')
// Expose the BotGuard sandbox RPp server (Qr=load, ak=run) so a spawned worker realm can answer the
// bframe's ak request (worker.js pattern). RPp lives in the WORKER realm; expose to its __cap.
tryPatch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),', 'RPp/Qr expose')
tryPatch('}],[ak,function', '}],[(__cap.ak=ak),function', 'ak expose')
// expose aq (the BotGuard VM state holder) so after ak we can snapshot aq.Z().get().CE() (bgRequest).
tryPatch(',aq).Z().init(', ',(self.__cap.aq=aq)).Z().init(', 'aq expose')
// fire __onAE(instance) at the very end of every AE ctor (so we can install the page-side
// catch-all + tap inbound frames). This is page_rpc.PATCHES[1]; apply it here so page.js's
// own applyPatches (which also looks for it) still finds its OWN anchor untouched? No — page.js
// applies PR.PATCHES on top of OUR file. To avoid a double-apply collision we let page.js own
// the __onAE patch and only add the three above (none overlap PR.PATCHES anchors except the AE
// ctor prefix, which PR re-finds harmlessly as a substring — verified by driver_core).
const PATCHED = path.join(os.tmpdir(), 'recaptcha__en.emp.js')
fs.writeFileSync(PATCHED, CODE)
process.env.ENJS = PATCHED

const { buildRealm, MessageChannelShim, makePort } = require('./page.js')
const PR = require('./page_rpc.js')

// ----------------------------------------------------------------------------
// 1) Config.
// ----------------------------------------------------------------------------
const SITEKEY = process.env.SITEKEY || '6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-'
const ORIGIN_HOST = process.env.ORIGIN_HOST || 'www.google.com'   // host/embedder page origin (-> co)
const VER = process.env.VER || 'TnA7HacJFoBWt9hnlunBlYfK'
const HOST_ORIGIN = 'https://' + ORIGIN_HOST                      // where the parent/host page lives
const ANCHOR_ORIGIN = 'https://www.google.com'                   // where the /anchor iframe is served
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
const TRACE = !!process.env.TRACE
const log = (...a) => console.log(...a)

// ----------------------------------------------------------------------------
// 2) Network plumbing shared by the anchor realm's instrumented XHR.
// ----------------------------------------------------------------------------
let COOKIE = process.env.COOKIE_SEED || ''
const RELOADS = []
let resolveFirstReload; const firstReload = new Promise(r => { resolveFirstReload = r })
let resolveReloadResp; const firstReloadResp = new Promise(r => { resolveReloadResp = r })
let resolveBftReady; const bftReady = new Promise(r => { resolveBftReady = r })
let BFRAME_BOOTED = false; let BFRAME_REALM = null
const BFRAME_AES = []   // bframe AE instances (to inject the "n" activate onto the right channel)
let BF_T_MSG = null     // this-session program: the decoded bframe "t" frame payload (for Lq.vy)
let BF_T_RAW = null     // the RAW pre-parse JSON array string of the program (what new bC() wants)
const ANCHOR_CLIENT_AES = []   // anchor-realm AEs (the shared-d5 BotGuard client is among these)
const ANCHOR_WORKER_AES = []   // anchor-worker-realm AEs (the shared-d5 RPp server is among these)
let NATIVE_F16 = null   // a live-computed bgRequest (Dw().request) once vy/ak runs this session
function mergeSetCookie(headers) {
  let sc = []; try { sc = headers.getSetCookie ? headers.getSetCookie() : [] } catch {}
  if (!sc.length) { const one = headers.get && headers.get('set-cookie'); if (one) sc = [one] }
  for (const c of sc) { const kv = c.split(';')[0]; if (kv && kv.includes('=')) COOKIE = COOKIE ? COOKIE + '; ' + kv : kv }
}
function toBuf(body) {
  if (body == null) return Buffer.alloc(0)
  if (Buffer.isBuffer(body)) return body
  if (typeof body === 'string') return Buffer.from(body, 'latin1')
  if (body instanceof ArrayBuffer) return Buffer.from(body)
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength)
  try { return Buffer.from(body) } catch { return Buffer.alloc(0) }
}
function extractField16(buf) {
  let fields; try { fields = pb.decode(buf) } catch (e) { return { error: 'decode failed: ' + e.message } }
  const map = {}
  for (const f of fields) map['f' + f.field] = (f.type === 'string') ? `"${f.preview.slice(0, 20)}"(${f.len})` : (f.wire === 2 ? `<${f.len}b>` : f.value)
  const f16 = fields.find(f => f.field === 16 && f.wire === 2)
  if (!f16) return { fields, map, present: false }
  const text = f16.raw.toString('latin1')
  return { fields, map, present: true, len: f16.len, text, urlSafeB64: /^[A-Za-z0-9_-]+$/.test(text) }
}
function makeDriverXHR(opts) {
  opts = opts || {}
  const tag = opts.tag || 'anchor', refererDefault = opts.referer || ('https://www.google.com/recaptcha/api2/bframe?hl=en&v=' + VER + '&k=' + SITEKEY)
  return class XHR {
    constructor() { this._h = {}; this.readyState = 0; this.status = 0; this.responseText = ''; this.response = '' }
    open(m, u) { this._m = m; this._u = u }
    setRequestHeader(k, v) { this._h[k] = v }
    addEventListener(t, f) { this['on' + t] = f }
    getAllResponseHeaders() { return Object.entries(this._rh || {}).map(([k, v]) => k + ': ' + v).join('\r\n') }
    abort() {}
    send(body) {
      // the bframe/anchor issue RELATIVE api2 URLs (/recaptcha/api2/reload?...) which node fetch
      // can't parse; resolve them against the google.com origin (where these frames are served).
      const self = this; let url = String(this._u); if (url.startsWith('/')) url = 'https://www.google.com' + url
      const path_ = url.split('?')[0].replace(/^https?:\/\/[^/]+/, ''), buf = toBuf(body)
      const isReload = /recaptcha\/api2\/reload/.test(url)
      if (/recaptcha\/api2\/(reload|userverify|replaceimage|anchor|bframe|payload)/.test(url)) log('  [' + tag + ' XHR]', this._m, path_, 'bodyLen=' + buf.length)
      if (isReload) {
        const info = extractField16(buf); RELOADS.push({ buf, info })
        log('  *** /reload INTERCEPTED:', buf.length, 'bytes | fields:', JSON.stringify(info.map))
        log(info.present ? '      field16: ' + info.len + 'B urlSafeB64=' + info.urlSafeB64 + ' head=' + info.text.slice(0, 40)
                         : '      field16: ABSENT/EMPTY (expected on the FIRST reload)')
        // field16 (BotGuard attestation) + field20 (interaction telemetry) size report — the two
        // trust fields. Browser ref (2captcha capture): f16=5205B, f20=430B. Log el2 event-type
        // stats + whether el3 origins look FOREIGN (2captcha/doubleclick => injected-"n" telemetry).
        try {
          const fld = pb.decode(buf)
          const gf = n => { const x = fld.find(f => f.field === n && f.wire === 2); return x ? x.len : null }
          let f20Note = ''
          try { const v = REAL.validateField20(buf); if (v && v.struct) { const el2 = (v.struct[2] || []).filter(e => Array.isArray(e)).map(e => '[t' + e[0] + ' n' + e[3] + ']').join(''); const el3 = v.struct[3] || []; const foreign = Array.isArray(el3) && el3.some(o => /2captcha|doubleclick|respond\.io|chatapi/.test(String(o))); f20Note = ' | el0=' + (Array.isArray(v.struct[0]) ? v.struct[0].length : '?') + 'ev el2stats=' + (el2 || 'none') + ' el3=' + (Array.isArray(el3) ? el3.length : 0) + 'origins' + (foreign ? ' <<FOREIGN(injected-n)>>' : ' (in-session)') } } catch {}
          const f16r = fld.find(f => f.field === 16 && f.wire === 2), f5r = fld.find(f => f.field === 5)
          const f16md5 = f16r ? crypto.createHash('md5').update(f16r.raw).digest('hex').slice(0, 8) : 'none'
          const f2r = fld.find(f => f.field === 2 && f.wire === 2), f2md5 = f2r ? crypto.createHash('md5').update(f2r.raw).digest('hex').slice(0, 8) : 'none'
          log('      >>> TRUST FIELDS: field16=' + gf(16) + 'B (ref~5205)  field20=' + gf(20) + 'B (ref~430)  field2=' + gf(2) + 'B' + f20Note)
          const f5v = f5r ? (f5r.value != null ? f5r.value : (f5r.preview != null ? f5r.preview : (f5r.raw && f5r.raw.toString('latin1')))) : 'none'
          log('      >>> NATIVE-CHECK: f16.md5=' + f16md5 + ' f2.md5=' + f2md5 + ' f5=' + f5v + '  (foreign-fixed => f16.md5=b3bab02d f5=400985673; NATIVE => these VARY per run)')
        } catch {}
        try { resolveFirstReload({ buf, info }) } catch {}
        try { fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/emp_reload_' + RELOADS.length + '.bin', buf) } catch {}
      }
      const headers = { 'User-Agent': UA, 'Origin': ANCHOR_ORIGIN, ...this._h }
      if (COOKIE) headers['Cookie'] = COOKIE
      if (!headers['Referer']) headers['Referer'] = refererDefault
      if (isReload) log('      [reload req] Cookie=' + (headers['Cookie'] ? headers['Cookie'].slice(0, 60) : '(NONE)') + ' | Referer=' + (headers['Referer'] || '').slice(0, 90))
      fetch(url, { method: this._m || 'GET', headers, body: (this._m === 'POST' || this._m === 'PUT') ? buf : undefined })
        .then(async r => { self.status = r.status; self._rh = Object.fromEntries(r.headers); mergeSetCookie(r.headers)
          const rb = Buffer.from(await r.arrayBuffer()); self.responseText = rb.toString('latin1'); self.response = self.responseText; self.readyState = 4
          if (/recaptcha\/api2\/(reload|userverify|replaceimage|anchor|bframe|payload|jsn|bg)/.test(url)) log('  [' + tag + ' XHR RESP]', r.status, path_, rb.length, 'bytes')
          if (isReload) {
            log('      /reload response:', r.status, rb.length, 'bytes |', self.responseText.slice(0, 80).replace(/\n/g, ' '))
            try { fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/emp_reload_resp_' + RELOADS.length + '.txt', self.responseText) } catch {}
            try { resolveReloadResp({ status: r.status, len: rb.length, text: self.responseText }) } catch {}
          }
          if (self.onreadystatechange) self.onreadystatechange(); if (self.onload) self.onload() })
        .catch(e => { if (isReload || /recaptcha\/api2/.test(url)) log('  [' + tag + ' XHR ERR]', path_, (e && e.message) || e); if (isReload) { try { resolveReloadResp({ status: 0, len: 0, text: '', error: (e && e.message) || String(e) }) } catch {} } self.status = 0; self.readyState = 4; if (self.onerror) self.onerror(e); if (self.onreadystatechange) self.onreadystatechange() })
    }
  }
}
// Per-realm performance object (feeds the ak/Xm attestation -> field16, and getEntriesByType
// resource/navigation -> field20 el3 for an in-session reload). Delegates to realism.js:
//   - usedJSHeapSize: BASE + real heapUsed delta, quantized to 100KB Chrome buckets, ratcheted
//     (monotonic across the ak before/after reads so U=N-K lands in a small positive band).
//   - now(): monotonic, 0.1ms-coarse (Chrome granularity), timeOrigin = real epoch.
//   - jsHeapSizeLimit: corrected to a real Chrome/Win desktop value (2172649472, not 2.19e9).
//   - getEntriesByType('navigation') -> nextHopProtocol:'h2' (satisfies the @43227 HTTP/2 check),
//     ('resource') -> plausible origin graph anchored to the embedder host.
function makePerf() {
  const p = REAL.makePerf({ resourceHost: ORIGIN_HOST, baseHeap: 12_600_000 })
  try { p.memory.jsHeapSizeLimit = 2172649472 } catch {}
  return p
}

// Canvas/WebGL context stub: BotGuard probes document.createElement('canvas').getContext(...) and
// (for the fingerprint) WEBGL_debug_renderer_info UNMASKED_VENDOR/RENDERER + getParameter. A null
// getContext is a hard automation tell. Only canvas elements return this (checkbox render still
// gets null via non-canvas els). Gated off by NOCANVAS=1. Every method is a safe no-op.
const _PNG1x1 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='
function makeCanvasCtx(type) {
  type = String(type || '2d')
  if (/webgl/.test(type)) {
    const P = { 37445: 'Google Inc. (Intel)', 37446: 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)', 7936: 'WebKit', 7937: 'WebKit WebGL', 7938: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)', 35724: 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)', 3379: 16384, 34930: 16, 35660: 16, 34076: 16384, 36349: 1024, 34024: 16384, 3386: [16384, 16384], 33902: [1, 1024], 33901: [1, 1024] }
    return {
      canvas: { width: 300, height: 150 }, drawingBufferWidth: 300, drawingBufferHeight: 150,
      getParameter: p => (p in P ? P[p] : 0),
      getExtension: n => (n === 'WEBGL_debug_renderer_info' ? { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 } : (/lose_context/i.test(n) ? { loseContext() {}, restoreContext() {} } : {})),
      getSupportedExtensions: () => ['ANGLE_instanced_arrays', 'EXT_blend_minmax', 'EXT_color_buffer_half_float', 'EXT_float_blend', 'EXT_texture_filter_anisotropic', 'OES_element_index_uint', 'OES_standard_derivatives', 'OES_texture_float', 'OES_texture_half_float', 'WEBGL_debug_renderer_info', 'WEBGL_lose_context'],
      getContextAttributes: () => ({ alpha: true, antialias: true, depth: true, desynchronized: false, failIfMajorPerformanceCaveat: false, powerPreference: 'default', premultipliedAlpha: true, preserveDrawingBuffer: false, stencil: false }),
      getShaderPrecisionFormat: () => ({ rangeMin: 127, rangeMax: 127, precision: 23 }),
      createBuffer: () => ({}), bindBuffer() {}, bufferData() {}, createShader: () => ({}), shaderSource() {}, compileShader() {}, getShaderParameter: () => true, createProgram: () => ({}), attachShader() {}, linkProgram() {}, getProgramParameter: () => true, useProgram() {}, getAttribLocation: () => 0, getUniformLocation: () => ({}), enableVertexAttribArray() {}, vertexAttribPointer() {}, uniform2f() {}, uniform4f() {}, drawArrays() {}, viewport() {}, clearColor() {}, clear() {}, enable() {}, disable() {}, readPixels() {}, activeTexture() {}, bindTexture() {}, texParameteri() {}, texImage2D() {}, createTexture: () => ({}), createFramebuffer: () => ({}), bindFramebuffer() {}, framebufferTexture2D() {}, deleteBuffer() {}, deleteShader() {}, deleteProgram() {}, finish() {}, flush() {}, pixelStorei() {}, isEnabled: () => false, checkFramebufferStatus: () => 36053,
    }
  }
  return {
    canvas: { width: 300, height: 150 },
    fillRect() {}, clearRect() {}, strokeRect() {}, save() {}, restore() {}, beginPath() {}, closePath() {}, moveTo() {}, lineTo() {}, bezierCurveTo() {}, quadraticCurveTo() {}, arc() {}, arcTo() {}, rect() {}, ellipse() {}, stroke() {}, fill() {}, clip() {}, scale() {}, rotate() {}, translate() {}, transform() {}, setTransform() {}, resetTransform() {}, drawImage() {}, putImageData() {}, setLineDash() {}, getLineDash: () => [],
    getImageData: (x, y, w, h) => ({ data: new Uint8ClampedArray(Math.max(4, (w || 1) * (h || 1) * 4)), width: w || 1, height: h || 1 }),
    createImageData: (w, h) => ({ data: new Uint8ClampedArray(Math.max(4, (w || 1) * (h || 1) * 4)), width: w || 1, height: h || 1 }),
    measureText: t => ({ width: (String(t).length * 7.234) , actualBoundingBoxAscent: 8, actualBoundingBoxDescent: 2, actualBoundingBoxLeft: 0, actualBoundingBoxRight: String(t).length * 7, fontBoundingBoxAscent: 9, fontBoundingBoxDescent: 2 }),
    fillText() {}, strokeText() {},
    createLinearGradient: () => ({ addColorStop() {} }), createRadialGradient: () => ({ addColorStop() {} }), createPattern: () => ({}), createConicGradient: () => ({ addColorStop() {} }),
    font: '10px sans-serif', textAlign: 'start', textBaseline: 'alphabetic', globalAlpha: 1, globalCompositeOperation: 'source-over', lineWidth: 1, lineCap: 'butt', lineJoin: 'miter', miterLimit: 10, fillStyle: '#000000', strokeStyle: '#000000', shadowColor: 'rgba(0, 0, 0, 0)', shadowBlur: 0, shadowOffsetX: 0, shadowOffsetY: 0,
  }
}

// ----------------------------------------------------------------------------
// 2b) REALISTIC HUMAN POINTER TELEMETRY (field20 el0/el2). Replaces the old fireAll() synthetic
//     fixed-(14,14) event storm. Builds a curved, variable-speed Bezier path with jitter + natural
//     inter-event timing, a hover dwell, a realistic pointerdown->pointerup gap, and (for the
//     bframe) drift between the checkbox and challenge-tile region. Events carry the full property
//     surface the goog.events BrowserEvent normalizer reads: client/page/screen/movement coords,
//     pointerType/pointerId/buttons/pressure, modifier flags, isTrusted, monotonic timeStamp.
//     NOTE: while BFINJECTN is the reload trigger, the bframe relays the *injected* activate's
//     telemetry into f20 (foreign session) — these events shape f20 only once an IN-SESSION "n"
//     is elicited; they are wired now so that path is human-shaped by default. Gate: LEGACYFIRE=1.
const _R = (a, b) => a + Math.random() * (b - a)
function _bez(p0, p1, p2, p3, t) { const u = 1 - t; return u * u * u * p0 + 3 * u * u * t * p1 + 3 * u * t * t * p2 + t * t * t * p3 }
function _humanPath(from, to, steps) {
  const n = steps || (20 + Math.floor(Math.random() * 16))
  const dx = to.x - from.x, dy = to.y - from.y
  const c1 = { x: from.x + dx * _R(0.2, 0.42) + _R(-38, 38), y: from.y + dy * _R(0.2, 0.42) + _R(-28, 28) }
  const c2 = { x: from.x + dx * _R(0.58, 0.82) + _R(-30, 30), y: from.y + dy * _R(0.58, 0.82) + _R(-22, 22) }
  const pts = []; let px = from.x, py = from.y
  for (let i = 1; i <= n; i++) {
    let t = i / n; const te = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2   // ease-in-out (accel/decel)
    const x = _bez(from.x, c1.x, c2.x, to.x, te) + _R(-1.2, 1.2)
    const y = _bez(from.y, c1.y, c2.y, to.y, te) + _R(-1.2, 1.2)
    pts.push({ x, y, dt: Math.round(_R(9, 34)), mvx: x - px, mvy: y - py }); px = x; py = y
  }
  return pts
}
const _SCREEN_LEFT = 0, _SCREEN_TOP = 84       // window chrome offset -> screenX/Y != clientX/Y
function _ptrEvent(type, x, y, ts, mv, down) {
  const cx = Math.round(x), cy = Math.round(y)
  return {
    type, target: null, currentTarget: null,
    clientX: cx, clientY: cy, pageX: cx, pageY: cy, x: cx, y: cy, offsetX: cx, offsetY: cy,
    screenX: cx + _SCREEN_LEFT, screenY: cy + _SCREEN_TOP,
    movementX: Math.round((mv && mv.mvx) || 0), movementY: Math.round((mv && mv.mvy) || 0),
    button: 0, buttons: down === 1 ? 1 : 0, which: down != null ? 1 : 0, detail: down != null ? 1 : 0,
    pointerType: 'mouse', pointerId: 1, isPrimary: true, pressure: down === 1 ? 0.5 : 0, tangentialPressure: 0, tiltX: 0, tiltY: 0, twist: 0, width: 1, height: 1,
    ctrlKey: false, altKey: false, shiftKey: false, metaKey: false,
    isTrusted: true, bubbles: true, cancelable: true, composed: true, timeStamp: +ts.toFixed(1),
    preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, getModifierState: () => false, composedPath: () => [],
  }
}
let _humanClock = null
// Drive a human-like gesture: approach curve -> hover dwell -> click, on the elements that carry
// the relevant listeners; also delivers to a document-level fireDoc if provided. `clickEls` (all
// realm els, for on*-prop + delegated coverage) receive the down/up/click so activation still fires
// exactly as the old fireAll did — only the telemetry shape is upgraded.
function humanGesture(moveEls, clickEls, docFire, opts) {
  opts = opts || {}
  const hasPtr = el => el && el._lis && (el._lis.pointermove || el._lis.mousemove || el._lis.pointerdown || el._lis.mousedown || el._lis.pointerup || el._lis.mouseup || el._lis.click || el._lis.pointerover || el._lis.pointerenter)
  const targets = (moveEls || []).filter(hasPtr)
  if (_humanClock == null) _humanClock = _R(650, 1500)
  let ts = _humanClock
  const dispatch = (type, ev, els) => {
    for (const el of (els || targets)) {
      try { if (el._fire && el._lis && el._lis[type]) el._fire(type, ev) } catch {}
      try { const on = el['on' + type]; if (typeof on === 'function') on.call(el, ev) } catch {}
    }
    if (docFire) { try { docFire(type, ev) } catch {} }
  }
  const target = { x: opts.tx != null ? opts.tx : _R(18, 34), y: opts.ty != null ? opts.ty : _R(18, 34) }
  const start = { x: opts.sx != null ? opts.sx : _R(120, 340), y: opts.sy != null ? opts.sy : _R(160, 380) }
  // approach path
  let first = true
  for (const p of _humanPath(start, target, opts.steps)) {
    ts += p.dt
    if (first) { dispatch('pointerover', _ptrEvent('pointerover', p.x, p.y, ts, p)); dispatch('pointerenter', _ptrEvent('pointerenter', p.x, p.y, ts, p)); dispatch('mouseover', _ptrEvent('mouseover', p.x, p.y, ts, p)); dispatch('mouseenter', _ptrEvent('mouseenter', p.x, p.y, ts, p)); first = false }
    dispatch('pointermove', _ptrEvent('pointermove', p.x, p.y, ts, p)); dispatch('mousemove', _ptrEvent('mousemove', p.x, p.y, ts, p))
  }
  // hover dwell before the click (a few tiny jittery settling moves)
  let hx = target.x, hy = target.y
  const dwell = 2 + Math.floor(Math.random() * 3)
  for (let i = 0; i < dwell; i++) { ts += _R(12, 40); const nx = target.x + _R(-1.6, 1.6), ny = target.y + _R(-1.6, 1.6); dispatch('pointermove', _ptrEvent('pointermove', nx, ny, ts, { mvx: nx - hx, mvy: ny - hy })); hx = nx; hy = ny }
  // press -> realistic hold -> release + click (delivered to the broad clickEls set for coverage)
  const all = (clickEls && clickEls.length ? clickEls : targets)
  ts += _R(18, 55); dispatch('pointerdown', _ptrEvent('pointerdown', hx, hy, ts, null, 1), all); dispatch('mousedown', _ptrEvent('mousedown', hx, hy, ts, null, 1), all)
  dispatch('focus', { type: 'focus', isTrusted: true, bubbles: false, timeStamp: +ts.toFixed(1), preventDefault() {}, stopPropagation() {} }, all)
  ts += _R(60, 150); dispatch('pointerup', _ptrEvent('pointerup', hx, hy, ts, null, 0), all); dispatch('mouseup', _ptrEvent('mouseup', hx, hy, ts, null, 0), all); dispatch('click', _ptrEvent('click', hx, hy, ts, null, 0), all)
  // keyboard-activation fallback (some checkbox handlers only bind keydown/space)
  const kev = { type: 'keydown', key: ' ', code: 'Space', keyCode: 32, which: 32, isTrusted: true, bubbles: true, timeStamp: +ts.toFixed(1), ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, preventDefault() {}, stopPropagation() {}, getModifierState: () => false }
  dispatch('keydown', kev, all)
  // optional post-click drift toward the challenge tiles (bframe realism: mouse travels to tiles)
  if (opts.tiles) {
    let cur = { x: hx, y: hy }
    for (const tile of opts.tiles) {
      for (const p of _humanPath(cur, tile, 8 + Math.floor(Math.random() * 8))) { ts += p.dt; dispatch('pointermove', _ptrEvent('pointermove', p.x, p.y, ts, p)); dispatch('mousemove', _ptrEvent('mousemove', p.x, p.y, ts, p)) }
      ts += _R(80, 220); cur = tile
    }
  }
  _humanClock = ts + _R(60, 220)
  return { targets: targets.length }
}

// ----------------------------------------------------------------------------
// 3) Shared DOM/Worker stubs (parameterized per realm so the parent + anchor can each have
//    their own element registry and their own window 'message' bus).
// ----------------------------------------------------------------------------
// NOTE: noop() must NOT masquerade as a never-resolving thenable — the top's o-handler collects
// browser signals via Promise.all(collectors.map(w=>run(w)())); if a collector hits a missing API
// and gets this proxy back, Promise.all would call proxy.then(res,rej) and hang forever (root cause
// of the o-handler stall). So we make `.then/.catch/.finally` non-callable => the proxy is a plain
// (non-thenable) value that Promise.all resolves immediately.
function noop() { const f = function () { return P }; const P = new Proxy(f, { get(t, k) { if (k === Symbol.toPrimitive || k === 'toString' || k === 'valueOf') return () => ''; if (k === 'length') return 0; if (k === 'nodeType') return 1; if (k === 'then' || k === 'catch' || k === 'finally') return undefined; return P }, apply() { return P }, construct() { return P }, set() { return true }, has() { return true } }); return P }

function makeDocument(ALL_ELS, opts) {
  opts = opts || {}
  const ELS = {}
  // ---- realm-level element registry (class/id index) + innerHTML mini-parser --------------
  // reCAPTCHA builds the anchor checkbox by setting .innerHTML to a soy HTML string, then finds
  // the nodes via document.getElementsByClassName("recaptcha-checkbox") / getElementById. The old
  // stub returned [] / throwaway divs, so 0 listeners bound. We parse the innerHTML into real,
  // class/id-indexed, layout-bearing, listener-capturing nodes so jO->Ic.Jb finds the checkbox
  // <span id="recaptcha-anchor" role="checkbox"> and binds the mousedown/mouseup/ACTION handlers.
  const byClass = new Map()   // className -> Set<P proxy>
  const byId = new Map()      // id -> P proxy
  function idxClass(P, cls) { let s = byClass.get(cls); if (!s) { s = new Set(); byClass.set(cls, s) } s.add(P) }
  function idxId(id, P) { if (id) byId.set(id, P) }
  function queryClass(cls) { const s = byClass.get(cls); return s ? [...s] : [] }
  function queryId(id) { return byId.get(id) || null }
  function querySel(sel) {
    for (const part of String(sel).split(',')) {
      const p = part.trim(); if (!p) continue
      const idm = p.match(/#([\w-]+)/); if (idm) { const e = queryId(idm[1]); if (e) return e }
      const clsm = p.match(/\.([\w-]+)/); if (clsm) { const arr = queryClass(clsm[1]); if (arr.length) return arr[0] }
    }
    return null
  }
  const VOID_TAGS = /^(br|hr|img|input|meta|link|area|base|col|embed|source|track|wbr)$/
  function parseHTML(html) {
    const roots = []; const stack = []
    const tagRe = /<(\/?)([a-zA-Z][\w-]*)((?:[^">]|"[^"]*")*?)(\/?)>/g
    let m
    while ((m = tagRe.exec(html))) {
      const close = m[1] === '/', tagName = m[2].toLowerCase(), attrStr = m[3] || '', selfClose = m[4] === '/'
      if (close) { if (stack.length) stack.pop(); continue }
      const el = makeEl(tagName)
      const are = /([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s">]+)))?/g
      let a
      while ((a = are.exec(attrStr))) { const name = a[1]; if (!name) continue; const val = a[2] != null ? a[2] : a[3] != null ? a[3] : a[4] != null ? a[4] : ''; try { el.setAttribute(name, val) } catch {} }
      const parent = stack[stack.length - 1]
      if (parent) { try { parent.children.push(el); parent.childNodes.push(el); if (!parent.firstChild) parent.firstChild = el; parent.lastChild = el } catch {}; el.parentNode = parent; el.offsetParent = parent } else roots.push(el)
      if (!selfClose && !VOID_TAGS.test(tagName)) stack.push(el)
    }
    return roots
  }
  // A terminating ancestor chain so layout walks (`el.offsetParent.offsetWidth`,
  // `el.parentNode.parentNode...`) read real numbers for a few levels then hit null and
  // the walk-loop ends. Hardcoding parentNode/offsetParent to null crashed the checkbox
  // render on `null.offsetWidth` / `null.style`. Plain objects (not Proxies) so `k in t`
  // style reads return numbers, not the noop proxy.
  function ancNode(depth) {
    const n = { nodeType: 1, tagName: depth === 0 ? 'BODY' : depth === 1 ? 'HTML' : 'DIV', id: '',
      offsetWidth: 304, offsetHeight: 78, offsetTop: 0, offsetLeft: 0, clientWidth: 304, clientHeight: 78,
      scrollWidth: 304, scrollHeight: 78, scrollTop: 0, scrollLeft: 0,
      style: new Proxy({}, { get: () => '', set: () => true }), currentStyle: null,
      classList: { add() {}, remove() {}, contains: () => false, toggle() {} }, dataset: {},
      getBoundingClientRect: () => ({ x: 0, y: 0, width: 304, height: 78, top: 0, left: 0, right: 304, bottom: 78 }),
      getClientRects: () => [], appendChild: x => x, removeChild: x => x, contains: () => false,
      addEventListener() {}, removeEventListener() {}, getAttribute: () => null, hasAttribute: () => false,
      children: [], childNodes: [], firstChild: null, lastChild: null, nextSibling: null, previousSibling: null }
    n.parentNode = depth >= 4 ? null : null   // set below to chain
    n.offsetParent = null
    return n
  }
  const ANC = ancNode(0); { let cur = ANC; for (let i = 1; i <= 4; i++) { const p = ancNode(i); cur.parentNode = p; cur.offsetParent = i <= 2 ? p : null; cur.ownerDocument = null; cur = p } }
  function makeEl(tag, id) {
    const lis = {}
    const classes = new Set()
    const attrs = {}
    const elLabel = () => '<' + ((tag || 'div') + '').toLowerCase() + (real.id ? '#' + real.id : '') + (classes.size ? '.' + [...classes].join('.') : '') + (attrs.role ? '[role=' + attrs.role + ']' : '') + '>'
    const setClass = v => { classes.clear(); String(v == null ? '' : v).split(/\s+/).filter(Boolean).forEach(c => classes.add(c)); for (const c of classes) idxClass(P, c); if (opts.onClass) opts.onClass(P, classes) }
    function fire(type, ev) { (lis[type] || []).slice().forEach(f => { try { f(ev || { type, target: P, currentTarget: P, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {}, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0 }) } catch {} }) }
    let _src = ''
    const real = { tagName: (tag || 'div').toUpperCase(), id: id || '', nodeType: 1, style: new Proxy({}, { get: () => '', set: () => true }), dataset: {},
      classList: { add: (...c) => { c.forEach(x => { classes.add(x); idxClass(P, x) }); if (opts.onClass) opts.onClass(P, classes) }, remove: (...c) => { c.forEach(x => classes.delete(x)) }, contains: x => classes.has(x), toggle: (x, f) => { const has = classes.has(x); const add = f === undefined ? !has : !!f; if (add) { classes.add(x); idxClass(P, x) } else classes.delete(x); return add }, item: i => [...classes][i] || null, get length() { return classes.size } },
      addEventListener: (t, f) => { (lis[t] = lis[t] || []).push(f); if (process.env.DOMTRACE) log('   [DOM listen]', elLabel(), t); if (opts.onListen) opts.onListen(P, t, real) }, removeEventListener: (t, f) => { if (lis[t]) lis[t] = lis[t].filter(x => x !== f) },
      setAttribute(k, v) { attrs[k] = v; if (k === 'class' || k === 'className') setClass(v); else if (k === 'id') { real.id = String(v); idxId(real.id, P) } else if (k === 'src') { _src = String(v); if (opts.onIframeSrc && /api2\/(anchor|bframe)/.test(_src)) opts.onIframeSrc(_src, P) } if (opts.onSetAttr) opts.onSetAttr(P, k, v) }, getAttribute: k => (k === 'class' ? ([...classes].join(' ') || null) : k === 'id' ? (real.id || null) : (k in attrs ? attrs[k] : null)), hasAttribute: k => (k === 'class' ? classes.size > 0 : k === 'id' ? !!real.id : (k in attrs)), removeAttribute(k) { delete attrs[k]; if (k === 'class') classes.clear() }, appendChild: x => x, removeChild: x => x, insertBefore: x => x, replaceChild: x => x, remove() {}, contains: () => false,
      querySelector: s => (querySel(s) || makeEl('div')), querySelectorAll: s => { const c = String(s).match(/\.([\w-]+)/); const arr = c ? queryClass(c[1]) : []; return arr }, getElementsByTagName: () => [makeEl('div')], getElementsByClassName: s => { const arr = queryClass(s); return arr.length ? arr : [makeEl('div')] },
      getBoundingClientRect: () => ({ x: 0, y: 0, width: 28, height: 28, top: 0, left: 0, right: 28, bottom: 28 }), getClientRects: () => [],
      focus() {}, blur() {}, click() { fire('click') }, cloneNode() { return makeEl(tag, id) },
      getContext: (type) => ((!process.env.NOCANVAS && /canvas/i.test((tag || '').toString())) ? makeCanvasCtx(type) : null),
      toDataURL: () => ((!process.env.NOCANVAS && /canvas/i.test((tag || '').toString())) ? _PNG1x1 : 'data:,'), toBlob: (cb) => { try { cb && cb(null) } catch {} },
      setPointerCapture() {}, releasePointerCapture() {},
      children: [], childNodes: [], firstChild: null, lastChild: null, parentNode: ANC, offsetParent: ANC, nextSibling: null, previousSibling: null, ownerDocument: null, hasChildNodes: () => false,
      innerHTML: '', outerHTML: '', textContent: '', value: '', checked: false, disabled: false, offsetWidth: 28, offsetHeight: 28,
      offsetTop: 0, offsetLeft: 0, clientWidth: 28, clientHeight: 28, scrollWidth: 28, scrollHeight: 28, scrollTop: 0, scrollLeft: 0, currentStyle: null,
      dispatchEvent(ev) { fire(ev && ev.type, ev); return true }, _lis: lis, _fire: fire, _classes: classes, _attrs: attrs, _label: elLabel }
    Object.defineProperty(real, 'src', { get() { return _src }, set(v) { real.setAttribute('src', v) }, configurable: true })
    // <iframe> contentWindow: the cross-frame channel iframe (src=anchor/bframe) must expose the
    // real cross-realm bridge (the establish validates source===iframe.contentWindow). BUT the
    // bundle ALSO creates a blank <iframe> (no src) for a clean-JSON parser (it deletes
    // Array/Object.prototype.toJSON then uses iframe.contentWindow.JSON to safely (de)serialize);
    // that one needs a working JSON or the inbound proto/JSON decode crashes with undefined.parse.
    if ((tag || '').toLowerCase() === 'iframe') {
      let _jcw = null
      Object.defineProperty(real, 'contentWindow', { configurable: true, get() {
        if (opts.iframeContentWindow && _src && /api2\/(anchor|bframe)/.test(_src)) {
          return (typeof opts.iframeContentWindow === 'function') ? opts.iframeContentWindow(_src, P) : opts.iframeContentWindow
        }
        if (!_jcw) _jcw = { JSON: JSON, Array: Array, Object: Object, postMessage() {}, addEventListener() {}, removeEventListener() {}, location: { href: 'about:blank', origin: 'null' }, document: { createElement: () => makeEl('div') } }
        return _jcw
      } })
      Object.defineProperty(real, 'contentDocument', { get: () => ({ createElement: () => makeEl('div'), documentElement: makeEl('html'), body: makeEl('body') }), configurable: true })
    }
    const P = new Proxy(real, { get(t, k) { if (k in t) return t[k]; if (typeof k === 'string' && /^on/.test(k)) return t['__' + k] || null; return noop() }, set(t, k, v) {
      if (k === 'className') { t.className = v; setClass(v); return true }
      if (k === 'id') { t.id = String(v); idxId(t.id, P); return true }
      if (k === 'innerHTML') {
        t.innerHTML = v
        if (process.env.DOMTRACE && /checkbox|rc-anchor/.test(String(v))) { log('   [DOM innerHTML]', elLabel(), String(v).length + 'B :', String(v).slice(0, 120).replace(/\s+/g, ' ')); if (process.env.DOMDUMP) try { fs.appendFileSync(process.env.DOMDUMP, '\n===innerHTML on ' + elLabel() + '===\n' + String(v) + '\n') } catch {} }
        if (!process.env.NODOMPARSE && /<[a-zA-Z]/.test(String(v))) { try { const roots = parseHTML(String(v)); t.children = roots; t.childNodes = roots.slice(); t.firstChild = roots[0] || null; t.lastChild = roots[roots.length - 1] || null; for (const r of roots) { r.parentNode = P; r.offsetParent = P } } catch (e) { if (process.env.DOMTRACE) log('   [DOM parse err]', e && e.message) } }
        if (opts.onInnerHTML) try { opts.onInnerHTML(P, v) } catch {}
        return true
      }
      t[k] = v; return true
    }, has() { return true } })
    real._el = P
    ALL_ELS.push(real); return P
  }
  // optional g-recaptcha container (parent realm) with a working data-sitekey
  let container = null
  if (opts.container) {
    container = makeEl('div', opts.container.id || 'cap')
    container.className = 'g-recaptcha'; container.dataset.sitekey = SITEKEY
    container.getAttribute = k => (k === 'data-sitekey' ? SITEKEY : (k === 'data-size' ? 'normal' : null))
    container.hasChildNodes = () => false
  }
  const document = new Proxy({
    createElement: t => makeEl(t), createElementNS: (ns, t) => makeEl(t), createDocumentFragment: () => makeEl('fragment'), createTextNode: () => makeEl('text'), createComment: () => makeEl('comment'), createEvent: () => ({ initEvent() {}, initCustomEvent() {} }),
    getElementById: id => { if (process.env.DOMTRACE) log('   [DOM getElementById]', JSON.stringify(id)); const e = queryId(id); if (e) return e; return (container && id === container.id ? container : (ELS[id] = ELS[id] || makeEl('div', id))) },
    querySelector: s => { if (process.env.DOMTRACE) log('   [DOM querySelector]', JSON.stringify(s)); const e = querySel(s); if (e) return e; return (container && /g-recaptcha/.test(s) ? container : (ELS['q:' + s] = ELS['q:' + s] || makeEl('div', 'q:' + s))) },
    querySelectorAll: s => { if (process.env.DOMTRACE) log('   [DOM querySelectorAll]', JSON.stringify(s)); const c = String(s).match(/\.([\w-]+)/); const arr = c ? queryClass(c[1]) : []; if (arr.length) return arr; return (container && /g-recaptcha/.test(s) ? [container] : []) },
    getElementsByTagName: () => [], getElementsByClassName: s => { if (process.env.DOMTRACE) log('   [DOM getElementsByClassName]', JSON.stringify(s)); const arr = queryClass(s); if (arr.length) return arr; return (container && /g-recaptcha/.test(s) ? [container] : []) }, getElementsByName: () => [],
    documentElement: makeEl('html'), head: makeEl('head'), body: makeEl('body'), cookie: '', referrer: HOST_ORIGIN + '/',
    // capture document-level listeners (reCAPTCHA often delegates the checkbox click to document)
    addEventListener(t, f) { (docLis[t] = docLis[t] || []).push(f) }, removeEventListener(t, f) { if (docLis[t]) docLis[t] = docLis[t].filter(x => x !== f) },
    dispatchEvent: () => true, readyState: 'complete', visibilityState: 'visible', hidden: false, currentScript: null, scripts: [], title: '', defaultView: null, characterSet: 'UTF-8', compatMode: 'CSS1Compat',
  }, { get(t, k) { if (k in t) return t[k]; return noop() }, has() { return true } })
  const docLis = {}
  function fireDoc(type, target) { (docLis[type] || []).slice().forEach(f => { try { f({ type, target: target || container, currentTarget: document, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0, which: 1, key: type === 'keydown' ? ' ' : undefined, keyCode: type === 'keydown' ? 32 : undefined, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {} }) } catch {} }) }
  return { document, makeEl, container, docLis, fireDoc }
}

// FakeWorker: spawns the BotGuard worker realm in-process over the by-ref loopback (anchor only).
function makeFakeWorker(holder, onAE) {
  return function FakeWorker(url) {
    log('  [anchor] new Worker(', String(url).slice(0, 64), ')')
    const self_ = this; self_._lis = []; self_._on = null
    const wmsgListeners = [], toPageQ = []
    function flush() { if (!(self_._on || self_._lis.length)) return; while (toPageQ.length) { const ev = toPageQ.shift(); if (self_._on) try { self_._on(ev) } catch {} for (const f of self_._lis) try { f(ev) } catch {} } }
    holder.workerRealm = buildRealm('worker', {
      __cap: {}, performance: makePerf(),
      __dispHook: (K, d) => { try { log('  [W-disp] K=' + JSON.stringify(String(K)) + ' inMap=' + (d && d.P && (d.P._inner && d.P._inner.has ? d.P._inner.has(K) : (d.P.has ? d.P.has(K) : '?')))) } catch {} },
      __msgHook: (mt, msg) => { try { log('  [W-msg] mt=' + JSON.stringify(String(mt)) + ' ' + (() => { try { return JSON.stringify(msg).slice(0, 60) } catch { return (msg && msg.constructor && msg.constructor.name) || typeof msg } })()) } catch {} },
      __ksHook: (b, n) => { if (n === 0) log('  [W-ks] XOR codec ran (frame de/encode start)'); return b },
      ...(typeof onAE === 'function' ? { __onAE: onAE } : {}),
      XMLHttpRequest: function () { return { open() {}, send() {}, setRequestHeader() {}, addEventListener() {}, getAllResponseHeaders: () => '', abort() {} } },
      postMessage: (m, transfer) => { if (process.env.WLOG) { const sz = (typeof m === 'string' ? m.length : (m && m.byteLength) || (Array.isArray(m) ? JSON.stringify(m).length : '?')); log('  [W->page]', 'sz=' + sz, typeof m === 'string' ? m.slice(0, 30) : desc(m)) } toPageQ.push({ data: m, ports: Array.isArray(transfer) ? transfer.filter(x => x && x.__isPort) : [] }); flush() },
      addEventListener: (t, f) => { if (t === 'message') wmsgListeners.push(f) },
    })
    function toWorker(ev) { const ws = holder.workerRealm.sandbox; if (ws.onmessage) try { ws.onmessage(ev) } catch {} for (const f of wmsgListeners) try { f(ev) } catch {} }
    self_.postMessage = (m, t) => { if (process.env.WLOG) { const sz = (typeof m === 'string' ? m.length : (m && m.byteLength) || (Array.isArray(m) ? JSON.stringify(m).length : '?')); log('  [page->W]', 'sz=' + sz, typeof m === 'string' ? m.slice(0, 30) : desc(m)) } toWorker({ data: m, ports: (t || []).filter(x => x && x.__isPort) }) }
    self_.addEventListener = (t, f) => { if (t === 'message') { self_._lis.push(f); flush() } }
    self_.removeEventListener = (t, f) => { self_._lis = self_._lis.filter(x => x !== f) }
    self_.terminate = () => {}
    Object.defineProperty(self_, 'onmessage', { get() { return self_._on }, set(f) { self_._on = f; flush() } })
  }
}

// ----------------------------------------------------------------------------
// 4) THE CROSS-REALM BRIDGE. Each realm gets its own window 'message' bus. We relay messages
//    between them preserving the EXACT source/origin identities the intakes hard-check:
//      anchor -> parent : source = iframe.contentWindow (cwBridge), origin = ANCHOR_ORIGIN
//      parent -> anchor : source = window.parent (anchor global), origin = HOST_ORIGIN
//    MessagePorts are by-ref loopback objects (page.js makePort), so a transferred port works
//    in BOTH realms with no copy — the adopting realm binds its AE straight to the object.
// ----------------------------------------------------------------------------
function mkBus(name) {
  const L = []
  return { name, add: (t, f) => { if (t === 'message') L.push(f) }, remove: (t, f) => { const i = L.indexOf(f); if (i >= 0) L.splice(i, 1) },
    deliver(ev) { for (const f of L.slice()) { try { f(ev) } catch (e) { if (TRACE) log('   [' + name + ' listener threw]', e.message) } } }, count: () => L.length }
}
function desc(d) { try { return typeof d === 'string' ? 'str:' + d.slice(0, 24) : Array.isArray(d) ? 'arr[' + d.length + ']' + (typeof d[1] === 'string' ? '(' + d[1] + ')' : '') : (d && d.constructor && d.constructor.name || typeof d) } catch { return '?' } }

const parentBus = mkBus('parent'), anchorBus = mkBus('anchor'), bframeBus = mkBus('bframe')
const REFS = { anchorWin: null, bframeWin: null, parentWin: null } // realm globals (set after each boot)
const PARENT_SELF_POSTS = []           // diagnostic: parent self.postMessage(data,[ports])
const PARENT_SELF_DELIVER = !!process.env.SELF_DELIVER  // deliver parent self-posts to parentBus
// PTRACK: tracked Promise subclass to catch never-settling promises (the o-handler hang) + stack.
const PENDING_PROMISES = []
function makeTrackedPromise() {
  return class TP extends Promise {
    constructor(exec) {
      const rec = { settled: false, stack: null }
      let capture = false
      super((res, rej) => {
        // only executors with 2 args that are real (heuristic: capture stack lazily)
        exec(v => { rec.settled = true; res(v) }, e => { rec.settled = true; rej(e) })
      })
      try { rec.stack = new Error().stack } catch {}
      PENDING_PROMISES.push(rec)
    }
  }
}
let anchorBusReady = false; const cwQueue = []   // queue parent->anchor posts made before anchor boots
const TAPPED = new Set()
const port8In = [], port8Out = []   // raw wire strings seen on the adopted parent port (id 8)
function tapPort(port, label) {
  if (!port || !port.__isPort || TAPPED.has(port)) return port
  TAPPED.add(port)
  try {
    port.addEventListener('message', ev => { const d = ev && ev.data; if (port.__id === 8 && typeof d === 'string') port8In.push(d); log('   [TAP ' + label + ' IN  port' + port.__id + ']', 'len=' + (typeof d === 'string' ? d.length : '?'), typeof d === 'string' ? d.slice(0, 34) : desc(d)) })
    const orig = port.postMessage.bind(port)
    port.postMessage = (data, transfer) => { if (port.__id === 8 && typeof data === 'string') port8Out.push(data); log('   [TAP ' + label + ' OUT port' + port.__id + ']', 'len=' + (typeof data === 'string' ? data.length : '?'), typeof data === 'string' ? data.slice(0, 34) : desc(data)); return orig(data, transfer) }
  } catch (e) { if (TRACE) log('   [tap failed]', e.message) }
  return port
}

// object the PARENT holds as the anchor iframe's contentWindow (its handle to the anchor window)
const cwBridge = {
  __isWindow: true, postMessage(data, targetOrigin, transfer) {
    const ports = (transfer || []).filter(x => x && x.__isPort)
    ports.forEach(p => tapPort(p, 'p->a'))
    const ev = { data, origin: HOST_ORIGIN, source: REFS.anchorWin, ports, type: 'message', preventDefault() {}, stopPropagation() {} }
    if (TRACE) log('   [parent->anchor]', desc(data), 'ports=' + ports.length)
    if (anchorBusReady) anchorBus.deliver(ev); else cwQueue.push(ev)
  }
}
// object the ANCHOR holds as window.parent (its handle to the host window). Posting on it lands
// in the parent realm's intake with source = iframe.contentWindow = cwBridge.
const parentWinHandle = {
  __isWindow: true, postMessage(data, targetOrigin, transfer) {
    const ports = (transfer || []).filter(x => x && x.__isPort)
    ports.forEach(p => tapPort(p, 'a->p'))
    if (TRACE) log('   [anchor->parent]', desc(data), 'to=' + targetOrigin, 'ports=' + ports.length)
    parentBus.deliver({ data, origin: ANCHOR_ORIGIN, source: cwBridge, ports, type: 'message', preventDefault() {}, stopPropagation() {} })
  }
}

// ---- BFRAME relays: the parent (api.js) is ALSO the bframe's parent; the anchor is its sibling.
// Mirror the anchor's two handles + add the sibling channel the bframe opens via parent.frames[N].
let bframeBusReady = false; const bframeQueue = []
// parent's handle to the bframe iframe contentWindow (parent api.js -> bframe posts land on bframeBus)
const bframeCwBridge = {
  __isWindow: true, postMessage(data, targetOrigin, transfer) {
    const ports = (transfer || []).filter(x => x && x.__isPort); ports.forEach(p => tapPort(p, 'p->b'))
    const ev = { data, origin: HOST_ORIGIN, source: REFS.bframeWin, ports, type: 'message', preventDefault() {}, stopPropagation() {} }
    if (TRACE) log('   [parent->bframe]', desc(data), 'ports=' + ports.length)
    if (bframeBusReady) bframeBus.deliver(ev); else bframeQueue.push(ev)
  }
}
// bframe.window.parent: bframe -> parent posts land in the PARENT intake, source = bframe iframe cw
const bframeParentWinHandle = {
  __isWindow: true, postMessage(data, targetOrigin, transfer) {
    const ports = (transfer || []).filter(x => x && x.__isPort); ports.forEach(p => tapPort(p, 'b->p'))
    if (TRACE) log('   [bframe->parent]', desc(data), 'to=' + targetOrigin, 'ports=' + ports.length)
    parentBus.deliver({ data, origin: ANCHOR_ORIGIN, source: bframeCwBridge, ports, type: 'message', preventDefault() {}, stopPropagation() {} })
  }
}
// bframe.parent.frames[<anchor name>]: the sibling channel; bframe -> anchor posts land on anchorBus
const bframeSiblingAnchorHandle = {
  __isWindow: true, addEventListener() {}, removeEventListener() {}, focus() {}, blur() {}, closed: false, location: { origin: ANCHOR_ORIGIN },
  postMessage(data, targetOrigin, transfer) {
    const ports = (transfer || []).filter(x => x && x.__isPort); ports.forEach(p => tapPort(p, 'b->a'))
    const toParent = !!process.env.SIBLING_TO_PARENT
    log('   [bframe->' + (toParent ? 'PARENT(via frames)' : 'anchor sibling') + ']', desc(data), 'ports=' + ports.length, '| anchorL=' + anchorBus.count() + ' parentL=' + parentBus.count())
    const bus = toParent ? parentBus : anchorBus
    bus.deliver({ data, origin: ANCHOR_ORIGIN, source: bframeCwBridge, ports, type: 'message', preventDefault() {}, stopPropagation() {} })
  }
}
bframeParentWinHandle.frames = new Proxy({ length: 2 }, { get(t, k) { if (k === 'length') return 2; if (typeof k === 'symbol') return t[k]; return bframeSiblingAnchorHandle }, has: () => true })
bframeParentWinHandle.length = 2
function flushBframeQueue() { bframeBusReady = true; const q = bframeQueue.splice(0); for (const ev of q) bframeBus.deliver(ev) }

// The ANCHOR's window.parent handle. In the top<->anchor<->bframe chain the anchor is the relay:
// parent.postMessage -> the parent(api.js) realm, AND parent.frames[<bframeName>] -> the BFRAME
// window (so the anchor can reference/validate the sibling bframe whose recaptcha-setup it adopts;
// the bframe's inbound setup arrives with source = bframeCwBridge, so frames[N] must be that same
// object for any `ev.source === parent.frames[N]` check to pass).
const anchorParentRef = {
  __isWindow: true,
  postMessage: (data, targetOrigin, transfer) => parentWinHandle.postMessage(data, targetOrigin, transfer),
  addEventListener() {}, removeEventListener() {}, focus() {}, blur() {}, closed: false, location: { origin: HOST_ORIGIN },
}
anchorParentRef.frames = new Proxy({ length: 2 }, { get(t, k) { if (k === 'length') return 2; if (typeof k === 'symbol') return t[k]; return bframeCwBridge }, has: () => true })
anchorParentRef.length = 2

// ----------------------------------------------------------------------------
// 5) Build the PARENT (api.js/host) realm: seed exactly like api.js, auto-render makes the
//    anchor iframe (we capture its src + bind contentWindow=cwBridge) and the parent intake.
// ----------------------------------------------------------------------------
function buildParentRealm() {
  const ALL_ELS = []
  const parentAEs = []
  const parentWorkerHolder = { workerRealm: null }
  let capturedAnchorSrc = null, capturedBframeSrc = null
  const dom = makeDocument(ALL_ELS, {
    container: { id: 'cap' },
    // anchor iframe -> cwBridge (relays to the anchor realm); bframe iframe -> bframeCwBridge
    // (relays to the bframe realm). Src-aware so the parent's api.js talks to the RIGHT child.
    iframeContentWindow: (src) => (/api2\/bframe/.test(src) ? bframeCwBridge : cwBridge),
    onIframeSrc: (src, el) => {
      if (/api2\/anchor/.test(src) && !capturedAnchorSrc) { capturedAnchorSrc = src; log('  [parent] anchor iframe src captured') }
      if (/api2\/bframe/.test(src)) {
        const bftM = src.match(/[?&]bft=([^&]+)/)
        if (!capturedBframeSrc) log('  [parent] *** bframe iframe src captured (interactive reached) ***')
        log('  [parent] bframe src set:', src, bftM ? '<< HAS bft' : '(no bft)')
        capturedBframeSrc = src; try { parent.bframeSrc = src } catch {}
        if (bftM) {
          try {
            fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/headless_bft.json',
              JSON.stringify({ bframeUrl: src, bft: decodeURIComponent(bftM[1]), sitekey: SITEKEY, ver: VER, host: HOST_ORIGIN, ts: Date.now() }, null, 1))
            log('  [parent] >>> BFT=' + decodeURIComponent(bftM[1]))
            log('  [parent] >>> wrote headless_bft.json')
            if (typeof resolveBftReady === 'function') resolveBftReady(src)
            // BOOT the bframe realm (once) so the parent's api.js drives it: config -> 336KB
            // bgprogram -> post-click activate -> the bframe fires POST /reload with field16.
            if (!BFRAME_BOOTED && !process.env.NOBFRAME) { BFRAME_BOOTED = true; const bel = el; setImmediate(() => { bootBframeRealm(src, bel).catch(e => log('  [bframe boot err]', e && e.message)) }) }
          } catch (e) { log('  [parent] bft write err', e.message) }
        }
      }
    },
  })
  const extra = {
    __cap: {},
    __onAE: (ae) => { try {
      // log the AE's REAL handler opcodes BEFORE the catch-all swaps ae.P (Agent E: the top<->anchor
      // program-generator AE has opcodes [D,E]; D=Qr generates the ~288KB bgprogram, E=ak).
      try { const ks = ae && ae.P && typeof ae.P.forEach === 'function' ? [] : null; if (ks) { ae.P.forEach((_v, k) => ks.push(String(k))); log('  [parent AE#' + (parentAEs.length + 1) + '] handler opcodes = [' + ks.join(',') + ']' + (ks.includes('D') ? '  <<< [D,E] PROGRAM-GENERATOR AE' : '')) } } catch (e) {}
      parentAEs.push(ae); if (!process.env.NOCATCHALL) PR.installOn(ae, { log: (...a) => { if (TRACE) log('  [parent-rpc]', ...a) } })
      // wrap the handler-map get() so we SEE whether dispatch decoded a frame and which opcode it
      // resolved (proves decode success/failure and whether the real handler ran).
      if (ae.P && typeof ae.P.get === 'function' && !ae.P.__wrappedGet) {
        const g = ae.P.get.bind(ae.P); ae.P.__wrappedGet = true
        ae.P.get = (K) => { const h = g(K); log('  [parent dispatch] opcode=' + JSON.stringify(String(K)) + ' -> ' + (h ? 'handler' : 'none'))
          if (typeof h !== 'function') return h
          return function (...args) {
            if (process.env.INSPECT) { try { const pay = args[0]; const fields = pay && typeof pay === 'object' ? Object.keys(pay).slice(0, 20) : typeof pay; log('  [INSPECT ' + String(K) + '] payload keys=' + JSON.stringify(fields) + ' | this keys=' + (this && typeof this === 'object' ? JSON.stringify(Object.keys(this).slice(0, 24)) : typeof this)); for (const fk of ['L', 'D', 'j_', 'Oo']) { try { const v = pay && pay[fk]; if (v !== undefined) log('      payload.' + fk + ' = ' + (Array.isArray(v) ? 'Array(' + v.length + ') ' + JSON.stringify(v).slice(0, 80) : JSON.stringify(v).slice(0, 80))) } catch {} } } catch (e) {} }
            try { const r = h.apply(this, args); if (process.env.INSPECT) { try { log('  [INSPECT ' + String(K) + '] returned ' + (r && typeof r.then === 'function' ? 'Promise(pending)' : desc(r)) + ' | this.Y=' + (this && this.Y ? (typeof this.Y.then === 'function' ? 'Promise' : desc(this.Y)) : this && ('Y' in this) ? 'null/absent' : 'no-this')) } catch {} } Promise.resolve(r).then(v => log('  [parent handler ' + String(K) + '] resolved ' + desc(v)), e => log('  [parent handler ' + String(K) + '] REJECTED ' + (e && e.message))); return r } catch (e) { log('  [parent handler ' + String(K) + '] THREW ' + e.message); throw e } }
        }
      }
    } catch (e) { if (TRACE) log('  [parent __onAE]', e.message) } return ae },  // capture + merge-preserving catch-all
    Worker: process.env.PWORKER ? makeFakeWorker(parentWorkerHolder) : function () { this.postMessage = () => {}; this.addEventListener = () => {}; this.removeEventListener = () => {}; this.terminate = () => {}; Object.defineProperty(this, 'onmessage', { set() {}, get() { return null } }) },
    document: dom.document,
    addEventListener: parentBus.add, removeEventListener: parentBus.remove,
    postMessage: (data, targetOrigin, transfer) => { const ports = (transfer || []).filter(x => x && x.__isPort); PARENT_SELF_POSTS.push({ data: (typeof data === 'string' ? data : desc(data)), ports: ports.map(p => p.__id), origin: targetOrigin }); if (TRACE) log('  [parent SELF-POST]', (typeof data === 'string' ? 'str:' + data : desc(data)), 'ports=[' + ports.map(p => p.__id).join(',') + '] to=' + targetOrigin); if (PARENT_SELF_DELIVER) { const ev = { data, origin: HOST_ORIGIN, source: REFS.parentWin || null, ports, type: 'message', preventDefault() {}, stopPropagation() {} }; parentBus.deliver(ev) } },
    performance: makePerf(),
    location: { href: HOST_ORIGIN + '/', origin: HOST_ORIGIN, protocol: 'https:', host: ORIGIN_HOST, hostname: ORIGIN_HOST, pathname: '/', search: '', hash: '', replace() {}, assign() {}, reload() {} },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 1280, innerHeight: 800, outerWidth: 1280, outerHeight: 880, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    // EXACT api.js loader seeds (verified to attach grecaptcha.render + auto-render the iframe):
    __recaptcha_api: 'https://www.google.com/recaptcha/api2/', __google_recaptcha_client: true,
    ...(process.env.PTRACK ? { Promise: makeTrackedPromise() } : {}),
    ___grecaptcha_cfg: { fns: [], render: ['onload'], 'anchor-ms': [20000], 'execute-ms': [30000] },
    // capture parent channel keys; if INJECT, reuse the anchor's latest channel key so both
    // realms share it (the anchor imports its key first, during its setup, before the parent).
    __keyHook: (cy) => { try { PARENT_KEYS.push(Buffer.from(Array.from(cy))) } catch {} if (INJECT && ANCHOR_KEYS.length) { try { return new Uint8Array(ANCHOR_KEYS[ANCHOR_KEYS.length - 1]) } catch {} } return cy },
    __ksHook: mkKsHook(PARENT_KS), __msgHook: mkMsgHook(PARENT_MSGS),
    __dispHook: (K, d) => { try { const k = String(K); PARENT_DISP.push(k); const inMap = d && d.P && d.P._inner && d.P._inner.has ? d.P._inner.has(K) : (d && d.P && d.P.has ? d.P.has(K) : '?'); if (TRACE) log('  [disp] K=' + JSON.stringify(k) + ' inRealMap=' + inMap) } catch (e) {} },
    // when the proto/format parser is undefined (r=0), the call site is JSON deserialization
    // (line 695 deletes toJSON then w(K.JSON)); so parse d as JSON.
    __pFB: (r, d) => { try { return JSON.parse(d) } catch (e) { return d } },
    __pHook: (f, d, r) => { try { const rec = { fType: typeof f, fDef: f != null, rType: typeof r, rCtor: r && r.constructor && r.constructor.name, rKeys: r && typeof r === 'object' ? Object.keys(r).slice(0, 10) : String(r).slice(0, 30), dType: typeof d, dLen: d && d.length }; if (f == null) rec.stack = (new Error().stack || '').split('\n').slice(2, 9).map(s => s.trim().replace(/.*recaptcha__en[^:]*/, 'en')).join(' <- '); PARENT_PARSE.push(rec) } catch (e) {} },
    __ceHook: (ce) => { try { const sz = (ce && ce.length != null) ? ce.length : (typeof ce === 'string' ? ce.length : '?'); log('  [parent] *** GR/CE ran in TOP realm: aq.Z().get().CE() size = ' + sz + ' ***') } catch (e) {} return ce },
  }
  extra.grecaptcha = { ready: function (f) { extra.___grecaptcha_cfg.fns.push(f) } }
  const realm = buildRealm('parent', extra, { pageWindow: true })
  return { realm, ALL_ELS, parentAEs, get anchorSrc() { return capturedAnchorSrc }, get bframeSrc() { return capturedBframeSrc }, extra }
}

// ----------------------------------------------------------------------------
// 6) Build the ANCHOR realm pointed at the captured /anchor src. pageWindow:true so
//    window.parent === self; we override `postMessage` (the unshadowed sandbox prop) so the
//    anchor's window.parent.postMessage forwards to the PARENT realm via parentWinHandle.
// ----------------------------------------------------------------------------
function buildAnchorRealm(anchorSrc) {
  const ALL_ELS = []
  const holder = { workerRealm: null }
  const dom = makeDocument(ALL_ELS, {})    // anchor has no g-recaptcha container; it IS the iframe
  const u = new URL(anchorSrc)
  const extra = {
    __cap: {},
    __onAE: (ae => { const base = PR.makeOnAE({ getPort: () => null, log: (...a) => { if (TRACE) log('  [anchor-rpc]', ...a) } }); return a => { try { ANCHOR_CLIENT_AES.push(a) } catch {} return base(a) } })(),
    Worker: makeFakeWorker(holder, (ae) => { try { ANCHOR_WORKER_AES.push(ae) } catch {} return ae }),
    document: dom.document,
    addEventListener: anchorBus.add, removeEventListener: anchorBus.remove,
    // window.parent.postMessage (== self.postMessage in pageWindow mode) -> forward to parent realm
    postMessage: (data, targetOrigin, transfer) => parentWinHandle.postMessage(data, targetOrigin, transfer),
    performance: makePerf(),
    XMLHttpRequest: makeDriverXHR(),
    location: { href: anchorSrc, origin: ANCHOR_ORIGIN, protocol: 'https:', host: u.host, hostname: u.hostname, pathname: u.pathname, search: u.search, hash: '', replace() {}, assign() {}, reload() {} },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 400, innerHeight: 580, outerWidth: 400, outerHeight: 580, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), frameElement: dom.makeEl('iframe'), scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
    // capture this anchor realm's channel AES key(s) so the parent can share/inject them.
    __keyHook: (cy) => { try { ANCHOR_KEYS.push(Buffer.from(Array.from(cy))) } catch {} return cy },
    __ksHook: mkKsHook(ANCHOR_KS), __msgHook: mkMsgHook(ANCHOR_MSGS),
    __pHook: (f, d, r) => { try { ANCHOR_PARSE.push({ fDef: f != null, fCtor: f && f.constructor && f.constructor.name, rType: typeof r, r: typeof r === 'number' ? r : (r && r.constructor && r.constructor.name), dLen: d && d.length }) } catch (e) {} },
    __ceHook: (ce) => { try { let sz = '?'; try { sz = (ce && ce.length != null) ? ce.length : (ce && ce.byteLength != null ? ce.byteLength : (typeof ce === 'string' ? ce.length : JSON.stringify(ce).length)) } catch { sz = 'n/a' } log('  [anchor] *** GR ran: aq.Z().get().CE() bgprogram size = ' + sz + ' (type ' + (ce && ce.constructor && ce.constructor.name || typeof ce) + ') ***') } catch (e) {} return ce },
    // window.botguard intentionally UNDEFINED -> anchor verify takes the worker-attestation path.
  }
  // parentRef makes anchor.parent a DISTINCT window (the real anchor IS framed) exposing
  // parent.frames[bframeName] -> the bframe window, so the anchor can adopt/relay to the bframe.
  // Gated: ANCHOR_TOPLEVEL=1 reverts to the old parent===self behaviour for A/B comparison.
  const aOpts = process.env.ANCHOR_TOPLEVEL ? { pageWindow: true } : { pageWindow: true, parentRef: anchorParentRef }
  const realm = buildRealm('anchor', extra, aOpts)
  REFS.anchorWin = realm.ctx                  // parent->anchor messages carry source = this (== window.parent)
  anchorBusReady = true                       // flush any parent->anchor posts queued during render
  while (cwQueue.length) anchorBus.deliver(cwQueue.shift())
  return { realm, ALL_ELS, holder, dom }
}

// ----------------------------------------------------------------------------
// 6b) Build the BFRAME (challenge iframe) realm. Its window.parent === the PARENT api.js realm
//     (via parentRef=bframeParentWinHandle), so the parent drives it: config -> 336KB bgprogram
//     -> post-click activate -> the bframe runs the program + fires POST /reload with field16
//     (reload_net.json protocol). pageWindow:true (window===self) but parent is a DISTINCT window.
// ----------------------------------------------------------------------------
async function bootBframeRealm(bframeSrc, iframeEl) {
  log('  [bframe] booting BFRAME realm for', bframeSrc.slice(0, 70) + '...')
  let bhtml
  try { const r = await fetch(bframeSrc, { headers: { 'User-Agent': UA, 'Referer': bframeSrc, 'Cookie': COOKIE || '' } }); mergeSetCookie(r.headers); bhtml = await r.text() }
  catch (e) { log('  [bframe] bframe HTML fetch failed:', e.message); return null }
  const binit = extractInitCall(bhtml, 'recaptcha.frame.Main.init(')
  if (!binit) { log('  [bframe] NO recaptcha.frame.Main.init literal in bframe HTML (', bhtml.length, 'B) — abort bframe'); return null }
  log('  [bframe] frame.Main.init literal:', binit.length, 'chars')
  const ALL_ELS = []
  const bframeWorkerHolder = { workerRealm: null }
  const dom = makeDocument(ALL_ELS, {})
  const u = new URL(bframeSrc)
  const bframeOnAE = PR.makeOnAE({ getPort: () => null, log: (...a) => { if (TRACE) log('  [bframe-rpc]', ...a) } })
  const extra = {
    __cap: {},
    __onAE: (ae) => {
      BFRAME_AES.push(ae)
      try { const ks = []; if (ae && ae.P && typeof ae.P.forEach === 'function') { ae.P.forEach((_v, k) => ks.push(String(k))); log('  [bframe AE] handler opcodes = [' + ks.join(',') + ']') } } catch {}
      // AKRUN: wrap the Lq BotGuard client (ae.C has vy/Dw) so we see whether vy(program) — the live
      // ak execution that produces field16 — is ever invoked (during "t"), + capture its result.
      if (process.env.AKRUN) { try { const C = ae.C; if (C && typeof C.vy === 'function' && typeof C.Dw === 'function' && !C.__akw) { C.__akw = true
        const ovy = C.vy.bind(C), oDw = C.Dw.bind(C)
        C.vy = function (prog, t) { const pl = prog && (prog.length || prog.byteLength || (prog.D && prog.D.length)) || '?'; log('[emp][AKRUN] Lq.vy(program~' + pl + 'B, t=' + t + ') CALLED — running ak'); const rr = ovy(prog, t); Promise.resolve(rr).then(v => { let rl = 0; try { const rq = v && (v.request || v.D); rl = rq ? (rq.length || rq.byteLength || String(rq).length) : 0 } catch {} log('[emp][AKRUN] Lq.vy resolved: attestation len=' + rl) }, e => log('[emp][AKRUN] Lq.vy REJECTED ' + (e && e.message))); return rr }
        C.Dw = function () { const rr = oDw(); Promise.resolve(rr).then(v => { let rl = 0, md5 = 'empty'; try { const rq = v && (v.request != null ? v.request : v.D); const b = rq ? (Buffer.isBuffer(rq) ? rq : Buffer.from(String(rq), 'latin1')) : null; rl = b ? b.length : 0; md5 = b && b.length ? crypto.createHash('md5').update(b).digest('hex').slice(0, 8) : 'empty' } catch {} log('[emp][AKRUN] Lq.Dw() -> bgRequest len=' + rl + ' md5=' + md5) }, () => {}); return rr }
        log('[emp][AKRUN] wrapped Lq (vy/Dw) on bframe [D,E] AE context') } } catch (e) { log('[emp][AKRUN] wrap err ' + (e && e.message)) } }
      const r = bframeOnAE(ae)
      // wrap dispatch to see which opcodes the bframe processes + whether any handler hangs
      if (ae.P && typeof ae.P.get === 'function' && !ae.P.__wg) { const g = ae.P.get.bind(ae.P); ae.P.__wg = true
        ae.P.get = (K) => { const h = g(K); if (typeof h !== 'function') return h
          return function (...args) { if (TRACE) log('  [bframe dispatch] opcode=' + JSON.stringify(String(K))); try { const rr = h.apply(this, args); Promise.resolve(rr).then(v => log('  [bframe handler ' + String(K) + '] resolved ' + desc(v)), e => log('  [bframe handler ' + String(K) + '] REJECTED ' + (e && e.message))); return rr } catch (e) { log('  [bframe handler ' + String(K) + '] THREW ' + e.message); throw e } } } }
      return r
    },
    // REAL worker: the bframe must run the ~336KB program in its BotGuard worker (Qr load -> ak run)
    // to produce field16 for POST /reload. A no-op Worker leaves the program un-executed.
    Worker: makeFakeWorker(bframeWorkerHolder),
    document: dom.document,
    addEventListener: bframeBus.add, removeEventListener: bframeBus.remove,
    // self.postMessage (posting to own window) -> deliver on the bframe bus (source = self)
    postMessage: (data, targetOrigin, transfer) => { const ports = (transfer || []).filter(x => x && x.__isPort); bframeBus.deliver({ data, origin: HOST_ORIGIN, source: REFS.bframeWin, ports, type: 'message', preventDefault() {}, stopPropagation() {} }) },
    performance: makePerf(),
    XMLHttpRequest: makeDriverXHR({ tag: 'bframe', referer: bframeSrc }),
    location: { href: bframeSrc, origin: ANCHOR_ORIGIN, protocol: 'https:', host: u.host, hostname: u.hostname, pathname: u.pathname, search: u.search, hash: '', replace() {}, assign() {}, reload() {} },
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    history: { length: 1, pushState() {}, replaceState() {}, back() {}, forward() {} },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {}, clear() {} },
    devicePixelRatio: 1, innerWidth: 400, innerHeight: 580, outerWidth: 400, outerHeight: 580, name: '', closed: false,
    matchMedia: () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} }),
    getComputedStyle: () => noop(), frameElement: dom.makeEl('iframe'), scrollTo() {}, focus() {}, blur() {},
    Image: function () { return noop() }, MutationObserver: function () { return { observe() {}, disconnect() {}, takeRecords: () => [] } }, IntersectionObserver: function () { return { observe() {}, disconnect() {} } }, ResizeObserver: function () { return { observe() {}, disconnect() {} } },
    ___grecaptcha_cfg: { clients: {}, count: 0, fns: [] },
    __keyHook: (cy) => { try { ANCHOR_KEYS.push(Buffer.from(Array.from(cy))) } catch {} return cy },
    __ksHook: mkKsHook(ANCHOR_KS), __msgHook: (mt, msg) => { mkMsgHook(ANCHOR_MSGS)(mt, msg); if (String(mt) === 't' && msg && typeof msg === 'object') { BF_T_MSG = msg; if (process.env.AKRUN) log('  [bframe] captured this-session "t" program (keys=[' + Object.keys(msg).slice(0, 14).join(',') + '])') } if (process.env.NDUMP) dumpDecoded('bframe', mt, msg) },
    __vyHook: (paInstance, N, A) => { try { log('  [bframe] __vyHook: vy CALLED naturally (N=' + (N && (N.length || typeof N)) + ' A=' + (A && (A.length || typeof A)) + ')') } catch {} return paInstance },
    // capture the RAW pre-parse program string (a large JSON array literal that new bC() consumes)
    __pHook: (f, d, r) => { try { if (typeof d === 'string' && d.length > 50000 && d[0] === '[' && (!BF_T_RAW || d.length > BF_T_RAW.length)) { BF_T_RAW = d; if (process.env.AKRUN) log('  [bframe] captured RAW program JSON-array string len=' + d.length + ' head=' + JSON.stringify(d.slice(0, 30))) } } catch {} },
    __ceHook: (ce) => { try { const sz = (ce && ce.length != null) ? ce.length : (ce && ce.byteLength != null ? ce.byteLength : (typeof ce === 'string' ? ce.length : 0)); log('  [bframe] *** GR/CE ran: bgprogram size = ' + sz + ' (type ' + (ce && ce.constructor && ce.constructor.name || typeof ce) + ') ***') } catch (e) {} return ce },
    botguard: undefined,
  }
  const realm = buildRealm('bframe', extra, { pageWindow: true, parentRef: bframeParentWinHandle })
  if (realm.err) log('  [bframe] realm load THREW:', realm.err.message)
  REFS.bframeWin = realm.ctx
  flushBframeQueue()   // release any parent->bframe posts queued before the realm existed
  if (!realm.sandbox.recaptcha || !realm.sandbox.recaptcha.frame) { log('  [bframe] no recaptcha.frame api — abort bframe'); return null }
  log('  [bframe] running recaptcha.frame.Main.init(cfg)...')
  try { vm.runInContext(binit, realm.ctx, { timeout: 20000 }) } catch (e) { log('  [bframe] frame init threw:', e.message, '|', (e.stack || '').split('\n')[1]) }
  log('  [bframe] frame.Main.init done | bframe intake listeners:', bframeBus.count())
  realm.ALL_ELS = ALL_ELS; realm.dom = dom   // expose so the bframe collector can receive human events
  realm.workerHolder = bframeWorkerHolder     // expose the bframe's BotGuard worker holder (shared-d5 probe)
  BFRAME_REALM = realm
  // Fire the bframe iframe element's load event so the PARENT api.js posts the initial config to
  // iframe.contentWindow (reload_net.json: msg#0 config lands right after the bframe iframe loads).
  if (iframeEl) {
    setTimeout(() => {
      try {
        if (typeof iframeEl.onload === 'function') { try { iframeEl.onload({ type: 'load', target: iframeEl }) } catch {} }
        if (iframeEl._fire) iframeEl._fire('load', { type: 'load', target: iframeEl, currentTarget: iframeEl })
        log('  [bframe] fired iframe load event (nudge parent -> post config)')
      } catch (e) { if (TRACE) log('  [bframe] iframe load fire err', e.message) }
    }, 300)
  }
  return realm
}

function extractInitCall(html, key) {
  key = key || 'recaptcha.anchor.Main.init('
  const i = html.indexOf(key); if (i < 0) return null
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) { const c = html[p]
    if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
    if (c === '"' || c === "'") { inStr = true; q = c; continue }
    if (c === '(') depth++; else if (c === ')') { depth--; if (depth === 0) { p++; break } } }
  return html.slice(i, p)
}
const clickable = ALL => ALL.filter(el => el._lis && (el._lis.click || el._lis.mousedown || el._lis.pointerdown || el._lis.keydown))

// ----------------------------------------------------------------------------
// 7) Main.
// ----------------------------------------------------------------------------
async function main() {
  process.on('unhandledRejection', (e) => { if (process.env.SHOWREJ) { const st = (e && e.stack || '').split('\n').filter(l => /recaptcha__en|driver_emulate/.test(l)).slice(0, 6).map(l => l.trim().replace(/.*recaptcha__en[^)]*/, m => m.replace(/.*(recaptcha__en[^:]*:\d+:\d+).*/, '$1'))).join(' <- '); log('  [REJ]', (e && e.message || e), '|', st) } })
  // en.js schedules deferred error-reporting on setTimeout; a null-deref in the (headless-crippled)
  // activation path bubbles there and its OWN reporter (@1546) can throw on an undefined error,
  // killing the process. Swallow uncaught en.js timer errors so the run reaches /reload; log them.
  process.on('uncaughtException', (e) => { const m = (e && e.message) || String(e); const st = (e && e.stack || '').split('\n').filter(l => /recaptcha__en/.test(l)).slice(0, 4).map(l => l.trim().replace(/.*(recaptcha__en[^:]*:\d+:\d+).*/, '$1')).join(' <- '); log('  [UNCAUGHT swallowed]', m, '|', st) })
  log('[emp] sitekey=%s host=%s anchor-origin=%s ver=%s', SITEKEY, HOST_ORIGIN, ANCHOR_ORIGIN, VER)

  // --- boot the PARENT realm; auto-render builds the anchor iframe + the intake at load ---
  log('[emp] booting PARENT (api.js host) realm...')
  const parent = buildParentRealm()
  log('[emp] parent load:', parent.realm.err ? 'THREW ' + parent.realm.err.message : 'OK')
  const gr = parent.realm.sandbox.grecaptcha
  log('[emp] grecaptcha:', gr ? Object.keys(gr).join(',') : '(none)', '| clients:', Object.keys(parent.realm.sandbox.___grecaptcha_cfg.clients || {}).length, '| parent intake listeners:', parentBus.count())
  await new Promise(r => setTimeout(r, 50))
  if (!parent.anchorSrc) { log('[emp] FATAL: parent did not create an anchor iframe src (render path changed) — abort'); process.exit(1) }
  log('[emp] anchor iframe src:', parent.anchorSrc.slice(0, 120))

  // --- fetch the REAL anchor HTML at the parent-derived src; extract its init literal ---
  log('[emp] GET anchor (real network)...')
  let html
  try { const r = await fetch(parent.anchorSrc, { headers: { 'User-Agent': UA, 'Referer': HOST_ORIGIN + '/' } }); mergeSetCookie(r.headers); html = await r.text() }
  catch (e) { log('[emp] anchor fetch failed:', e.message); process.exit(1) }
  const initCall = extractInitCall(html)
  if (!initCall) { log('[emp] no recaptcha.anchor.Main.init in anchor html (len=' + html.length + ') — sitekey/origin mismatch?'); process.exit(1) }
  log('[emp] anchor init literal:', initCall.length, 'chars | cookie:', COOKIE ? COOKIE.split(';')[0] : '(none)')

  // --- boot the ANCHOR realm (window.parent bridged to the parent realm) and run init ---
  log('[emp] booting ANCHOR realm + running recaptcha.anchor.Main.init(cfg)...')
  const anchor = buildAnchorRealm(parent.anchorSrc)
  log('[emp] anchor load:', anchor.realm.err ? 'THREW ' + anchor.realm.err.message : 'OK')
  try { vm.runInContext(initCall, anchor.realm.ctx, { timeout: 20000 }) }
  catch (e) { log('[emp] anchor init threw:', e.message, '\n', (e.stack || '').split('\n').slice(1, 4).join('\n')) }
  // EXPERIMENT: also run the anchor init in the PARENT realm to populate its proto/message-type
  // registry (the parent boots as a minimal host and lacks the type-0 parser -> r=0 decode crash).
  if (process.env.PARENTINIT) {
    try { vm.runInContext(initCall, parent.realm.ctx, { timeout: 20000 }); log('[emp] ran anchor init in PARENT realm too (proto reg experiment)') }
    catch (e) { log('[emp] PARENT extra-init threw:', e.message) }
    await new Promise(r => setTimeout(r, 1200))
  }

  // --- let the bridge carry: setup handshake -> port adoption -> AE "C"/"z" -> real MZ + drive ---
  for (let s = 0; s < 16 && !anchor.holder.workerRealm; s++) await new Promise(r => setTimeout(r, 250))
  log('[emp] worker spawned:', !!anchor.holder.workerRealm)
  await new Promise(r => setTimeout(r, 3500))

  // ========================================================================
  // BGWIRE (experiment): the parent's [D,E] BotGuard-generator AE (RPp Qr/ak) is bound to a port
  // whose PEER is never handed to the anchor -> the anchor's BotGuard client has no channel to
  // send "D"(Qr) on, so the ~288KB program is never requested. Offer that peer port to the anchor
  // (via the established parent->anchor cwBridge) as a "recaptcha-setup", then watch whether the
  // anchor opens a client AE on it and sends "D".  (proven: feeding "D" to the [D,E] AE mints 288KB)
  // ========================================================================
  if (process.env.BGWIRE) {
    const bgAE = parent.parentAEs.find(ae => { try { const inner = ae.P && ae.P._inner; const ks = inner ? [...inner.keys()].map(String) : []; return ks.includes('D') && ks.includes('E') } catch { return false } })
    if (!bgAE) log('[emp][BGWIRE] no [D,E] AE found on parent')
    else {
      const port1 = bgAE.D, port2 = port1 && port1._peer
      log('[emp][BGWIRE] parent [D,E] AE port=%s peer=%s', port1 && port1.__id, port2 && port2.__id)
      if (port2) {
        tapPort(port1, 'bg-p1'); tapPort(port2, 'bg-p2')
        const nBefore = (anchor.realm.sandbox.__cap && anchor.realm.sandbox.__cap.sends || []).length
        // INJECTD: confirm the [D,E] generator is functional IN THE DRIVER by posting a real "D"
        // frame onto port2 (peer) and capturing the ~288KB reply the parent emits on port1.
        if (process.env.INJECTD) {
          let dFrame = null
          try { const cf = JSON.parse(fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/comm_full.json', 'utf8')); dFrame = (cf.anchor.out || []).find(s => { try { return JSON.parse(s)[1] === 'D' } catch { return false } }) } catch {}
          if (dFrame) {
            let maxOut = 0
            const op1 = port1.postMessage.bind(port1)
            port1.postMessage = (d, t) => { const L = (typeof d === 'string' ? d.length : 0); if (L > maxOut) maxOut = L; if (L > 50000) log('[emp][INJECTD] parent [D,E] emitted ' + L + 'B on port1 (mt=' + (() => { try { return JSON.parse(d)[1] } catch { return '?' } })() + ')'); return op1(d, t) }
            log('[emp][INJECTD] posting real "D" frame (' + dFrame.length + 'B) onto parent [D,E] peer port2...')
            try { port2.postMessage(dFrame) } catch (e) { log('[emp][INJECTD] post threw', e.message) }
            await new Promise(r => setTimeout(r, 2000))
            log('[emp][INJECTD] RESULT: largest parent [D,E] reply on port1 = ' + maxOut + 'B  ' + (maxOut >= 250000 ? '<<< 288KB GENERATOR CONFIRMED IN-DRIVER' : '(no big program — check)'))
          } else log('[emp][INJECTD] no "D" frame in comm_full.json')
        }
        log('[emp][BGWIRE] offering [D,E] peer port to anchor via cwBridge recaptcha-setup...')
        try { cwBridge.postMessage('recaptcha-setup', ANCHOR_ORIGIN, [port2]) } catch (e) { log('[emp][BGWIRE] offer threw', e.message) }
        await new Promise(r => setTimeout(r, 3000))
        const aSendsNow = (anchor.realm.sandbox.__cap && anchor.realm.sandbox.__cap.sends || [])
        log('[emp][BGWIRE] anchor sends now: %d (%s) | new since offer: %d', aSendsNow.length, aSendsNow.map(s => s.opS).join(','), aSendsNow.length - nBefore)
      }
    }
  }

  const pcap = parent.realm.sandbox.__cap || {}, acap = anchor.realm.sandbox.__cap || {}
  log('[emp] caps: parent.d5=%s parent.AE=%s | anchor.d5=%s anchor.AE=%s',
      !!pcap.d5, !!pcap.AE, !!acap.d5, !!acap.AE)
  log('[emp] buses: parent listeners=%d anchor listeners=%d', parentBus.count(), anchorBus.count())
  // INSPECT the parent's AE endpoints: which port each is bound to, and its handler opcodes.
  log('[emp] parent AEs: %d', parent.parentAEs.length)
  parent.parentAEs.forEach((ae, i) => {
    let portId = '?'; try { portId = ae.D && ae.D.__id } catch {}
    let handlerKeys = '?'; try { const inner = ae.P && ae.P._inner; handlerKeys = inner ? [...inner.keys()].map(String).join(',') : (ae.P && ae.P.size != null ? 'size=' + ae.P.size : '?') } catch {}
    let pending = '?'; try { pending = ae.L && ae.L.size } catch {}
    let lis = '?', on = '?', started = '?'; try { lis = ae.D && ae.D._lis && ae.D._lis.length; on = ae.D && !!ae.D._on; started = ae.D && ae.D._started } catch {}
    log('   AE#%d port=%s handlerOpcodes=[%s] pendingCalls=%s | port._lis=%s _on=%s _started=%s', i, portId, handlerKeys, pending, lis, on, started)
  })
  // PTRACK: dump parent-realm promises that never settled (the o-handler hang), with source line.
  if (process.env.PTRACK) {
    const stuck = PENDING_PROMISES.filter(p => !p.settled && /recaptcha__en/.test(p.stack || ''))
    log('[emp][PTRACK] never-settled promises created in en.js: %d / %d total', stuck.length, PENDING_PROMISES.length)
    const locs = {}
    stuck.forEach(p => { const lines = (p.stack || '').split('\n'); const m = lines.find(l => /recaptcha__en/.test(l) && !/TP\b/.test(l)); const key = m ? m.trim() : '?'; locs[key] = (locs[key] || 0) + 1 })
    Object.entries(locs).sort((a, b) => b[1] - a[1]).slice(0, 14).forEach(([k, n]) => log('   [%dx] %s', n, k))
    if (process.env.PTRACK === '2') { log('[emp][PTRACK] raw stacks (first 3 stuck):'); stuck.slice(0, 3).forEach((p, i) => log('  --- stuck#' + i + ' ---\n' + (p.stack || '').split('\n').slice(0, 8).join('\n'))) }
  }
  // OSRC: dump the main-channel handler bodies (o hangs, z works) to see what o awaits.
  if (process.env.OSRC) {
    const mainAE = parent.parentAEs.find(ae => { try { return ae.P._inner && ae.P._inner.has('o') } catch { return false } })
    if (mainAE) for (const K of ['o', 'z', 'C', 't']) { try { const h = mainAE.P._inner.get(K); if (typeof h === 'function') { const s = h.toString(); log('[emp][OSRC] handler "' + K + '" (' + s.length + '): ' + s.slice(0, 300).replace(/\n/g, ' ')) } } catch {} }
  }

  // ---- DECISIVE KEY EXPERIMENT: recover each realm's 12-byte AE keystream and compare ----
  // The codec (map entry 3): wire = ["B"+b64url(XOR12(utf8(JSON.stringify(envelope)))), mt, callid].
  // Recover a realm's key by known-plaintext from its OWN first send: key = ct XOR utf8(json).
  const b64url = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const unb64url = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4), 'base64')
  function recoverKeyFrom(structMsg, wireStr) {
    let arr; try { arr = JSON.parse(wireStr) } catch { return null }
    if (!Array.isArray(arr) || typeof arr[0] !== 'string' || arr[0][0] !== 'B') return null
    const ct = unb64url(arr[0].slice(1))
    // the plaintext is JSON.stringify(envelope) where envelope = {message:structMsg, messageType, D:callid};
    // but the serializer stringifies [R.P,...]; the INNER message is JSON.stringify(structMsg). We KP the
    // inner-message bytes against the START of ct (period-12 key repeats, so any aligned plaintext works).
    const pt = Buffer.from(JSON.stringify(structMsg), 'latin1')
    if (ct.length < 12 || pt.length < 12) return null
    const k = Buffer.alloc(12); for (let i = 0; i < 12; i++) k[i] = ct[i] ^ pt[i]
    // validate: does this key XOR the whole ct back to valid JSON?
    const out = Buffer.alloc(ct.length); for (let i = 0; i < ct.length; i++) out[i] = ct[i] ^ k[i % 12]
    let ok = false, head = out.slice(0, 40).toString('latin1'); try { JSON.parse(out.toString('latin1')); ok = true } catch {}
    return { key: k.toString('hex'), validJSON: ok, head }
  }
  try {
    const aSends = (anchor.realm.sandbox.__cap && anchor.realm.sandbox.__cap.sends) || []
    log('[emp] anchor sends captured: %d (opcodes: %s)', aSends.length, aSends.map(s => s.opS).join(','))
    const pSends = (parent.realm.sandbox.__cap && parent.realm.sandbox.__cap.sends) || []
    log('[emp] PARENT sends captured: %d (opcodes: %s)', pSends.length, pSends.map(s => s.opS + '(' + (() => { try { return JSON.stringify(s.msg).length } catch { return '?' } })() + ')').join(','))
    const aWire = port8In[0] || null
    let wireMt = null; try { wireMt = JSON.parse(aWire)[1] } catch {}
    const tmpl = aSends.find(s => s.opS === wireMt) || aSends[0]
    let kAnchor = null
    if (tmpl && aWire) { const r = recoverKeyFrom(tmpl.msg, aWire); kAnchor = r && r.validJSON ? r.key : null
      log('[emp] ANCHOR key (mt=%s):', wireMt, r ? (r.key + ' validJSON=' + r.validJSON + ' head=' + JSON.stringify(r.head)) : '(KP failed)') }
    else log('[emp] anchor key: insufficient capture (sends=%d wire=%s)', aSends.length, !!aWire)
    // is the key PER-SESSION (constant)? decode EVERY inbound frame with the single recovered key.
    if (kAnchor) {
      const kb = Buffer.from(kAnchor, 'hex')
      port8In.forEach((w, i) => { try { const a = JSON.parse(w); const ct = unb64url(a[0].slice(1)); const out = Buffer.alloc(ct.length); for (let j = 0; j < ct.length; j++) out[j] = ct[j] ^ kb[j % 12]; let ok = false; try { JSON.parse(out.toString('latin1')); ok = true } catch {} log('   inbound frame#%d mt=%s len=%d decodesWithAnchorKey=%s head=%s', i, a[1], ct.length, ok, JSON.stringify(out.slice(0, 28).toString('latin1'))) } catch (e) { log('   inbound frame#%d decode err %s', i, e.message) } })
    }
    // parent key: force the parent's AE#1 to encode the SAME message; capture its OUT wire; recover.
    const pae = parent.parentAEs.find(a => a.D && a.D.__id === 8)
    if (pae && tmpl) {
      port8Out.length = 0
      try { pae.send(tmpl.opS, tmpl.msg) } catch (e) { log('[emp] parent probe send threw:', e.message) }
      await new Promise(r => setTimeout(r, 80))
      const pWire = port8Out[0] || null
      if (pWire) { const r = recoverKeyFrom(tmpl.msg, pWire)
        log('[emp] PARENT key (mt=%s):', tmpl.opS, r ? (r.key + ' validJSON=' + r.validJSON) : '(KP failed)')
        if (kAnchor && r) log('[emp] >>> KEYS %s <<<', kAnchor === r.key ? 'MATCH (decode SHOULD work — blocker is elsewhere)' : 'DIFFER (per-realm session secret — the emulate-parent core blocker)') }
      else log('[emp] parent key: AE#1.send produced no OUT frame on port8')
    } else log('[emp] parent key: no AE on port8 or no anchor send template')
  } catch (e) { log('[emp] key experiment threw:', e.message) }

  // ---- SEED HUNT: dump AE-instance + channel-object properties to locate the per-session seed ----
  try {
    function dumpObj(o, label, depth) {
      if (!o || typeof o !== 'object' || depth > 2) return
      for (const k of Object.keys(o)) {
        let v; try { v = o[k] } catch { continue }
        if (v instanceof Uint8Array || v instanceof ArrayBuffer || (v && v.buffer instanceof ArrayBuffer && typeof v.length === 'number')) {
          const b = Buffer.from(v.buffer ? v.buffer : v); log(`   [seed?] ${label}.${k} = ${b.length}B ${b.slice(0, 16).toString('hex')}`)
        } else if (v && typeof v === 'object' && depth < 2 && !(v instanceof Map) && !(v.__isPort)) {
          const cn = v.constructor && v.constructor.name
          if (/key|crypt|cod|seed|chan|cy|cipher/i.test(k) || /key|crypt|cod/i.test(cn || '')) { log(`   [obj] ${label}.${k} (${cn}) keys=${Object.keys(v).slice(0, 8).join(',')}`); dumpObj(v, label + '.' + k, depth + 1) }
        } else if (typeof v === 'string' && v.length >= 12 && v.length <= 64 && /^[A-Za-z0-9_\-+/=]+$/.test(v)) {
          log(`   [str?] ${label}.${k} = "${v.slice(0, 40)}" (${v.length})`)
        }
      }
    }
    const pae = parent.parentAEs.find(a => a.D && a.D.__id === 8)
    if (pae) {
      log('[emp] parent AE#1 ALL props:')
      for (const k of Object.keys(pae)) { let v; try { v = pae[k] } catch { v = '<err>' }
        const t = v && v.constructor ? v.constructor.name : typeof v
        let prev = ''
        try { if (v instanceof Map) prev = 'Map(' + v.size + ')[' + [...v.keys()].slice(0, 6).join(',') + ']'; else if (typeof v === 'function') prev = 'fn'; else if (typeof v === 'object' && v) prev = '{' + Object.keys(v).slice(0, 6).join(',') + '}'; else prev = String(v).slice(0, 40) } catch {}
        log(`     .${k} : ${t} = ${prev}`) }
      dumpObj(pae, 'pAE', 0)
      // dump the GH channel object C (the codec/secret holder) fully
      const C = pae.C
      if (C) { log('[emp] pae.C (GH channel) props:')
        for (const k of Object.keys(C)) { let v; try { v = C[k] } catch { v = '<err>' }
          const t = v && v.constructor ? v.constructor.name : typeof v
          let prev = ''
          try { if (v instanceof Uint8Array || (v && v.buffer)) prev = 'BYTES ' + Buffer.from(v.buffer || v).slice(0, 24).toString('hex'); else if (v instanceof Map) prev = 'Map(' + v.size + ')'; else if (typeof v === 'object' && v) prev = '{' + Object.keys(v).slice(0, 8).join(',') + '}'; else prev = String(v).slice(0, 50) } catch {}
          log(`     C.${k} : ${t} = ${prev}`) }
        // recurse one level into C's object props to find buried byte arrays / secrets
        for (const k of Object.keys(C)) { let v; try { v = C[k] } catch { continue }
          if (v && typeof v === 'object' && !(v instanceof Map) && !v.buffer) { for (const k2 of Object.keys(v)) { let v2; try { v2 = v[k2] } catch { continue }
            if (v2 instanceof Uint8Array || (v2 && v2.buffer instanceof ArrayBuffer)) log(`     C.${k}.${k2} = BYTES ${Buffer.from(v2.buffer || v2).slice(0, 24).toString('hex')}`)
            else if (typeof v2 === 'string' && v2.length >= 16 && v2.length <= 64) log(`     C.${k}.${k2} = STR "${v2.slice(0, 44)}"`) } } }
      }
    }
    // any anchor AE captured via page_rpc __onAE seen[]
    const aAEs = (anchor.realm.sandbox.__onAE && anchor.realm.sandbox.__onAE.seen) || anchor.anchorAEs || []
    log('[emp] anchor AEs available:', aAEs.length)
    if (aAEs[0]) { log('[emp] anchor AE[0] own keys:', Object.keys(aAEs[0]).join(',')); dumpObj(aAEs[0], 'aAE', 0) }
  } catch (e) { log('[emp] seed hunt threw:', e.message) }

  // --- KEYSTREAM comparison (the emulate-parent core blocker) ---
  // each "run" is one XOR'd frame; the first 12 bytes are the period (the per-frame key).
  const period = run => Buffer.from(run.slice(0, 12)).toString('hex')
  const aKeys = ANCHOR_KS.filter(r => r.length >= 12).map(period)
  const pKeys = PARENT_KS.filter(r => r.length >= 12).map(period)
  const uniqA = [...new Set(aKeys)], uniqP = [...new Set(pKeys)]
  log('[emp] XOR keystream runs — anchor:%d (uniq %d) | parent:%d (uniq %d)', ANCHOR_KS.length, uniqA.length, PARENT_KS.length, uniqP.length)
  log('[emp]   anchor keys: %s', uniqA.slice(0, 6).join(' '))
  log('[emp]   parent keys: %s', uniqP.slice(0, 6).join(' '))
  const shared = uniqA.filter(k => uniqP.includes(k))
  log('[emp] SHARED keystream keys (anchor∩parent): %d %s', shared.length, shared.slice(0, 4).join(' '))
  log('[emp]   => keystream is %s', shared.length ? 'SHARED for some frames (decode CAN work — fix routing/which-frame)' : (uniqA.length && uniqP.length ? 'PER-SESSION/REALM (need to share the seed)' : 'inconclusive'))
  log('[emp] AES __keyHook calls — anchor:%d parent:%d (0 = AES path unused)', ANCHOR_KEYS.length, PARENT_KEYS.length)
  log('[emp] PARSED inbound msgs — anchor:%d [%s] | parent:%d [%s]', ANCHOR_MSGS.length, ANCHOR_MSGS.map(m => m.mt).join(','), PARENT_MSGS.length, PARENT_MSGS.map(m => m.mt).join(','))
  log('[emp] parent DISPATCH saw messageTypes: [%s] (%d total) | port8 OUT frames: %d', [...new Set(PARENT_DISP)].join(','), PARENT_DISP.length, port8Out.length)
  log('[emp] parser-resolve calls: %d | undefined-f calls: %d', PARENT_PARSE.length, PARENT_PARSE.filter(p => !p.fDef).length)
  PARENT_PARSE.filter(p => !p.fDef).slice(0, 2).forEach((p, i) => { log('   [parse-miss#%d] r=%s dLen=%s', i, p.rKeys, p.dLen); log('     stack:', p.stack) })
  log('[emp] ANCHOR parser-resolve (working): %d | defined-f: %d', ANCHOR_PARSE.length, ANCHOR_PARSE.filter(p => p.fDef).length)
  ANCHOR_PARSE.slice(0, 4).forEach((p, i) => log('   [anchor-parse#%d] fDef=%s fCtor=%s r=%j(%s) dLen=%s', i, p.fDef, p.fCtor, p.r, p.rType, p.dLen))
  const pConf = PARENT_MSGS.find(m => m.mt === 'C')
  log('[emp] >>> PARENT decoded a "C"(conf) frame: %s %s', !!pConf, pConf ? pConf.prev : '(=> if FALSE: decode threw on the conf = KEYSTREAM blocker; if TRUE: decode WORKED, blocker is the handler-map/routing)')

  // --- INTERACTIVITY CHECK + checkbox trigger in the anchor realm ---
  if (process.env.DUMPLIS) {
    log('[emp] --- anchor element listeners ---')
    for (const el of anchor.ALL_ELS) { const ks = el._lis && Object.keys(el._lis).filter(k => el._lis[k] && el._lis[k].length); if (ks && ks.length) log('   <' + (el.tagName || '?') + (el.id ? ' #' + el.id : '') + '> ' + ks.map(k => k + '(' + el._lis[k].length + ')').join(',')) }
    log('[emp] --- bframe element listeners ---')
    if (BFRAME_REALM) for (const el of (BFRAME_REALM.ALL_ELS || [])) { const ks = el._lis && Object.keys(el._lis).filter(k => el._lis[k] && el._lis[k].length); if (ks && ks.length) log('   <' + (el.tagName || '?') + (el.id ? ' #' + el.id : '') + '> ' + ks.map(k => k + '(' + el._lis[k].length + ')').join(',')) }
  }
  const aClick = clickable(anchor.ALL_ELS)
  log('[emp] anchor DOM els:', anchor.ALL_ELS.length, '| with click/key listeners:', aClick.length,
      aClick.length ? '(' + aClick.map(e => e.id || e.tagName).slice(0, 8).join(',') + ')' : '')
  // AGGRESSIVE checkbox trigger: the anchor's #recaptcha-anchor checkbox may register its handler
  // via addEventListener OR an on* property OR event delegation. Fire the full pointer/keyboard
  // gesture on EVERY anchor element AND invoke any on* handler props, so the verify -> the anchor's
  // "n"(activate) frame -> bframe /reload chain kicks off. (reload_net.json: reload fires ~4ms after
  // the "n" activate; the anchor emits "n" only after the checkbox verify.)
  function fireAll(els, label) {
    let fired = 0
    for (const el of els) {
      const P = el // real element object (has _fire + on* props stored directly)
      try {
        for (let k = 0; k < 3; k++) if (P._fire) P._fire('pointermove', { type: 'pointermove', clientX: 8 + k * 3, clientY: 9 + k * 2, isTrusted: true, target: P, preventDefault() {}, stopPropagation() {} })
        const evs = ['pointerover', 'pointerenter', 'pointerdown', 'mousedown', 'focus', 'mouseup', 'pointerup', 'click']
        for (const t of evs) {
          const ev = { type: t, target: P, currentTarget: P, isTrusted: true, bubbles: true, clientX: 14, clientY: 14, button: 0, which: 1, preventDefault() {}, stopPropagation() {}, stopImmediatePropagation() {} }
          if (P._fire) { P._fire(t, ev); fired++ }
          try { const on = P['on' + t]; if (typeof on === 'function') { on.call(P, ev); fired++ } } catch {}
        }
        const kev = { type: 'keydown', key: ' ', code: 'Space', keyCode: 32, which: 32, isTrusted: true, target: P, preventDefault() {}, stopPropagation() {} }
        if (P._fire) P._fire('keydown', kev); if (typeof P.onkeydown === 'function') try { P.onkeydown(kev) } catch {}
      } catch {}
    }
    if (TRACE) log('  [emp] fireAll(' + label + '): ' + els.length + ' els, ' + fired + ' handler invocations')
  }
  // document-delegated checkbox handler (captured now that document.addEventListener records):
  if (anchor.dom && anchor.dom.docLis) {
    const dk = Object.keys(anchor.dom.docLis).filter(k => (anchor.dom.docLis[k] || []).length)
    log('[emp] anchor DOCUMENT listeners: [' + dk.map(k => k + '(' + anchor.dom.docLis[k].length + ')').join(',') + ']')
  }
  function fireDocGesture() { if (!anchor.dom || !anchor.dom.fireDoc) return; const cb = anchor.ALL_ELS.find(e => e.id === 'recaptcha-anchor') || anchor.dom.container; for (const t of ['pointerdown', 'mousedown', 'focus', 'keydown', 'mouseup', 'pointerup', 'click']) anchor.dom.fireDoc(t, cb) }
  if (process.env.LEGACYFIRE) { fireAll(anchor.ALL_ELS, 'anchor'); fireDocGesture() }
  else { humanGesture(anchor.ALL_ELS, anchor.ALL_ELS, anchor.dom && anchor.dom.fireDoc); log('[emp] humanGesture(anchor): curved human path + click delivered to ' + anchor.ALL_ELS.length + ' els') }
  try { if (gr && typeof gr.execute === 'function') gr.execute(0) } catch (e) { if (TRACE) log('  [emp] gr.execute threw', e.message) }

  // WR = the anchor's checkbox controller (captured via the `self.__grWR=new WR(r)` patch). The DOM
  // click never wires a listener headlessly, so drive the checkbox verify directly through WR: dump
  // its methods, then (WRKICK) invoke likely verify/click entry points and watch for the anchor's
  // "n"(activate) send that gates the bframe /reload.
  try {
    const WR = anchor.realm.sandbox.__grWR
    if (WR) {
      const fnsOf = (o) => { if (!o) return []; try { const proto = Object.getPrototypeOf(o) || {}; return [...new Set([...Object.keys(o), ...Object.getOwnPropertyNames(proto)])].filter(k => { try { return typeof o[k] === 'function' && k !== 'constructor' } catch { return false } }) } catch { return [] } }
      log('[emp][WR] __grWR own keys: [' + Object.keys(WR).join(',') + ']')
      log('[emp][WR] __grWR methods: [' + fnsOf(WR).join(',') + ']')
      const WD = WR.D
      if (WD) { log('[emp][WR] __grWR.D ctor=' + (WD.constructor && WD.constructor.name) + ' own keys: [' + Object.keys(WD).join(',') + ']'); log('[emp][WR] __grWR.D methods: [' + fnsOf(WD).join(',') + ']') }
      // WRTREE: walk the controller tree to locate the Ic/Un checkbox controller (holds the
      // recaptcha-checkbox element in this.L, label in this.M), dump its full method chain + state.
      const findCb = () => {
        const seen = new Set(); let found = null
        const isEl = v => { try { return v && typeof v === 'object' && v.nodeType === 1 } catch { return false } }
        const isCbEl = v => { try { return isEl(v) && v.id === 'recaptcha-anchor' } catch { return false } }
        function walk(o, depth) {
          if (found || !o || typeof o !== 'object' || depth > 5 || seen.has(o)) return
          seen.add(o)
          let keys = []; try { keys = Object.keys(o) } catch {}
          for (const k of keys) { let v; try { v = o[k] } catch { continue } if (isCbEl(v)) { found = o; return } }
          for (const k of keys) { let v; try { v = o[k] } catch { continue } if (v && typeof v === 'object' && !Array.isArray(v) && !v.__isPort && !v.nodeType && !(v instanceof Map)) walk(v, depth + 1) }
        }
        walk(WD, 0)
        return found
      }
      const protoChain = o => { const out = []; let p = Object.getPrototypeOf(o); while (p && p !== Object.prototype) { for (const m of Object.getOwnPropertyNames(p)) { try { if (typeof o[m] === 'function' && m !== 'constructor' && !out.includes(m)) out.push(m) } catch {} } p = Object.getPrototypeOf(p) } return out }
      if (process.env.WRTREE && WD) {
        const cb = findCb()
        if (!cb) log('[emp][WRTREE] checkbox controller NOT found')
        else {
          const elD = v => { try { return v && v.nodeType === 1 ? (v.tagName + (v.id ? '#' + v.id : '')) : (v === null ? 'null' : typeof v) } catch { return '?' } }
          log('[emp][WRTREE] checkbox controller ctor=' + (cb.constructor && cb.constructor.name) + ' | L=' + elD(cb.L) + ' M=' + elD(cb.M))
          log('[emp][WRTREE] full methods: [' + protoChain(cb).join(',') + ']')
          const scal = Object.keys(cb).filter(k => { try { const v = cb[k]; return typeof v === 'boolean' || typeof v === 'number' || (typeof v === 'string' && v.length < 20) } catch { return false } }).map(k => { try { return k + '=' + JSON.stringify(cb[k]) } catch { return k } })
          log('[emp][WRTREE] scalar state: [' + scal.join(' ') + ']')
        }
      }
      // DRIVE: elicit a NATIVE this-session activation by driving the captured checkbox controller
      // (Un/Ic). rU=true already, so it entered the document; 0 listeners bound => this.B was false
      // at Jb time. We (a) force this.B + re-bind, (b) fire a realistic gesture on the bound element,
      // (c) directly call the verify path sh()->Ti() (ACTION dispatch via Closure EventTarget, not
      // DOM). Watch anchor __cap.sends for a NEW native opcode (e/n) sealed with THIS session's key.
      if (process.env.DRIVE && WD) {
        const cb = findCb()
        const acap = anchor.realm.sandbox.__cap || {}
        const base0 = (acap.sends || []).length
        const newSends = () => (acap.sends || []).slice(base0).map(s => s.opS)
        const listenCount = () => { let n = 0; for (const el of anchor.ALL_ELS) { if (el._lis) for (const k of Object.keys(el._lis)) n += (el._lis[k] || []).length } return n }
        const cbEl = () => { try { return cb && cb.i() } catch { return null } }
        if (!cb) log('[emp][DRIVE] checkbox controller NOT found — abort drive')
        else {
          log('[emp][DRIVE] cb.B=' + JSON.stringify(cb.B) + ' cb.rU=' + JSON.stringify(cb.rU) + ' cb.D=' + JSON.stringify(cb.D) + ' WD.rU=' + JSON.stringify(WD.rU) + ' | listeners before=' + listenCount() + ' | reloads=' + RELOADS.length)
          // (a) enter the WHOLE component tree into document: GK (anchor Main, WD) never entered
          // (WD.rU=undefined) so its ACTION->activation listener was never wired. Call each
          // component's Jb (enterDocument) top-down so GK.Jb binds `checkbox ACTION -> dispatch "e"`.
          try {
            const comps = []
            const seen = new Set()
            ;(function collect(o, d) { if (!o || typeof o !== 'object' || d > 6 || seen.has(o)) return; seen.add(o); try { if (typeof o.Jb === 'function' && typeof o.uY === 'function' || (typeof o.Jb === 'function' && ('rU' in o))) comps.push(o) } catch {}; let ks = []; try { ks = Object.keys(o) } catch {}; for (const k of ks) { let v; try { v = o[k] } catch { continue } if (v && typeof v === 'object' && !Array.isArray(v) && !v.nodeType && !v.__isPort && !(v instanceof Map)) collect(v, d + 1) } })(WD, 0)
            try { cb.B = true } catch {}
            // GK first (so ACTION listener binds), then the rest, then the checkbox last.
            const order = [WD, ...comps.filter(c => c !== WD && c !== cb), cb]
            for (const c of order) { try { c.B = true } catch {}; try { c.rU = false; c.Jb() } catch (e) { if (process.env.TRACE) log('[emp][DRIVE] ' + (c.constructor && c.constructor.name) + '.Jb threw', e && e.message) } }
            log('[emp][DRIVE] after tree enterDocument: WD.rU=' + JSON.stringify(WD.rU) + ' cb.rU=' + JSON.stringify(cb.rU) + ' listeners=' + listenCount() + ' new sends=[' + newSends().join(',') + ']')
          } catch (e) { log('[emp][DRIVE] enterDocument strat threw', e && e.message) }
          await new Promise(r => setTimeout(r, 150))
          // (b) realistic human gesture on the (now hopefully bound) checkbox + label elements.
          const el = cbEl()
          try { const gs = [el, cb.M].filter(x => x && x._fire); if (gs.length) { humanGesture(gs, gs, anchor.dom && anchor.dom.fireDoc, { tx: 14, ty: 14 }); log('[emp][DRIVE] humanGesture on checkbox: listeners=' + listenCount() + ' new sends=[' + newSends().join(',') + ']') } } catch (e) { log('[emp][DRIVE] gesture threw', e && e.message) }
          await new Promise(r => setTimeout(r, 250))
          // probe the controller's parent component (cb.o) + its ACTION wiring
          try { const par = cb.o; log('[emp][DRIVE] cb.o ctor=' + (par && par.constructor && par.constructor.name) + ' cb.o.rU=' + JSON.stringify(par && par.rU) + ' | cb keys=[' + Object.keys(cb).join(',') + ']') } catch {}
          // (c) direct verify path: sh() then Ti() (ACTION handler @791 -> L[18](30,this,k$)
          // dispatches ACTION -> GK listener -> activation). The handler calls r.D() (a goog event
          // method) and checks !r.target.href, so pass a proper goog-BrowserEvent-like object with a
          // no-op D() and a CLEAN target (href undefined; NOT the Proxy element whose href is truthy).
          const gEv = () => ({ D() {}, KH() {}, Zg() {}, target: { href: undefined, nodeType: 1, tagName: 'SPAN', getAttribute: () => null }, currentTarget: { href: undefined, nodeType: 1 }, relatedTarget: null, type: 'action', keyCode: 32, which: 32, button: 0, buttons: 1, clientX: 14, clientY: 14, isTrusted: true, defaultPrevented: false, preventDefault() { this.defaultPrevented = true }, stopPropagation() {}, stopImmediatePropagation() {}, getBrowserEvent: () => ({}) })
          for (const m of ['sh', 'Ti', 'VA', 'Sa', 'HI']) { try { if (typeof cb[m] === 'function') { if (m === 'VA') cb.VA(gEv()); else cb[m](gEv()); await new Promise(r => setTimeout(r, 90)); const ns = newSends(); log('[emp][DRIVE] after cb.' + m + '(): sends=[' + ns.join(',') + '] reloads=' + RELOADS.length) } } catch (e) { const st = (e && e.stack || '').split('\n').filter(l => /recaptcha__en/.test(l)).slice(0, 4).map(l => l.trim().replace(/.*(recaptcha__en[^:]*:\d+:\d+).*/, '$1')).join(' <- '); log('[emp][DRIVE] cb.' + m + ' threw:', e && e.message, '|', st) } }
          // (d) also try GK-level activation helpers the RE named (pq=set checked+focus; LL=sh; Os/dH=nr).
          for (const m of ['pq', 'LL', 'Os', 'dH', 'pE']) { try { if (typeof WD[m] === 'function') { WD[m](); await new Promise(r => setTimeout(r, 80)); const ns = newSends(); log('[emp][DRIVE] after WD.' + m + '(): sends=[' + ns.join(',') + '] reloads=' + RELOADS.length) } } catch (e) { if (process.env.TRACE) log('[emp][DRIVE] WD.' + m + ' threw', e && e.message) } }
          await new Promise(r => setTimeout(r, 500))
          log('[emp][DRIVE] FINAL cb.D=' + JSON.stringify(cb.D) + ' | native anchor sends=[' + newSends().join(',') + '] | reloads=' + RELOADS.length)
        }
      }
      if (process.env.WRKICK && WD) {
        const only = process.env.WRONLY ? process.env.WRONLY.split(',') : null
        for (const m of fnsOf(WD)) {
          if (only && !only.includes(m)) continue
          const before = (anchor.realm.sandbox.__cap && anchor.realm.sandbox.__cap.sends || []).length
          const rBefore = RELOADS.length
          try { WD[m]() } catch (e) { /* wrong-arity ok */ }
          await new Promise(r => setTimeout(r, 120))
          const after = (anchor.realm.sandbox.__cap && anchor.realm.sandbox.__cap.sends || [])
          if (after.length > before) log('[emp][WR] D.' + m + '() -> new anchor sends: [' + after.slice(before).map(s => s.opS).join(',') + ']')
          if (RELOADS.length > rBefore) { log('[emp][WR] *** D.' + m + '() TRIGGERED A RELOAD ***'); break }
        }
      }
    } else log('[emp][WR] no __grWR captured')
  } catch (e) { log('[emp][WR] err', e.message) }

  // re-nudge after the bframe realm has booted: fire the checkbox again (anchor + bframe els) so the
  // anchor->parent verify -> parent/anchor "n" activate -> bframe /reload chain completes.
  for (const delay of [1500, 3500, 6000]) setTimeout(() => {
    try {
      if (process.env.LEGACYFIRE) {
        fireAll(anchor.ALL_ELS, 'anchor-renudge')
        if (BFRAME_REALM && BFRAME_REALM.ALL_ELS) fireAll(BFRAME_REALM.ALL_ELS, 'bframe-renudge')
      } else {
        humanGesture(anchor.ALL_ELS, anchor.ALL_ELS, anchor.dom && anchor.dom.fireDoc)
        if (BFRAME_REALM && BFRAME_REALM.ALL_ELS) humanGesture(BFRAME_REALM.ALL_ELS, BFRAME_REALM.ALL_ELS, BFRAME_REALM.dom && BFRAME_REALM.dom.fireDoc, { sx: _R(60, 300), sy: _R(120, 420), tx: _R(180, 250), ty: _R(90, 150), tiles: [{ x: _R(70, 300), y: _R(150, 360) }, { x: _R(70, 300), y: _R(150, 360) }] })
      }
      if (gr && typeof gr.execute === 'function') { try { gr.execute(0) } catch {} }
      const aS = (anchor.realm.sandbox.__cap && anchor.realm.sandbox.__cap.sends || [])
      if (TRACE) log('  [emp] re-nudge@' + delay + ' | anchor sends now: [' + aS.map(s => s.opS).join(',') + ']')
    } catch {}
  }, delay)

  // BFKICK: the bframe has the ~336KB program loaded (its "t" handler ran) and processes an "n"
  // (activate) to fire POST /reload. Since the anchor's checkbox verify never runs headlessly (no
  // DOM listener), drive the bframe's own controller directly: capture its i_/WR controller and
  // invoke its methods, watching for a /reload. Runs a few times as the bframe settles.
  async function bframeKick(tag) {
    const bf = BFRAME_REALM
    if (!bf || !bf.realm) return
    const WR = bf.realm.sandbox.__grWR
    const WD = WR && WR.D
    const fnsOf = (o) => { if (!o) return []; try { const proto = Object.getPrototypeOf(o) || {}; return [...new Set([...Object.keys(o), ...Object.getOwnPropertyNames(proto)])].filter(k => { try { return typeof o[k] === 'function' && k !== 'constructor' } catch { return false } }) } catch { return [] } }
    if (!WD) { if (TRACE) log('  [emp][BFKICK ' + tag + '] no bframe controller (__grWR.D) yet'); return }
    if (!bframeKick._logged) { bframeKick._logged = true; log('[emp][BFKICK] bframe controller __grWR.D ctor=' + (WD.constructor && WD.constructor.name) + ' methods: [' + fnsOf(WD).join(',') + ']') }
    const only = process.env.BFONLY ? process.env.BFONLY.split(',') : null
    for (const m of fnsOf(WD)) {
      if (only && !only.includes(m)) continue
      const rBefore = RELOADS.length
      try { WD[m]() } catch (e) {}
      await new Promise(r => setTimeout(r, 80))
      if (RELOADS.length > rBefore) { log('[emp][BFKICK] *** bframe D.' + m + '() TRIGGERED /reload ***'); return true }
    }
  }
  if (process.env.BFKICK) { for (const d of [500, 3000, 6000, 9000]) setTimeout(() => { bframeKick('t' + d).catch(() => {}) }, d) }

  // BFINJECTN: inject a real "n"(activate) frame onto the bframe's [C,t,n,...] channel (the anchor's
  // checkbox-verify that normally emits "n" can't run headlessly). reload_net.json: the bframe fires
  // POST /reload ~3ms after receiving "n". Tests whether a captured "n" drives the loaded program.
  // AKRUN: the DECISIVE native-field16 experiment. Per the reload-builder RE, field16 is COMPUTED
  // live: the reload trigger awaits Lq.Dw() (-> send(Kk) snapshot) whose .request is the bgRequest,
  // and Lq.vy(program) -> the RPp[ak] handler EXECUTES the ~336KB BotGuard program in the sandbox
  // (reading performance.memory/now + navigator.deviceMemory — our hardened env). Find the bframe's
  // Lq channel, run Dw()/vy(), and see whether the node-vm produces a NATIVE bgRequest (len+md5).
  if (process.env.AKRUN) {
    setTimeout(async () => {
      try {
        // isLq must EXCLUDE the noop-proxy false positives (document/frameElement): require a real
        // channel object `.D` with a `send` fn and NOT be a DOM node / our proxy.
        const isLq = o => { try { return o && typeof o === 'object' && o.nodeType == null && typeof o.Dw === 'function' && typeof o.vy === 'function' && o.D && typeof o.D === 'object' && !o.createElement } catch { return false } }
        const searchRealm = (realm, aes, label) => {
          if (!realm) return []
          const seen = new Set(); const found = []
          function walk(o, path, d) {
            if (!o || typeof o !== 'object' || d > 5 || seen.has(o)) return
            seen.add(o)
            if (isLq(o)) found.push({ o, path })
            let ks = []; try { ks = Object.keys(o) } catch {}
            for (const k of ks) { let v; try { v = o[k] } catch { continue } if (v && typeof v === 'object' && !Array.isArray(v) && !v.__isPort && !v.nodeType && !(v instanceof Map) && !(v instanceof ArrayBuffer)) walk(v, path + '.' + k, d + 1) }
          }
          for (const ae of (aes || [])) { walk(ae, label + 'AE', 0); try { if (ae.C) walk(ae.C, label + 'AE.C', 0) } catch {} }
          try { for (const k of Object.keys(realm.sandbox)) { const v = realm.sandbox[k]; if (v && typeof v === 'object') walk(v, label + '.' + k, 3) } } catch {}
          try { if (realm.sandbox.__grWR) walk(realm.sandbox.__grWR, label + '.grWR', 0) } catch {}
          return found
        }
        // anchor AEs: gather from __cap or PR seen list
        const anchorAEs = []
        try { const s = anchor.realm.sandbox; if (s.__onAE && s.__onAE.seen) anchorAEs.push(...s.__onAE.seen) } catch {}
        const found = [
          ...searchRealm(BFRAME_REALM, BFRAME_AES, 'bf').map(f => ({ ...f, label: 'bframe' })),
          ...searchRealm(anchor.realm, anchorAEs, 'an').map(f => ({ ...f, label: 'anchor' })),
        ]
        log('[emp][AKRUN] Lq (Dw+vy) instances found: ' + found.length + (found.length ? ' at ' + found.map(f => f.label + ':' + f.path).join(', ') : ''))
        // SHARED-D5 DIAGNOSIS: did the bframe spawn its OWN BotGuard worker (like the anchor), and is
        // Lq.D bound to that shared-d5 channel — or did it fall back to the main cross-frame channel?
        try {
          const bwh = BFRAME_REALM && BFRAME_REALM.workerHolder, bwr = bwh && bwh.workerRealm
          const awh = anchor && anchor.holder, awr = awh && awh.workerRealm
          const rppOps = r => { try { return r && r.sandbox.__cap && r.sandbox.__cap.RPp ? [...r.sandbox.__cap.RPp.keys()].length : 'none' } catch { return '?' } }
          log('[emp][AKRUN][SHARED-D5] bframe spawned worker=' + !!bwr + ' (RPp ops=' + rppOps(bwr) + ') | anchor spawned worker=' + !!awr + ' (RPp ops=' + rppOps(awr) + ')')
          const lq0 = found.find(f => f.label === 'bframe')
          if (lq0) { const dPort = lq0.o.D && lq0.o.D.D; const dOps = (() => { try { const P = lq0.o.D.P, inner = P && (P._inner || P); const k = []; if (inner && inner.forEach) inner.forEach((_v, kk) => k.push(String(kk))); return k.join(',') } catch { return '?' } })(); log('[emp][AKRUN][SHARED-D5] bframe Lq.D is AE port=' + (dPort && dPort.__id) + ' handlers=[' + dOps + '] (main-channel [C,t,F,e,n,g,i,B] = fell back; a bare [Qr,ak]/worker map = shared-d5 sandbox)') }
        } catch (e) { log('[emp][AKRUN][SHARED-D5] diag threw ' + (e && e.message)) }
        // ANCHORDRIVE: the anchor's client<->worker share a d5 channel (RPp ops=2). Drive the program
        // on the anchor's SHARED-D5 worker: send Qr(program)+ak from the anchor client AE (encodes with
        // the anchor codec) -> the anchor worker decodes (shared) -> RPp[ak] runs -> its "x" requests
        // come back to the anchor client (handlers + catch-all answer) -> watch aq.Z().CE() grow.
        if (process.env.ANCHORDRIVE) try {
          const awr = anchor && anchor.holder && anchor.holder.workerRealm
          const akOpA = awr && awr.sandbox.__cap && awr.sandbox.__cap.ak, qrOpA = awr && awr.sandbox.__cap && awr.sandbox.__cap.Qr, aqA = awr && awr.sandbox.__cap && awr.sandbox.__cap.aq
          const hasOp = (ae, op) => { try { const inner = ae.P && (ae.P._inner || ae.P); let f = false; if (inner && inner.forEach) inner.forEach((_v, k) => { if (k === op) f = true }); return f } catch { return false } }
          const wRppAE = ANCHOR_WORKER_AES.find(ae => hasOp(ae, akOpA)); const wPort = wRppAE && wRppAE.D
          const opsOf = ae => { try { const P = ae.P, inner = P && (P._inner || P), k = []; if (inner && inner.forEach) inner.forEach((_v, kk) => k.push(String(kk))); return k.join(',') } catch { return '?' } }
          log('[emp][AKRUN][ANCHORDRIVE] worker RPp-AEs=' + ANCHOR_WORKER_AES.length + ' wRppAE.port=' + (wPort && wPort.__id) + ' wPort._peer=' + (wPort && wPort._peer && wPort._peer.__id))
          ANCHOR_WORKER_AES.forEach((ae, i) => log('   [wAE#' + i + '] port=' + (ae.D && ae.D.__id) + ' peer=' + (ae.D && ae.D._peer && ae.D._peer.__id) + ' handlers=[' + opsOf(ae) + ']'))
          ANCHOR_CLIENT_AES.forEach((ae, i) => { let cinfo = 'noC'; try { const C = ae.C; if (C && typeof C === 'object') cinfo = 'C{' + Object.keys(C).slice(0, 8).join(',') + '}' + (typeof C.vy === 'function' && typeof C.Dw === 'function' ? ' <<Lq(vy,Dw) C.D.port=' + (C.D && C.D.D && C.D.D.__id) + '>>' : '') } catch {} log('   [aAE#' + i + '] port=' + (ae.D && ae.D.__id) + ' peer=' + (ae.D && ae.D._peer && ae.D._peer.__id) + ' handlers=[' + opsOf(ae) + '] ' + cinfo) })
          // the anchor client on the SHARED channel = the AE whose port is the peer of the worker RPp port
          const clientAE = ANCHOR_CLIENT_AES.find(ae => { try { return ae.D && wPort && ae.D._peer === wPort } catch { return false } }) || ANCHOR_CLIENT_AES.find(ae => { try { return ae.D && wPort && ae.D === wPort._peer } catch { return false } })
          log('[emp][AKRUN][ANCHORDRIVE] anchorWorker=' + !!awr + ' RPpOps=' + (awr && awr.sandbox.__cap.RPp ? [...awr.sandbox.__cap.RPp.keys()].length : '?') + ' | matched clientAE.port=' + (clientAE && clientAE.D && clientAE.D.__id) + ' | akTokenMatch=' + (akOpA === (anchor.realm.sandbox.__cap && anchor.realm.sandbox.__cap.ak)))
          if (awr) { try { const wdom = makeDocument([], {}); awr.sandbox.document = wdom.document } catch {}
            const RPp = awr.sandbox.__cap && awr.sandbox.__cap.RPp
            if (RPp) for (const [op, nm] of [[akOpA, 'ak'], [qrOpA, 'Qr']]) { if (op != null && RPp.has(op) && !RPp.get(op).__w) { const o = RPp.get(op); const wf = function (...a) { log('[emp][AKRUN][ANCHORDRIVE] anchor-worker RPp[' + nm + '] INVOKED'); try { return o.apply(this, a) } catch (e) { log('[emp][AKRUN][ANCHORDRIVE] RPp[' + nm + '] THREW ' + (e && e.name) + ':' + (e && e.message)); throw e } }; wf.__w = true; RPp.set(op, wf) } } }
          // wrap the worker RPp AE's dispatch to see which opcodes actually arrive at the worker
          try { if (wRppAE && wRppAE.P && typeof wRppAE.P.get === 'function' && !wRppAE.P.__wg) { const g = wRppAE.P.get.bind(wRppAE.P); wRppAE.P.__wg = true; wRppAE.P.get = (K) => { log('[emp][AKRUN][ANCHORDRIVE] worker RPp-AE received opcode=' + JSON.stringify(String(K))); return g(K) } } } catch {}
          const ceLen = () => { try { const ce = aqA.Z().get().CE(); return Buffer.from(String(ce), 'latin1').length } catch { return 'n/a' } }
          // Drive the anchor's shared-d5 worker via its worker-channel client (clientAE = port6, peer of RPp).
          if (clientAE && BF_T_RAW) {
            log('[emp][AKRUN][ANCHORDRIVE] clientAE keys=[' + Object.keys(clientAE).join(',') + '] hasSend=' + (typeof clientAE.send) + ' hasC=' + (clientAE.C != null))
            // install a page_rpc catch-all on the client so the worker's outbound "x" requests get MZ-acked
            try { if (!clientAE.P || !clientAE.P.__isPageHandlerSet) { PR.installOn(clientAE, { log: () => {} }); log('[emp][AKRUN][ANCHORDRIVE] installed catch-all on clientAE (answers worker "x" requests)') } } catch (e) { log('[emp][AKRUN][ANCHORDRIVE] catch-all install threw ' + (e && e.message)) }
            // instrument the shared channel ports to see the frame flow
            try { const p6 = clientAE.D, p5 = wPort
              if (p6 && !p6.__pw) { p6.__pw = true; const op = p6.postMessage.bind(p6); p6.postMessage = (d, t) => { log('[emp][AKRUN][ANCHORDRIVE] client->worker port' + p6.__id + '->' + (p6._peer && p6._peer.__id) + ' ' + (typeof d === 'string' ? 'str(' + d.length + '):' + JSON.stringify(d.slice(0, 40)) : desc(d))); return op(d, t) } }
              if (p5 && !p5.__pw) { p5.__pw = true; const od = p5._deliver.bind(p5); p5._deliver = (ev) => { const d = ev && ev.data; log('[emp][AKRUN][ANCHORDRIVE] worker port' + p5.__id + ' RECEIVED ' + (typeof d === 'string' ? 'str(' + d.length + '):' + JSON.stringify(d.slice(0, 40)) : desc(d))); return od(ev) } }
            } catch (e) { log('[emp][AKRUN][ANCHORDRIVE] port instrument threw ' + (e && e.message)) }
            const before = ceLen()
            log('[emp][AKRUN][ANCHORDRIVE] anchor-worker CE before=' + before + ' | sending Qr(program) via clientAE.send on shared channel...')
            if (typeof clientAE.send === 'function') {
              try { const p1 = clientAE.send(qrOpA, { L: BF_T_RAW, D: BF_T_RAW, Oo: BF_T_MSG && BF_T_MSG.Oo }); await Promise.race([Promise.resolve(p1).catch(e => ({ __e: (e && e.name) + ':' + (e && e.message) })).then(r => log('[emp][AKRUN][ANCHORDRIVE] Qr resolved ' + JSON.stringify(r).slice(0, 60))), new Promise(r => setTimeout(r, 4000))]) } catch (e) { log('[emp][AKRUN][ANCHORDRIVE] Qr send threw ' + (e && e.message)) }
              await new Promise(r => setTimeout(r, 500))
              try { const p2 = clientAE.send(akOpA, { D: BF_T_RAW }); await Promise.race([Promise.resolve(p2).catch(e => ({ __e: (e && e.name) + ':' + (e && e.message) })).then(r => log('[emp][AKRUN][ANCHORDRIVE] ak resolved ' + JSON.stringify(r).slice(0, 60))), new Promise(r => setTimeout(r, 8000))]) } catch (e) { log('[emp][AKRUN][ANCHORDRIVE] ak send threw ' + (e && e.message)) }
            } else log('[emp][AKRUN][ANCHORDRIVE] clientAE has no send()')
            await new Promise(r => setTimeout(r, 2000))
            const after = ceLen()
            log('[emp][AKRUN][ANCHORDRIVE] >>> anchor-worker CE ' + before + '->' + after + '  (grew past conf? ' + (typeof after === 'number' && after > 1500 ? 'YES — program running to token!' : 'NO — stayed at conf') + ')')
          } else log('[emp][AKRUN][ANCHORDRIVE] no clientAE to drive (clientAE=' + !!clientAE + ')')
        } catch (e) { log('[emp][AKRUN][ANCHORDRIVE] threw ' + (e && e.message)) }
        for (const { o: lq, path, label } of found.slice(0, 4)) {
          log('[emp][AKRUN] ' + label + ' Lq@' + path + ' keys=[' + Object.keys(lq).join(',') + '] | D.send=' + (lq.D && typeof lq.D.send))
          try {
            const snap = await Promise.resolve(lq.Dw()).catch(e => ({ __err: e && e.message }))
            if (snap && snap.__err) { log('[emp][AKRUN] ' + label + ' Dw() threw ' + snap.__err) }
            else {
              const req = snap && (snap.request != null ? snap.request : (snap.D != null ? snap.D : snap))
              const buf = req == null ? null : (Buffer.isBuffer(req) ? req : (req.buffer ? Buffer.from(req.buffer) : Buffer.from(String(req), 'latin1')))
              const md5 = buf && buf.length ? crypto.createHash('md5').update(buf).digest('hex').slice(0, 8) : 'empty'
              log('[emp][AKRUN] *** ' + label + ' Dw() bgRequest: len=' + (buf ? buf.length : 0) + ' md5=' + md5 + ' head=' + (buf ? JSON.stringify(buf.slice(0, 24).toString('latin1')) : 'null') + ' (NATIVE if non-empty & varies per run) ***')
            }
          } catch (e) { log('[emp][AKRUN] ' + label + ' Dw() outer threw ' + (e && e.message)) }
          // DRIVE vy on THIS session's captured "t" program so the worker runs ak, then re-read Dw().
          if (label === 'bframe' && typeof lq.vy === 'function') {
            const bfsb = (BFRAME_REALM && BFRAME_REALM.sandbox) || {}
            const Pa = bfsb.__cap && bfsb.__cap.Pa
            const Rl = bfsb.__cap && bfsb.__cap.Rl
            log('[emp][AKRUN] vy-drive: BF_T_MSG=' + (BF_T_MSG ? 'captured(keys=' + Object.keys(BF_T_MSG).slice(0, 10).join(',') + ')' : 'NONE') + ' | __cap.Pa=' + (!!Pa) + ' __cap.Rl=' + (!!Rl))
            // inspect Lq.D (the BotGuard sandbox channel) — is it wired to a real worker running RPp[ak]?
            try { const D = lq.D; log('[emp][AKRUN] Lq.D ctor=' + (D && D.constructor && D.constructor.name) + ' keys=[' + (D ? Object.keys(D).join(',') : '') + ']')
              const port = D && (D.D || D.port || D.M); log('[emp][AKRUN] Lq.D.port ctor=' + (port && port.constructor && port.constructor.name) + ' __isPort=' + (port && port.__isPort) + ' peer=' + (port && port._peer ? 'yes' : 'no') + ' handlers=[' + (D && D.P && D.P._inner ? [...D.P._inner.keys()].map(String).join(',') : (D && D.P && typeof D.P.forEach === 'function' ? (() => { const k = []; D.P.forEach((_v, kk) => k.push(String(kk))); return k.join(',') })() : '?')) + ']') } catch (e) { log('[emp][AKRUN] Lq.D inspect threw ' + (e && e.message)) }
            // WIRE a real BotGuard worker realm to Lq.D so "ak"/"Kk" get answered by RPp (worker.js pattern).
            if (!process.env.NOWORKERWIRE) try {
              const holder = {}
              let rppPort = null
              const workerAEs = []
              const FW = makeFakeWorker(holder, (ae) => { try { workerAEs.push(ae) } catch {} return ae })
              const w = new FW('https://www.google.com/recaptcha/api2/webworker.js?hl=en&v=' + VER + '&pk=' + SITEKEY)
              w.onmessage = (ev) => { const ports = (ev && ev.ports) || []; for (const p of ports) if (p && p.__isPort && !rppPort) rppPort = p }
              w.addEventListener && w.addEventListener('message', (ev) => { const ports = (ev && ev.ports) || []; for (const p of ports) if (p && p.__isPort && !rppPort) rppPort = p })
              await new Promise(r => setTimeout(r, 400))
              const wr = holder.workerRealm
              // find the worker's RPp AE (its handler map has Qr/ak) + its actual port — the coordinator's
              // shared-channel fix routes Lq.D to THIS server, not the d5-handshake main port.
              const akOpW = wr && wr.sandbox.__cap && wr.sandbox.__cap.ak
              const rppAE = workerAEs.find(ae => { try { const inner = ae.P && (ae.P._inner || ae.P); return inner && inner.has && (inner.has(akOpW) || (typeof inner.forEach === 'function' && (() => { let f = false; inner.forEach((_v, k) => { if (k === akOpW) f = true }); return f })())) } catch { return false } })
              const rppAEPort = rppAE && rppAE.D
              log('[emp][AKRUN] worker AEs captured=' + workerAEs.length + ' | RPp-AE found=' + !!rppAE + ' RPp-AE.port=' + (rppAEPort ? rppAEPort.__id : 'none') + ' | transferred rppPort=' + (rppPort ? rppPort.__id : 'none'))
              // AKSHARE: route Lq.D's port directly to the RPp-AE's port PEER (shared-channel test) —
              // does Lq.D's frame then decode + run RPp[ak]? (vs the transferred main port used below).
              if (process.env.AKSHARE && rppAEPort && rppAEPort._peer) rppPort = rppAEPort._peer
              log('[emp][AKRUN] BotGuard worker: RPp exposed=' + !!(wr && wr.sandbox.__cap && wr.sandbox.__cap.RPp) + ' RPpOps=' + (wr && wr.sandbox.__cap && wr.sandbox.__cap.RPp ? [...wr.sandbox.__cap.RPp.keys()].length : '?') + ' loadErr=' + (wr && wr.err ? wr.err.message : 'none') + ' | rppPort=' + (rppPort ? rppPort.__id : 'NONE'))
              // wrap the worker's RPp[ak]/RPp[Qr] to capture the exact payload shape + any throw.
              try {
                const RPp = wr && wr.sandbox.__cap && wr.sandbox.__cap.RPp, akOp = wr && wr.sandbox.__cap && wr.sandbox.__cap.ak, qrOp = wr && wr.sandbox.__cap && wr.sandbox.__cap.Qr
                const wrap = (op, name) => { if (RPp && op != null && RPp.has(op)) { const orig = RPp.get(op); RPp.set(op, function (...a) { const pl = a[0]; let pld = 'n/a'; try { pld = pl == null ? String(pl) : (typeof pl === 'object' ? ('{' + Object.keys(pl).slice(0, 8).join(',') + '}' + (pl.D != null ? ' D=' + (pl.D.length || pl.D.byteLength || typeof pl.D) : '')) : (typeof pl + ':' + String(pl).slice(0, 30))) } catch {} ; log('[emp][AKRUN] worker RPp[' + name + '] invoked payload=' + pld); try { return orig.apply(this, a) } catch (e) { log('[emp][AKRUN] worker RPp[' + name + '] THREW ' + (e && e.name) + ': ' + (e && e.message) + ' | ' + (e && e.stack || '').split('\n').filter(l => /recaptcha__en/.test(l)).slice(0, 3).map(l => l.trim().replace(/.*(recaptcha__en[^:]*:\d+:\d+).*/, '$1')).join(' <- ')); throw e } }) } }
                wrap(akOp, 'ak'); wrap(qrOp, 'Qr')
              } catch (e) { log('[emp][AKRUN] RPp wrap threw ' + (e && e.message)) }
              // DIRECT RPp[ak] call — bypass the seeded frame codec: run ak on this-session program.
              try {
                const RPp = wr && wr.sandbox.__cap && wr.sandbox.__cap.RPp, akOp = wr && wr.sandbox.__cap && wr.sandbox.__cap.ak
                const ak = RPp && akOp != null && RPp.get(akOp)
                if (ak && BF_T_MSG) {
                  const gv = BF_T_MSG.gv
                  let jmsg = ''; try { jmsg = JSON.stringify(BF_T_MSG) } catch {}
                  const forms = []
                  if (BF_T_RAW) forms.push(['{D:RAW-array}', { D: BF_T_RAW }])
                  forms.push(['{D:JSON(msg)}', { D: jmsg }], ['{D:JSON(gv)}', { D: JSON.stringify(gv) }])
                  log('[emp][AKRUN] direct-ak forms: BF_T_RAW=' + (BF_T_RAW ? 'len' + BF_T_RAW.length : 'NONE'))
                  // the BotGuard program probes document (feed.js HOT:document); the worker realm lacks
                  // it. Inject a document + window so the program can emit its token (R.P) instead of aborting.
                  try { const wdom = makeDocument([], {}); wr.sandbox.document = wdom.document; if (!wr.sandbox.window) wr.sandbox.window = wr.ctx; log('[emp][AKRUN] injected document into worker realm') } catch (e) { log('[emp][AKRUN] doc-inject threw ' + (e && e.message)) }
                  // Qr(program) FIRST to init the BotGuard VM state (aq.Z().init) so ak's program run
                  // produces a token (else f=R.P stays undefined). Qr reads q.D(program), q.L, q.Oo.
                  try {
                    const qrOp2 = wr && wr.sandbox.__cap && wr.sandbox.__cap.Qr, qr = RPp && qrOp2 != null && RPp.get(qrOp2)
                    if (qr) {
                      for (const [qfn, qform] of [['msg', BF_T_MSG], ['{D:RAW,L:RAW,Oo}', { D: BF_T_RAW, L: BF_T_RAW, Oo: BF_T_MSG.Oo }], ['{D:JSON(msg)}', { D: jmsg, L: jmsg, Oo: BF_T_MSG.Oo }]]) {
                        try { const qr2 = await Promise.race([Promise.resolve(qr.call(wr.ctx, qform, qrOp2)).catch(e => ({ __err: (e && e.name) + ': ' + (e && e.message) })), new Promise(r => setTimeout(() => r({ __t: 1 }), 8000))]); if (qr2 && qr2.__err) log('[emp][AKRUN] Qr(' + qfn + ') THREW ' + qr2.__err); else { log('[emp][AKRUN] Qr(' + qfn + ') OK (aq.Z init) -> ' + desc(qr2)); break } } catch (e) { log('[emp][AKRUN] Qr(' + qfn + ') outer ' + (e && e.message)) }
                      }
                    } else log('[emp][AKRUN] no Qr handler exposed')
                  } catch (e) { log('[emp][AKRUN] Qr-init threw ' + (e && e.message)) }
                  for (const [fn, prog] of forms) {
                    try {
                      const rr = await Promise.race([Promise.resolve(ak.call(wr.ctx, prog, akOp)).catch(e => ({ __err: (e && e.name) + ': ' + (e && e.message), __st: (e && e.stack || '').split('\n').filter(l => /recaptcha__en/.test(l)).slice(0, 2).map(l => l.trim().replace(/.*(recaptcha__en[^:]*:\d+:\d+).*/, '$1')).join(' <- ') })), new Promise(r => setTimeout(() => r({ __t: 1 }), 10000))])
                      if (rr && rr.__err) { log('[emp][AKRUN] direct RPp[ak](' + fn + ') THREW ' + rr.__err + ' | ' + (rr.__st || '')) }
                      else if (rr && rr.__t) { log('[emp][AKRUN] direct RPp[ak](' + fn + ') did not settle in 10s (running program?)') }
                      else {
                        const xm = rr
                        const fields = {}; try { for (const k of Object.keys(xm)) { const v = xm[k]; fields[k] = (typeof v === 'string' ? 'str(' + v.length + ')' : (v && v.length != null ? 'arr(' + v.length + ')' : (typeof v === 'number' ? v : typeof v))) } } catch {}
                        log('[emp][AKRUN] *** direct RPp[ak](' + fn + ') RETURNED ' + (xm && xm.constructor && xm.constructor.name) + ' fields=' + JSON.stringify(fields) + ' ***')
                        // the bgRequest token = the largest string/bytes field of the Xm (f = R.P)
                        let best = null, bestLen = 0, bestKey = null
                        try { for (const k of Object.keys(xm)) { const v = xm[k]; const b = (typeof v === 'string' && v.length) ? Buffer.from(v, 'latin1') : (Buffer.isBuffer(v) ? v : (v && v.buffer ? Buffer.from(v.buffer) : null)); if (b && b.length > bestLen) { bestLen = b.length; best = b; bestKey = k } } } catch {}
                        if (best && bestLen > 100) { const md5 = crypto.createHash('md5').update(best).digest('hex').slice(0, 8); log('[emp][AKRUN] >>> NATIVE attestation token: Xm.' + bestKey + ' len=' + bestLen + ' md5=' + md5 + ' head=' + JSON.stringify(best.slice(0, 28).toString('latin1')) + '  <<< NATIVE field16 CANDIDATE (per-run varying = success)'); NATIVE_F16 = best; try { fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/native_field16_' + bestLen + '.bin', best) } catch {}; break }
                        else {
                          // the bgRequest is the aq.Z().get().CE() snapshot AFTER ak populates the VM (Kk/Dw equiv)
                          try {
                            await new Promise(r => setTimeout(r, 3500))   // allow any async program execution to complete
                            const aq = wr && wr.sandbox.__cap && wr.sandbox.__cap.aq
                            if (aq && aq.Z) { let ce = null; try { ce = aq.Z().get().CE() } catch (e) { log('[emp][AKRUN] aq.Z().get().CE() threw ' + (e && e.message)) }
                              if (ce != null) { const b = Buffer.isBuffer(ce) ? ce : Buffer.from(String(ce), 'latin1'); const md5 = b.length ? crypto.createHash('md5').update(b).digest('hex').slice(0, 8) : 'empty'; log('[emp][AKRUN] >>> aq.Z().CE() snapshot: len=' + b.length + ' md5=' + md5 + ' head=' + JSON.stringify(b.slice(0, 28).toString('latin1')) + (b.length > 100 ? '  <<< NATIVE bgRequest (per-run varying = success)' : '')); if (b.length > 100) { NATIVE_F16 = b; try { fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/native_field16_ce_' + b.length + '.bin', b) } catch {}; break } }
                            } else log('[emp][AKRUN] aq not exposed (Qr may not have run)')
                          } catch (e) { log('[emp][AKRUN] CE-snapshot threw ' + (e && e.message)) }
                          log('[emp][AKRUN] Xm.h1(R.P) undefined + CE snapshot checked')
                        }
                      }
                    } catch (e) { log('[emp][AKRUN] direct RPp[ak](' + fn + ') outer ' + (e && e.message)) }
                  }
                } else log('[emp][AKRUN] direct RPp[ak] skip: ak=' + !!ak + ' BF_T_MSG=' + !!BF_T_MSG)
              } catch (e) { log('[emp][AKRUN] AKDIRECT threw ' + (e && e.message)) }
              const bframePort = lq.D && lq.D.D
              if (rppPort && bframePort && bframePort.__isPort) {
                bframePort.postMessage = (data, transfer) => { try { if (!bframePort.__flog) { bframePort.__flog = true; log('[emp][AKRUN] Lq.D->worker FRAME: ' + (typeof data === 'string' ? 'str(' + data.length + '): ' + JSON.stringify(data.slice(0, 70)) : desc(data))) } rppPort.postMessage(data, transfer) } catch (e) { log('[emp][AKRUN] route->worker threw ' + (e && e.message)) } }
                rppPort.onmessage = (ev) => { try { const d = ev && ev.data; let op = '?'; try { op = JSON.parse(d)[1] } catch {} log('[emp][AKRUN] worker->Lq.D reply#' + ((rppPort.__rn = (rppPort.__rn || 0) + 1)) + ' op=' + JSON.stringify(op) + ' ' + (typeof d === 'string' ? 'str(' + d.length + ')' : desc(d))); bframePort._deliver(ev) } catch (e) {} }
                log('[emp][AKRUN] ROUTED Lq.D.port(' + bframePort.__id + ') <-> BotGuard worker RPp port(' + rppPort.__id + ')')
              } else log('[emp][AKRUN] could NOT route (rppPort=' + !!rppPort + ' bframePort=' + !!(bframePort && bframePort.__isPort) + ')')
            } catch (e) { log('[emp][AKRUN] worker-wire threw ' + (e && e.message)) }
            if (BF_T_MSG) {
              // try several arg forms: raw msg, Pa(msg), Pa(Rl(msg)) — whichever the worker accepts.
              const forms = []
              try { forms.push(['raw', BF_T_MSG]) } catch {}
              try { if (Pa) forms.push(['Pa(msg)', new Pa(BF_T_MSG)]) } catch (e) { log('[emp][AKRUN] Pa(msg) ctor threw ' + (e && e.message)) }
              try { if (Pa && Rl) forms.push(['Pa(Rl(msg))', new Pa(Rl(BF_T_MSG))]) } catch (e) { log('[emp][AKRUN] Pa(Rl(msg)) ctor threw ' + (e && e.message)) }
              let __hbN = 0, __hbT0 = Date.now()
              const __hb = setInterval(() => log('[emp][AKRUN][hb] +' + Math.round((Date.now() - __hbT0) / 1000) + 's loop-alive tick' + (++__hbN) + ' workerReplies=' + ((rppPort && rppPort.__rn) || 0)), 5000)
              for (const [fname, arg] of forms) {
                try {
                  log('[emp][AKRUN] calling lq.vy(' + fname + ', 30000) ...')
                  const vr = await Promise.race([Promise.resolve(lq.vy(arg, 30000)).catch(e => ({ __err: (e && e.message) || String(e), __stack: (e && e.stack || '').split('\n').filter(l => /recaptcha__en/.test(l)).slice(0, 3).map(l => l.trim().replace(/.*(recaptcha__en[^:]*:\d+:\d+).*/, '$1')).join(' <- ') })), new Promise(r => setTimeout(() => r({ __timeout: true }), parseInt(process.env.VYWAIT || '60000', 10)))])
                  if (vr && vr.__err) { log('[emp][AKRUN] vy(' + fname + ') REJECTED: ' + vr.__err + ' | ' + (vr.__stack || '')) ; continue }
                  if (vr && vr.__timeout) { log('[emp][AKRUN] vy(' + fname + ') did not settle in ' + Math.round(parseInt(process.env.VYWAIT||'60000',10)/1000) + 's (hb ticks => async-wait not CPU-block; workerReplies tells if worker answered)') }
                  else { let vl = 0; try { const rq = vr && (vr.request || vr.D); vl = rq ? (rq.length || String(rq).length) : 0 } catch {} log('[emp][AKRUN] vy(' + fname + ') settled: attestation len=' + vl) }
                  await new Promise(r => setTimeout(r, 800))
                  const snap2 = await Promise.resolve(lq.Dw()).catch(e => ({ __err: e && e.message }))
                  const rq2 = snap2 && !snap2.__err && (snap2.request != null ? snap2.request : snap2.D)
                  const b2 = rq2 == null ? null : (Buffer.isBuffer(rq2) ? rq2 : Buffer.from(String(rq2), 'latin1'))
                  const md52 = b2 && b2.length ? crypto.createHash('md5').update(b2).digest('hex').slice(0, 8) : 'empty'
                  log('[emp][AKRUN] >>> after vy(' + fname + '): Dw().request len=' + (b2 ? b2.length : 0) + ' md5=' + md52 + (b2 && b2.length ? '  <<< NATIVE bgRequest CANDIDATE' : ''))
                  if (b2 && b2.length) { NATIVE_F16 = b2; break }
                } catch (e) { log('[emp][AKRUN] vy(' + fname + ') outer threw ' + (e && e.message)) }
              }
              clearInterval(__hb)
            }
          }
        }
      } catch (e) { log('[emp][AKRUN] err ' + (e && e.message)) }
    }, process.env.AKRUN === '1' ? 6000 : (parseInt(process.env.AKRUN, 10) || 6000))
  }

  if (process.env.BFINJECTN) {
    setTimeout(() => {
      try {
        let nFrame = null
        try { const cf = JSON.parse(fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/comm_full.json', 'utf8')); nFrame = (cf.anchor.out || []).find(s => { try { return JSON.parse(s)[1] === 'n' } catch { return false } }) } catch {}
        const nAE = BFRAME_AES.find(ae => { try { const inner = ae.P && ae.P._inner; return inner && inner.has && inner.has('n') } catch { return false } })
        if (!nFrame) return log('[emp][BFINJECTN] no "n" frame in comm_full.json')
        if (!nAE) return log('[emp][BFINJECTN] no bframe AE with "n" handler (AEs=' + BFRAME_AES.length + ')')
        const port = nAE.D, peer = port && port._peer
        log('[emp][BFINJECTN] injecting real "n" (' + nFrame.length + 'B) onto bframe channel port=' + (port && port.__id) + ' peer=' + (peer && peer.__id) + '...')
        if (peer) peer.postMessage(nFrame); else if (port && port._deliver) port._deliver({ data: nFrame, ports: [] })
      } catch (e) { log('[emp][BFINJECTN] err', e.message) }
    }, 7000)
  }

  log('[emp] waiting for /reload (bframe realm booting)...')
  const winner = await Promise.race([firstReload, new Promise(r => setTimeout(() => r(null), parseInt(process.env.RELOADWAIT || '120000', 10)))])
  if (winner) {
    log('[emp] /reload intercepted — awaiting server response (up to 15s)...')
    const resp = await Promise.race([firstReloadResp, new Promise(r => setTimeout(() => r(null), 15000))])
    if (resp) {
      log('[emp] >>> /reload SERVER RESPONSE: status=' + resp.status + ' len=' + resp.len)
      log('[emp] >>> head: ' + (resp.text || '').slice(0, 300).replace(/\n/g, ' '))
      // decide accept vs soft-block: a real challenge response is a )]}'-array with a payload token
      const advanced = /"?rresp"?|payload|dynamic|multicaptcha|pmeta/.test(resp.text || '')
      log('[emp] >>> VERDICT: ' + (resp.status === 200 && advanced ? 'SERVER ACCEPTED field16 — real challenge returned (ADVANCED)' : (resp.status === 200 ? 'HTTP 200 but no challenge markers — inspect emp_reload_resp' : 'status ' + resp.status)))
    } else { log('[emp] >>> /reload response did NOT return within 15s (network-restricted or fetch stalled)') }
  }

  log('\n[emp] ===== RESULT =====')
  log('parent created bframe iframe:', !!parent.bframeSrc, parent.bframeSrc ? '(' + parent.bframeSrc.slice(0, 80) + ')' : '')
  log('anchor click listeners:', clickable(anchor.ALL_ELS).length, '| reloads intercepted:', RELOADS.length)
  RELOADS.forEach((R, i) => log(`  reload#${i + 1}: ${R.buf.length}B | field16 ${R.info.present ? R.info.len + 'B' : 'EMPTY'} | ${JSON.stringify(R.info.map)}`))
  if (clickable(anchor.ALL_ELS).length || RELOADS.length || parent.bframeSrc) {
    log('[emp] SUCCESS SIGNAL: the emulated parent drove the anchor past the setup gate.')
  } else {
    log('[emp] NOT INTERACTIVE — but the bridge is structurally COMPLETE up to the codec:')
    log('     * parent (api.js role) auto-rendered, created the anchor <iframe>, installed the intake')
    log('     * the anchor TRANSFERRED its comm port; the parent ADOPTED it and bound the REAL parent')
    log('       AE (handler map includes the conf opcode "C") on that port (see "AE#1 port=8 ... C")')
    log('     * the anchor\'s "C"/"z" frames ARRIVE at the parent AE (taps fire), listener is bound')
    log('     CONFIRMED BLOCKER (riskiest unknown): the cross-frame AE payload is keyed by a PER-SESSION')
    log('     secret that the two independently-booted en.js realms DO NOT share. Proof: the anchor "C"')
    log('     frame decodes ONLY with the anchor realm\'s own recovered keystream (-> conf JSON), the')
    log('     parent AE holds a different key, so its dispatch decode fails silently (no throw, handler')
    log('     never runs) and no MZ render-response is emitted -> anchor stays non-interactive.')
    log('     NEXT: copy the anchor realm\'s AE session SEED into the parent codec (the keystream is')
    log('     re-derived per frame from messageType+callId, so one recovered keystream is NOT enough —')
    log('     the C-frame key does not decode the z-frame). Locate the seed slot in C[23]/the AE ctor.')
  }
  process.exit(0)
}

if (require.main === module) main()
module.exports = { buildParentRealm, buildAnchorRealm, makeDriverXHR, extractInitCall, RELOADS }
