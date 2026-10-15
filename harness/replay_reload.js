// replay_reload.js — STEP 2 of the field16 HTTP-replay experiment.
//
// Reads reload_full_capture.json (produced by capture_reload_full.js) and replays the
// captured browser's FIRST POST /recaptcha/api2/reload byte-for-byte over Node `fetch`:
//   same URL, same raw POST body bytes, same UA / Referer / Content-Type / Origin, and the
//   captured google cookies (incl _GRECAPTCHA). It then:
//     - prints response status + length,
//     - checks whether the replay response body is BYTE-IDENTICAL to the browser's (base64 cmp),
//     - minimally deobfuscates both bodies ( )]}' + JSON array, or protobuf ) and pulls the
//       challenge/payload tokens (array idx ~1 and ~9) + any bgdata/dynamic markers,
//     - repeats the replay 2 more times to see whether the server issues a fresh/advancing
//       challenge (bytes change) or a degenerate/soft-blocked reply (bytes identical).
//
// Exports runReplay() so capture_reload_full.js can chain capture->replay in ONE invocation
// (field16 / session is time-bound, so replay must be immediate).
'use strict'
const fs = require('fs')
const pb = require('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\pb.js')
const DEFAULT_CAP = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\reload_full_capture.json'

// ---- minimal deobfuscation of a /reload response body buffer ----
// Standard reCAPTCHA /reload replies are  )]}'\n[ ...json-ish array... ].  Newer x-protobuffer
// flows may return a binary protobuf.  Return a normalized view either way.
function decodeReload(buf) {
  if (!buf || !buf.length) return { kind: 'empty', first200: '', tokens: {} }
  const isJsonEnvelope = buf.length >= 4 && buf[0] === 0x29 && buf[1] === 0x5d && buf[2] === 0x7d && buf[3] === 0x27 // )]}'
  const asText = buf.toString('utf8')
  if (isJsonEnvelope) {
    // strip )]}'\n , then JSON.parse
    let payload = asText.replace(/^\)\]\}'\s*/, '')
    let arr = null, parseErr = null
    try { arr = JSON.parse(payload) } catch (e) { parseErr = String(e) }
    const tokens = {}
    if (Array.isArray(arr)) {
      tokens.idx0 = trunc(arr[0])
      tokens.idx1 = trunc(arr[1])
      tokens.idx9 = trunc(arr[9])
      tokens.arrayLen = arr.length
    }
    tokens.hasBgdata = /bgdata|dynamic|payload/i.test(payload)
    return { kind: 'json', parseErr, first200: payload.slice(0, 200), tokens, arr: Array.isArray(arr) ? arr : null }
  }
  // maybe protobuf
  let fields = {}, protoErr = null
  try {
    for (const f of pb.decode(buf)) {
      const len = f.wire === 2 ? f.len : (f.wire === 0 ? String(f.value).length : f.wire === 5 ? 4 : f.wire === 1 ? 8 : 0)
      fields[f.field] = (f.type || f.wire) + ':' + len
    }
  } catch (e) { protoErr = String(e) }
  const printable = asText.slice(0, 200).replace(/[^\x20-\x7e]/g, '.')
  return { kind: 'binary/proto', protoErr, first200: printable, tokens: { protoFields: fields }, arr: null }
}
function trunc(v) {
  if (v == null) return v === null ? 'null' : undefined
  let s = typeof v === 'string' ? v : JSON.stringify(v)
  return s.length > 80 ? s.slice(0, 80) + `…(${s.length})` : s
}

// ---- build the replay headers from the captured request ----
function buildHeaders(cap) {
  const req = cap.reload1.request
  const H = req.headersAll || req.headers || {}
  const get = (name) => {
    const k = Object.keys(H).find(x => x.toLowerCase() === name)
    return k ? H[k] : null
  }
  const headers = {}
  const ct = get('content-type'); if (ct) headers['content-type'] = ct
  const ref = get('referer'); if (ref) headers['referer'] = ref
  const org = get('origin'); if (org) headers['origin'] = org
  const ua = get('user-agent') || (cap.meta && cap.meta.userAgent); if (ua) headers['user-agent'] = ua
  const acc = get('accept'); if (acc) headers['accept'] = acc
  const al = get('accept-language'); if (al) headers['accept-language'] = al
  // Cookie: prefer the exact Cookie header the browser sent; else reconstruct from google cookies.
  let cookie = get('cookie')
  if (!cookie) {
    const gc = (cap.cookies && cap.cookies.google) || []
    if (gc.length) cookie = gc.map(c => `${c.name}=${c.value}`).join('; ')
    else if (cap.cookies && cap.cookies.grecaptcha) cookie = `_GRECAPTCHA=${cap.cookies.grecaptcha}`
  }
  if (cookie) headers['cookie'] = cookie
  return headers
}

async function doReplay(cap, headers, label) {
  const req = cap.reload1.request
  const bodyBuf = Buffer.from(req.bodyB64, 'base64')
  const t0 = Date.now()
  let res, buf, err = null
  try {
    res = await fetch(req.url, { method: req.method || 'POST', headers, body: bodyBuf, redirect: 'manual' })
    const ab = await res.arrayBuffer()
    buf = Buffer.from(ab)
  } catch (e) { err = String(e && e.stack || e) }
  if (err) return { label, error: err }
  const respHeaders = {}
  for (const [k, v] of res.headers) respHeaders[k] = v
  return {
    label, ms: Date.now() - t0,
    status: res.status, statusText: res.statusText,
    len: buf.length, bodyB64: buf.toString('base64'),
    respHeaders, decoded: decodeReload(buf)
  }
}

async function runReplay(capPath) {
  capPath = capPath || DEFAULT_CAP
  if (!fs.existsSync(capPath)) { console.log('[replay] capture file not found:', capPath); return null }
  const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'))
  if (!cap.reload1 || !cap.reload1.request || !cap.reload1.request.bodyB64) {
    console.log('[replay] capture has no reload#1 request body — nothing to replay. capture note:', cap.note || '(none)')
    return null
  }

  const browserResp = cap.reload1.response || {}
  const browserBodyB64 = browserResp.bodyB64 || null
  const browserBuf = browserBodyB64 ? Buffer.from(browserBodyB64, 'base64') : null
  const browserDecoded = browserBuf ? decodeReload(browserBuf) : { kind: 'MISSING', first200: '', tokens: {} }

  const headers = buildHeaders(cap)
  const req = cap.reload1.request
  const bodyLen = Buffer.from(req.bodyB64, 'base64').length
  const f16 = (cap.reload1.request.field16_bgRequest_len)

  console.log('\n================ REPLAY (field16 HTTP-replay experiment) ================')
  console.log('capture age at replay start:', cap.meta ? (Date.now() - cap.meta.capturedAtMs) + ' ms' : 'unknown')
  console.log('reload#1 URL :', req.url)
  console.log('reload#1 body:', bodyLen, 'bytes | field16(bgRequest):', f16, '| content-type:', headers['content-type'])
  console.log('referer      :', headers['referer'])
  console.log('origin       :', headers['origin'])
  console.log('cookie sent  :', headers['cookie'] ? (headers['cookie'].slice(0, 80) + (headers['cookie'].length > 80 ? '…' : '')) : '(NONE)')
  console.log('_GRECAPTCHA  :', /(_GRECAPTCHA=)/.test(headers['cookie'] || '') ? 'present in Cookie' : 'ABSENT')

  const replays = []
  for (let i = 1; i <= 3; i++) {
    const r = await doReplay(cap, headers, 'replay#' + i)
    replays.push(r)
    if (r.error) { console.log(`\n[${r.label}] FETCH ERROR: ${r.error.split('\n')[0]}`); continue }
    const identicalToBrowser = browserBodyB64 != null && r.bodyB64 === browserBodyB64
    console.log(`\n[${r.label}] HTTP ${r.status} ${r.statusText || ''} | ${r.len} bytes | ${r.ms}ms`)
    console.log(`  content-type: ${r.respHeaders['content-type'] || '(none)'}`)
    console.log(`  byte-identical to BROWSER response: ${browserBodyB64 == null ? 'N/A (browser body not captured)' : identicalToBrowser}`)
    console.log(`  decoded kind: ${r.decoded.kind} | tokens: ${JSON.stringify(r.decoded.tokens)}`)
    console.log(`  first200 (deobf): ${JSON.stringify(r.decoded.first200)}`)
  }

  // ---- cross-replay comparison: does the server return a FRESH challenge on repeat? ----
  const ok = replays.filter(r => !r.error)
  let repeatVerdict = 'inconclusive'
  if (ok.length >= 2) {
    const allSame = ok.every(r => r.bodyB64 === ok[0].bodyB64)
    repeatVerdict = allSame ? 'IDENTICAL across repeats (static/degenerate reply)' : 'DIFFER across repeats (server issuing changing content)'
  }

  // ---- token match browser vs replay ----
  const r1 = ok[0]
  let tokenMatch = 'N/A'
  if (r1 && browserBuf) {
    const bt = JSON.stringify(browserDecoded.tokens)
    const rt = JSON.stringify(r1.decoded.tokens)
    tokenMatch = (bt === rt) ? 'SAME tokens as browser' : 'DIFFERENT tokens than browser'
  }

  console.log('\n================ BROWSER (captured) reload#1 response ================')
  console.log('status:', browserResp.status, '| len:', browserBuf ? browserBuf.length : '(NOT CAPTURED)')
  console.log('decoded kind:', browserDecoded.kind, '| tokens:', JSON.stringify(browserDecoded.tokens))
  console.log('first200 (deobf):', JSON.stringify(browserDecoded.first200))

  // ---- VERDICT ----
  const statuses = ok.map(r => r.status)
  const anyIdenticalToBrowser = browserBodyB64 != null && ok.some(r => r.bodyB64 === browserBodyB64)
  // Heuristic for "real advancing challenge": HTTP 200 AND response carries challenge payload
  // tokens (json envelope with a non-null idx1/idx9 or a bgdata/dynamic marker) that look like a
  // genuine issued challenge, not an error/degenerate blob.
  const looksReal = r1 && r1.status === 200 && r1.decoded.kind === 'json' &&
    (r1.decoded.tokens.hasBgdata || (r1.decoded.tokens.idx1 && r1.decoded.tokens.idx1 !== 'null') || (r1.decoded.tokens.idx9 && r1.decoded.tokens.idx9 !== 'null'))

  console.log('\n================ VERDICT ================')
  console.log('replay HTTP statuses      :', JSON.stringify(statuses))
  console.log('replay repeats            :', repeatVerdict)
  console.log('replay vs browser tokens  :', tokenMatch)
  console.log('replay body == browser    :', anyIdenticalToBrowser)
  const verdict = looksReal
    ? 'field16 HTTP-replay DOES yield a real advancing challenge (HTTP 200 + genuine challenge payload).'
    : 'field16 HTTP-replay DOES NOT yield a real advancing challenge (soft-block / degenerate reply).'
  console.log('>>>', verdict)

  const out = {
    capturedAtMs: cap.meta ? cap.meta.capturedAtMs : null,
    replayAtMs: Date.now(),
    reloadUrl: req.url, reqBodyLen: bodyLen, field16: f16,
    headersSent: headers,
    browser: { status: browserResp.status, len: browserBuf ? browserBuf.length : null, decoded: browserDecoded },
    replays: replays.map(r => r.error ? { label: r.label, error: r.error } : {
      label: r.label, status: r.status, len: r.len, respHeaders: r.respHeaders, decoded: r.decoded,
      byteIdenticalToBrowser: browserBodyB64 != null && r.bodyB64 === browserBodyB64
    }),
    analysis: { repeatVerdict, tokenMatch, anyIdenticalToBrowser, verdict }
  }
  const outPath = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\replay_result.json'
  fs.writeFileSync(outPath, JSON.stringify(out, null, 1))
  console.log('\nsaved', outPath)
  return out
}

module.exports = { runReplay, decodeReload }

if (require.main === module) {
  runReplay(process.argv[2]).catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
}
