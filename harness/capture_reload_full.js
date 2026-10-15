// capture_reload_full.js — STEP 1 of the field16 HTTP-replay experiment.
//
// Based on capture_reload_net.js (puppeteer-real-browser + CDP auto-attach, captures the
// bframe's FIRST POST /recaptcha/api2/reload). Extended to record, for reload#1, EVERYTHING
// needed to replay it verbatim over HTTP:
//   REQUEST : method, url, all request headers (incl Referer w/ bft, Content-Type, Origin,
//             Cookie via requestWillBeSentExtraInfo) and the raw POST body bytes (base64).
//   RESPONSE: status, response headers (incl Set-Cookie via responseReceivedExtraInfo) and the
//             raw response BODY bytes (base64) via CDP Network.getResponseBody.
//   COOKIES : document.cookie of the bframe, plus all google.* cookies via Network.getAllCookies
//             (with the _GRECAPTCHA value pulled out).
//   bframe URL (with bft).
// Saved to reload_full_capture.json. Then, because field16/session is time-bound, it IMMEDIATELY
// chains into replay_reload.js in the SAME invocation.
'use strict'
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require(ROOT + '\\node_modules\\puppeteer-real-browser')
const pb = require('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\pb.js')
const { runReplay } = require('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\replay_reload.js')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\reload_full_capture.json'
const DEMO = process.env.DEMO_URL || 'https://2captcha.com/demo/recaptcha-v2'

const FILTER = /\/recaptcha\/api2\/(reload|bframe|userverify|payload|replaceimage)/
const isReloadUrl = u => /\/recaptcha\/api2\/reload/.test(u)

// scan the reload POST body: top-level {field: byteLen} + field16(bgRequest) length.
function scanProto(buf) {
  const fields = {}; const detail = []
  try {
    for (const f of pb.decode(buf)) {
      const len = f.wire === 2 ? f.len : (f.wire === 0 ? Buffer.from(pb.encVarint(f.value)).length : f.wire === 5 ? 4 : f.wire === 1 ? 8 : 0)
      fields[f.field] = len
      detail.push({ field: f.field, wire: f.wire, type: f.type, len })
    }
  } catch (e) { detail.push({ err: String(e) }) }
  return { fields, detail }
}

// per-requestId capture state
const reqInfo = new Map()      // requestId -> {url,method,headers,documentURL,hasPostData,postData}
const reqExtra = new Map()     // requestId -> extra request headers (incl cookie)
const respInfo = new Map()     // requestId -> {status, headers, mimeType}
const respExtra = new Map()    // requestId -> {headers, setCookie}
const respBody = new Map()     // requestId -> {b64, base64Encoded}
let firstReloadId = null       // requestId of the bframe's FIRST POST /reload
let firstReloadCh = null       // CDP session that owns it (needed for getResponseBody)
let bodyReadyResolve
const bodyReady = new Promise(r => { bodyReadyResolve = r })

async function fetchPostData(ch, requestId) {
  const info = reqInfo.get(requestId)
  let body = info && info.postData
  if ((body == null || body === '') && info && info.hasPostData) {
    try { const r = await ch.send('Network.getRequestPostData', { requestId }); body = r && r.postData } catch (e) { info.postDataErr = String(e) }
  }
  if (body == null) return null
  return Buffer.from(body, 'latin1') // preserve raw bytes
}

function wire(ch) {
  ch.on('Network.requestWillBeSent', p => {
    const url = p.request.url
    if (!FILTER.test(url)) return
    reqInfo.set(p.requestId, {
      requestId: p.requestId, url, method: p.request.method,
      headers: p.request.headers || {}, documentURL: p.documentURL,
      hasPostData: !!p.request.hasPostData,
      postData: p.request.postData != null ? p.request.postData : null
    })
    if (isReloadUrl(url) && p.request.method === 'POST' && firstReloadId == null) {
      firstReloadId = p.requestId; firstReloadCh = ch
      console.log('[+] first POST /reload seen, requestId', p.requestId)
    }
  })
  ch.on('Network.requestWillBeSentExtraInfo', p => {
    // includes the REAL headers actually put on the wire (Cookie, etc.)
    if (p.headers) reqExtra.set(p.requestId, p.headers)
  })
  ch.on('Network.responseReceived', p => {
    if (!FILTER.test(p.response.url)) return
    respInfo.set(p.requestId, { status: p.response.status, headers: p.response.headers || {}, mimeType: p.response.mimeType, url: p.response.url })
  })
  ch.on('Network.responseReceivedExtraInfo', p => {
    if (!respExtra.has(p.requestId)) respExtra.set(p.requestId, { headers: p.headers || {}, setCookie: p.headers && (p.headers['set-cookie'] || p.headers['Set-Cookie']) || null })
  })
  ch.on('Network.loadingFinished', async p => {
    if (p.requestId !== firstReloadId) return
    try {
      const r = await ch.send('Network.getResponseBody', { requestId: p.requestId })
      // CDP: if base64Encoded, body is already base64; else body is a string (decoded text).
      const b64 = r.base64Encoded ? r.body : Buffer.from(r.body, 'latin1').toString('base64')
      respBody.set(p.requestId, { b64, base64Encoded: r.base64Encoded })
      console.log('[+] captured reload#1 response body:', Buffer.from(b64, 'base64').length, 'bytes')
    } catch (e) {
      respBody.set(p.requestId, { b64: null, err: String(e) })
      console.log('[!] getResponseBody failed:', String(e))
    }
    bodyReadyResolve()
  })
  ch.on('Network.loadingFailed', p => {
    if (p.requestId === firstReloadId) { respBody.set(p.requestId, { b64: null, err: 'loadingFailed:' + p.errorText }); bodyReadyResolve() }
  })
}

;(async () => {
  let browser
  try {
    ({ browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } }))
  } catch (e) {
    console.log('FATAL: puppeteer-real-browser could not launch:', e.stack || e)
    process.exit(1)
  }
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()
  let userAgent = null
  try { userAgent = await page.evaluate(() => navigator.userAgent) } catch {}

  client.on('Target.attachedToTarget', async e => {
    const ch = conn.session(e.sessionId); if (!ch) return
    try {
      if (e.targetInfo.type === 'page' || e.targetInfo.type === 'iframe') {
        await ch.send('Network.enable').catch(() => {})
        wire(ch)
      }
    } catch {}
    try { await ch.send('Runtime.runIfWaitingForDebugger') } catch {}
  })

  await client.send('Network.enable').catch(() => {})
  wire(client)
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: true })

  await page.goto(DEMO, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)

  // click the anchor checkbox
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('[+] clicked checkbox')

  await sleep(10000)

  // wait (bounded) for the reload#1 response body to be pulled
  if (firstReloadId != null) await Promise.race([bodyReady, sleep(4000)])

  // bframe URL (with bft) + bframe document.cookie
  let bframeUrl = null, bframeCookie = null, bft = null
  for (const f of page.frames()) { const u = f.url(); if (/api2\/bframe/.test(u)) { bframeUrl = u; const m = u.match(/[?&]bft=([^&]+)/); if (m) bft = decodeURIComponent(m[1]); try { bframeCookie = await f.evaluate(() => document.cookie) } catch {} } }
  if (!bframeUrl) {
    const src = await page.evaluate(() => { const i = [...document.querySelectorAll('iframe')].find(x => /bframe/.test(x.src)); return i ? i.src : null }).catch(() => null)
    if (src) { bframeUrl = src; const m = src.match(/[?&]bft=([^&]+)/); if (m) bft = decodeURIComponent(m[1]) }
  }

  // all google.* cookies via CDP (browser-wide), pull out _GRECAPTCHA
  let googleCookies = [], grecaptcha = null
  try {
    const all = await client.send('Network.getAllCookies')
    googleCookies = (all.cookies || []).filter(c => /google\./.test(c.domain))
    const g = googleCookies.find(c => c.name === '_GRECAPTCHA')
    if (g) grecaptcha = g.value
  } catch (e) { console.log('[!] getAllCookies failed', String(e)) }

  // ---- assemble reload#1 record ----
  let reload1 = null, note = null
  if (firstReloadId != null) {
    const info = reqInfo.get(firstReloadId)
    const bodyBuf = await fetchPostData(firstReloadCh, firstReloadId)
    const extra = reqExtra.get(firstReloadId) || {}
    // merged (lowercased) headers: base request headers overlaid with the real on-wire extra headers
    const headersAll = {}
    for (const [k, v] of Object.entries(info.headers || {})) headersAll[k.toLowerCase()] = v
    for (const [k, v] of Object.entries(extra)) headersAll[k.toLowerCase()] = v
    const rinfo = respInfo.get(firstReloadId) || {}
    const rextra = respExtra.get(firstReloadId) || {}
    const rbody = respBody.get(firstReloadId) || {}
    let protoFields = {}, f16 = 'ABSENT'
    if (bodyBuf) { const s = scanProto(bodyBuf); protoFields = s.fields; f16 = (16 in s.fields) ? s.fields[16] : 'ABSENT' }
    reload1 = {
      request: {
        url: info.url, method: info.method,
        headers: info.headers || {},        // as reported by requestWillBeSent
        extraHeaders: extra,                 // real on-wire headers (incl cookie)
        headersAll,                          // merged, lowercased (used by replay)
        bodyB64: bodyBuf ? bodyBuf.toString('base64') : null,
        bodyLen: bodyBuf ? bodyBuf.length : 0,
        contentType: headersAll['content-type'] || null,
        referer: headersAll['referer'] || null,
        origin: headersAll['origin'] || null,
        cookieHeader: headersAll['cookie'] || null,
        protoFields, field16_bgRequest_len: f16,
        bftInReferer: !!(bft && headersAll['referer'] && headersAll['referer'].indexOf(bft) >= 0)
      },
      response: {
        status: rinfo.status || null,
        mimeType: rinfo.mimeType || null,
        headers: rinfo.headers || {},
        extraHeaders: rextra.headers || {},
        setCookie: rextra.setCookie || null,
        bodyB64: rbody.b64 || null,
        bodyLen: rbody.b64 ? Buffer.from(rbody.b64, 'base64').length : 0,
        bodyErr: rbody.err || null
      }
    }
  } else {
    note = 'No POST /recaptcha/api2/reload was captured (checkbox may not have triggered a challenge, or launch/flow failed).'
    console.log('[!]', note)
  }

  const result = {
    meta: { demo: DEMO, userAgent, capturedAt: new Date().toISOString(), capturedAtMs: Date.now() },
    bframe: { url: bframeUrl, bft, documentCookie: bframeCookie },
    cookies: { google: googleCookies.map(c => ({ name: c.name, value: c.value, domain: c.domain, path: c.path })), grecaptcha },
    reload1, note
  }
  fs.writeFileSync(OUT, JSON.stringify(result, null, 1))
  console.log('\nsaved', OUT)
  if (reload1) {
    console.log('reload#1 request  :', reload1.request.method, reload1.request.url)
    console.log('  body            :', reload1.request.bodyLen, 'bytes | protoFields', JSON.stringify(reload1.request.protoFields), '| field16', reload1.request.field16_bgRequest_len)
    console.log('  referer(bft)    :', reload1.request.bftInReferer, '|', (reload1.request.referer || '').slice(0, 80))
    console.log('  cookie present  :', !!reload1.request.cookieHeader, '| _GRECAPTCHA', grecaptcha ? 'captured' : 'absent')
    console.log('reload#1 response :', reload1.response.status, '|', reload1.response.bodyLen, 'bytes', reload1.response.bodyErr ? '(bodyErr: ' + reload1.response.bodyErr + ')' : '')
  }

  // close the browser BEFORE replay so we're a pure HTTP client, then chain replay immediately.
  await sleep(400); try { await browser.close() } catch {}

  if (reload1 && reload1.request.bodyB64) {
    console.log('\n[+] chaining into HTTP replay (same invocation, session is time-bound)…')
    try { await runReplay(OUT) } catch (e) { console.log('[replay] error', e.stack || e) }
  } else {
    console.log('[!] skipping replay — no reload#1 body captured.')
  }
  process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
