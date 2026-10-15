// serve_and_capture.js — STEP 1 of the HYBRID test (own key).
//
// 1. Serves a local page containing <div class="g-recaptcha" data-sitekey=OWN> + api.js.
//    The browser is launched with --host-resolver-rules MAP lucille.sh -> 127.0.0.1:PORT, and
//    navigates to http://lucille.sh/, so the page ORIGIN hostname == the key's registered
//    domain (lucille.sh). This satisfies origin verification whether it is ON or OFF.
// 2. Launches Edge (puppeteer-real-browser), clicks the anchor checkbox, lets the bframe mint a
//    VALID field16 and POST /recaptcha/api2/reload. Captures EVERY reload (raw body b64 + real
//    on-wire headers incl Cookie + response body), the bframe URL (bft), _GRECAPTCHA, UA, anchor c.
// 3. Writes capture_own.json, closes the browser, and IMMEDIATELY chains into solve_hybrid.py
//    (field16 / session is time-bound => replay must be immediate).
'use strict'
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const http = require('http')
const { execFileSync } = require('child_process')
const { connect } = require(ROOT + '\\node_modules\\puppeteer-real-browser')
const pb = require('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\pb.js')
const sleep = ms => new Promise(r => setTimeout(r, ms))

const HYB = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\hybrid'
const OUT = HYB + '\\capture_own.json'
const KEY = JSON.parse(fs.readFileSync('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\own_key.json', 'utf8'))
const SITEKEY = KEY.sitekey
const DOMAIN = KEY.domain              // lucille.sh

const FILTER = /\/recaptcha\/api2\/(reload|bframe|userverify|payload|replaceimage|anchor)/
const isReload = u => /\/recaptcha\/api2\/reload/.test(u)

const PAGE_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>own-key test</title>
<script src="https://www.google.com/recaptcha/api.js" async defer></script></head>
<body style="font-family:sans-serif;padding:40px"><h3>own-key hybrid capture</h3>
<form action="?" method="POST"><div class="g-recaptcha" data-sitekey="${SITEKEY}"></div></form>
</body></html>`

function scanProto(buf) {
  const fields = {}
  try { for (const f of pb.decode(buf)) { fields[f.field] = f.wire === 2 ? f.len : (f.wire === 0 ? Buffer.from(pb.encVarint(f.value)).length : f.wire === 5 ? 4 : f.wire === 1 ? 8 : 0) } } catch (e) {}
  return fields
}

// per-requestId capture
const reqInfo = new Map(), reqExtra = new Map(), respBody = new Map(), respMeta = new Map()
const reloadIds = []
const chById = new Map()

function wire(ch) {
  ch.on('Network.requestWillBeSent', p => {
    const url = p.request.url; if (!FILTER.test(url)) return
    reqInfo.set(p.requestId, { url, method: p.request.method, headers: p.request.headers || {}, hasPostData: !!p.request.hasPostData, postData: p.request.postData != null ? p.request.postData : null })
    chById.set(p.requestId, ch)
    if (isReload(url) && p.request.method === 'POST') { reloadIds.push(p.requestId) }
  })
  ch.on('Network.requestWillBeSentExtraInfo', p => { if (p.headers) reqExtra.set(p.requestId, p.headers) })
  ch.on('Network.responseReceived', p => { if (FILTER.test(p.response.url)) respMeta.set(p.requestId, { status: p.response.status, mimeType: p.response.mimeType }) })
  ch.on('Network.loadingFinished', async p => {
    if (!isReload((reqInfo.get(p.requestId) || {}).url || '')) return
    try { const r = await ch.send('Network.getResponseBody', { requestId: p.requestId }); const b64 = r.base64Encoded ? r.body : Buffer.from(r.body, 'latin1').toString('base64'); respBody.set(p.requestId, b64) } catch (e) { respBody.set(p.requestId, null) }
  })
}

async function fetchPostData(ch, requestId) {
  const info = reqInfo.get(requestId); let body = info && info.postData
  if ((body == null || body === '') && info && info.hasPostData) { try { const r = await ch.send('Network.getRequestPostData', { requestId }); body = r && r.postData } catch (e) {} }
  return body == null ? null : Buffer.from(body, 'latin1')
}

;(async () => {
  // ---- local server ----
  const server = http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(PAGE_HTML) })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  const PORT = server.address().port
  const NAV = `http://${DOMAIN}/`
  console.log(`[+] local server on 127.0.0.1:${PORT} ; nav ${NAV} (MAP ${DOMAIN} -> 127.0.0.1:${PORT})`)

  let browser
  try {
    ({ browser } = await connect({ headless: false, turnstile: true,
      args: ['--start-maximized', `--host-resolver-rules=MAP ${DOMAIN} 127.0.0.1:${PORT}`],
      connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } }))
  } catch (e) { console.log('FATAL launch:', e.stack || e); process.exit(1) }

  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()
  let userAgent = null; try { userAgent = await page.evaluate(() => navigator.userAgent) } catch {}

  client.on('Target.attachedToTarget', async e => {
    const ch = conn.session(e.sessionId); if (!ch) return
    try { if (e.targetInfo.type === 'page' || e.targetInfo.type === 'iframe') { await ch.send('Network.enable').catch(() => {}); wire(ch) } } catch {}
    try { await ch.send('Runtime.runIfWaitingForDebugger') } catch {}
  })
  await client.send('Network.enable').catch(() => {})
  wire(client)
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: true })

  await page.goto(NAV, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(4000)

  // read any reCAPTCHA error text (invalid domain / key)
  let widgetErr = null
  try { widgetErr = await page.evaluate(() => { const e = document.querySelector('.rc-anchor-error-msg, .rc-anchor-invalid-msg'); return e ? e.textContent : null }) } catch {}

  // click the anchor checkbox
  let clicked = false
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) { await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {}); clicked = true }
  console.log('[+] clicked checkbox:', clicked)
  await sleep(12000)

  // bframe url (bft) + version, and anchor c token
  let bframeUrl = null, bft = null, version = null, anchorC = null
  for (const f of page.frames()) {
    const u = f.url()
    if (/api2\/bframe/.test(u)) { bframeUrl = u; const m = u.match(/[?&]bft=([^&]+)/); if (m) bft = decodeURIComponent(m[1]); const v = u.match(/[?&]v=([^&]+)/); if (v) version = v[1] }
    if (/api2\/anchor/.test(u)) { const v = u.match(/[?&]v=([^&]+)/); if (v && !version) version = v[1]; try { anchorC = await f.evaluate(() => document.getElementById('recaptcha-token')?.value || null) } catch {} }
  }
  if (!bframeUrl) { const src = await page.evaluate(() => { const i = [...document.querySelectorAll('iframe')].find(x => /bframe/.test(x.src)); return i ? i.src : null }).catch(() => null); if (src) { bframeUrl = src; const m = src.match(/[?&]bft=([^&]+)/); if (m) bft = decodeURIComponent(m[1]); const v = src.match(/[?&]v=([^&]+)/); if (v) version = v[1] } }

  // _GRECAPTCHA
  let grecaptcha = null, googleCookies = []
  try { const all = await client.send('Network.getAllCookies'); googleCookies = (all.cookies || []).filter(c => /google\./.test(c.domain)); const g = googleCookies.find(c => c.name === '_GRECAPTCHA'); if (g) grecaptcha = g.value } catch (e) {}

  // ---- assemble all reloads, pick the one with the biggest field16 ----
  const reloads = []
  for (const id of reloadIds) {
    const info = reqInfo.get(id); if (!info) continue
    const bodyBuf = await fetchPostData(chById.get(id), id)
    const extra = reqExtra.get(id) || {}
    const merged = {}; for (const [k, v] of Object.entries(info.headers || {})) merged[k.toLowerCase()] = v; for (const [k, v] of Object.entries(extra)) merged[k.toLowerCase()] = v
    const fields = bodyBuf ? scanProto(bodyBuf) : {}
    reloads.push({
      url: info.url, method: info.method,
      bodyB64: bodyBuf ? bodyBuf.toString('base64') : null, bodyLen: bodyBuf ? bodyBuf.length : 0,
      contentType: merged['content-type'] || null, referer: merged['referer'] || null,
      origin: merged['origin'] || null, cookie: merged['cookie'] || null,
      field16_len: (16 in fields) ? fields[16] : 0, protoFields: fields,
      responseB64: respBody.get(id) || null, responseStatus: (respMeta.get(id) || {}).status || null
    })
  }
  reloads.sort((a, b) => (b.field16_len || 0) - (a.field16_len || 0))
  const best = reloads[0] || null

  const result = {
    meta: { nav: NAV, domain: DOMAIN, sitekey: SITEKEY, userAgent, widgetError: widgetErr, checkboxClicked: clicked,
            capturedAt: new Date().toISOString(), capturedAtMs: Date.now(), nReloads: reloads.length },
    version, bft, bframeUrl, anchorC, grecaptcha,
    cookies: googleCookies.map(c => ({ name: c.name, value: c.value, domain: c.domain })),
    reload: best, allReloads: reloads
  }
  fs.writeFileSync(OUT, JSON.stringify(result, null, 1))
  console.log('\n[+] saved', OUT)
  console.log('    widgetError :', widgetErr)
  console.log('    nReloads    :', reloads.length, '| best field16_len:', best ? best.field16_len : 'n/a')
  console.log('    bframe/bft  :', !!bframeUrl, '/', bft ? bft.slice(0, 20) + '…' : 'none', '| version:', version)
  console.log('    _GRECAPTCHA :', grecaptcha ? 'captured' : 'absent', '| cookie on reload:', best && best.cookie ? 'yes' : 'no')

  await sleep(400); try { await browser.close() } catch {}; try { server.close() } catch {}

  if (best && best.bodyB64 && best.field16_len > 500) {
    console.log('\n[+] chaining into pure-HTTP solve (solve_hybrid.py) — session is time-bound…\n')
    try { execFileSync('python', [HYB + '\\solve_hybrid.py'], { stdio: 'inherit' }) } catch (e) { console.log('[solve] python exited non-zero:', e.status) }
  } else {
    console.log('\n[!] No reload with a real field16 (>500B) captured — cannot run hybrid solve.')
    console.log('    (If widgetError is set, the own key rejected origin', DOMAIN, '— consider 127.0.0.1 or 2captcha demo fallback.)')
  }
  process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
