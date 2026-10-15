// PHASE 0 capture — get the EXACT /reload (and /userverify) request bytes + response.
// The reCAPTCHA bframe is a cross-origin OOPIF (separate CDP target), so we use
// flattened Target.setAutoAttach to enable Network on every child session and read
// the raw protobuf body via postDataEntries (base64).
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\capture.json'

const reqs = {}        // requestId -> {url, method, headers, bodyB64, sessionId}
const captures = []
const WANT = /\/recaptcha\/(api2|enterprise)\/(reload|userverify)/

function wireSession(session) {
  session.on('Network.requestWillBeSent', (e) => {
    if (!WANT.test(e.request.url)) return
    let bodyB64 = null
    const entries = e.request.postDataEntries
    if (Array.isArray(entries) && entries.length) bodyB64 = Buffer.concat(entries.map(x => Buffer.from(x.bytes || '', 'base64'))).toString('base64')
    else if (e.request.postData) bodyB64 = Buffer.from(e.request.postData, 'latin1').toString('base64')
    reqs[e.requestId] = { url: e.request.url, method: e.request.method, headers: e.request.headers, bodyB64, _s: session }
    console.log(`[req] ${e.request.method} ${e.request.url.split('?')[0].replace(/^https:\/\/[^/]+/, '')} body=${bodyB64 ? Buffer.from(bodyB64, 'base64').length + 'B' : 'none'}`)
  })
  session.on('Network.loadingFinished', async (e) => {
    const r = reqs[e.requestId]; if (!r) return
    let resp = null
    try { const b = await r._s.send('Network.getResponseBody', { requestId: e.requestId }); resp = { body: b.body, base64: b.base64Encoded } } catch (err) { resp = { error: err.message } }
    delete r._s
    captures.push({ ...r, response: resp })
    console.log(`[resp] ${r.url.split('?')[0].replace(/^https:\/\/[^/]+/, '')} -> ${resp.body ? String(resp.body).slice(0, 60) : resp.error}`)
  })
}

;(async () => {
  const { browser } = await connect({
    headless: false, turnstile: true, args: ['--start-maximized'],
    connectOption: { defaultViewport: null }, disableXvfb: true,
    customConfig: { chromePath: process.env.CHROME_PATH },
  })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession()
  const conn = client.connection()
  await client.send('Network.enable')
  wireSession(client)
  // auto-attach to OOPIFs (the bframe) and enable Network on each child session
  client.on('Target.attachedToTarget', async (e) => {
    const child = conn.session(e.sessionId)
    if (!child) return
    try { await child.send('Network.enable'); wireSession(child) } catch {}
    try { await child.send('Runtime.runIfWaitingForDebugger') } catch {}
  })
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: false })

  console.log('[capture] loading demo...')
  await page.goto('https://2captcha.com/demo/recaptcha-v2', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) {
    await f.evaluate(() => { const b = document.getElementById('recaptcha-anchor'); if (b) b.click() }).catch(() => {})
    console.log('[capture] checkbox clicked')
  }
  await sleep(8000)
  fs.writeFileSync(OUT, JSON.stringify({ userAgent: await browser.userAgent().catch(() => null), items: captures }, null, 2))
  console.log(`[capture] ${captures.length} items -> ${OUT}`)
  await sleep(1200)
  try { await browser.close() } catch {}
  process.exit(0)
})().catch(e => { console.log('FATAL', e && e.stack || e); process.exit(1) })
