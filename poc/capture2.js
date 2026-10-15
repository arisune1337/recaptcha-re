// Broader capture: log EVERY /recaptcha/ request URL+method the browser makes
// (anchor, reload, payload, userverify, replaceimage...) so we learn exact URL formats,
// and store reload/userverify/payload bodies+responses. Click checkbox, then wait so the
// bframe renders the image grid (the /payload request fires).
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\capture2.json'
const reqs = {}, captures = [], urls = []
const BODYWANT = /\/recaptcha\/(api2|enterprise)\/(reload|userverify|payload)/

function wire(session) {
  session.on('Network.requestWillBeSent', (e) => {
    const u = e.request.url
    if (!/\/recaptcha\//.test(u)) return
    urls.push(`${e.request.method} ${u.replace(/^https:\/\/[^/]+/, '')}`)
    if (BODYWANT.test(u)) {
      let bodyB64 = null
      const en = e.request.postDataEntries
      if (Array.isArray(en) && en.length) bodyB64 = Buffer.concat(en.map(x => Buffer.from(x.bytes || '', 'base64'))).toString('base64')
      reqs[e.requestId] = { url: u, method: e.request.method, headers: e.request.headers, bodyB64, _s: session }
    }
  })
  session.on('Network.loadingFinished', async (e) => {
    const r = reqs[e.requestId]; if (!r) return
    let resp = null
    try { const b = await r._s.send('Network.getResponseBody', { requestId: e.requestId }); resp = { body: (b.base64Encoded ? '[b64]' : '') + String(b.body).slice(0, 500), base64: b.base64Encoded } } catch (err) { resp = { error: err.message } }
    delete r._s; captures.push({ ...r, response: resp })
  })
}

;(async () => {
  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession()
  const conn = client.connection()
  await client.send('Network.enable'); wire(client)
  client.on('Target.attachedToTarget', async (e) => { const ch = conn.session(e.sessionId); if (!ch) return; try { await ch.send('Network.enable'); wire(ch); await ch.send('Runtime.runIfWaitingForDebugger') } catch {} })
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: false })

  await page.goto('https://2captcha.com/demo/recaptcha-v2', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) { await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {}); console.log('clicked') }
  await sleep(9000)   // let challenge + payload render
  fs.writeFileSync(OUT, JSON.stringify({ userAgent: await browser.userAgent().catch(() => null), urls, items: captures }, null, 2))
  console.log('=== all recaptcha URLs ===')
  urls.forEach(u => console.log('  ' + u.split('?')[0] + (u.includes('?') ? '?' + u.split('?')[1].split('&').slice(0, 6).join('&') : '')))
  console.log(`\n${captures.length} bodied items -> ${OUT}`)
  await sleep(1000); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
