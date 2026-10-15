// Capture the FULL on-wire request headers of every /recaptcha/ call during a real
// browser solve — specifically to find the BotGuard attestation HEADER (the workflow's
// "BV") that a JS XHR hook injects and that Network.requestWillBeSent.request.headers
// does NOT show. We subscribe to BOTH requestWillBeSent (body) AND
// requestWillBeSentExtraInfo (the real headers, incl. JS-set + cookies), merged by id.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
const USER_DATA = process.env.LOCALAPPDATA + '\\Microsoft\\Edge\\User Data'
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\headers.json'
const byId = {}   // requestId -> {url, method, reqHeaders, extraHeaders, bodyLen}

function wire(s) {
  s.on('Network.requestWillBeSent', e => {
    if (!/\/recaptcha\/(api2|enterprise)\//.test(e.request.url)) return
    let bodyLen = 0
    const en = e.request.postDataEntries
    if (Array.isArray(en)) bodyLen = en.reduce((a, x) => a + Buffer.from(x.bytes || '', 'base64').length, 0)
    byId[e.requestId] = byId[e.requestId] || {}
    Object.assign(byId[e.requestId], { url: e.request.url.split('?')[0].replace(/^https:\/\/[^/]+/, ''), method: e.request.method, reqHeaders: e.request.headers, bodyLen })
  })
  s.on('Network.requestWillBeSentExtraInfo', e => {
    byId[e.requestId] = byId[e.requestId] || {}
    byId[e.requestId].extraHeaders = e.headers
  })
}

;(async () => {
  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized', '--profile-directory=Default'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH, userDataDir: USER_DATA } })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()
  await client.send('Network.enable'); wire(client)
  client.on('Target.attachedToTarget', async e => { const ch = conn.session(e.sessionId); if (!ch) return; try { await ch.send('Network.enable'); wire(ch); await ch.send('Runtime.runIfWaitingForDebugger') } catch {} })
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: false })

  await page.goto('https://2captcha.com/demo/recaptcha-v2', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('clicked checkbox'); await sleep(6000)

  // click a couple tiles (real coords) to trigger replaceimage
  const ifRect = await page.evaluate(() => { const ifr = [...document.querySelectorAll('iframe')].find(i => /bframe/.test(i.src)); if (!ifr) return null; const r = ifr.getBoundingClientRect(); return { x: r.x, y: r.y } }).catch(() => null)
  for (const f of page.frames()) if (/api2\/bframe/.test(f.url()) && ifRect) {
    const rects = await f.evaluate(() => [...document.querySelectorAll('.rc-imageselect-tile')].map(t => { const r = t.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height } })).catch(() => [])
    for (const r of rects.slice(0, 2)) { await page.mouse.click(ifRect.x + r.x + r.w / 2, ifRect.y + r.y + r.h / 2).catch(() => {}); await sleep(700) }
    const vb = await f.evaluate(() => { const b = document.getElementById('recaptcha-verify-button'); if (!b) return null; const r = b.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height } }).catch(() => null)
    if (vb) { await page.mouse.click(ifRect.x + vb.x + vb.w / 2, ifRect.y + vb.y + vb.h / 2).catch(() => {}) }
  }
  await sleep(4000)

  const items = Object.values(byId)
  fs.writeFileSync(OUT, JSON.stringify(items, null, 2))
  console.log(`\n=== ${items.length} /recaptcha/ requests — header sizes ===`)
  for (const it of items) {
    const rh = it.reqHeaders || {}, eh = it.extraHeaders || {}
    const merged = { ...rh, ...eh }
    // flag any unusually large / non-standard header (candidate BotGuard attestation)
    const big = Object.entries(merged).filter(([k, v]) => String(v).length > 100 && !/cookie|user-agent|sec-ch-ua/i.test(k))
    console.log(`${it.method} ${it.url} body=${it.bodyLen}B hdrs(req=${Object.keys(rh).length},extra=${Object.keys(eh).length})` +
      (big.length ? ' BIG:[' + big.map(([k, v]) => `${k}=${String(v).length}B`).join(',') + ']' : ''))
  }
  console.log(`\nfull headers -> ${OUT}`)
  await sleep(800); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
