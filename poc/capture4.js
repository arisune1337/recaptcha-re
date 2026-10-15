// Capture /userverify from a TRUSTED session: launch with the user's REAL Edge profile
// (Edge is closed) so reCAPTCHA reputation/cookies are intact and tile selections
// actually register. Any answer is fine — we only need the userverify WIRE FORMAT.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
const USER_DATA = process.env.LOCALAPPDATA + '\\Microsoft\\Edge\\User Data'
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\userverify.json'
const reqs = {}, captures = []
const WANT = /\/recaptcha\/(api2|enterprise)\/(reload|userverify|replaceimage)/

const allUrls = []
function wire(s) {
  s.on('Network.requestWillBeSent', e => {
    if (/\/recaptcha\//.test(e.request.url)) allUrls.push(e.request.method + ' ' + e.request.url.replace(/^https:\/\/[^/]+/, '').split('?')[0])
    if (!WANT.test(e.request.url)) return
    let b64 = null; const en = e.request.postDataEntries
    if (Array.isArray(en) && en.length) b64 = Buffer.concat(en.map(x => Buffer.from(x.bytes || '', 'base64'))).toString('base64')
    reqs[e.requestId] = { url: e.request.url, headers: e.request.headers, bodyB64: b64, _s: s }
    console.log('[req]', e.request.url.replace(/^https:\/\/[^/]+/, '').split('?')[0], b64 ? Buffer.from(b64, 'base64').length + 'B' : '')
  })
  s.on('Network.loadingFinished', async e => {
    const r = reqs[e.requestId]; if (!r) return
    let resp = null; try { const b = await r._s.send('Network.getResponseBody', { requestId: e.requestId }); resp = { body: String(b.body).slice(0, 300), base64: b.base64Encoded } } catch (err) { resp = { error: err.message } }
    delete r._s; captures.push({ ...r, response: resp })
    console.log('[resp]', r.url.replace(/^https:\/\/[^/]+/, '').split('?')[0], '->', resp.body ? resp.body.slice(0, 45) : resp.error)
  })
}

;(async () => {
  const { browser } = await connect({
    headless: false, turnstile: true, args: ['--start-maximized', '--profile-directory=Default'],
    connectOption: { defaultViewport: null }, disableXvfb: true,
    customConfig: { chromePath: process.env.CHROME_PATH, userDataDir: USER_DATA },
  })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()
  await client.send('Network.enable'); wire(client)
  client.on('Target.attachedToTarget', async e => { const ch = conn.session(e.sessionId); if (!ch) return; try { await ch.send('Network.enable'); wire(ch); await ch.send('Runtime.runIfWaitingForDebugger') } catch {} })
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: false })

  await page.goto('https://2captcha.com/demo/recaptcha-v2', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('clicked checkbox'); await sleep(6000)

  const ifRect = await page.evaluate(() => { const ifr = [...document.querySelectorAll('iframe')].find(i => /bframe/.test(i.src)); if (!ifr) return null; const r = ifr.getBoundingClientRect(); return { x: r.x, y: r.y } }).catch(() => null)
  for (const f of page.frames()) if (/api2\/bframe/.test(f.url()) && ifRect) {
    const desc = await f.evaluate(() => document.querySelector('.rc-imageselect-desc-no-canonical, .rc-imageselect-desc')?.innerText || '').catch(() => '')
    const rects = await f.evaluate(() => [...document.querySelectorAll('.rc-imageselect-tile')].map(t => { const r = t.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height } })).catch(() => [])
    console.log('challenge:', JSON.stringify(desc.replace(/\n/g, ' ')), '| tiles:', rects.length)
    // click 2 tiles with a human-ish move+click, then verify
    for (const r of rects.slice(0, 2)) {
      const cx = ifRect.x + r.x + r.w / 2, cy = ifRect.y + r.y + r.h / 2
      await page.mouse.move(cx - 20, cy - 15).catch(() => {}); await sleep(80)
      await page.mouse.move(cx, cy).catch(() => {}); await sleep(60)
      await page.mouse.click(cx, cy).catch(() => {}); await sleep(700)
    }
    const sel = await f.evaluate(() => ({ selected: document.querySelectorAll('.rc-imageselect-tile-selected,.rc-imageselect-dynamic-selected').length, disabled: document.getElementById('recaptcha-verify-button')?.disabled, btn: document.getElementById('recaptcha-verify-button')?.innerText })).catch(() => ({}))
    console.log('SELECTED:', JSON.stringify(sel))
    const clickVerify = async () => {
      const vb = await f.evaluate(() => { const b = document.getElementById('recaptcha-verify-button'); if (!b) return null; const r = b.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, dis: b.disabled } }).catch(() => null)
      if (vb) { const cx = ifRect.x + vb.x + vb.w / 2, cy = ifRect.y + vb.y + vb.h / 2; await page.mouse.move(cx, cy).catch(() => {}); await sleep(80); await page.mouse.click(cx, cy).catch(() => {}); console.log(`clicked verify @(${Math.round(cx)},${Math.round(cy)}) disabled=${vb.dis}`) }
    }
    await clickVerify(); await sleep(3000)
    if (!captures.some(c => /userverify/.test(c.url))) { console.log('no userverify, retry'); await clickVerify(); await sleep(3500) }
    const after = await f.evaluate(() => ({ desc: document.querySelector('.rc-imageselect-desc-no-canonical, .rc-imageselect-desc')?.innerText?.replace(/\n/g,' '), err: document.querySelector('.rc-imageselect-error-select-more, .rc-imageselect-incorrect-response')?.innerText, tiles: document.querySelectorAll('.rc-imageselect-tile').length })).catch(() => ({}))
    console.log('AFTER verify:', JSON.stringify(after))
  }
  await sleep(2500)
  console.log('all recaptcha URLs:', allUrls.join('  '))
  fs.writeFileSync(OUT, JSON.stringify({ userAgent: await browser.userAgent().catch(() => null), items: captures }, null, 2))
  console.log(`\n${captures.length} items (`, captures.map(c => c.url.split('?')[0].replace(/^https:..[^/]+/, '')).join(', '), ') ->', OUT)
  await sleep(800); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
