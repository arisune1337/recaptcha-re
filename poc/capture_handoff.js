// Trust-locus test (capture half): in a TRUSTED real-profile browser, click the
// checkbox, capture the reload challenge token + payload token + targets (this token
// was minted WITH a real BotGuard field16), and hand it off to pure Node to continue.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
const USER_DATA = process.env.LOCALAPPDATA + '\\Microsoft\\Edge\\User Data'
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\handoff.json'
const dejson = t => JSON.parse(t.replace(/^\)\]\}'\n?/, ''))
let reloadArr = null, reloadHeaders = null

function wire(s) {
  const reqs = {}
  s.on('Network.requestWillBeSent', e => { if (/api2\/reload/.test(e.request.url)) reqs[e.requestId] = e.request })
  s.on('Network.loadingFinished', async e => {
    if (!reqs[e.requestId]) return
    try { const b = await s.send('Network.getResponseBody', { requestId: e.requestId }); reloadArr = dejson(b.body); reloadHeaders = reqs[e.requestId].headers; console.log('captured reload, type:', reloadArr[5]) } catch (err) { console.log('body err', err.message) }
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
  console.log('clicked checkbox'); await sleep(5000)
  if (reloadArr) {
    let cookieHeader = ''
    try { const all = (await client.send('Network.getAllCookies')).cookies; const g = all.filter(c => /google\.com$/.test(c.domain) || c.domain === '.google.com' || /google/.test(c.domain)); cookieHeader = g.map(c => `${c.name}=${c.value}`).join('; '); console.log('google cookies:', g.map(c => c.name).join(',') || '(none)') } catch (e) { console.log('cookie err', e.message) }
    const referer = (reloadHeaders && (reloadHeaders.Referer || reloadHeaders.referer)) || ''
    console.log('reload Referer (bft):', referer.slice(0, 90))
    fs.writeFileSync(OUT, JSON.stringify({ ts: 'now', type: reloadArr[5], challengeToken: reloadArr[1], payloadToken: reloadArr[9], pmeta: reloadArr[4], cookieHeader, referer, userAgent: await browser.userAgent().catch(() => null) }, null, 2))
    console.log('handoff written:', reloadArr[5], '| token', String(reloadArr[1]).slice(0, 20) + '…')
  } else console.log('NO reload captured')
  try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
