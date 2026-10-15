// Capture a fresh `bft` token (the anchor's type-0d token that gates the bframe) from a
// real browser, for reload_now.js. Loads the Google reCAPTCHA demo, clicks the checkbox,
// reads the bframe iframe src (...&bft=<token>). Prints BFT + the embedder origin.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const URL = process.env.DEMO_URL || 'https://www.google.com/recaptcha/api2/demo'

;(async () => {
  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } })
  const page = (await browser.pages())[0] || await browser.newPage()
  await page.goto(URL, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  await sleep(5000)
  let bft = null, bframeUrl = null
  for (const f of page.frames()) { const u = f.url(); if (/api2\/bframe/.test(u)) { bframeUrl = u; const m = u.match(/[?&]bft=([^&]+)/); if (m) bft = decodeURIComponent(m[1]) } }
  // also check iframe element src (in case the frame url is stripped)
  if (!bft) { const src = await page.evaluate(() => { const i = [...document.querySelectorAll('iframe')].find(x => /bframe/.test(x.src)); return i ? i.src : null }).catch(() => null); if (src) { bframeUrl = src; const m = src.match(/[?&]bft=([^&]+)/); if (m) bft = decodeURIComponent(m[1]) } }
  console.log('BFRAME_URL=' + (bframeUrl || 'NOT FOUND'))
  console.log('BFT=' + (bft || 'NOT FOUND'))
  const v = bframeUrl && (bframeUrl.match(/[?&]v=([^&]+)/) || [])[1]
  console.log('VER=' + (v || '?'))
  await sleep(500); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.message); process.exit(1) })
