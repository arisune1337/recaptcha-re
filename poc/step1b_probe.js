// Step 1b GO/NO-GO: is the 5KB reload field16 produced by the PAGE botguard interpreter
// (window.botguard.bg -> canvas/webgl/dom fingerprint, needs a renderer) or by the light
// WORKER Xm (heap/timing/deviceMemory, fakeable in node)? Inspect the bframe at runtime.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))

;(async () => {
  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } })
  const page = (await browser.pages())[0] || await browser.newPage()
  // count worker creations + canvas/webgl probes via CDP on every target
  const client = await page.target().createCDPSession(); const conn = client.connection()
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: true })
  const probes = { workers: 0 }
  client.on('Target.attachedToTarget', async e => {
    const ti = e.targetInfo
    if (ti.type === 'worker' || ti.type === 'shared_worker' || ti.type === 'service_worker') { probes.workers++; console.log('[worker target]', ti.url.slice(0, 80)) }
    const ch = conn.session(e.sessionId); if (!ch) return
    try { await ch.send('Runtime.runIfWaitingForDebugger') } catch {}
  })

  await page.goto('https://2captcha.com/demo/recaptcha-v2', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('clicked checkbox'); await sleep(8000)

  for (const f of page.frames()) {
    if (!/api2\/bframe/.test(f.url())) continue
    const r = await f.evaluate(() => {
      const out = { url: location.href.split('?')[0] }
      out.botguard = typeof window.botguard
      try { out.bgKeys = window.botguard ? Object.keys(window.botguard).slice(0, 20) : null } catch { out.bgKeys = 'err' }
      out.bg_invoke = typeof (window.botguard && window.botguard.bg)
      // scan globals for big strings (the ~5KB attestation candidate)
      const big = []
      for (const k in window) { try { const v = window[k]; if (typeof v === 'string' && v.length > 1500) big.push(k + ':' + v.length) } catch {} }
      out.bigStrings = big.slice(0, 12)
      // is a Worker constructor used / any worker ref?
      out.WorkerCtor = typeof Worker
      // probe whether canvas/webgl are reachable (page path needs them)
      out.canvas = typeof document.createElement('canvas').getContext
      try { out.webgl = !!document.createElement('canvas').getContext('webgl') } catch { out.webgl = 'err' }
      return out
    }).catch(e => ({ err: e.message }))
    console.log('\n=== bframe runtime inspection ===')
    console.log(JSON.stringify(r, null, 1))
  }
  console.log('\nworker targets created during session:', probes.workers)
  await sleep(800); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
