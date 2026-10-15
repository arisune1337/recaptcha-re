// Capture the FULL bidirectional api.js<->anchor comm in a real browser: both the anchor's
// OUTBOUND MessagePort.postMessage AND its INBOUND (onmessage / addEventListener) frames, with
// full content. The parent->anchor frames are the render/setup commands that flip the anchor
// interactive. Since the cross-frame codec is NOT session-keyed (decode works cross-realm), we
// can decode these + replay them into our headless anchor to drive it past the setup gate.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\comm_full.json'

const HOOK = "var __comm={out:[],in:[],notes:[]};try{window.__comm=__comm}catch(e){};try{self.__comm=__comm}catch(e){};" +
  "(function(){try{var MP=(self.MessagePort||window.MessagePort);if(!MP){__comm.notes.push('no MessagePort');return}MP=MP.prototype;" +
  "var oPost=MP.postMessage;MP.postMessage=function(m,t){try{if(typeof m==='string')__comm.out.push(m)}catch(e){}return oPost.apply(this,arguments)};" +
  "var oAdd=MP.addEventListener;MP.addEventListener=function(t,fn,o){if(t==='message'&&typeof fn==='function'){var s=this;return oAdd.call(this,t,function(ev){try{if(ev&&typeof ev.data==='string')__comm.in.push(ev.data)}catch(e){}return fn.call(s,ev)},o)}return oAdd.apply(this,arguments)};" +
  "try{Object.defineProperty(MP,'onmessage',{configurable:true,get:function(){return this.__omfn||null},set:function(fn){this.__omfn=fn;var s=this;oAdd.call(this,'message',function(ev){try{if(ev&&typeof ev.data==='string')__comm.in.push(ev.data)}catch(e){}return fn&&fn.call(s,ev)})}})}catch(e){__comm.notes.push('defprop:'+e)}" +
  "__comm.notes.push('installed')}catch(e){__comm.notes.push('outer:'+e)}})();";

;(async () => {
  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()
  client.on('Target.attachedToTarget', async e => {
    const ti = e.targetInfo; const ch = conn.session(e.sessionId); if (!ch) return
    try { if (ti.type === 'page' || ti.type === 'iframe') { await ch.send('Page.enable').catch(() => {}); await ch.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {}) } } catch {}
    try { await ch.send('Runtime.runIfWaitingForDebugger') } catch {}
  })
  await client.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {})
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: true })

  await page.goto('https://2captcha.com/demo/recaptcha-v2', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('clicked checkbox'); await sleep(9000)

  const dump = {}
  for (const f of page.frames()) {
    const tag = /bframe/.test(f.url()) ? 'bframe' : /anchor/.test(f.url()) ? 'anchor' : /2captcha|google.com\/recaptcha\/api2\/demo/.test(f.url()) ? 'top' : null
    if (!tag) continue
    const c = await f.evaluate(() => window.__comm || { err: 'missing' }).catch(e => ({ err: e.message }))
    dump[tag] = c
    console.log(`=== ${tag} === out:${(c.out || []).length} in:${(c.in || []).length}` + (c.err ? ' err:' + c.err : ''))
    ;(c.in || []).slice(0, 8).forEach((m, i) => console.log(`  IN#${i} (${m.length}):`, m.slice(0, 55)))
  }
  fs.writeFileSync(OUT, JSON.stringify(dump, null, 1))
  console.log('saved', OUT)
  await sleep(800); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
