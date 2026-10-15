// Capture the real BotGuard bg-program + bframe config so we can feed the node-vm worker.
// Hooks (before-load) the bframe's MessagePort.postMessage + Worker.postMessage to grab the
// exact bytes the page hands the BotGuard VM (the Qr program / ak input), and dumps any
// program-ish globals (___grecaptcha_cfg, bgdata). Saves to prog_capture.json.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))

const HOOK = `(function(){ try{
  window.__prog = { portMsgs:[], workerMsgs:[], workerUrls:[], notes:[] };
  function desc(m){ try{ if(m==null) return String(m);
    if(m instanceof ArrayBuffer) return 'AB('+m.byteLength+')';
    if(ArrayBuffer.isView(m)) return m.constructor.name+'('+m.byteLength+')';
    if(typeof m==='string') return 'str('+m.length+'):'+m.slice(0,40);
    if(Array.isArray(m)) return 'arr['+m.length+']:'+m.slice(0,6).map(desc).join(',');
    if(typeof m==='object'){ var o={}; for(var k in m){ try{o[k]=desc(m[k])}catch(e){o[k]='?'} } return JSON.stringify(o).slice(0,200); }
    return typeof m; }catch(e){ return 'err'; } }
  function b64(m){ try{ var v=ArrayBuffer.isView(m)?m:(m instanceof ArrayBuffer?new Uint8Array(m):null); if(!v) return null;
    var s=''; var a=new Uint8Array(v.buffer||v); for(var i=0;i<a.length;i++) s+=String.fromCharCode(a[i]); return btoa(s); }catch(e){ return null; } }
  var MP = window.MessagePort && MessagePort.prototype;
  if(MP && MP.postMessage){ var oMP=MP.postMessage; MP.postMessage=function(m,t){ try{ window.__prog.portMsgs.push({d:desc(m), b64:b64(m), full:(typeof m==='string'?m:null)}); }catch(e){} return oMP.apply(this,arguments); }; }
  var OW=window.Worker;
  if(OW){ window.Worker=function(u,o){ try{window.__prog.workerUrls.push(String(u).slice(0,90))}catch(e){} var w=new OW(u,o);
    try{ var op=w.postMessage.bind(w); w.postMessage=function(m,t){ try{window.__prog.workerMsgs.push({d:desc(m),b64:b64(m)})}catch(e){} return op(m,t); }; }catch(e){}
    return w; }; window.Worker.prototype=OW.prototype; }
}catch(e){ window.__progErr=String(e); } })();`

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
    const tag = /bframe/.test(f.url()) ? 'bframe' : /anchor/.test(f.url()) ? 'anchor' : /2captcha/.test(f.url()) ? 'top' : null
    if (!tag) continue
    const p = await f.evaluate(() => window.__prog || { err: window.__progErr || 'missing' }).catch(e => ({ err: e.message }))
    dump[tag] = p
    console.log(`\n=== ${tag} ===`)
    console.log('worker urls:', (p.workerUrls || []).join(' ') || '(none)')
    console.log('worker msgs:', (p.workerMsgs || []).length, (p.workerMsgs || []).slice(0, 4).map(m => m.d).join(' | '))
    console.log('port msgs:', (p.portMsgs || []).length, (p.portMsgs || []).slice(0, 6).map(m => m.d).join(' | '))
  }
  fs.writeFileSync('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\prog_capture.json', JSON.stringify(dump, null, 1))
  console.log('\nsaved prog_capture.json')
  await sleep(800); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
