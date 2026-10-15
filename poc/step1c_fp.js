// GO/NO-GO settle: does field16 generation use canvas/webgl/audio fingerprinting?
// Instrument those APIs in the bframe BEFORE its scripts run, click the checkbox (which
// triggers /reload carrying the 5KB field16), and count calls. Heavy canvas/webgl use in
// the checkbox->reload window => field16 needs a renderer => node-vm worker-only is NO-GO.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))

const HOOK = `(function(){ try{
  var C = window.__fp = { calls:{}, toDataURL:0, getImageData:0, webglCtx:0, webglParam:0, canvas2dCtx:0, createCanvas:0, audio:0, getParameterVals:[] };
  function bump(n){ C.calls[n]=(C.calls[n]||0)+1; }
  var oCreate = document.createElement.bind(document);
  document.createElement = function(t){ if(String(t).toLowerCase()==='canvas') C.createCanvas++; return oCreate.apply(document,arguments); };
  var P = HTMLCanvasElement && HTMLCanvasElement.prototype;
  if(P){ var oGC=P.getContext; P.getContext=function(type){ var t=String(type); if(t.indexOf('webgl')>=0)C.webglCtx++; else if(t==='2d')C.canvas2dCtx++; bump('getContext:'+t); return oGC.apply(this,arguments); };
    if(P.toDataURL){ var oD=P.toDataURL; P.toDataURL=function(){ C.toDataURL++; return oD.apply(this,arguments); }; }
    if(P.toBlob){ var oB=P.toBlob; P.toBlob=function(){ C.toDataURL++; return oB.apply(this,arguments); }; } }
  if(window.CanvasRenderingContext2D){ var c2=CanvasRenderingContext2D.prototype; if(c2.getImageData){ var oGI=c2.getImageData; c2.getImageData=function(){ C.getImageData++; return oGI.apply(this,arguments); }; } }
  ['WebGLRenderingContext','WebGL2RenderingContext'].forEach(function(g){ if(window[g]){ var pr=window[g].prototype; if(pr.getParameter){ var oP=pr.getParameter; pr.getParameter=function(p){ C.webglParam++; try{var v=oP.apply(this,arguments); if(C.getParameterVals.length<8)C.getParameterVals.push(p+'='+String(v).slice(0,30)); return v;}catch(e){return oP.apply(this,arguments);} }; }
    if(pr.readPixels){ var oR=pr.readPixels; pr.readPixels=function(){ bump('readPixels'); return oR.apply(this,arguments); }; } } });
  ['AudioContext','OfflineAudioContext','webkitOfflineAudioContext'].forEach(function(a){ if(window[a]){ var oA=window[a]; window[a]=function(){ C.audio++; return new oA(...arguments); }; } });
}catch(e){ window.__fpErr=String(e); } })();`

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
  // snapshot top+anchor fp BEFORE click, then click, then read again (the checkbox->reload window)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('clicked checkbox'); await sleep(7000)

  for (const f of page.frames()) {
    const tag = /bframe/.test(f.url()) ? 'BFRAME' : /anchor/.test(f.url()) ? 'ANCHOR' : /2captcha/.test(f.url()) ? 'TOP' : null
    if (!tag) continue
    const fp = await f.evaluate(() => window.__fp || { missing: true, err: window.__fpErr }).catch(e => ({ err: e.message }))
    console.log(`\n=== ${tag} fingerprint API usage ===`)
    console.log(JSON.stringify(fp, null, 1))
  }
  await sleep(800); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
