// Step 1b (proper): inject a hook into the bframe BEFORE its scripts run (CDP auto-attach
// with waitForDebuggerOnStart + addScriptToEvaluateOnNewDocument on the bframe target) to
// capture, at runtime: every Worker created + what it postMessages, whether window.botguard
// is assigned, and the size of any BotGuard token produced. Decides worker-Xm vs page-bg.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const { connect } = require('puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))

const HOOK = `(function(){
  try{
    window.__cap = { workers: [], workerPosts: [], botguardSet:false, bgSizes:[], newWorkerUrls:[] };
    var OW = self.Worker;
    if (OW){ self.Worker = function(u,o){ try{window.__cap.newWorkerUrls.push(String(u).slice(0,90))}catch(e){}
      var w = new OW(u,o);
      try{ var op=w.postMessage.bind(w); w.postMessage=function(m,t){ try{window.__cap.workerPosts.push((m&&m.constructor&&m.constructor.name)||typeof m)}catch(e){} return op(m,t);}; }catch(e){}
      try{ Object.defineProperty(w,'onmessage',{configurable:true,set:function(fn){ this.__fn=fn; var self2=this; OW.prototype.addEventListener.call(this,'message',function(ev){ try{var d=ev.data; var sz = d&&d.byteLength?d.byteLength:(typeof d==='string'?d.length:JSON.stringify(d).length); window.__cap.workers.push('reply~'+sz+'B');}catch(e){} return fn&&fn(ev);}); }}); }catch(e){}
      return w; }; }
    var _bg;
    Object.defineProperty(self,'botguard',{configurable:true,
      get:function(){return _bg;},
      set:function(v){ window.__cap.botguardSet=true;
        try{ var OBG=v&&v.bg; if(OBG){ v.bg=function(prog,cb){ var wrapCb = cb; if(typeof cb==='function'){ wrapCb=function(tok){ try{window.__cap.bgSizes.push(typeof tok==='string'?tok.length:typeof tok)}catch(e){} return cb.apply(this,arguments);} } var inst=new OBG(prog,wrapCb);
          try{ if(inst&&inst.invoke){ var oi=inst.invoke.bind(inst); inst.invoke=function(){ var r=oi.apply(this,arguments); try{window.__cap.bgSizes.push('inv:'+(typeof r==='string'?r.length:typeof r))}catch(e){} return r; }; } }catch(e){}
          return inst; }; } }catch(e){}
        _bg=v; }
    });
  }catch(e){ window.__capErr=String(e); }
})();`

;(async () => {
  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()
  const seen = []
  client.on('Target.attachedToTarget', async e => {
    const ti = e.targetInfo; const ch = conn.session(e.sessionId); if (!ch) return
    seen.push(ti.type + ':' + ti.url.split('?')[0].replace(/^https:\/\/[^/]+/, '').slice(0, 40))
    try {
      if (ti.type === 'page' || ti.type === 'iframe') {
        await ch.send('Page.enable').catch(() => {})
        await ch.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {})
      }
    } catch {}
    try { await ch.send('Runtime.runIfWaitingForDebugger') } catch {}
  })
  await client.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {})
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: true })

  await page.goto('https://2captcha.com/demo/recaptcha-v2', { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('clicked checkbox'); await sleep(9000)

  for (const f of page.frames()) {
    if (!/api2\/bframe/.test(f.url())) continue
    const r = await f.evaluate(() => window.__cap || { missing: true, err: window.__capErr }).catch(e => ({ err: e.message }))
    console.log('\n=== bframe __cap (before-load hook) ===')
    console.log(JSON.stringify(r, null, 1))
  }
  console.log('\nattached targets:', seen.join('  '))
  await sleep(800); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
