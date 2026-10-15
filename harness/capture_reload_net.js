// capture_reload_net.js — READ-ONLY empirical capture of the reCAPTCHA v2 bframe's FIRST
// POST /recaptcha/api2/reload after the checkbox is clicked. Records, on a single relative-ms
// clock: (a) every cross-frame MessagePort postMessage (in/out) per frame, and (b) every CDP
// Network request/response for the api2 endpoints (reload/bframe/userverify/payload/replaceimage)
// on the page target AND every OOPIF (anchor/bframe) target. Lets us see which parent->bframe
// messages precede reload#1, and decode the reload#1 POST body (protobuf field lengths + bft).
// Based on capture_comm.js connect + auto-attach + MessagePort hook boilerplate.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const { connect } = require(ROOT + '\\node_modules\\puppeteer-real-browser')
const pb = require('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\pb.js')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\reload_net.json'
const DEMO = process.env.DEMO_URL || 'https://2captcha.com/demo/recaptcha-v2'

// t0 wall-clock origin so in-page Date.now() (messages) and CDP wallTime (network) share one axis.
const T0 = Date.now()
const rel = () => Date.now() - T0

// MessagePort hook (out/in, {t,m}) PLUS Window.postMessage + inbound window-message hooks so we
// can see the recaptcha-setup handshake: who posts to whom (tgt: self/parent/top/sibling#i) and
// how many MessagePorts are transferred, and the inbound port handoff (win: origin + nPorts).
const HOOK = "var __comm={out:[],in:[],wout:[],win:[],notes:[]};try{window.__comm=__comm}catch(e){};try{self.__comm=__comm}catch(e){};" +
  "(function(){" +
  "try{var MP=(self.MessagePort||window.MessagePort);if(MP){MP=MP.prototype;" +
  "var oPost=MP.postMessage;MP.postMessage=function(m,t){try{if(typeof m==='string')__comm.out.push({t:Date.now(),m:m})}catch(e){}return oPost.apply(this,arguments)};" +
  "var oAdd=MP.addEventListener;MP.addEventListener=function(t,fn,o){if(t==='message'&&typeof fn==='function'){var s=this;return oAdd.call(this,t,function(ev){try{if(ev&&typeof ev.data==='string')__comm.in.push({t:Date.now(),m:ev.data})}catch(e){}return fn.call(s,ev)},o)}return oAdd.apply(this,arguments)};" +
  "try{Object.defineProperty(MP,'onmessage',{configurable:true,get:function(){return this.__omfn||null},set:function(fn){this.__omfn=fn;var s=this;oAdd.call(this,'message',function(ev){try{if(ev&&typeof ev.data==='string')__comm.in.push({t:Date.now(),m:ev.data})}catch(e){}return fn&&fn.call(s,ev)})}})}catch(e){__comm.notes.push('defprop:'+e)}" +
  "}else{__comm.notes.push('no MessagePort')}}catch(e){__comm.notes.push('mp:'+e)}" +
  "try{var WP=(self.Window||window.Window).prototype;var oWP=WP.postMessage;WP.postMessage=function(msg,a2,a3){try{" +
  "var ports=(a3&&a3.length!=null)?a3:((a2&&typeof a2==='object'&&a2.transfer)?a2.transfer:null);var to=(a2&&a2.targetOrigin)?a2.targetOrigin:a2;var nP=ports?ports.length:0;var tgt='other';" +
  "if(this===self){tgt='self'}else if(this===window.parent){tgt='parent'}else if(this===window.top){tgt='top'}else{try{var pf=window.parent.frames;for(var k=0;k<pf.length;k++){if(pf[k]===this){tgt='sibling#'+k;break}}}catch(e){tgt='sib?'}}" +
  "var dp;try{dp=(typeof msg==='string')?msg.slice(0,90):JSON.stringify(msg).slice(0,90)}catch(e){dp='?'}" +
  "__comm.wout.push({t:Date.now(),tgt:tgt,to:(''+to).slice(0,40),nPorts:nP,dp:dp})}catch(e){}return oWP.apply(this,arguments)}}catch(e){__comm.notes.push('wpm:'+e)}" +
  "try{(self||window).addEventListener('message',function(ev){try{" +
  "var dp=typeof ev.data==='string'?ev.data.slice(0,90):(ev.data&&ev.data.length!=null?JSON.stringify(ev.data).slice(0,90):Object.prototype.toString.call(ev.data));" +
  "var s=ev.source,st='other';try{if(!s){st='none'}else if(s===self){st='self'}else if(s===window.parent){st='parent(top)'}else if(s===window.top){st='top'}else{var pf=window.parent&&window.parent.frames;if(pf){for(var k=0;k<pf.length;k++){if(pf[k]===s){st='sibling#'+k;break}}}if(st==='other'){var mf=window.frames;if(mf){for(var j=0;j<mf.length;j++){if(mf[j]===s){st='child#'+j;break}}}}}}catch(e){st='xo'}" +
  "__comm.win.push({t:Date.now(),origin:ev.origin,nPorts:(ev.ports||[]).length,src:st,dp:dp})}catch(e){}},true)}catch(e){__comm.notes.push('winmsg:'+e)}" +
  "__comm.notes.push('installed')})();";

const FILTER = /\/recaptcha\/api2\/(reload|bframe|userverify|payload|replaceimage)/
const classify = u => !u ? 'top' : /api2\/bframe/.test(u) ? 'bframe' : /api2\/anchor/.test(u) ? 'anchor' : /recaptcha\/api2\//.test(u) ? 'recaptcha' : 'top'

const netEvents = []           // {t, kind:'net-req'|'net-resp', frame, detail}
const reloadReqs = []          // filled reloadRequests
const pending = new Map()      // requestId -> {ch, ev, isReload}
let bftToken = null

// scan a length-delimited protobuf buffer into top-level {field: byteLen} + wire-type detail.
function scanProto(buf) {
  let fields = {}, detail = []
  try {
    const list = pb.decode(buf)
    for (const f of list) {
      const len = f.wire === 2 ? f.len : (f.wire === 0 ? Buffer.from(pb.encVarint(f.value)).length : f.wire === 5 ? 4 : f.wire === 1 ? 8 : 0)
      fields[f.field] = len
      detail.push({ field: f.field, wire: f.wire, type: f.type, len })
    }
  } catch (e) { detail.push({ err: String(e) }) }
  return { fields, detail }
}

async function resolvePostData(rec) {
  const { ch, ev } = rec
  let body = ev.detail.postData
  if ((body == null || body === '') && ev.detail.hasPostData) {
    try { const r = await ch.send('Network.getRequestPostData', { requestId: ev.detail.requestId }); body = r && r.postData } catch (e) { ev.detail.postDataErr = String(e) }
  }
  if (body == null) { ev.detail.bodyB64 = null; return }
  // CDP returns postData as a JS string (latin1-ish). Preserve bytes via latin1.
  const buf = Buffer.from(body, 'latin1')
  ev.detail.bodyB64 = buf.toString('base64')
  ev.detail.bodyLen = buf.length
  if (ev.detail.isReload) {
    const { fields, detail } = scanProto(buf)
    const ct = (ev.detail.headers && (ev.detail.headers['content-type'] || ev.detail.headers['Content-Type'])) || null
    const asAscii = buf.toString('latin1')
    const bftIn = !!(bftToken && asAscii.indexOf(bftToken) >= 0)
    const rr = {
      url: ev.detail.url,
      reason: (ev.detail.url.match(/[?&]reason=([^&]*)/) || [])[1] || null,
      headers: ev.detail.headers || {},
      bodyB64: ev.detail.bodyB64,
      contentType: ct,
      isProtobuffer: !!(ct && /x-protobuffer/i.test(ct)),
      protoFields: fields,
      protoDetail: detail,
      field16_bgRequest_len: (16 in fields) ? fields[16] : 'ABSENT',
      bftInBody: bftIn
    }
    reloadReqs.push(rr)
  }
}

function wire(ch, ownTag) {
  ch.on('Network.requestWillBeSent', p => {
    const url = p.request.url
    if (!FILTER.test(url)) return
    const frame = classify(p.documentURL || url) === 'top' ? ownTag : classify(p.documentURL || url)
    const isReload = /\/recaptcha\/api2\/reload/.test(url)
    const ev = {
      t: p.wallTime != null ? Math.round(p.wallTime * 1000 - T0) : rel(),
      kind: 'net-req',
      frame,
      detail: {
        requestId: p.requestId, url, method: p.request.method,
        headers: p.request.headers || {},
        hasPostData: !!p.request.hasPostData,
        postData: p.request.postData != null ? p.request.postData : null,
        documentURL: p.documentURL, isReload
      }
    }
    netEvents.push(ev)
    const rec = { ch, ev, isReload }
    pending.set(p.requestId, rec)
    resolvePostData(rec).catch(() => {})
  })
  ch.on('Network.responseReceived', p => {
    const url = p.response.url
    if (!FILTER.test(url)) return
    const frame = classify(p.response.url) === 'top' ? ownTag : classify(url)
    netEvents.push({
      t: rel(), kind: 'net-resp', frame,
      detail: { requestId: p.requestId, url, status: p.response.status, mimeType: p.response.mimeType, headers: p.response.headers || {} }
    })
  })
}

;(async () => {
  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()

  client.on('Target.attachedToTarget', async e => {
    const ti = e.targetInfo; const ch = conn.session(e.sessionId); if (!ch) return
    const ownTag = classify(ti.url)
    try {
      if (ti.type === 'page' || ti.type === 'iframe') {
        await ch.send('Page.enable').catch(() => {})
        await ch.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {})
        await ch.send('Network.enable').catch(() => {})
        wire(ch, ownTag)
      }
    } catch {}
    try { await ch.send('Runtime.runIfWaitingForDebugger') } catch {}
  })

  await client.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {})
  await client.send('Network.enable').catch(() => {})
  wire(client, 'top')
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: true })

  await page.goto(DEMO, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)

  // click the anchor checkbox
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  console.log('[+] clicked checkbox @', rel(), 'ms')

  await sleep(10000)

  // grab bft token from the bframe url (for bftInBody correlation)
  for (const f of page.frames()) { const u = f.url(); const m = u.match(/[?&]bft=([^&]+)/); if (m) bftToken = decodeURIComponent(m[1]) }
  if (!bftToken) { const src = await page.evaluate(() => { const i = [...document.querySelectorAll('iframe')].find(x => /bframe/.test(x.src)); return i ? i.src : null }).catch(() => null); if (src) { const m = src.match(/[?&]bft=([^&]+)/); if (m) bftToken = decodeURIComponent(m[1]) } }

  // re-run reload proto scan now that bftToken is known (recompute bftInBody for any reload captured before token was read)
  reloadReqs.length = 0
  for (const rec of pending.values()) if (rec.isReload) await resolvePostData(rec).catch(() => {})

  // collect in-page MessagePort messages, merge into a single relative-ms timeline
  const msgEvents = []
  const winMsgs = []   // {t, frame, dir:'wpm-out'|'wpm-in', ...}  Window.postMessage handshake
  for (const f of page.frames()) {
    const tag = classify(f.url())
    if (tag === 'top' && !/2captcha|recaptcha\/api2\/demo/.test(f.url())) { /* still allow top */ }
    const c = await f.evaluate(() => window.__comm || { err: 'missing' }).catch(e => ({ err: e.message }))
    if (!c || c.err) continue
    for (const o of (c.out || [])) msgEvents.push({ t: o.t - T0, kind: 'msg-out', frame: tag, detail: { text: o.m, len: o.m.length } })
    for (const o of (c.in || [])) msgEvents.push({ t: o.t - T0, kind: 'msg-in', frame: tag, detail: { text: o.m, len: o.m.length } })
    for (const o of (c.wout || [])) winMsgs.push({ t: o.t - T0, frame: tag, dir: 'wpm-out', tgt: o.tgt, to: o.to, nPorts: o.nPorts, dp: o.dp })
    for (const o of (c.win || [])) winMsgs.push({ t: o.t - T0, frame: tag, dir: 'wpm-in', origin: o.origin, nPorts: o.nPorts, src: o.src, dp: o.dp })
  }
  winMsgs.sort((a, b) => a.t - b.t)

  const events = [...msgEvents, ...netEvents].sort((a, b) => a.t - b.t)

  // ---- resolve MessagePort SENDER->RECEIVER by exact byte match (len+prefix, near-simultaneous) ----
  const outs = msgEvents.filter(e => e.kind === 'msg-out')
  const matchSender = (inEv) => {
    let best = null
    for (const o of outs) {
      if (o.frame === inEv.frame) continue
      if (o.detail.len !== inEv.detail.len) continue
      if (o.detail.text.slice(0, 24) !== inEv.detail.text.slice(0, 24)) continue
      if (Math.abs(o.t - inEv.t) > 500) continue
      if (!best || Math.abs(o.t - inEv.t) < Math.abs(best.t - inEv.t)) best = o
    }
    return best ? best.frame : 'UNCAPTURED(top/host)'
  }
  const senderTable = msgEvents.filter(e => e.kind === 'msg-in').map(inEv => ({
    t: inEv.t, receiver: inEv.frame, len: inEv.detail.len, prefix: inEv.detail.text.slice(2, 26), sender: matchSender(inEv)
  }))
  const bframeInbound = senderTable.filter(r => r.receiver === 'bframe')

  // find reload#1 time and the parent->bframe messages that precede it
  const firstReload = events.find(e => e.kind === 'net-req' && e.detail.isReload)
  const reloadT = firstReload ? firstReload.t : Infinity
  const preReloadToBframe = events.filter(e => e.kind === 'msg-in' && e.frame === 'bframe' && e.t < reloadT)
  const rr0 = reloadReqs[0]

  let summary
  if (rr0) {
    const fnums = Object.keys(rr0.protoFields).map(Number).sort((a, b) => a - b)
    summary = `Before the bframe's first POST /recaptcha/api2/reload (reason=${rr0.reason || 'none'}, at t=${reloadT}ms), the bframe RECEIVED ${preReloadToBframe.length} parent->bframe MessagePort message(s). ` +
      `The reload#1 body is ${rr0.contentType || 'unknown'}${rr0.isProtobuffer ? ' (x-protobuffer)' : ''}, ${rr0.bodyB64 ? Buffer.from(rr0.bodyB64, 'base64').length : 0} bytes, with top-level protobuf fields [${fnums.join(',')}]. ` +
      `Field 16 (bgRequest) is ${rr0.field16_bgRequest_len === 'ABSENT' ? 'ABSENT/empty' : rr0.field16_bgRequest_len + ' bytes'} on reload#1, and the anchor bft token ${rr0.bftInBody ? 'DOES' : 'does NOT'} appear in the body.`
  } else {
    summary = `No POST /recaptcha/api2/reload was captured. Parent->bframe messages seen before end: ${preReloadToBframe.length}. (launch/flow may have failed — check events).`
  }

  const result = { meta: { demo: DEMO, t0: T0, bftToken: bftToken ? bftToken.slice(0, 24) + '…' : null, capturedAt: new Date().toISOString() }, events, winMsgs, senderTable, reloadRequests: reloadReqs, summary }
  fs.writeFileSync(OUT, JSON.stringify(result, null, 1))

  console.log('\n================ SUMMARY ================')
  console.log(summary)
  console.log('\n--- parent(->)bframe messages BEFORE reload#1 (in order) ---')
  preReloadToBframe.forEach((m, i) => console.log(`  #${i} t=${m.t}ms (${m.detail.len}b): ${m.detail.text.slice(0, 80)}`))
  console.log('\n--- reload#1 protoFields {field:byteLen} ---')
  console.log(rr0 ? JSON.stringify(rr0.protoFields) : 'NONE')
  if (rr0) { console.log('reload#1 url:', rr0.url); console.log('reason:', rr0.reason, '| contentType:', rr0.contentType, '| field16:', rr0.field16_bgRequest_len, '| bftInBody:', rr0.bftInBody) }

  console.log('\n================ TOPOLOGY ================')
  console.log('--- MessagePort inbound SENDER->RECEIVER (byte-matched) ---')
  for (const r of senderTable) console.log(`  t=${String(r.t).padStart(5)} ${String(r.sender).padEnd(20)} -> ${r.receiver.padEnd(7)} ${String(r.len).padStart(7)}b ${r.prefix}`)
  console.log('\n--- bframe INBOUND only ---')
  for (const r of bframeInbound) console.log(`  t=${r.t} sender=${r.sender} len=${r.len} prefix=${r.prefix}`)
  console.log('\n--- Window.postMessage handshake (wpm-out=posted, wpm-in=received) ---')
  for (const w of winMsgs) {
    if (w.dir === 'wpm-out') console.log(`  t=${String(w.t).padStart(5)} ${w.frame.padEnd(7)} POST-> tgt=${String(w.tgt).padEnd(10)} origin=${w.to} ports=${w.nPorts}  ${JSON.stringify(w.dp)}`)
    else console.log(`  t=${String(w.t).padStart(5)} ${w.frame.padEnd(7)} RECV<- from=${String(w.src).padEnd(12)} origin=${String(w.origin).padEnd(26)} ports=${w.nPorts}  ${JSON.stringify(w.dp)}`)
  }
  console.log('\nsaved', OUT, '| events:', events.length, '| reloadRequests:', reloadReqs.length)

  await sleep(600); try { await browser.close() } catch {}; process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
