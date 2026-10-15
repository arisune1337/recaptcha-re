// capture_bgprogram_src.js — Find WHERE the ~288KB BotGuard bgprogram (that the anchor receives
// from the TOP over MessagePort, then re-serializes ~336KB to the bframe) ORIGINATES, and whether
// it is constant-per-release or minted-per-session. READ-ONLY. Reuses capture_reload_net.js infra
// (puppeteer-real-browser connect + CDP Target.setAutoAttach + Network on every target + a
// MessagePort in/out hook). Runs the demo flow TWICE (two fresh browser sessions) and diffs bytes.
const ROOT = 'C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss'
process.chdir(ROOT)
process.env.CHROME_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const fs = require('fs')
const crypto = require('crypto')
const { connect } = require(ROOT + '\\node_modules\\puppeteer-real-browser')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const OUT = 'C:\\Users\\user\\Desktop\\a\\recaptcha-re\\harness\\bgprogram_source.json'
const DEMO = process.env.DEMO_URL || 'https://2captcha.com/demo/recaptcha-v2'

// swallow the known-harmless chrome-launcher EPERM temp cleanup race on browser close
process.on('unhandledRejection', e => { if (e && /lighthouse|EPERM/.test(String(e && e.message || e))) return; console.log('unhandledRejection', e && (e.stack || e)) })
process.on('uncaughtException', e => { if (e && /lighthouse|EPERM/.test(String(e && e.message || e))) return; console.log('uncaughtException', e && (e.stack || e)) })

const sha = b => crypto.createHash('sha256').update(b).digest('hex')

// simple MessagePort in/out capture (strings only)
const HOOK = "var __comm={out:[],in:[]};try{window.__comm=__comm}catch(e){};try{self.__comm=__comm}catch(e){};" +
  "(function(){try{var MP=(self.MessagePort||window.MessagePort);if(!MP)return;MP=MP.prototype;" +
  "var oP=MP.postMessage;MP.postMessage=function(m,t){try{if(typeof m==='string')__comm.out.push(m)}catch(e){}return oP.apply(this,arguments)};" +
  "var oA=MP.addEventListener;MP.addEventListener=function(t,fn,o){if(t==='message'&&typeof fn==='function'){var s=this;return oA.call(this,t,function(ev){try{if(ev&&typeof ev.data==='string')__comm.in.push(ev.data)}catch(e){}return fn.call(s,ev)},o)}return oA.apply(this,arguments)};" +
  "try{Object.defineProperty(MP,'onmessage',{configurable:true,get:function(){return this.__om||null},set:function(fn){this.__om=fn;var s=this;oA.call(this,'message',function(ev){try{if(ev&&typeof ev.data==='string')__comm.in.push(ev.data)}catch(e){}return fn&&fn.call(s,ev)})}})}catch(e){}}catch(e){}})();"

const classify = u => !u ? 'top' : /api2\/bframe/.test(u) ? 'bframe' : /api2\/anchor/.test(u) ? 'anchor' : /recaptcha\/api2\//.test(u) ? 'recaptcha' : 'top'

// runs in-page: enumerate big globals + deep string leaves in ___grecaptcha_cfg / grecaptcha
const DUMP_GLOBALS = function () {
  const out = []
  let names = []
  try { names = Object.getOwnPropertyNames(window) } catch (e) {}
  for (const k of names) {
    let size = 0, kind = ''
    try {
      const v = window[k]
      if (typeof v === 'string') { size = v.length; kind = 'string' }
      else if (v && typeof v === 'object') { try { const s = JSON.stringify(v); if (s) { size = s.length; kind = 'json' } } catch (_) {} }
    } catch (e) {}
    if (size > 100000) out.push({ key: k, size, kind })
  }
  const leaves = []
  function scan(obj, path, depth) {
    if (depth > 6 || obj == null) return
    const t = typeof obj
    if (t === 'string') { if (obj.length > 50000) leaves.push({ path, len: obj.length, head: obj.slice(0, 28) }); return }
    if (t !== 'object') return
    let keys = []
    try { keys = Object.keys(obj) } catch (_) { return }
    for (const k of keys) { try { scan(obj[k], path + '.' + k, depth + 1) } catch (_) {} }
  }
  try { scan(window.___grecaptcha_cfg, 'cfg', 0) } catch (e) {}
  try { scan(window.grecaptcha, 'grecaptcha', 0) } catch (e) {}
  return { bigGlobals: out.sort((a, b) => b.size - a.size), bigLeaves: leaves.sort((a, b) => b.len - a.len) }
}

async function runSession(idx) {
  const responses = []                  // {url, frame, mimeType, status, contentEncoding, onWire, decodedLen, sha, fetched}
  const byReqId = new Map()             // requestId -> {ch, meta}
  const bodyJobs = []

  const { browser } = await connect({ headless: false, turnstile: true, args: ['--start-maximized'], connectOption: { defaultViewport: null }, disableXvfb: true, customConfig: { chromePath: process.env.CHROME_PATH } })
  const page = (await browser.pages())[0] || await browser.newPage()
  const client = await page.target().createCDPSession(); const conn = client.connection()

  function wireNet(ch, ownTag) {
    ch.on('Network.responseReceived', p => {
      const url = p.response.url
      const h = p.response.headers || {}
      byReqId.set(p.requestId, { ch, url, frame: ownTag, mimeType: p.response.mimeType, status: p.response.status, contentEncoding: h['content-encoding'] || h['Content-Encoding'] || null })
    })
    ch.on('Network.loadingFinished', p => {
      const rec = byReqId.get(p.requestId); if (!rec) return
      rec.onWire = p.encodedDataLength
      const want = /recaptcha|gstatic|botguard|bframe|anchor|reload|\/jsn|payload|webworker|releases/.test(rec.url) || (p.encodedDataLength || 0) > 50000
      const meta = { url: rec.url, frame: rec.frame, mimeType: rec.mimeType, status: rec.status, contentEncoding: rec.contentEncoding, onWire: rec.onWire, decodedLen: null, sha: null, fetched: false }
      responses.push(meta)
      if (want) {
        const job = (async () => {
          try {
            const r = await rec.ch.send('Network.getResponseBody', { requestId: p.requestId })
            const buf = r.base64Encoded ? Buffer.from(r.body, 'base64') : Buffer.from(r.body, 'utf8')
            meta.decodedLen = buf.length; meta.sha = sha(buf); meta.fetched = true
            meta.head = buf.subarray(0, 24).toString('latin1').replace(/[^ -~]/g, '.')
          } catch (e) { meta.bodyErr = String(e).slice(0, 60) }
        })()
        bodyJobs.push(job)
      }
    })
  }

  client.on('Target.attachedToTarget', async e => {
    const ti = e.targetInfo; const ch = conn.session(e.sessionId); if (!ch) return
    const ownTag = classify(ti.url)
    try {
      if (ti.type === 'page' || ti.type === 'iframe') {
        await ch.send('Page.enable').catch(() => {})
        await ch.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {})
        await ch.send('Network.enable').catch(() => {})
        wireNet(ch, ownTag)
      }
    } catch {}
    try { await ch.send('Runtime.runIfWaitingForDebugger') } catch {}
  })
  await client.send('Page.addScriptToEvaluateOnNewDocument', { source: HOOK }).catch(() => {})
  await client.send('Network.enable').catch(() => {})
  wireNet(client, 'top')
  await client.send('Target.setAutoAttach', { autoAttach: true, flatten: true, waitForDebuggerOnStart: true })

  await page.goto(DEMO, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(e => console.log('goto', e.message))
  await sleep(3500)
  for (const f of page.frames()) if (/api2\/anchor/.test(f.url())) await f.evaluate(() => document.getElementById('recaptcha-anchor')?.click()).catch(() => {})
  await sleep(9000)
  await Promise.allSettled(bodyJobs)

  // the ~288KB program the ANCHOR receives from the TOP (its largest inbound MessagePort string)
  // and the ~336KB the anchor forwards to the bframe (bframe's largest inbound)
  let anchorProg = null, bframeProg = null, cfgTop = null, cfgAnchor = null, bframeUrl = null, ver = null
  for (const f of page.frames()) {
    const tag = classify(f.url())
    if (tag === 'bframe') { bframeUrl = f.url(); ver = (f.url().match(/[?&]v=([^&]+)/) || [])[1] || ver }
    const c = await f.evaluate(() => window.__comm || null).catch(() => null)
    if (c) {
      const maxIn = (c.in || []).reduce((a, s) => s.length > (a ? a.length : 0) ? s : a, null)
      if (tag === 'anchor' && maxIn) anchorProg = maxIn
      if (tag === 'bframe' && maxIn) bframeProg = maxIn
    }
    if (tag === 'top') cfgTop = await f.evaluate(DUMP_GLOBALS).catch(e => ({ err: String(e) }))
    if (tag === 'anchor') cfgAnchor = await f.evaluate(DUMP_GLOBALS).catch(e => ({ err: String(e) }))
  }

  const progMeta = anchorProg ? { len: anchorProg.length, bytes: Buffer.byteLength(anchorProg, 'latin1'), sha: sha(Buffer.from(anchorProg, 'latin1')), head: anchorProg.slice(0, 40), tail: anchorProg.slice(-40) } : null
  const bframeProgMeta = bframeProg ? { len: bframeProg.length, sha: sha(Buffer.from(bframeProg, 'latin1')), head: bframeProg.slice(0, 40) } : null

  try { await browser.close() } catch {}
  await sleep(400)

  // rank network bodies by decoded size
  responses.sort((a, b) => (b.decodedLen || b.onWire || 0) - (a.decodedLen || a.onWire || 0))
  return { idx, ver, bframeUrl, anchorProgram: progMeta, bframeProgram: bframeProgMeta, rawAnchorProgram: anchorProg,
    topBodies: responses.slice(0, 14), cfgTop, cfgAnchor }
}

function lcp(a, b) { if (!a || !b) return 0; const n = Math.min(a.length, b.length); let i = 0; while (i < n && a[i] === b[i]) i++; return i }

;(async () => {
  console.log('=== SESSION 1 ===')
  const s1 = await runSession(1)
  console.log('  anchor program:', s1.anchorProgram ? `${s1.anchorProgram.bytes}B sha=${s1.anchorProgram.sha.slice(0, 16)}` : 'NONE', '| ver', s1.ver)
  console.log('=== SESSION 2 ===')
  const s2 = await runSession(2)
  console.log('  anchor program:', s2.anchorProgram ? `${s2.anchorProgram.bytes}B sha=${s2.anchorProgram.sha.slice(0, 16)}` : 'NONE', '| ver', s2.ver)

  const p1 = s1.rawAnchorProgram, p2 = s2.rawAnchorProgram
  const identical = !!(p1 && p2 && p1 === p2)
  const prefix = lcp(p1, p2)
  const verdict = !p1 || !p2 ? 'INCONCLUSIVE (missing capture)' :
    identical ? 'CONSTANT-PER-RELEASE (byte-identical across two fresh sessions -> capture once, reusable)' :
      (prefix > 200 ? `PER-SESSION (differ; share a ${prefix}-char common prefix then diverge -> session token embedded)` :
        `PER-SESSION (totally different from offset ${prefix} -> freshly minted each load)`)

  // pick the network body whose decoded size is closest to the anchor program size (candidate source)
  const target = (s1.anchorProgram && s1.anchorProgram.bytes) || 288000
  const cand = [...s1.topBodies].filter(b => b.decodedLen).sort((a, b) => Math.abs(a.decodedLen - target) - Math.abs(b.decodedLen - target))[0] || null

  const result = {
    demo: DEMO, capturedAt: new Date().toISOString(), release_v: s1.ver,
    session1: { anchorProgram: s1.anchorProgram, bframeProgram: s1.bframeProgram, topBodies: s1.topBodies, cfgTop: s1.cfgTop, cfgAnchor: s1.cfgAnchor },
    session2: { anchorProgram: s2.anchorProgram, bframeProgram: s2.bframeProgram, topBodies: s2.topBodies, cfgTop: s2.cfgTop, cfgAnchor: s2.cfgAnchor },
    comparison: { session1_bytes: s1.anchorProgram && s1.anchorProgram.bytes, session2_bytes: s2.anchorProgram && s2.anchorProgram.bytes,
      session1_sha: s1.anchorProgram && s1.anchorProgram.sha, session2_sha: s2.anchorProgram && s2.anchorProgram.sha,
      byteIdentical: identical, commonPrefixChars: prefix },
    sessionBoundednessVerdict: verdict,
    closestNetworkBodyToProgram: cand
  }
  fs.writeFileSync(OUT, JSON.stringify(result, null, 1))

  console.log('\n================ BGPROGRAM SOURCE ================')
  console.log('release v =', s1.ver)
  console.log('\n-- SESSION1 top network bodies (by decoded size) --')
  for (const b of s1.topBodies.slice(0, 10)) console.log(`  ${String(b.decodedLen || b.onWire || 0).padStart(8)}B  ${b.frame.padEnd(7)} ${b.mimeType || ''}  ${b.url.slice(0, 78)}`)
  console.log('\n-- big page globals (top frame) --')
  console.log('  bigGlobals:', JSON.stringify((s1.cfgTop && s1.cfgTop.bigGlobals) || []))
  console.log('  bigLeaves :', JSON.stringify((s1.cfgTop && s1.cfgTop.bigLeaves) || []))
  console.log('  anchor cfg bigLeaves:', JSON.stringify((s1.cfgAnchor && s1.cfgAnchor.bigLeaves) || []))
  console.log('\n-- anchor-received program size --')
  console.log('  S1:', s1.anchorProgram, '\n  S2:', s2.anchorProgram)
  console.log('\n-- closest network body to program size --')
  console.log('  ', cand ? `${cand.decodedLen}B  ${cand.url}` : 'none matched')
  console.log('\n================ VERDICT ================')
  console.log(verdict)
  console.log('byteIdentical:', identical, '| commonPrefixChars:', prefix, '| S1sha:', s1.anchorProgram && s1.anchorProgram.sha.slice(0, 16), '| S2sha:', s2.anchorProgram && s2.anchorProgram.sha.slice(0, 16))
  console.log('\nsaved', OUT)
  process.exit(0)
})().catch(e => { console.log('FATAL', e.stack || e); process.exit(1) })
