// Feed the REAL captured anchor->worker MessagePort frames (same release as our local
// recaptcha__en.js) into our node-vm worker's AE server over the loopback port, and watch
// what it replies + whether it touches canvas/webgl. Decisive: can our VM process a real
// BotGuard program and emit an attestation?
const fs = require('fs')
const W = require('./worker.js')
const { WORKER_PORT, hotHits, accessed, cap } = W
const CAPF = 'C:/Users/user/Desktop/a/recaptcha-re/poc/prog_capture.json'

process.on('unhandledRejection', (e) => { /* swallow async VM rejections from partial input */ })

if (!WORKER_PORT) { console.log('no WORKER_PORT'); process.exit(1) }
const cap0 = JSON.parse(fs.readFileSync(CAPF, 'utf8'))
const msgs = (cap0.anchor && cap0.anchor.portMsgs || []).map(m => m.full).filter(Boolean)
console.log('replaying', msgs.length, 'captured anchor->worker frames; sizes:', msgs.map(m => m.length).join(','))

const replies = []
WORKER_PORT.onmessage = (ev) => { const d = ev && ev.data; replies.push(typeof d === 'string' ? d : JSON.stringify(d)) }

;(async () => {
  const tick = () => new Promise(r => setImmediate(r))
  for (let i = 0; i < msgs.length; i++) {
    const before = replies.length, beforeHot = hotHits.length
    try { WORKER_PORT.postMessage(msgs[i]) } catch (e) { console.log(`  frame ${i} post threw:`, e.message) }
    await tick(); await tick()
    const newReplies = replies.slice(before)
    const newHot = hotHits.slice(beforeHot)
    if (newReplies.length || newHot.length || i < 8 || msgs[i].length > 100000)
      console.log(`frame ${i} (${msgs[i].length}B) -> replies:${newReplies.length}${newReplies.length ? ' [' + newReplies.map(r => r.slice(0, 40)).join(' | ') + ']' : ''}${newHot.length ? ' HOT:' + [...new Set(newHot)].join(',') : ''}`)
  }
  await tick(); await tick(); await tick()
  console.log('\n=== summary ===')
  console.log('total replies from worker:', replies.length)
  function innerSize(r) { try { const a = JSON.parse(r); const s = a[0]; const b = s.replace(/^B/, ''); return Buffer.from(b, 'base64').length } catch { return '?' } }
  replies.forEach((r, i) => { const a = (() => { try { return JSON.parse(r) } catch { return null } })(); const kind = a ? a[1] : '?'; console.log(`  reply ${i}: kind=${kind} wire=${r.length}B payload=${innerSize(r)}B head=${r.slice(0, 50)}`) })
  // the largest-payload reply is the attestation candidate (field16-like)
  const big = replies.map((r, i) => ({ i, sz: innerSize(r), r })).filter(x => typeof x.sz === 'number').sort((a, b) => b.sz - a.sz)[0]
  if (big) { console.log('\nLARGEST attestation payload: reply', big.i, '=', big.sz, 'bytes (field16 in captured /reload was ~5109B)'); fs.writeFileSync('C:/Users/user/Desktop/a/recaptcha-re/harness/attestation_sample.txt', big.r) }
  console.log('HOT env hits (canvas/webgl/dom/audio) during feed:', hotHits.length ? [...new Set(hotHits)].join(' ') : 'NONE')
  const memReads = [...accessed.keys()].filter(k => /memory|heap|deviceMemory|performance|now/i.test(k))
  console.log('memory/timing env reads:', memReads.join(' ') || '(none)')
})()
