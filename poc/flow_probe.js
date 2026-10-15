// Pure-Node flow probe: anchor -> reload(fresh c, no field16) -> parse challenge
// metadata -> fetch /payload image. Dumps the full /reload response structure so we
// can see task type, grid size, challenge token, and the payload params.
'use strict'
const fs = require('fs')
const { decode, encode } = require('./pb')
const CAP = require('./capture.json')
const SITEKEY = '6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u'
const VER = 'TnA7HacJFoBWt9hnlunBlYfK'
const UA = CAP.items[0].headers['User-Agent']
const headers = (() => { const h = {}; for (const [k, v] of Object.entries(CAP.items[0].headers)) if (!k.startsWith(':') && k.toLowerCase() !== 'content-length' && k.toLowerCase() !== 'host') h[k] = v; return h })()
const setStr = (fields, fnum, str) => { const f = fields.find(x => x.field === fnum); if (f) f.raw = Buffer.from(str, 'latin1'); return fields }
const dejson = t => JSON.parse(t.replace(/^\)\]\}'\n?/, ''))

async function anchorC() {
  const url = `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=${VER}&size=normal&cb=poc`
  const r = await fetch(url, { headers: { 'User-Agent': UA } })
  return (await r.text()).match(/id="recaptcha-token"[^>]*value="([^"]+)"/)?.[1]
}

;(async () => {
  const base = Buffer.from(CAP.items[0].bodyB64, 'base64')
  const c = await anchorC()
  console.log('c:', c.slice(0, 30) + '…')

  // reload with fresh c, EMPTY field16 (proven accepted), reason "fi"
  const f = decode(base); setStr(f, 2, c); setStr(f, 16, '')
  const r = await fetch(CAP.items[0].url, { method: 'POST', headers, body: encode(f) })
  const raw = await r.text()
  const arr = dejson(raw)
  console.log('\n=== /reload response array ===')
  arr.forEach((v, i) => {
    let s = typeof v === 'string' ? (v.length > 50 ? v.slice(0, 50) + `…(${v.length})` : v) : JSON.stringify(v)
    console.log(`  [${i}] ${typeof v === 'string' ? 'str' : typeof v}: ${s}`)
  })

  const challengeToken = arr[1]   // used as `c` in /userverify
  const ctype = arr[5]
  const payloadToken = arr[9]     // the `p` param for /payload (06AFcWeA...)
  const pmeta = arr[4]
  console.log('\nchallenge type:', ctype)
  console.log('pmeta:', JSON.stringify(pmeta))
  const MID = { '/m/0pg52': 'taxi', '/m/01bjv': 'bus', '/m/04_sv': 'motorcycle', '/m/015qff': 'traffic_light', '/m/01lynh': 'stairs', '/m/0k4j': 'car', '/m/0199g': 'bicycle', '/m/015qbp': 'parking_meter', '/m/01pns0': 'hydrant', '/m/014j1m': 'mountain', '/m/0cdl1': 'palm', '/m/079cl': 'crosswalk', '/m/06bt6': 'chimney', '/m/0c9ph5': 'bridge', '/m/013xlm': 'tractor' }
  try { const tiles = pmeta[5][0]; console.log('targets:', tiles.map(t => `${MID[t[0]] || t[0]} ${t[3]}x${t[4]}`).join(' | ')) } catch {}

  const payloadUrl = `https://www.google.com/recaptcha/api2/payload?p=${encodeURIComponent(payloadToken)}&k=${SITEKEY}`
  console.log('\n=== GET /payload (p=arr[9]) ===')
  const pr = await fetch(payloadUrl, { headers: { 'User-Agent': UA, Referer: headers.Referer } })
  console.log('status:', pr.status, 'type:', pr.headers.get('content-type'), 'len:', pr.headers.get('content-length'))
  if (pr.ok && /image/.test(pr.headers.get('content-type') || '')) {
    const buf = Buffer.from(await pr.arrayBuffer())
    fs.writeFileSync('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\payload.png', buf)
    console.log('saved payload.png', buf.length, 'bytes')
  } else {
    console.log('payload body head:', (await pr.text()).slice(0, 160))
  }
})().catch(e => console.log('ERR', e.stack || e))
