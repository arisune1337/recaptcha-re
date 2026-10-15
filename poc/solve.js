// Full PURE-NODE reCAPTCHA v2 image solve attempt (no browser, no field16):
//   anchor -> reload -> payload -> OUR MODEL classifies tiles -> replaceimage(ds) -> ...
// The server is the oracle: we dump every response to learn the dynamic/multicaptcha
// loop + whether a pure-request correct answer is ACCEPTED (final token) or trust-rejected.
'use strict'
const fs = require('fs')
const { decode, encode } = require('./pb')
const model = require('C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss\\lib\\recaptchaModel')
const CAP = require('./capture.json')
const SITEKEY = '6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u'
const VER = 'TnA7HacJFoBWt9hnlunBlYfK'
const UA = CAP.items[0].headers['User-Agent']
const REF = 'https://www.google.com/recaptcha/api2/bframe?hl=en&v=' + VER + '&k=' + SITEKEY
const dejson = t => JSON.parse(t.replace(/^\)\]\}'\n?/, ''))
const sleep = ms => new Promise(r => setTimeout(r, ms))
const MID = { '/m/0199g': 'bicycle', '/m/01bjv': 'bus', '/m/0k4j': 'car', '/m/015qff': 'traffic light', '/m/01pns0': 'fire hydrant', '/m/04_sv': 'motorcycle', '/m/01lynh': 'stairs', '/m/079cl': 'crosswalk', '/m/014j1m': 'mountain', '/m/0cdl1': 'palm tree', '/m/06bt6': 'chimney', '/m/013xlm': 'tractor', '/m/0c9ph5': 'bridge', '/m/0pg52': 'taxi', '/m/01_5g': 'parking meter', '/m/0d4v4': 'window' }

const RBASE = Buffer.from(CAP.items[0].bodyB64, 'base64')
const reloadHeaders = { 'User-Agent': UA, 'Content-Type': 'application/x-protobuffer', Referer: REF, Origin: 'https://www.google.com' }
const formHeaders = { 'User-Agent': UA, 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', Referer: REF, Origin: 'https://www.google.com' }

async function anchorC() {
  const url = `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=${VER}&size=normal&cb=p`
  return (await (await fetch(url, { headers: { 'User-Agent': UA } })).text()).match(/id="recaptcha-token"[^>]*value="([^"]+)"/)?.[1]
}
function setF(fields, n, str) { const f = fields.find(x => x.field === n); if (f) f.raw = Buffer.from(str, 'latin1'); return fields }

async function reload(c) {
  const f = decode(RBASE); setF(f, 2, c); setF(f, 16, ''); setF(f, 6, 'fi')
  const r = await fetch(`https://www.google.com/recaptcha/api2/reload?k=${SITEKEY}`, { method: 'POST', headers: reloadHeaders, body: encode(f) })
  return dejson(await r.text())
}
async function getPayload(tok) {
  const r = await fetch(`https://www.google.com/recaptcha/api2/payload?p=${encodeURIComponent(tok)}&k=${SITEKEY}`, { headers: { 'User-Agent': UA, Referer: REF } })
  if (!r.ok || !/image/.test(r.headers.get('content-type') || '')) return null
  return Buffer.from(await r.arrayBuffer())
}
async function replaceimage(c, ds) {
  const body = `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(c)}&ds=${encodeURIComponent(JSON.stringify(ds))}`
  const r = await fetch(`https://www.google.com/recaptcha/api2/replaceimage?k=${SITEKEY}`, { method: 'POST', headers: formHeaders, body })
  const t = await r.text()
  return { status: r.status, arr: (() => { try { return dejson(t) } catch { return t.slice(0, 200) } })() }
}

;(async () => {
  // retry reload until we get a (cleaner) dynamic 3x3 challenge
  let arr, tries = 0
  do {
    const c0 = await anchorC()
    arr = await reload(c0)
    tries++
    if (arr[5] !== 'dynamic') console.log(`try ${tries}: type=${arr[5]}, retrying for dynamic...`)
    if (arr[5] !== 'dynamic') await sleep(400)
  } while (arr[5] !== 'dynamic' && tries < 8)
  const token = arr[1], type = arr[5], payloadToken = arr[9], pmeta = arr[4]
  console.log('type:', type, '| token:', token.slice(0, 22) + '…', '| payloadTok:', String(payloadToken).slice(0, 18) + '…')
  const HUMAN = { bike: 'bicycle', bicycle: 'bicycle', bus: 'bus', car: 'car', 'pedestrian crossing': 'crosswalk', crosswalk: 'crosswalk', 'fire hydrant': 'fire hydrant', hydrant: 'fire hydrant', 'traffic light': 'traffic light', stairs: 'stairs', motorcycle: 'motorcycle', chimney: 'chimney', bridge: 'bridge', mountain: 'mountain', tractor: 'tractor', 'palm tree': 'palm tree', taxi: 'car' }
  const kwOf = (mid, human) => MID[mid] || HUMAN[String(human || '').toLowerCase()] || human || mid
  let subs = []
  if (type === 'dynamic' && pmeta[1]) subs = [{ mid: pmeta[1][0], kw: kwOf(pmeta[1][0], pmeta[1][6]), rows: pmeta[1][2], cols: pmeta[1][3] }]
  else { try { subs = pmeta[5][0].map(t => ({ mid: t[0], kw: MID[t[0]] || t[0], rows: t[3], cols: t[4] })) } catch {} }
  console.log('targets:', subs.map(s => `${s.kw} ${s.rows}x${s.cols}`).join(' | '))

  const img = await getPayload(payloadToken)
  if (!img) { console.log('PAYLOAD FAILED'); return }
  fs.writeFileSync('C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\sub0.png', img)
  const sub0 = subs[0] || { kw: 'bus', rows: 4, cols: 4 }
  const count = sub0.rows * sub0.cols
  const res = await model.classifyGrid(img.toString('base64'), sub0.kw, count)
  if (!res) { console.log('model: keyword', sub0.kw, 'not a class'); return }
  const selected = res.confs.filter(x => x.conf > 0.5).map(x => x.i).sort((a, b) => a - b)
  console.log(`classify "${sub0.kw}" (${count} tiles): selected=${JSON.stringify(selected)} top3=${res.confs.slice(0, 3).map(x => x.i + ':' + x.conf.toFixed(2)).join(',')}`)

  if (type !== 'dynamic') { console.log('non-dynamic, stopping (handle separately)'); return }

  // DYNAMIC LOOP: each round we submit the matching tile positions; the server replaces
  // them and returns a fresh payload (full grid). Keep going until no tile matches.
  const Jimp = require('C:\\Users\\user\\Desktop\\a\\cf-bypass\\cf-bypasss\\node_modules\\jimp').Jimp
  let c = token, curImg = img, round = 0
  while (round < 10) {
    const r = await model.classifyGrid(curImg.toString('base64'), sub0.kw, count)
    const sel = r.confs.filter(x => x.conf > 0.5).map(x => x.i).sort((a, b) => a - b)
    console.log(`round ${round}: sel=${JSON.stringify(sel)} top=${r.confs.slice(0, 3).map(x => x.i + ':' + x.conf.toFixed(2)).join(',')}`)
    if (!sel.length) { console.log('  no matches left -> challenge satisfied'); break }
    const rr = await replaceimage(c, [sel])
    if (!Array.isArray(rr.arr)) { console.log('  replaceimage non-array:', rr.status, rr.arr); break }
    c = rr.arr[1]
    const ptok = rr.arr[5]
    console.log(`  replaceimage ${rr.status} -> newC(${String(c).length}) payload=${ptok ? 'yes' : 'NONE'}`)
    if (!ptok) { console.log('  no new payload -> done replacing'); break }
    const ni = await getPayload(ptok)
    if (!ni) { console.log('  replacement payload fetch failed'); break }
    curImg = ni
    fs.writeFileSync(`C:\\Users\\user\\Desktop\\a\\recaptcha-re\\poc\\round${round + 1}.png`, ni)
    round++
  }

  // COMMIT attempt: try userverify (urlencoded, mirroring replaceimage) with final c.
  console.log('\n=== COMMIT (userverify) ===')
  for (const variant of [
    { name: 'v+c only', body: `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(c)}` },
    { name: 'v+c+response[]', body: `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(c)}&response=${encodeURIComponent('[]')}` },
  ]) {
    const r = await fetch(`https://www.google.com/recaptcha/api2/userverify?k=${SITEKEY}`, { method: 'POST', headers: formHeaders, body: variant.body })
    const t = await r.text()
    console.log(`[${variant.name}] ${r.status}: ${t.replace(/^\)\]\}'\n?/, '').slice(0, 140)}`)
  }
})().catch(e => console.log('ERR', e.stack || e))
