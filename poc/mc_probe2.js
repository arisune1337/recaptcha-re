// Does multicaptcha ADVANCE in pure Node? Submit sub0's answer via replaceimage and
// check whether the next payload image differs (advanced to sub1) — distinguishes a
// protocol detail from a low-trust soft-block.
const fs = require('fs'), crypto = require('crypto')
const { decode, encode } = require('./pb')
const model = require('C:/Users/user/Desktop/a/cf-bypass/cf-bypasss/lib/recaptchaModel')
const CAP = require('./capture.json'), SITEKEY = '6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u', VER = 'TnA7HacJFoBWt9hnlunBlYfK', UA = CAP.items[0].headers['User-Agent']
const REF = `https://www.google.com/recaptcha/api2/bframe?k=${SITEKEY}`, dejson = t => JSON.parse(t.replace(/^\)\]\}'\n?/, ''))
const setF = (f, n, s) => { const x = f.find(y => y.field === n); if (x) x.raw = Buffer.from(s, 'latin1'); return f }
const md5 = b => crypto.createHash('md5').update(b).digest('hex').slice(0, 8)
const MID = { '/m/0199g': 'bicycle', '/m/01bjv': 'bus', '/m/0k4j': 'car', '/m/015qff': 'traffic light', '/m/01pns0': 'fire hydrant', '/m/04_sv': 'motorcycle', '/m/01lynh': 'stairs', '/m/079cl': 'crosswalk' }
const fh = { 'User-Agent': UA, 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', Referer: REF, Origin: 'https://www.google.com' }
async function anchorC() { return (await (await fetch(`https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=${VER}&size=normal&cb=p`, { headers: { 'User-Agent': UA } })).text()).match(/value="([^"]+)"/)[1] }
async function getP(t) { const r = await fetch(`https://www.google.com/recaptcha/api2/payload?p=${encodeURIComponent(t)}&k=${SITEKEY}`, { headers: { 'User-Agent': UA, Referer: REF } }); return r.ok ? Buffer.from(await r.arrayBuffer()) : null }
;(async () => {
  let arr, t = 0
  do { const c = await anchorC(); const f = decode(Buffer.from(CAP.items[0].bodyB64, 'base64')); setF(f, 2, c); setF(f, 16, ''); setF(f, 6, 'fi'); arr = dejson(await (await fetch(`https://www.google.com/recaptcha/api2/reload?k=${SITEKEY}`, { method: 'POST', headers: { 'User-Agent': UA, 'Content-Type': 'application/x-protobuffer', Referer: REF }, body: encode(f) })).text()); t++ } while (arr[5] !== 'multicaptcha' && t < 8)
  console.log('type:', arr[5]); const subs = arr[4][5][0].map(x => ({ kw: MID[x[0]] || x[0] })); console.log('subs:', subs.map(s => s.kw).join(','))
  let c = arr[1], ptok = arr[9]
  const img0 = await getP(ptok); console.log('sub0 payload md5:', md5(img0), img0.length + 'B')
  const r = await model.classifyGrid(img0.toString('base64'), subs[0].kw, 16)
  const sel = r.confs.filter(x => x.conf > 0.5).map(x => x.i).sort((a, b) => a - b)
  console.log(`classify ${subs[0].kw}: sel=${JSON.stringify(sel)}`)
  const body = `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(c)}&ds=${encodeURIComponent(JSON.stringify([sel]))}`
  const rr = await fetch(`https://www.google.com/recaptcha/api2/replaceimage?k=${SITEKEY}`, { method: 'POST', headers: fh, body })
  const ra = dejson(await rr.text()); console.log('replaceimage:', rr.status, '-> [1]c(' + String(ra[1]).length + ') [5]payload:', ra[5] ? String(ra[5]).slice(0, 16) + '…' : 'NONE')
  if (ra[5]) { const img1 = await getP(ra[5]); console.log('next payload md5:', md5(img1), img1.length + 'B', '=> ' + (md5(img1) !== md5(img0) ? 'CHANGED (advanced!)' : 'SAME (did not advance)')); fs.writeFileSync('mc_sub1.png', img1) }
})().catch(e => console.log('ERR', e.message))
