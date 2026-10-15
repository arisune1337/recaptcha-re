// Trust-locus test (continue half): take the TRUSTED browser's challenge token and try
// to progress the challenge from PURE NODE. If the image now ADVANCES (vs the soft-block
// we saw with anchor-minted tokens), trust lives in the (harvestable) token. If it still
// soft-blocks, trust is bound to the live TLS/IP connection.
const fs = require('fs'), crypto = require('crypto')
const model = require('C:/Users/user/Desktop/a/cf-bypass/cf-bypasss/lib/recaptchaModel')
const H = require('./handoff.json')
const SITEKEY = '6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u', VER = 'TnA7HacJFoBWt9hnlunBlYfK'
const UA = H.userAgent || 'Mozilla/5.0'
const REF = `https://www.google.com/recaptcha/api2/bframe?k=${SITEKEY}`, dejson = t => JSON.parse(t.replace(/^\)\]\}'\n?/, ''))
const md5 = b => crypto.createHash('md5').update(b).digest('hex').slice(0, 8)
const MID = { '/m/0199g': 'bicycle', '/m/01bjv': 'bus', '/m/0k4j': 'car', '/m/015qff': 'traffic light', '/m/01pns0': 'fire hydrant', '/m/04_sv': 'motorcycle', '/m/01lynh': 'stairs', '/m/079cl': 'crosswalk' }
const HUMAN = { bike: 'bicycle', 'pedestrian crossing': 'crosswalk' }
const COOKIE = H.cookieHeader || ''
const fh = { 'User-Agent': UA, 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', Referer: REF, Origin: 'https://www.google.com', ...(COOKIE ? { Cookie: COOKIE } : {}) }
console.log('using cookies:', COOKIE ? COOKIE.slice(0, 60) + '…' : '(none)')
async function getP(t) { const r = await fetch(`https://www.google.com/recaptcha/api2/payload?p=${encodeURIComponent(t)}&k=${SITEKEY}`, { headers: { 'User-Agent': UA, Referer: REF, ...(COOKIE ? { Cookie: COOKIE } : {}) } }); return r.ok ? Buffer.from(await r.arrayBuffer()) : null }
async function replaceimage(c, ds) { const body = `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(c)}&ds=${encodeURIComponent(JSON.stringify(ds))}`; const r = await fetch(`https://www.google.com/recaptcha/api2/replaceimage?k=${SITEKEY}`, { method: 'POST', headers: fh, body }); const t = await r.text(); return { status: r.status, arr: (() => { try { return dejson(t) } catch { return t } })() } }

;(async () => {
  console.log('handoff type:', H.type, '| token age: just now')
  const p = H.pmeta
  let kw, rows, cols
  if (H.type === 'dynamic') { kw = MID[p[1][0]] || HUMAN[String(p[1][6]).toLowerCase()] || p[1][6]; rows = p[1][2]; cols = p[1][3] }
  else { const s0 = p[5][0][0]; kw = MID[s0[0]] || s0[0]; rows = s0[3]; cols = s0[4] }
  const count = rows * cols
  console.log(`target: ${kw} ${rows}x${cols}`)

  let c = H.challengeToken
  const img0 = await getP(H.payloadToken)
  if (!img0) { console.log('payload fetch FAILED (token expired?)'); return }
  console.log('payload md5:', md5(img0))
  const r = await model.classifyGrid(img0.toString('base64'), kw, count)
  if (!r) { console.log('kw not a class:', kw); return }
  const sel = r.confs.filter(x => x.conf > 0.5).map(x => x.i).sort((a, b) => a - b)
  console.log(`classify ${kw}: sel=${JSON.stringify(sel)} top=${r.confs.slice(0, 4).map(x => x.i + ':' + x.conf.toFixed(2)).join(',')}`)

  const rr = await replaceimage(c, [sel])
  if (!Array.isArray(rr.arr)) { console.log('replaceimage:', rr.status, rr.arr); return }
  c = rr.arr[1]
  console.log('replaceimage', rr.status, '-> newC(' + String(c).length + ') payload:', rr.arr[5] ? 'yes' : 'NONE')
  if (rr.arr[5]) {
    const img1 = await getP(rr.arr[5])
    console.log('next payload md5:', md5(img1), '=>', md5(img1) !== md5(img0) ? '*** CHANGED — pure-Node ADVANCED with trusted token! ***' : 'SAME — soft-block persists (trust is connection-bound)')
  }
  // try a userverify commit and report the token slot
  const uv = await fetch(`https://www.google.com/recaptcha/api2/userverify?k=${SITEKEY}`, { method: 'POST', headers: fh, body: `v=${encodeURIComponent(VER)}&c=${encodeURIComponent(c)}` })
  console.log('userverify:', (await uv.text()).replace(/^\)\]\}'\n?/, '').slice(0, 120))
})().catch(e => console.log('ERR', e.stack || e))
