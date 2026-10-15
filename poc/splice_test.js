// Is field16 (BotGuard) reusable/bound? Rebuild /reload with a FRESH c from /anchor,
// reusing the captured field16, and see if the server accepts it. Plus a control with
// a corrupted field16 to learn whether /reload validates field16 at all (vs /userverify).
'use strict'
const { decode, encode } = require('./pb')
const CAP = require('./capture.json')
const SITEKEY = '6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u'
const VER = 'TnA7HacJFoBWt9hnlunBlYfK'
const UA = CAP.items[0].headers['User-Agent']
const RELOAD_URL = CAP.items[0].url
const headers = (() => { const h = {}; for (const [k, v] of Object.entries(CAP.items[0].headers)) if (!k.startsWith(':') && k.toLowerCase() !== 'content-length' && k.toLowerCase() !== 'host') h[k] = v; return h })()

const setStr = (fields, fnum, str) => { const f = fields.find(x => x.field === fnum); f.raw = Buffer.from(str, 'latin1'); return fields }

async function getFreshC() {
  const url = `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=${VER}&size=normal&cb=poc`
  const r = await fetch(url, { headers: { 'User-Agent': UA } })
  const html = await r.text()
  const m = html.match(/id="recaptcha-token"[^>]*value="([^"]+)"/)
  return m ? m[1] : null
}

async function postReload(body, label) {
  try {
    const r = await fetch(RELOAD_URL, { method: 'POST', headers, body })
    const t = await r.text()
    const ok = t.includes('rresp')
    console.log(`  ${label}: ${r.status} ${ok ? 'ACCEPTED rresp=' + (t.match(/"(0[a-zA-Z]?AFcWeA[^"]+)"/) || [, '?'])[1].slice(0, 24) + '…' : 'REJECTED ' + JSON.stringify(t.slice(0, 120))}`)
    return ok
  } catch (e) { console.log(`  ${label}: ERR ${e.message}`); return false }
}

;(async () => {
  const base = Buffer.from(CAP.items[0].bodyB64, 'base64')
  const origFields = decode(base)
  const origF16 = origFields.find(f => f.field === 16).raw.toString('latin1')

  const c = await getFreshC()
  console.log('fresh c from /anchor:', c ? c.slice(0, 40) + '…(' + c.length + ')' : 'NULL')
  if (!c) return

  // 1) fresh c + reused field16
  console.log('\n[1] fresh c  +  REUSED field16:')
  let f = decode(base); setStr(f, 2, c)
  await postReload(encode(f), 'result')

  // 2) fresh c + corrupted field16 (flip last 20 chars) -> does /reload validate f16?
  console.log('\n[2] fresh c  +  CORRUPTED field16 (control):')
  f = decode(base); setStr(f, 2, c)
  setStr(f, 16, origF16.slice(0, -20) + 'AAAAAAAAAAAAAAAAAAAA')
  await postReload(encode(f), 'result')

  // 3) fresh c + EMPTY field16
  console.log('\n[3] fresh c  +  EMPTY field16 (control):')
  f = decode(base); setStr(f, 2, c); setStr(f, 16, '')
  await postReload(encode(f), 'result')

  // 4) original c + reused field16 (re-confirm verbatim still works now)
  console.log('\n[4] original c + original field16 (verbatim re-confirm):')
  await postReload(base, 'result')
})()
