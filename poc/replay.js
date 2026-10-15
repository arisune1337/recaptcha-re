// PHASE 0 replay — POST the captured /reload body VERBATIM from Node (no browser).
// Tests three things at once:
//   1. wire: can a plain Node HTTPS request to /reload even get a 200 + rresp?
//   2. c-token: is the reload `c` single-use? (replay reuses the same body/c)
//   3. anti-replay/field16: does the server reject a byte-identical resend?
// Then a second variant: GET a FRESH c from /anchor and splice it into the body,
// to isolate "stale c" from "stale field16 / IP / TLS" rejection.
const fs = require('fs')
const CAP = require('./capture.json')
const it = CAP.items[0]
const SITEKEY = '6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u'

function printableRuns(buf, min = 8) {
  const runs = []; let cur = ''
  for (const b of buf) {
    if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b)
    else { if (cur.length >= min) runs.push(cur); cur = '' }
  }
  if (cur.length >= min) runs.push(cur)
  return runs
}

async function post(url, body, headers) {
  const res = await fetch(url, { method: 'POST', headers, body })
  const txt = await res.text()
  return { status: res.status, txt }
}

function cleanHeaders(h) {
  const out = {}
  for (const [k, v] of Object.entries(h)) {
    if (k.startsWith(':') || k.toLowerCase() === 'content-length' || k.toLowerCase() === 'host') continue
    out[k] = v
  }
  return out
}

;(async () => {
  const body = Buffer.from(it.bodyB64, 'base64')
  console.log('=== captured /reload ===')
  console.log('url   :', it.url)
  console.log('bytes :', body.length)
  const runs = printableRuns(body)
  console.log('ascii fields in body:')
  runs.forEach(r => console.log('   ', r.length > 90 ? r.slice(0, 90) + `…(${r.length})` : r))
  console.log('orig response head:', String(it.response.body).slice(0, 60))

  const headers = cleanHeaders(it.headers)

  // --- Variant A: verbatim replay (same c, same field16) ---
  console.log('\n=== A) VERBATIM replay (same body) ===')
  try {
    const r = await post(it.url, body, headers)
    console.log('status:', r.status)
    console.log('body  :', r.txt.slice(0, 200))
    console.log('VERDICT:', r.txt.includes('rresp') ? 'ACCEPTED (valid rresp!)' : 'REJECTED / no rresp')
  } catch (e) { console.log('FETCH ERR:', e.message) }

  // --- Variant B: fresh c from /anchor spliced into the same body ---
  console.log('\n=== B) fresh c from /anchor, same field16 ===')
  try {
    // mirror the bframe's anchor url params (co = base64 origin). Use a generic anchor fetch.
    const anchorUrl = `https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=${'TnA7HacJFoBWt9hnlunBlYfK'}&size=normal`
    const a = await fetch(anchorUrl, { headers: { 'User-Agent': it.headers['User-Agent'] } })
    const html = await a.text()
    const m = html.match(/id="recaptcha-token"[^>]*value="([^"]+)"/)
    console.log('anchor status:', a.status, 'c token:', m ? m[1].slice(0, 40) + '…' : 'NOT FOUND')
    if (m) {
      // The reload body encodes c as a length-delimited field. Find the OLD c bytes
      // (an ascii run starting with the same prefix) and replace with the fresh one.
      const oldC = runs.find(r => /^[0-9]{2}A[A-Za-z]/.test(r) && r.length > 200) || runs.find(r => r.length > 200)
      if (oldC && oldC.length === m[1].length) {
        const nb = Buffer.from(body.toString('latin1').replace(oldC, m[1]), 'latin1')
        const r = await post(it.url, nb, headers)
        console.log('status:', r.status, '| body:', r.txt.slice(0, 160))
        console.log('VERDICT:', r.txt.includes('rresp') ? 'ACCEPTED' : 'REJECTED')
      } else {
        console.log('skip splice: oldC len', oldC && oldC.length, 'vs new', m[1].length, '(length-prefix would shift)')
      }
    }
  } catch (e) { console.log('ANCHOR ERR:', e.message) }
})()
