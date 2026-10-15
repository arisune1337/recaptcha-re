'use strict'
const fetch = globalThis.fetch
async function main() {
  const url = 'https://www.google.com/recaptcha/api2/anchor?ar=1&k=6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=TnA7HacJFoBWt9hnlunBlYfK&size=normal&cb=p'
  const html = await (await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }})).text()

  const key = 'recaptcha.anchor.Main.init('
  const i = html.indexOf(key)
  if (i < 0) { console.log('no init call'); return }
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) {
    const c = html[p]
    if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }
    if (c === '"' || c === "'") { inStr = true; q = c; continue }
    if (c === '(') depth++; else if (c === ')') { if (--depth === 0) { p++; break } }
  }
  const call = html.slice(i, p)
  // The argument to init() is a string literal in the HTML — just grab it between the parens
  // It's a JSON-encoded string (with \x escapes from the HTML)
  // Use node's JSON.parse after fixing the \x escapes
  const rawArg = call.slice(key.length, -1)
  console.log('rawArg[0:60]:', rawArg.slice(0, 60))
  // The arg is a double-quoted JS string literal; eval it
  let cfgStr
  try {
    // Safe: we only eval the string literal extracted from Google's anchor page
    cfgStr = Function('return ' + rawArg)()
  } catch(e) { console.log('eval err:', e.message); return }
  let cfg
  try { cfg = JSON.parse(cfgStr) } catch(e) { console.log('cfg parse err:', e.message); return }
  console.log('cfg length:', cfg.length)
  console.log('cb= param:', 'p')
  for (let j = 0; j < Math.min(35, cfg.length); j++) {
    const v = cfg[j]
    if (v != null) console.log(`cfg[${j}] (${typeof v}):`, typeof v === 'string' ? v.slice(0, 80) : JSON.stringify(v).slice(0, 80))
  }
}
main().catch(e => { console.error('ERR:', e.message); process.exit(1) })
