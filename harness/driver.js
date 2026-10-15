// Drive the captured RPp opcode handlers directly (the synth's bring-up shortcut) to learn
// the exact shape Qr(init)/ak(run) need and whether running them touches canvas/webgl/dom.
const W = require('./worker.js')
const { cap, WORKER_PORT, hotHits, accessed } = W

console.log('\n=== driver: opcode handlers ===')
if (!cap.RPp) { console.log('no RPp captured'); process.exit(1) }
const Qr = cap.Qr, ak = cap.ak
const qrH = cap.RPp.get(Qr), akH = cap.RPp.get(ak)
console.log('Qr handler:', typeof qrH, '| ak handler:', typeof akH)

function probe(label, fn) {
  const before = hotHits.length
  let r, e = null
  try { r = fn() } catch (err) { e = err }
  const newHot = hotHits.slice(before)
  console.log(`\n[${label}] ${e ? 'threw: ' + e.message : 'returned: ' + (r && r.constructor ? r.constructor.name : typeof r)}`)
  if (newHot.length) console.log('  HOT env touched:', [...new Set(newHot)].join(' '))
}

// Try Qr (init) with progressively richer inputs to see what it reads off q.
probe('Qr({})', () => qrH({}))
probe('Qr({Oo:Uint8Array, D:Uint8Array, L:0})', () => qrH({ Oo: new Uint8Array([1, 2, 3, 4]), D: new Uint8Array([0]), L: 0 }))
// Try ak (run/attest)
probe('ak({})', () => akH({}))
probe('ak({D:Uint8Array})', () => akH({ D: new Uint8Array([0, 1, 2, 3]) }))

// Drive via the real AE channel too (page-side mirror), if WORKER_PORT present.
if (WORKER_PORT && cap.AE) {
  try {
    const pageAE = new cap.AE(WORKER_PORT, new Map(), W.ctx, 'https://www.google.com', null)
    console.log('\npage AE created over WORKER_PORT:', typeof pageAE, '| has send:', typeof (pageAE && pageAE.send))
  } catch (e) { console.log('\npage AE construct threw:', e.message) }
}

console.log('\n=== cumulative HOT env hits across all opcode probes ===', hotHits.length ? [...new Set(hotHits)].join(' ') : 'NONE (no canvas/webgl/dom needed)')
console.log('env reads referencing memory/heap/timing/deviceMemory:',
  [...accessed.keys()].filter(k => /memory|heap|deviceMemory|now|performance|hardwareConcurrency/i.test(k)).join(' ') || '(none yet)')
