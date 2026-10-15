// Minimal protobuf wire decoder/encoder — enough to inspect + rebuild the reCAPTCHA
// /reload and /userverify bodies (no .proto, just wire types). Exported for reuse.
'use strict'

function readVarint(buf, p) {
  let shift = 0, result = 0n
  for (;;) {
    const b = buf[p++]
    result |= BigInt(b & 0x7f) << BigInt(shift)
    if (!(b & 0x80)) break
    shift += 7
  }
  return [result, p]
}

// Decode a buffer into a flat list of {field, wire, value/preview, raw}.
function decode(buf, depth = 0) {
  const out = []
  let p = 0
  while (p < buf.length) {
    const start = p
    let tag; [tag, p] = readVarint(buf, p)
    const field = Number(tag >> 3n)
    const wire = Number(tag & 7n)
    if (wire === 0) {
      let v; [v, p] = readVarint(buf, p)
      out.push({ field, wire, type: 'varint', value: v.toString() })
    } else if (wire === 2) {
      let len; [len, p] = readVarint(buf, p)
      const n = Number(len)
      const slice = buf.subarray(p, p + n)
      p += n
      // try to classify: printable string vs nested message vs bytes
      const printable = slice.length > 0 && slice.every(b => b === 9 || b === 10 || (b >= 0x20 && b < 0x7f))
      out.push({ field, wire, type: printable ? 'string' : 'bytes', len: n, raw: slice,
        preview: printable ? slice.toString('latin1') : '<' + n + ' bytes> ' + slice.subarray(0, 16).toString('hex') })
    } else if (wire === 5) {
      const v = buf.readUInt32LE(p); p += 4
      out.push({ field, wire, type: 'i32', value: v })
    } else if (wire === 1) {
      const v = buf.readBigUInt64LE(p); p += 8
      out.push({ field, wire, type: 'i64', value: v.toString() })
    } else { out.push({ field, wire, type: 'UNKNOWN', at: start }); break }
  }
  return out
}

// Varint encoder
function encVarint(n) {
  n = BigInt(n)
  const bytes = []
  for (;;) {
    let b = Number(n & 0x7fn)
    n >>= 7n
    if (n) { bytes.push(b | 0x80) } else { bytes.push(b); break }
  }
  return Buffer.from(bytes)
}
function tag(field, wire) { return encVarint((BigInt(field) << 3n) | BigInt(wire)) }

// Re-encode a field list (must carry .raw for wire2, .value for varint/i32/i64)
function encode(fields) {
  const parts = []
  for (const f of fields) {
    if (f.wire === 0) { parts.push(tag(f.field, 0), encVarint(BigInt(f.value))) }
    else if (f.wire === 2) { const raw = f.raw; parts.push(tag(f.field, 2), encVarint(raw.length), raw) }
    else if (f.wire === 5) { const b = Buffer.alloc(4); b.writeUInt32LE(Number(f.value)); parts.push(tag(f.field, 5), b) }
    else if (f.wire === 1) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(f.value)); parts.push(tag(f.field, 1), b) }
  }
  return Buffer.concat(parts)
}

module.exports = { decode, encode, encVarint, tag }

if (require.main === module) {
  const CAP = require('./capture.json')
  const buf = Buffer.from(CAP.items[0].bodyB64, 'base64')
  const fields = decode(buf)
  console.log('=== /reload protobuf fields ===')
  for (const f of fields) {
    let v = f.type === 'string' || f.type === 'bytes' ? (f.preview.length > 70 ? f.preview.slice(0, 70) + `…(${f.len})` : f.preview) : f.value
    console.log(`  f${f.field} [${f.type}] ${v}`)
  }
  // round-trip check
  const re = encode(fields)
  console.log('\nround-trip identical:', re.equals(buf), `(${re.length} vs ${buf.length})`)
}
