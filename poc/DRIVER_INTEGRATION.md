# Driver bring-up — plan and integration notes

How the two-realm driver (`harness/page.js` and its descendants) was brought
up: what already works, the one real blocker, the ordered steps, and the
integration of the four driver components (driver_core, page_rpc, solveloop,
realism). Byte offsets refer to `recaptcha__en.js` release
`TnA7HacJFoBWt9hnlunBlYfK`.

## 1. What already works (measured on a live run)

`harness/page.js` (Node v26.3.1):

- en.js loads in page mode; `recaptcha.anchor` + `recaptcha.frame` install;
  `recaptcha.anchor.Main.init(cfg)` runs from a freshly fetched anchor
  (35,937-char init literal) with no throw.
- `new Worker(webworker.js)` spawns the worker realm; the `d5`
  "recaptcha-setup" handshake transfers the port; the page-side BotGuard AE
  binds to that exact port (`port-match=true`) and the page-RPC catch-all ACK
  installs. The previously assumed "#1 blocker = page AE not bound to
  Z$.port2" is false — binding already works.
- BotGuard AE frames flow during bootstrap (`port 5→6`: one 1154-byte
  ak-shaped frame + one 266-byte frame). The page-RPC ACK logged zero
  inbound worker→page requests, so a bare MZ-ACK map is sufficient for this
  phase.

## 2. The one real blocker

No `/reload` ever fires, because the anchor never becomes interactive.
Measured after init+wait:

- `XHR requests issued: 0`; `___grecaptcha_cfg.clients: 0`.
- Element listeners registered: `{}` (zero). The only listeners the page
  registers are `window.addEventListener('message' | 'storage' | 'test')`.
  No element ever gets a `click`/`keydown` listener.
- Two cheap triggers tested, both failed: (a) richer env
  (`trustedTypes`+`PerformanceObserver`+`isSecureContext`) → still 0 element
  listeners; (b) detect-by-effect sweep of all 29 prototype methods on the
  captured controller `__grWR.D` (calling each with a synthetic click event)
  → none produced `/reload`, and some throw/hang (the verify method needs
  real `this`/state — do not blind-poke). The controller's methods are on
  the prototype (`M,init,nE,OM,m,X3,W,GR,X,v,QK,S,Bj,m_,D_,da,Y7,u8,gU,Lr,EO,sM,Vn,eF,UM,CV,CL,Ab,QI`);
  own props `U/H/C/D/L…` are data, not functions.

Root cause: the anchor iframe waits for the parent/api.js cross-frame
`message` handshake (the `cb=` RPC channel) before wiring the clickable
checkbox / creating the bframe. There is no api.js parent in-process, so it
stalls after the bg handshake. Step 4 below is the critical path; everything
else is already built or trivial.

## 3. Ordered steps

### Step 0 — wire realism into the realm builder (both roles)

In `page.js` (covers page AND worker realms, since `FakeWorker` calls the
same `buildRealm`):

- Replace the inline perf stub with:
  ```js
  const realism = require('./realism')
  const perf = realism.makePerf({ resourceHost: process.env.ORIGIN_HOST || 'lucille.sh' })
  ```
- After `vm.runInContext(CODE, ctx, …)`, before `return`:
  ```js
  try { const mk = realism.installNativeToString(ctx); realism.markRealmNatives(sandbox, mk) } catch (e) {}
  ```
- Drop the now-obsolete `setHeap` export (perf no longer closes over `heap`).

This gives the ak/Xm attestation `U>0, x>0, timeOrigin+now()≈Date.now()`, a
non-empty `getEntriesByType('resource')` (field20 el3), and native-toString
spoofing. Verify in isolation: `node harness/realism.js` (self-test must
print `now monotonic: true`, `heap U= >0`, `field20 capture.json -> VALID`).

### Step 1 — page-RPC handlers (already wired; confirm)

`page.js` passes `__onAE: PR.makeOnAE({ getPort: () => pageWorkerPort, … })`;
`page_rpc.js` installs the catch-all on the worker-port AE. The load-bearing
contract (verified against AE dispatch @byte 212085):

```js
// page_rpc.js makePageHandlerMap — has() total, get() ACKs unknown opcodes same-callid MZ
has(_K) { return true },                               // never hit the V3-unknown branch
get(K)  { return inner.has(K) ? inner.get(K) : ack },  // real handler wins, else ACK
function ack(payload, K){ /* log; */ return undefined } // -> b[5](10,0,d, undefined||w, MZ, N)
```

Keep one assertion after the bootstrap wait so the binding stays visibly
green:

```js
console.assert(pageWorkerPort, 'worker port NOT captured — handshake broken')
```

### Step 2 — reload interception (replace the record-only XHR)

`page.js`'s `makeXHR` only records; swap in the response-hooking version that
already exists in `solveloop.js`, plus its cookie jar and the `onResp` body
parser:

```js
function makeJar(){ const m={}; return { get cookie(){return Object.entries(m).map(([k,v])=>k+'='+v).join('; ')},
  absorb(sc){ String(sc).split(/,(?=[^;]+=)/).forEach(c=>{const[kv]=c.split(';');const i=kv.indexOf('=');if(i>0)m[kv.slice(0,i).trim()]=kv.slice(i+1).trim()})} } }
const { decode } = require('../poc/pb.js')
const realism = require('./realism')
function onResp(m){ try {
  if (/api2\/reload/.test(m.url) && m.reqBody) {
    fs.writeFileSync('harness/selfdriven_reload.bin', m.reqBody)
    const f16 = decode(m.reqBody).find(f=>f.field===16)
    const ok16 = f16 && f16.len>0 && /^[A-Za-z0-9_-]+$/.test(f16.raw.toString('latin1'))
    console.log('[reload] body', m.reqBody.length, 'B | field16', f16?f16.len+'B urlSafe='+!!ok16:'EMPTY',
                '| field20', realism.validateField20(m.reqBody).valid ? 'VALID':'DEGENERATE')
    const a = JSON.parse(m.text.replace(/^\)\]\}'\n?/,'')); if (a[0]==='rresp') sess.reload={c:a[1],type:a[5],payloadToken:a[9],pmeta:a[4]}
  } else if (/api2\/userverify/.test(m.url)) { const a=JSON.parse(m.text.replace(/^\)\]\}'\n?/,'')); if(a[0]==='uvresp'&&a[1]){sess.token=a[1];sess.ttl=a[2]} }
} catch(e){} }
```

Build the realm's XHR as `XMLHttpRequest: makeXHR(onResp, jar)` and forward
`jar.cookie` on every request so the session advances. Do not parse/re-encode
the reload body — forward the raw `Buffer` (latin1 round-trip).

### Step 3 — capture the anchor + bframe controllers

Two source patches right after `PR.applyPatches(...)` in `page.js`
(verified-unique anchors; bframe needs THREE close-parens):

```js
CODE = CODE.replace('(new WR(r)).D).init()', '(self.__grWR=new WR(r)).D).init()')   // anchor controller
CODE = CODE.replace('new Ac(r)).D.init(',     '(self.__grAC=new Ac(r))).D.init(')   // bframe controller
```

### Step 4 — THE GATE: make a /reload actually fire (the only unsolved work)

The anchor stalls because no parent posts the `message` handshake.
Diagnostic-first, in order:

**4a. Disambiguate why the anchor stalls (30 min, decisive).** Instrument the
page realm's window `addEventListener` to store handlers instead of no-op,
and instrument `AE.send`/its reply branch to confirm whether the page's
`ak`/`Qr` request to the worker ever resolves. Change
`addEventListener: () => {}` → a version capturing `(type, fn)` into a
`winListeners` map. Patch en.js to expose the send/resolve path: the page's
bg send is `I.vy=…send(ak,…)` (@887860); log when its returned Promise
settles. If the `ak` Promise never resolves, the bg-ready gate never opens →
the checkbox never wires. If it does resolve but still no checkbox, the stall
is purely the missing parent `message`.

**4b. If bg resolves → emulate the parent `message` handshake (primary
route).** Replay into the captured `winListeners['message']` a synthetic
`MessageEvent` mimicking api.js's setup, which the intake validates @byte
246582 as `G.source===K() && U.D(G.origin) && name===N && token zG===f` then
adopts `G.ports[0]`:

```js
const ch = new MessageChannelShim()  // give the anchor a port back to "api.js"
for (const fn of (winListeners['message']||[]))
  fn({ data: /* the name+token frame api.js posts; reconstruct from cfg cb= + cfg[24]/[30] */,
       origin: 'https://www.google.com', source: page.ctx /* parent===self in pageWindow mode */, ports: [ch.port2] })
```

The `name`/`token` come from the live anchor URL `cb=` param and the cfg
session fields (`cfg[24]` RC-handle, `cfg[30]` token). Reconstruct by logging
what the intake compares against (temporary patch around @246582 printing
`N`, `f`, `K()`), then post the matching frame. Success = the anchor renders
the checkbox (an element gains a `click` listener) → fire it with
`realism.synthPointerPath(ALL_ELS)` (also seeds non-degenerate field20).

**4c. Fallback → drive the bframe directly (solveloop CLIENT_DRIVEN).**
`recaptcha.frame.Main.init(bframeCfg)` emits `/reload` itself without a
checkbox click. Blocker = `bft` provenance: it is minted by the anchor's bg
handshake and normally carried into the bframe `src`. Once 4b makes the
anchor interactive, `makeDom`'s `captureSrc` harvests `…/bframe?…&bft=<token>`;
then boot the bframe realm sharing the same loopback worker + jar
(solveloop `solveViaClient`).

Gate exit criterion: `selfdriven_reload.bin` written and the `[reload]` log
shows a body. First reload legitimately carries field16 EMPTY; a populated
~5 KB field16 only appears from reload #2 (the @382690 response-field18 →
`vy(ak)` re-attest loop) — keep the worker session alive across both.

### Step 5 — validate before spending a siteverify attempt

On every captured reload body: `realism.validateField20(buf).valid===true`
(el0≥2, el3≥1, el2 stat count>1 & variance>0) AND reload #2 field16 len ~5 KB
matching `^[A-Za-z0-9_-]+$`. If degenerate, fix inputs (Step 0 perf +
`synthPointerPath`) before proceeding.

### Step 6 — solve loop

Hand the intercepted `sess.reload` to solveloop's existing verified classify
loop: `classifyCurrent(sess, jar)` → `GET /payload` →
`model.classifyGrid(b64, kwOf(pmeta), rows*cols)` → tiles. Default
`solveViaHybrid` (hand-built `/replaceimage`+`/userverify` reusing live `c`)
runs today but does NOT re-attest → expect soft-block; the faithful path is
`solveViaClient` once Step 4c's bframe is live so the in-VM client re-attests
every interaction.

### Step 7 — siteverify oracle (GO/NO-GO)

```js
const r = await fetch('https://www.google.com/recaptcha/api/siteverify', { method:'POST',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body: new URLSearchParams({ secret: OWN.secret, response: token }) })
console.log(JSON.stringify(await r.json()))   // {success:true,...} == the ONLY ground truth
```

Token source: `sess.token` (uvresp[1]) or
`page.sandbox.grecaptcha.getResponse()`. TTL ~110s — siteverify promptly.

## 4. The three most likely failure points

1. **No /reload fires (the anchor never goes interactive) — highest, already
   reproduced.** Check: after init+wait, dump `XHR_REQS.length` and element
   listeners (`for (const el of ALL_ELS) for (const t of Object.keys(el._lis||{})) types[t]=(types[t]||0)+1`).
   If `types` lacks `click`/`keydown` and only window-level
   `message`/`storage`/`test` exist, you're stalled at the parent handshake →
   execute 4a/4b.
2. **field16 empty/degenerate on the reload you forward.** Check:
   `pb.decode(reloadBuf).find(f=>f.field===16)`. Reload #1 EMPTY is expected;
   assert reload #2 ≈ 5000 B, `^[A-Za-z0-9_-]+$`. If still empty, the worker
   session died between interactions (the @382690 `vy(ak)` loop didn't run) —
   confirm the loopback port + page-RPC ACK are still live (no
   "reCAPTCHA Timeout" rejections) and the same worker realm persists across
   the whole solve.
3. **Token mints but siteverify returns success:false (low-trust Xm /
   field20).** Check before spending the attempt:
   `realism.validateField20(reloadBuf).valid===true` AND the ak attestation
   read `U=N−K>0`, `x=round(now_after−now_before)>0`. If valid-but-rejected,
   the wall is statistical realism (Node heap jitter vs Chrome's quantized
   `usedJSHeapSize`; Node interpretation slower than Chrome JIT inflates `x`)
   — only the own-key siteverify boolean falsifies it; no static check can.

Net: Steps 0–3, 5–7 are built/trivial and downstream-proven. The entire
remaining risk is Step 4. Start with the 4a diagnostic — it tells you in one
run whether you're blocked on bg-resolution or purely on the missing parent
message, which selects route 4b vs 4c.

## 5. driver_core.js

`harness/driver_core.js` (no new deps — reuses `./page.js` `buildRealm` + the
loopback primitives, and `../poc/pb.js`). Run: `node harness/driver_core.js`
(env: `SITEKEY`, `ORIGIN_HOST`, `VER`, `TRACE=1`).

1. Source-patches en.js (5 anchors, all verified unique) to capture
   `__cap`={RPp,Qr,ak,AE,d5} in both realms + the `WR` anchor controller as
   `self.__grWR`, writes the patched copy to tmp, and points `page.js` at it
   via `process.env.ENJS` set before `require('./page.js')`.
2. Boots the page realm, `GET /anchor`, balanced-paren/string-safe slice of
   the verbatim `recaptcha.anchor.Main.init("…")` literal, runs it.
3. `FakeWorker` spawns the worker realm over the by-reference loopback;
   `makePerf()` gives a monotonic 0.1ms clock + a heap that grows off real
   `process.memoryUsage()` so the Xm reads `U=N−K>0` and `x>0` stay
   non-degenerate (fixes page.js's static-heap `U=0` / `now()+random`
   giveaways).
4. Supplies its own `XMLHttpRequest` that, on any `/api2/reload`, captures
   the body as raw bytes via `toBuf` (latin1 string → Buffer, no UTF-8
   mangling), runs `extractField16` (pb.decode → field 16 wire-2 →
   URL-safe-base64 check + full f1/f2/f6/f14/f20/f25 context map), dumps
   `selfdriven_reload_N.bin`, then forwards the same Buffer to the network
   with a cookie jar so the session can advance.
5. Trigger = synthesized pointer path + checkbox click/space on every
   listener-bearing element; `window.botguard` deliberately left undefined
   so the verify method stays on the worker-attestation path
   (`Promise.resolve().then(this.U)`), not the page-side `ew.execute()` that
   can't run in node.

Verified: `extractField16` on the real captured reload body →
`present=true len=5044 urlSafeB64=true`, map `{f1,f2,f5,f6,f14,f16,f20,f25}`
(f6="fi", f16=5044B, f25="W10"); the init extractor correctly keeps a `)`
that sits inside a string. Live: page loads, anchor fetched (35950-char init
literal), worker spawns, `__cap` captured in both realms (RPp opcodes=2),
`__grWR.D` keys match the expected set. The interception path is wired and
proven; it just had nothing to capture because no `/reload` fired.

## 6. page_rpc.js — the page-side AE handler set

### 6.1 Why a handler set fixes a stall (source grounding)

Confirmed verbatim from the local `recaptcha__en.js`:

- AE dispatch @byte 212085: `...else if(d.P["has"](K))A=d.P.get(K),(new Promise(function(h){h(A.call(d.C,x||void 0,K))})).then(function(h){b[5](10,0,d,h||w,MZ,N)},function(h){b[5](9,0,d,(h=h instanceof Error?h.name:h||w,h),V3,N)});else b[5](8,0,d,w,V3,N)`
  — `K`=opcode, `N`=callid, `x`=decoded payload, `d.C`=handler `this`.
- AE ctor @byte ~254860 copies arg2 into a fresh plain Map — a clever Map
  passed as arg2 is discarded; the catch-all MUST overwrite `this.P` after
  construction.
- send watchdog @byte 794881: `D.reject(Error("reCAPTCHA Timeout ("+q+")"))`
  armed at 15000 ms.

So a worker→page request stalls iff the page fails to reply MZ with the same
callid in 15s — exactly two cases: (a) `d.P.has(K)` false → V3 error, or (b)
the handler throws/rejects → V3. The set removes both: `has()` is total and
the ACK never throws.

### 6.2 The handler set

```js
function makePageHandlerMap(specific, opts) {                     // specific = the AE's existing this.P
  const inner = specific instanceof Map ? specific : new Map()
  const stats = opts.stats || new Map(), log = opts.log || (()=>{})
  function ack(payload, K) {                                       // this === d.C (page global)
    try { stats.set(K,(stats.get(K)||0)+1); log('inbound op='+String(K)+' '+describe(payload)); if (opts.onRequest) opts.onRequest(K,payload,opts.instance) }
    catch (_) {}                                                   // logging must never turn an ack into V3
    return undefined                                               // -> b[5](10,0,d, undefined||w, MZ, N): same-callid MZ ack
  }
  return { __isPageHandlerSet:true, _inner:inner, _stats:stats,
    has(_K){ return true },                                        // never reach the V3-unknown branch
    get(K){ return inner.has(K) ? inner.get(K) : ack },            // real seeded handler wins, else ACK
    set(K,v){ inner.set(K,v); return this }, delete(K){ return inner.delete(K) },
    forEach(cb,t){ return inner.forEach(cb,t) }, keys(){ return inner.keys() }, get size(){ return inner.size } }
}
function installOn(ae, opts) {                                     // idempotent, merge-preserving
  if (!ae || ae.P==null || ae.P.__isPageHandlerSet) return ae
  ae.P = makePageHandlerMap(ae.P instanceof Map ? ae.P : new Map(), Object.assign({instance:ae}, opts||{}))
  return ae
}
```

Returning `undefined` is deliberate: dispatch emits `b[5](10,0,d, h||w, MZ, N)`,
so an `undefined` return yields the bundle's own default ack payload `w` —
the same ~4-byte "y" ack the real page emits for the worker's liveness/echo
polls (matches the feed.js / prog_capture measurement: only the page's
`ak`/`D` call drew the big 215 KB reply; everything else got a tiny
same-callid ack). More faithful than fabricating a payload.

### 6.3 Installation

Two unique source patches:

```js
const PATCHES = [
  ['AE=function(q,r,w,D,d,A){return b[32]',  'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]'],
  ['this.D.start()),q^6)>>3',                'this.D.start(),typeof __onAE==="function"&&__onAE(x)),q^6)>>3'],  // x===this
]
```

The second fires `__onAE(instance)` at the end of every AE ctor. It is
`typeof`-guarded so it's a no-op in the worker realm (the worker's `RPp`
server map is never touched). `makeOnAE({getPort})` calls `installOn` on each
page-realm AE — merge-preserving, so real handlers survive and only gain a
default-ACK.

Wiring in `page.js`: (1) `let CODE = PR.applyPatches(fs.readFileSync(ENJS,'utf8'))`;
(2) `base = { __cap: {}, ... }` in `buildRealm` (both realms); (3) capture
the worker's transferred port in `FakeWorker`'s relay
(`if (tp.length && !pageWorkerPort) pageWorkerPort = tp[0]`); (4)
`__onAE: PR.makeOnAE({ getPort:()=>pageWorkerPort, log, onRequest })` in
`windowExtra`.

### 6.4 Verification

`node page_rpc.selftest.js` — all 6 checks pass: patches apply uniquely +
patched bundle still compiles; every UNKNOWN inbound opcode → same-callid MZ
ack (never V3-unknown); seeded real handler preserved and invoked with
`this===page global`; `P.has(K)` total; ACK throw-proof even if logging
blows up; `installOn` idempotent + merge-preserving. Booting the wired page
realm: page loads, `__cap.AE` captured, constructing a `new __cap.AE(...)`
fires the hook and yields an instance whose `.P` is the handler set.

Observed: one `new AE` trips the hook on 2 distinct AE-shaped instances (the
dispatch-merged ctor body runs for selector 8 and a sibling selector).
Benign — both are AE-shaped, `installOn` is idempotent. To restrict to only
the worker-port AE, pass `makeOnAE({ getPort, allPageAEs:false })` (matches
`ae.D === pageWorkerPort`), at the cost of relying on raw port identity
surviving any wrap Google applies to `ev.ports[0]`.

### 6.5 Open risk

The expected reply *shape* of a genuine worker→page BotGuard request cannot
be statically enumerated — those semantics live in the server-delivered
~336 KB BotGuard bytecode (the `bC`-VM input), not in `recaptcha__en.js`.
The bare MZ ack is provably correct for liveness/echo polls (matches the
measured 4-byte "y" acks) and eliminates stalling as a failure mode — but if
the bytecode ever issues a page-directed request expecting real structured
data ("read navigator.X / a DOM value / echo this nonce"), the ACK returns
the default `w` instead, producing a structurally-valid-but-low-trust
attestation rather than a hard stall. Invisible to static analysis and to
this harness; only the siteverify oracle can falsify it.

## 7. solveloop.js

The full solve loop on top of the two-realm harness. Verified: syntax check
passes; all 5 source patches apply and the realm boots clean
(`recaptcha.anchor` + `recaptcha.frame` install, both `Main.init`s present);
the ONNX classify branch runs end to end (`classifyGrid('bus',9)` →
`selected [5]`); deps (`pb.js`, `page.js`, recaptchaModel, `own_key.json`)
resolve.

Flow:

1. Boot anchor page realm + BotGuard worker realm over the by-reference
   loopback.
2. Fetch live `/anchor`, run `recaptcha.anchor.Main.init(cfg)` verbatim
   (init is NOT the trigger, @810567).
3. Fire the checkbox on captured DOM listeners → the client self-emits
   `POST /reload`; the response-hooking XHR captures the body, decodes
   field16, and parses `rresp` → `{c, type, payloadToken=arr[9], pmeta=arr[4]}`.
4. `GET /payload` → `model.classifyGrid(b64, kwOf(pmeta...), rows*cols)` →
   `confs.filter(c>0.5).map(i)`.
5. Deliver the answer; capture `uvresp[1]` (or `grecaptcha.getResponse()`);
   POST siteverify with `OWN.secret` as the GO/NO-GO oracle.

Key capability over `page.js`: a response-hooking `makeXHR(onResp, jar)`
(routes VM XHR → `fetch`, fires `onResp({url,status,text,buf,reqBody})` so
`rresp`/`dresp`/`uvresp` are read the instant the client receives them) + a
cookie jar + iframe-`src` capture to harvest the server-minted `bft`. The
perf stub is upgraded per the integrity layer (monotonic 0.1ms clock + real
`process.memoryUsage().heapUsed` so the Xm attestation's `heapDelta U>0`,
`execMs x>0`).

Two answer-delivery modes:

- `solveViaHybrid` (default, runs today): classify loop + hand-built
  urlencoded `/replaceimage`+`/userverify` reusing the live `c`. Gives a
  real siteverify verdict but does NOT re-attest.
- `solveViaClient` (`CLIENT_DRIVEN=1`): boots the bframe realm from the
  captured `bft`, captures the bframe controller via the `__grAC` patch, and
  injects the selection so the client builds the continuation XHRs itself
  (continuous in-VM attestation).

Bring-up gotcha worth remembering: capturing the bframe controller needs
`new Ac(r)).D.init(` → `(self.__grAC=new Ac(r))).D.init(` — **three**
closing parens, because (unlike the `WR` anchor) the original
`(r=new XZ(TP(q)),new Ac(r))` has no wrapping parens, so the naive
two-paren wrapper unbalances the source and en.js throws
`Unexpected token '}'`.

Open risk: the client-built `/replaceimage`+`/userverify` selection seam —
getting the model's tile choice INTO the live client so recaptcha__en.js
emits the continuation XHRs itself with live per-interaction attestation.
`driveSelection()` returns `false` because the tile-select + Verify methods
on the bframe controller `ctrl.D` are minified, dispatch-encoded, and rotate
per release — they must be traced at runtime (enumerate `ctrl.D` fn props,
poke `(tileIndex)` while watching for a tile-state flip / a `/replaceimage`
XHR), never hardcoded. Coupled to two unproven sub-risks: `bft` provenance +
the bframe↔anchor cross-frame channel, and Xm realism.

## 8. realism.js

The integrity/realism layer (no deps beyond `../poc/pb.js`). Self-test
(`node realism.js`) passes all three concerns; an extra test confirmed it
spoofs in-context (bytecode-style) functions across every probe form
(`String(fn)`, `""+fn`, `fn.toString()`,
`Function.prototype.toString.call(fn)`).

Exports:

- `makePerf({resourceHost, baseHeap, resourceEntries})` → the realism
  `performance` object (concern 2).
- `installNativeToString(ctx)` → returns a host-callable `markNative(fn,name)`;
  `markRealmNatives(sandbox, markNative)` tags the whole hand-stub surface
  (concern 1).
- `makeResourceEntries(host)` / `synthPointerPath(ALL_ELS)` /
  `validateField20(reloadBodyBuf)` (concern 3).

### 8.1 Timing + heap (feeds ak/Xm: `d`,`U`,`x` @886328)

Grounded in the ak handler reading `usedJSHeapSize` before/after and
`performance.now()` before/after:

- `now()`: `process.hrtime.bigint()`-based, floored to 0.1 ms (Chrome
  granularity), strictly monotonic, starts ~0.
- `timeOrigin`: real `Date.now()` at realm construction (not 0) →
  `timeOrigin+now() ≈ Date.now()` (the @270990 coherence holds; self-test
  confirms within 5 ms).
- `memory.usedJSHeapSize`: `quantize(BASE + max(0, heapUsed−heap0), 100000)`
  with a ratchet so it never shrinks between the two ak reads → `U = N−K > 0`
  organically (self-test showed `U≈18 MB` after a forced allocation).
  `jsHeapSizeLimit = 2190000000`.

### 8.2 Native toString spoof

The load-bearing fix uncovered during testing: a `vm` context has TWO
`Function.prototype`s. In-context literals (the bundle + the bC-VM bytecode)
inherit the context-internal FP; host-authored stubs (`perf.now`, `atob`)
inherit the host FP. The override must patch both with one shared `WeakSet`:

```js
var fnFP = Object.getPrototypeOf(function(){});            // context-internal (bundle/bytecode)
var gFP  = Function.prototype || fnFP;                     // global-binding FP (host stubs)
fnFP.toString = nativeToString; if (gFP!==fnFP) gFP.toString = nativeToString;
```

`nativeToString` returns `function <name>() { [native code] }` for any
function in the WeakSet, else delegates to the real original (genuine
intrinsics like `Object`/`Math.round` stay correct; real bundle functions
still show source). The override, both originals, and `.call/.apply/.bind`
are themselves in the set, so `Function.prototype.toString.toString()` and
method identity both read native. Tagging is by object identity in a
realm-resident WeakSet → invisible to `getOwnPropertyNames` enumeration.

### 8.3 field20 non-degeneracy (builder @392015 / telemetry @398953)

- `getEntriesByType('resource')` returns ~8 plausible 3rd-party entries
  (full-URL `name` → the client takes `new URL(name).hostname` for el3) with
  monotonic `startTime`, positive `duration`, `responseStatus:200`,
  `nextHopProtocol:'h2'` — replaces the degenerate `()=>[]` stub that yields
  `el3=[]`.
- `synthPointerPath(ALL_ELS)` dispatches an eased pointermove→down→up/click
  stream with jittered `clientX/clientY` and non-uniform increasing
  `timeStamp`s into the elements that registered listeners → el0 events ≥2
  and el2 per-type stats with `count>1, variance>0`.
- `validateField20(body)` decodes the `/reload` body via `pb.js`, takes
  field 20, `JSON.parse(atob("W1"+s))`, asserts arity 5 / el0≥2 / el3≥1 /
  some el2 stat `count>1 & variance>0`. Verified against `capture.json` →
  `VALID, el0len 2, el3len 8` (matches the real wire).

### 8.4 Wiring

`page.js`: replace the inline perf with `realism.makePerf(...)`; after
`vm.runInContext(CODE, ctx, …)` add the `installNativeToString` +
`markRealmNatives` pair (install ordering is load-bearing: after CODE loads —
intrinsics present — but before `init`/`ak` drives the bytecode); replace
the manual fire-loop with `realism.synthPointerPath(ALL_ELS)`; at the reload
capture, log `realism.validateField20(reload.body)` before forwarding.

`worker.js` (the attestation-critical realm): same perf replacement at line
36 and the same toString pair right after its `vm.runInContext`.

Cheap adjacent fix: the realm Proxy uses `has(){return true}`, so
`('anyProp' in self)===true` while `self.anyProp===undefined` — a global-shape
inconsistency no real `window` has. Constrain `has` to
`Reflect.has(t,k) || ALLOWLIST.has(k)` to close it.

### 8.5 Open risk

The actual integrity/coherence probe set lives inside the server-delivered
BotGuard bytecode (`new bC(D)`, run via `B[27]` in the `ak` handler), which
is not present in `recaptcha__en.js` — there is no way to enumerate which
functions it `toString`s, whether it cross-checks accessor `descriptor.get`
natives or `Reflect.ownKeys` global shape, or how it joins
`(heapDelta U, execMs x, deviceMemory d)` against a server-side model. The
shims are necessary but maybe insufficient: `process.memoryUsage().heapUsed`
is V8-process-wide and GC-noisy, not Chrome's privacy-quantized renderer
`usedJSHeapSize`, so `U`'s magnitude/jitter may mismatch even after 100 KB
bucketing; and node interpreting the ~336 KB program is far slower than
Chrome's JIT, inflating `x`. Only the own-key siteverify oracle can falsify
the result.
