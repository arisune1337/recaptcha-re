# Routes to a captured /reload body

Three routes were built to get a live, client-built `/reload` body out of
`recaptcha__en.js` running in-process, plus the fire-and-capture driver that
reuses them. Byte offsets refer to release `TnA7HacJFoBWt9hnlunBlYfK`.

## 1. reload_now.js — bframe-direct, reload #1

`harness/reload_now.js`. Run:
`BFT=<fresh> SITEKEY=<k> ORIGIN_HOST=<embedder> VER=<ver> node harness/reload_now.js`.
Reuses `driver_core`'s instrumented-XHR/field16/perf primitives via
`bframe_direct.js` (whose `module.exports` was extended to also surface
`makeJar, makePerf, makeDom, MessageChannelShim, makePort, locFrom, noop` —
backward-compatible).

### Why bframe-direct and not parent emulation

The `/reload` is always emitted by the **bframe**, never the anchor
(`poc/flow.json`: the `/reload` Referer is the bframe URL). The bframe entry,
confirmed verbatim at byte 893462, is
`(r=new XZ(TP(q)),new Ac(r)).D.init(E[40](4,r,1,P))` — `Ac.D.init()`
auto-schedules the `reason=fi` `POST /reload` on load. Reload #1's field16 is
empty, so it needs nothing from BotGuard. This skips the per-session AE
crypto wall that dead-ends `driver_emulate_parent.js` (a second realm derives
a different keystream seed and can't encode the render-config MZ). Zero AE
frames are sent. Single input: a fresh in-session `bft`.

### Flow

1. Require `bframe_direct.js` → module-load patches `recaptcha__en.js`
   (`new Ac(r)).D.init(` → `(self.__grAC=new Ac(r))).D.init(`, plus
   WR/RPp/ak/d5 + page_rpc AE hooks). `buildRealm` compiles the patched
   bundle in every realm.
2. Resolve `BFT` (env; hard-fail with capture instructions if absent — it's
   the anchor's type-0d token, time/session-bound).
3. `GET https://www.google.com/recaptcha/api2/bframe?hl=en&v=<VER>&k=<SITEKEY>&bft=<BFT>`
   (UA + Referer=burl); absorb `Set-Cookie` into the jar.
4. `extractInitCall(bhtml,'recaptcha.frame.Main.init')` — the exact
   `recaptcha.frame.Main.init("...")` literal. Null ⇒ bft dead → abort.
5. Boot the bframe realm: instrumented `makeXHR` (captures `/reload`
   verbatim), `location`=burl, `window.parent` = a minimal `parentStub`
   (≠ window so the framed gate @190196 passes), no-op `Worker`,
   `botguard:undefined`.
6. `vm.runInContext(binit, bframe.ctx)` → `Ac.D.init()` auto-fires
   `POST /reload`. No trigger needed (contrast the anchor route's checkbox).
7. Capture + validate field16, write `bframe_reload_1.bin`.

### Exact bytes on the wire

- Only outbound request: the `GET /bframe?...&bft=<BFT>` above.
- Only "frame": the parent-stub's one-shot reply to the bframe's
  `"recaptcha-setup"`+MessagePort post —
  `{data:"recaptcha-setup", origin:HOST_ORIGIN, source:parentStub, ports:[ch.port2]}`
  delivered into the bframe's window `message` listeners (origin must equal
  the bframe cfg's `co` = the **embedder** origin, not www.google.com).
  Whatever the bframe sends back is swallowed — no AE encoding needed for
  reload #1.
- For reload #2's populated field16 only, the codec is already recovered:
  wire = `JSON.stringify(["B"+base64url(XOR12(utf8(JSON.stringify(envelope)))), msgType, callid])`,
  `MZ="x"`/`V3="y"`, 12-byte per-session key from known-plaintext
  (`scratchpad/keystream.bin`, `wire_pairs.jsonl`). Not used by reload_now.

### field16 capture + validation

`extractField16(buf)` → `pb.decode` →
`fields.find(f=>f.field===16 && f.wire===2)`. PASS = the body
protobuf-decodes and shows reload fields (`f1`=VER, `f2`=c, `f14`=sitekey).
`field16 present:false` is the **correct** state for reload #1 — it is
populated only from reload #2, built from this rresp's field18 attestation,
which needs the anchor-worker relay (fall back to `bframe_direct.js`).

### Failure points

1. **bft invalid/expired** → the `/bframe` HTML has no `frame.Main.init`
   literal. Check: `extractInitCall(...)===null`, small `bhtml.length`, no
   `"frame.Main.init"` substring → re-capture a fresh bft (it expires fast).
2. **reload #1 gated on real parent setup, not the auto-timer** → 15 s
   elapse with `__grAC=true` and a bframe `message` listener present but
   `RELOADS.length===0`. Check with `TRACE=1` that (a) the bframe's
   `"recaptcha-setup"` post is seen and (b) the reply's `origin` matches the
   bframe cfg `co`; if mismatched, the port is silently dropped → fix
   `HOST_ORIGIN` to the embedder origin, or run the fallback
   `node harness/bframe_direct.js` (boots anchor+worker+relay).
3. **/reload returns non-protobuf (HTML error/redirect) or no rresp** →
   bft↔cookie session mismatch. Check: `extractField16(buf).error` set or the
   info map lacks `f1/f2/f14`; the `/reload` response head must be
   `)]}'\n["rresp",...]`. If 200 but no rresp, supply the matching
   `_GRECAPTCHA` cookie from the same session that minted the bft.

Caveat: both routes need one external in-session input across the BotGuard
wall. Bframe-direct needs a *fresh* `bft` per session (recurring capture);
parent emulation would need the render-config MZ plaintext
(session-independent, capture-once, but blocked on the recovered-but-unkeyed
cross-frame seed). Bframe-direct is the shortest path to a *captured /reload
body*; it is not a standing bypass.

## 2. driver_emulate_parent.js — parent emulation

`harness/driver_emulate_parent.js`. Run: `node harness/driver_emulate_parent.js`
(env: `SITEKEY/ORIGIN_HOST/VER/TRACE`). Plus one TRACE-gated diagnostic line
in `page.js` (`_deliver` logs swallowed loopback-port listener throws under
`TRACE=1`).

Instead of hand-crafting the MZ render-response (impossible — opaque/
encrypted), it boots a **second en.js realm as the api.js/parent host** and
lets Google's own parent code answer the anchor's comm frame.

1. **Parent role unlock (verified).** The bundle only attaches the host API
   if seeded exactly like `api.js`. The load-bearing seeds:
   ```js
   __recaptcha_api:'https://www.google.com/recaptcha/api2/', __google_recaptcha_client:true,
   ___grecaptcha_cfg:{ fns:[], render:['onload'], 'anchor-ms':[20000], 'execute-ms':[30000] },
   grecaptcha:{ ready:function(f){ cfg.fns.push(f) } }   // MUST pre-exist or render/execute never attach
   ```
   Result: `grecaptcha = ready,render,reset,getResponse,execute,getPageId`.
   Auto-render (`render:['onload']`) on an empty `.g-recaptcha[data-sitekey]`
   container registers the client (cfg.count=1), creates the anchor
   `<iframe>` with `co` derived from the parent's `location.origin`, and
   installs the parent intake listener — no hand-built co/cb.
2. **Cross-realm bridge (load-bearing identities).** The anchor realm stays
   `pageWindow:true`; the get-trap shadows `parent/top/window` but NOT
   `postMessage/addEventListener`, so those sandbox props are overridden
   directly (no `page.js` fork):
   - anchor → parent: delivered with `source = cwBridge` (the parent's
     `iframe.contentWindow`), `origin = https://www.google.com`.
   - parent → anchor: delivered with `source = anchorRealm.ctx`
     (= `window.parent`), `origin = HOST_ORIGIN`.
   - MessagePorts are `page.js` by-ref `makePort` objects — transferred, not
     copied, so the adopting realm binds its AE straight to the object.
3. **The correct api.js responses are delegated to Google's code.** Once the
   parent adopts the anchor's transferred port, the bundle's real parent AE
   is live on it with the genuine conf handler — the correct
   render/create-client MZ response is produced by construction, not faked.

### Result — the bridge is structurally complete up to the codec

Live run: `AE#1 port=8 handlerOpcodes=[j,e,d,i,m,C,t,o,a,f,v,z,l,A] ...
port._lis=2 _on=false _started=true` → the parent adopted the port and bound
the real AE whose handler map includes the conf opcode `C`. The anchor's `C`
(839 B conf) and `z` frames arrive at the parent AE (taps fire), no throw —
but `.P.get("C")` is never reached.

### The confirmed blocker

The cross-frame AE payload is keyed by a per-session secret that two
independently-booted en.js realms do not share. Proof:

- The anchor's `C` frame decodes cleanly only with the anchor realm's own
  recovered 12-byte keystream → `{"j_":"","D":"[\"conf\",null,\"6Le-wvkSA…`
  (the register/conf message). Recovered key e.g.
  `0055f2270d0040843609a903`, `validJSON=true`.
- The parent AE holds a different key, so its dispatch decode fails
  silently (listener bound, frame present, no throw, handler never runs) →
  no MZ render-response → the anchor stays non-interactive (0 click
  listeners, 0 `/reload`).
- Refinement: the recovered `C`-frame keystream does **not** decode the same
  channel's `z` frame (`decodesWithAnchorKey=false`). The keystream is
  re-derived per frame from `messageType+callId` over a session seed — a
  single recovered keystream is insufficient; the parent needs the anchor's
  session seed.

In a real browser the two en.js instances share that seed via the
server-issued cfg; a parent realm with only local render state derives a
different one. Next step: copy the anchor realm's AE session seed into the
parent codec (locate the seed slot fed to `C[23]`/the AE ctor keystream
generator) so the parent's real conf handler decodes the anchor frames and
emits correctly-keyed MZ replies automatically — the minimal change that
flips interactivity. Everything upstream of the codec (parent role, iframe
creation, port adoption, real-AE binding, frame delivery) is proven working.

## 3. bframe_direct.js — anchor + worker + bframe

`harness/bframe_direct.js`. Run: `node harness/bframe_direct.js` (env:
`SITEKEY`, `ORIGIN_HOST`, `VER`, `BFT`, `TRACE=1`). Exports
`{ buildRealm, makeWorkerHub, makeXHR, extractField16, extractInitCall }`.

- Source-patches `recaptcha__en.js` to capture the bframe controller `Ac`
  (entry @byte 893462), the anchor `WR`, the BotGuard tokens `RPp/Qr/ak`,
  and `d5` ("recaptcha-setup"); then layers `page_rpc.applyPatches` on top.
  The patch anchors are disjoint; all five apply.
- Own `buildRealm` (not `page.js`/`solveloop.js`'s) because those force
  `parent===self` for `pageWindow`, which breaks the bframe's framed
  detection (`@190196`) and the relay. In the bframe realm
  `window===self` yet `window.parent===relay !== window` → the framed gate
  passes.
- Worker hub: a single worker realm both the anchor and bframe attach to —
  the same loopback worker. The worker's `d5` bootstrap
  (`postMessage("recaptcha-setup", [port])`, `str(15) ports=1`) is delivered
  by-ref to the anchor handle.
- Boots the anchor realm (parent-collapse, the proven `driver_core` boot) →
  spawns the worker → BotGuard handshake; then boots the bframe realm with
  `parent` = a relay handle into the anchor's window listeners, the same
  worker hub, the same cookie jar, instrumented XHR (extracts field16 via
  `pb.decode`, forwards raw bytes), and a shared `___grecaptcha_cfg`.
- Runs the scraped `recaptcha.frame.Main.init("...")` verbatim so
  `Ac.D.init()` auto-schedules the reason=fi `POST /reload` (no checkbox),
  intercepts the body, reports field16, writes `bframe_reload_*.bin`.
- The bframe→anchor relay sends the bframe's "recaptcha-setup"+port into the
  anchor's d5 intake (`@246348`, which ignores source and adopts `ports[0]`)
  so attestation RPC can ride the by-ref MessagePort.

Offline validation: the worker realm spawns from the captured init literal,
the d5 handshake binds the keep-alive AE, field16 extraction matches the
real captured body (5044 B, tag `09`, urlSafeB64), and `parseRresp` isolates
the re-attest seed (idx18) from the c-token/payload-token.

The known circularity: `bft` is the anchor BotGuard type-0d attestation
token, minted in-session, and only the parent/api.js sets it onto the bframe
iframe src after the anchor goes interactive — the exact blocker
bframe-direct hoped to skip. This route removes the checkbox click but not
the anchor BotGuard handshake nor the parent emulation that mints `bft`; it
requires `BFT=<token>` from a real or parent-emulated session
(`tryHarvestBft()` is best-effort and documented-insufficient). Close
behind: the bframe has no worker, so a populated field16 needs the
bframe↔anchor attestation relay to be live (the anchor only opens its
sibling channel once interactive — again parent-gated), and field16 is empty
on reload #1 regardless (populated only from reload #2's prior rresp
field18).

## 4. fire_capture.js — fire and capture

`harness/fire_capture.js`. Run: `node harness/fire_capture.js` (env:
`SITEKEY, ORIGIN_HOST, VER, MODE=anchor|bframe`). Reuses `page.js`
`buildRealm` + the `page_rpc` `__onAE` hook; exports
`{ runFireCapture, fireTrigger, extractField16, parseRresp, makeDriverXHR,
makePerf, FakeWorker, onAE, windowExtra, RELOADS, RRESP, AK_CALLS }` so an
upstream parent-handshake driver can call `runFireCapture(page)` the moment
the anchor reports a `click` listener.

### The trigger (verify @440088, builder @392011)

With `window.botguard` left undefined, the verify method takes
`Promise.resolve().then(this.U)` → the reload builder where `field16 = p`.
The trigger is the checkbox activate sequence on whatever element gained a
listener, with a short pointer path first so the builder's `f20` telemetry is
non-degenerate, plus a deterministic `grecaptcha.execute()` nudge that routes
to the same verify via `e[31]`:

```js
for (let k=0;k<5;k++) el._fire('pointermove',{clientX:7+k*3,clientY:9+k*2,movementX:3,movementY:2,isTrusted:true,...})
el._fire('pointerdown'); el._fire('mousedown'); el._fire('focus')
el._fire('keydown',{key:' ',keyCode:32,...}); el._fire('keyup',{...})
el._fire('mouseup'); el._fire('pointerup'); el._fire('click')
try { page.sandbox.grecaptcha.execute() } catch {}   // belt-and-braces, invisible-style route
```

In `MODE=bframe`, `recaptcha.frame.Main.init` auto-emits reload reason=`fi`,
so `fireTrigger` is a no-op there.

### Capture + field16 verify (validated against poc/capture.json)

Instrumented XHR captures the body verbatim as a Buffer, forwards raw bytes
so the protobuf isn't UTF-8 mangled, then `pb.decode` → `field 16, wire 2`.
Verified on the real body: `f16=5044B, tag=09, urlSafeB64=true` (empty on #1
per `extractField16(...).present===false`).

### rresp field18 → ak re-attest loop

The `/reload` response is JSON `["rresp", c, …]`; `parseRresp` scans for the
longest opaque base64url element that is *not* idx1 (c-token) or idx9
(payload token) — on the synthetic fixture it correctly returns the seed at
idx18. The faithful path lets the anchor feed that seed to `ak` over the
live channel itself; `onAE` wraps the worker-channel AE's `.send` to observe
each `ak` re-attest call and its ~5 KB reply (`AK_CALLS`). A
`manualReattest()` fallback pumps the seed via
`workerChannelAE.send(akTok, seed, 30000)` if the client stalls.

### Keeping the worker session alive across reloads

One worker realm, never torn down (`terminate` is a logged no-op); the
`page_rpc` catch-all answers every worker liveness `"x"` poll with a
same-callid MZ ack inside the 15 s watchdog (a missed ack soft-blocks the
run); `makePerf` supplies a monotonic 0.1 ms clock + growing heap so the
second attestation's Xm reads (`heapDelta>0`, `execMs>0`) stay
non-degenerate (a static heap makes reload #2 low-trust even when
structurally valid). Confirmed live: `[page] captured worker port (d5)` →
`[page] bound worker-channel AE`. `runFireCapture` waits for reload #1
(empty) → rresp → drives reload #2 via a three-rung ladder (auto-wait →
re-fire → manual ak pump), all without teardown, and asserts field16 flips
empty → ~5 KB urlSafeB64.

### Open risk

Whether reload #2 actually re-attests in an anchor-only realm, and the `ak`
seed wrapper if it doesn't. In a real browser the *bframe* (not the anchor)
drives the subsequent reload that carries the populated field16; running
only the anchor realm, the controller may never schedule reload #2, so
`havePopulated16()` stays false. The fallback is `manualReattest()`, but it
depends on the opaque jspb class of the `ak` payload — the worker's `ak`
handler expects a specific message type, and four shapes are tried blind
(raw b64 string / decoded bytes / 1-field array / `{D:seed}`); the correct
wrapper is build-specific and unverified, so a wrong shape is silently
rejected (same stall signature as no re-attest). The robust fix is to also
boot the bframe realm (`MODE=bframe`, `recaptcha.frame.Main.init`) bridged
to the live anchor worker, so Google's own bframe code performs the
rresp→ak→field16 hop and the driver stays purely fire-and-capture. Even with
a correct ~5 KB field16, trust is only falsifiable by the own-key
`/siteverify` oracle.
