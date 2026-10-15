# Node-VM harness — build plan and component designs

Working notes for the request-based reCAPTCHA v2 solver: the build order,
the worker-environment specification, and the designs of the four harness
components (worker loader, XHR forwarding, integrity shims, harvest wiring).
Grounded against release `TnA7HacJFoBWt9hnlunBlYfK` of `recaptcha__en.js`
(895,421 bytes); byte offsets refer to that file.

## 1. Build order

### Step 1a — own key + siteverify oracle, no VM yet (~half day)

Every prior soft-block used the 2captcha demo key (pathologically hard,
origin-bound) with only an md5-of-image proxy — never an authoritative
accept. Before building a VM:

1. Register a free v2-checkbox key, default security, "verify origin" off
   (fill `own_key.json`).
2. Run the existing browserless pipeline (`solve_own.py`) end to end and POST
   the resulting token to your own `/api/siteverify`.
3. If siteverify accepts, the whole VM track is unnecessary — ship the
   browserless harvester as a solver. If it soft-blocks even an easy key, the
   live-attestation gate is real and key-independent; continue to 1b.

### Step 1b — capture real worker port traffic (~1 day, the hard gate)

Resolves the biggest unknown: is the reload field16 / `X-Recaptcha-Token`
value the **worker `Xm`** or the **page `window.botguard.bg` token**? Use the
headful-Chrome path + Playwright/CDP:

- Inject (via `Page.addScriptToEvaluateOnNewDocument`) a shim wrapping
  `Worker.prototype.postMessage`, the worker's `onmessage`, and
  `MessagePort.prototype.postMessage` in the bframe, dumping `{data, ports}`
  for every frame to a file.
- Also dump the `/reload` response bgdata (protobuf field 2 = inline
  interpreter source, field 3 = program), whether `window.botguard` becomes
  defined, and what `bg.invoke()` returns (~5 KB?).

Decision: if the value landing in field16 is the worker `Xm`
(heap/timing/deviceMemory) routed back over the AE port → GO for a
worker-only harness. If it is the page `window.botguard.bg` ~5 KB token
minted by an eval'd server interpreter probing canvas/WebGL/DOM → a
worker-only harness mints the wrong artifact → NO-GO (pivot to headful or
stop).

### Step 2 — port capture + RPp drive (~1–2 days, mechanical)

Extend `jsvm_probe.js` → `harness/worker.js`:

- Four source-instrumentation patches to capture the runtime-internal tokens
  (`Qr/ak/AE/d5`) into a `__cap` object (they rotate per release; never
  hardcode).
- Replace the port shim with a real by-reference loopback that delivers
  `{data, ports}` and honors transfer lists.
- Capture the load-time `postMessage("recaptcha-setup",[port2])` → `port2` is
  the handle to the worker AE server.
- Drive `Qr` (init, program in `.Oo`) then `ak` (run, `.D` = input); read
  back `Xm`. Validate: heapDelta > 0, timing > 0, deviceMemory === 8. Feed
  `Qr.Oo` from the Step-1b-captured bgdata field 3.

### Step 3 — curl_cffi egress + XHR/fetch shim (~2 days)

- Persistent Python sidecar: one `curl_cffi.requests.Session(impersonate="chrome")`
  (one cookie jar for `_GRECAPTCHA`, one JA3, connection reuse) over a
  localhost socket, newline-delimited JSON frames (headers as ORDERED
  pair-arrays).
- Replace the no-network `XHRStub` with a real `open/send/setRequestHeader`
  that forwards the already-stamped request verbatim (never synthesize
  `X-Recaptcha-Token`; it is set by the bundle's own j5 hook only on
  registered URLs). Provide the `fetch` twin; never return status 431 (the
  bundle drops the header and retries clean on 431).
- Tap `setRequestHeader`/`Headers.set` for the BV name to confirm a live
  token is actually present before forwarding.

### Step 4 — answer injection + full loop on own key (~2–3 days)

- Reuse `solve.js`'s ONNX `classifyGrid` only. Inject selected tile indices
  at the selection layer so the client builds `ds`/`response` itself
  (synthesize pointer events if the bframe UI renders under jsdom; else poke
  the widget selection model directly — loses the field20 mouse path).
- Run reload→payload→classify→replaceimage→…→userverify, keeping the worker
  BotGuard session alive across every interaction (continuous attestation;
  one-shot won't advance).
- Gate on the own-key siteverify oracle from Step 1a.

### Step 5 — scale + fingerprint hardening (only if Step 4 accepts)

Pin curl_cffi `header_order`, A/B wire bytes against a fresh real-Chrome
capture of the same registered URL, run N concurrent solves, measure the
siteverify accept rate over time (watch for delayed reputation decay).

## 2. Harness skeleton

    harness/
      worker.js        # extends poc/jsvm_probe.js: src-instrument + loopback port + RPp drive
      bframe.js        # page-role ctx: seeds ___grecaptcha_cfg, installs real XHR/fetch shim
      bridge.js        # Node<->sidecar JSON-over-socket client
      sidecar.py       # curl_cffi Session forwarder (extends poc/solve_tls.py)
      loop.js          # orchestrates anchor->reload->payload->ONNX->replaceimage->userverify
      reuse: poc/pb.js (read-only observability), models/recaptcha_cls_effv2s_128_single.onnx

The two pieces everything hinges on (the rest is plumbing):

```js
// (A) capture rotating tokens by surgical string-replace BEFORE vm.runInContext (worker.js)
const __cap = {};
function patch(find, repl){ const i = CODE.indexOf(find);
  if (i<0 || CODE.indexOf(find, i+1)>=0) throw new Error('anchor moved/non-unique: '+find);
  CODE = CODE.slice(0,i)+repl+CODE.slice(i+find.length); }
patch('RPp=new Map([[Qr,', 'RPp=__cap.RPp=new Map([[(__cap.Qr=Qr),');   // @886328
patch('}],[ak,function',   '}],[(__cap.ak=ak),function');               // @886328
patch('AE=function(q,r,w,D,d,A){return b[32]', 'AE=__cap.AE=function(q,r,w,D,d,A){return b[32]'); // @464867
patch('d5=lZ()',          'd5=__cap.d5=lZ()');                          // @794667

// (B) real by-reference loopback MessagePort (NO worker_threads/structuredClone -> DataCloneError)
function makePort(){ const p={__isPort:true,_peer:null,_started:false,_q:[],_on:null,_lis:[],
  get onmessage(){return this._on}, set onmessage(f){this._on=f;this._started=true;this._flush()},
  addEventListener(t,f){ if(t==='message'){this._lis.push(f);this._started=true;this._flush()} },
  removeEventListener(t,f){ this._lis=this._lis.filter(x=>x!==f) },
  start(){this._started=true;this._flush()}, close(){this._closed=true},
  postMessage(data,transfer){ const ports=(transfer||[]).filter(x=>x&&x.__isPort);
    const ev={data,ports,type:'message',target:this._peer,source:null};
    queueMicrotask(()=> this._peer && this._peer._deliver(ev)); },     // async-but-prompt
  _deliver(ev){ if(this._closed)return; if(!this._started){this._q.push(ev);return}
    if(this._on)try{this._on(ev)}catch(e){} for(const f of this._lis)try{f(ev)}catch(e){} },
  _flush(){ if(!this._started)return; const q=this._q;this._q=[]; for(const ev of q)this._deliver(ev) } };
  return p; }
function MessageChannelShim(){ const a=makePort(),b=makePort(); a._peer=b;b._peer=a;
  this.port1=a; this.port2=b; }

// global postMessage must capture the transferred port2 (bare call @886958)
let WORKER_PORT=null;
base.postMessage=(msg,transfer)=>{ if(transfer&&transfer[0]&&transfer[0].__isPort) WORKER_PORT=transfer[0]; };
base.MessageChannel=MessageChannelShim;

// (C) after load: drive the two opcodes
vm.runInContext(CODE, ctx, {timeout:20000});
const {AE,Qr,ak}=__cap;
const pageAE=new AE(WORKER_PORT,new Map(),ctx,'https://2captcha.com',null);   // mirror @446226
await pageAE.send(Qr,{Oo:bgProgramBytesFromReload, D:initD, L:progL});        // init
heap += 180000;                                                              // non-zero delta
const xm = await pageAE.send(ak,{D:runD});                                   // live attestation
```

Bring-up shortcut if AE framing fights you: `__cap.RPp.get(Qr)({Oo,D,L})`
then `__cap.RPp.get(ak)({D})` calls the handlers directly (they do plain
`q.Oo/q.D` reads), bypassing the wire codec.

Sidecar core (extends `solve_tls.py`): one `Session(impersonate="chrome")`,
per-endpoint stack-default headers merged UNDER the JS-set headers,
`referer` = live bframe URL with bft, body base64 round-trip,
`allow_redirects=False`, return `headers.multi_items()` (preserve duplicate
`Set-Cookie`).

## 3. The three risks that survive a byte-perfect request

### 3.1 The worker `Xm` may be the wrong artifact (architecture risk, highest)

The notes conflict in one place: the worker `ak` handler mints `Xm` from
`aq.Z().init(program)`, but the real ~5 KB field16 may come from the page
`window.botguard.bg(...).invoke()` — an eval'd server interpreter not present
in `recaptcha__en.js` that probes canvas/WebGL/DOM. If field16 is the page
token and `Xm` is only a lightweight heap/timing signal, a worker-only
harness mints a low-trust artifact and soft-blocks exactly as before.
Step 1b's CDP dump settles it before anything is built.

### 3.2 Statistical realism of `Xm` under server scoring

`performance.memory` is Chrome-proprietary (absent in Node),
`performance.now()` timing distributions differ from V8-in-Chrome, and
`deviceMemory` must stay mutually consistent with the heap limit, the UA, and
the curl_cffi impersonation profile. A flat heap delta, a Node-clock timing
ladder, or `deviceMemory:0` are cheap discriminators → structurally-valid
`Xm` that scores low-trust. The own-key siteverify oracle is the only ground
truth; locally, assert `heapDelta>0`, timing clamped to Chrome's 100 µs grid,
`used<total<limit` quantized ~100 KB.

### 3.3 field20 degeneracy + HTTP/2 header order

field20 = base64(JSON of mouse path + inter-event timing variance + host-page
resource origins).slice(2). A worker/jsdom harness produces empty/2-point
mouse arrays, zero timing variance, and an empty resource-origin list — each
a low-cost server discriminator. Separately, the position of
`X-Recaptcha-Token` in Chrome's HTTP/2 header order is itself a fingerprint
that curl_cffi's merge may not reproduce, and no captured attested request
exists to copy the order from. Decode the outgoing field20 with `pb.js`
before forwarding; A/B wire bytes against a fresh real-Chrome capture once
the live path mints a real token.

## 4. Odds and GO/NO-GO checkpoints

Honest odds of siteverify-accepted tokens at scale: roughly one in ten. The
wire protocol, port loopback, token capture, and curl_cffi egress are all
mechanically buildable. The residual risk is entirely §3 — three independent,
server-side, unobservable scoring surfaces, any one of which reproduces the
proven soft-block even with a byte-perfect request. Running the JS in a node
VM raises the floor (an attestation is now emitted at all) but does not make
it indistinguishable from a real Edge worker; Google scores distinguishability
continuously and can decay reputation after initial accepts.

Checkpoints — do not write the harness before these:

1. End of Step 1a: own-key siteverify on the existing browserless pipeline.
   Accept → ship browserless, skip the VM. Reject → the gate is confirmed.
2. End of Step 1b (the hard gate): CDP capture of real worker port traffic.
   field16 = worker `Xm` → GO, build Steps 2–4. field16 = page
   `window.botguard.bg` token needing a DOM/canvas/WebGL surface → NO-GO for
   worker-only; the viable path is the headful-Chrome solver.

Net: spend the ~1.5 days on Steps 1a+1b only. They are cheap, decisive, and
one of them very likely settles the project — either by working without the
VM, or by proving the worker-only VM mints the wrong artifact.

## 5. Worker environment spec (env-stub)

### 5.1 Scope

Target the **DedicatedWorkerGlobalScope** role, not the bframe page.
`webworker.js` = `importScripts(recaptcha__en.js)`, and the in-worker
attestation (`RPp` opcodes `Qr`/`ak`, byte 886328) mints the live `Xm`
heap/timing/deviceMemory attestation. The worker surface is strictly smaller
than the page (no DOM, no `window.botguard.bg` loader — that is the page
path). Two hard consequences:

- `window`, `document`, `screen` MUST be absent (`typeof === "undefined"`).
  The bundle branches on `typeof document!=="undefined"` /
  `typeof window!=="undefined"` (4 sites each). Defining them forces the
  page branch, which dereferences real DOM and throws.
- `navigator` here is a WorkerNavigator (reduced): no `plugins`/`mimeTypes`.

### 5.2 Global object construction

```js
const realm = globalThis;                 // host realm intrinsics
const sandbox = Object.create(null);
// ...assign props below...
const handler = {
  get(t,k){ if (k==='self'||k==='globalThis') return proxy; return t[k]; },
  has(){ return true; },                  // makes `x in self` / typeof resolve
  set(t,k,v){ t[k]=v; return true; },
};
const proxy = new Proxy(sandbox, handler);
const ctx = vm.createContext(proxy);
vm.runInContext(CODE, ctx, {filename:'recaptcha__en.js', timeout:15000});
```

Invariants the bundle enforces:

| Invariant | Why | Severity |
|---|---|---|
| `self === globalThis === ctx` | `yKq=self` @886958; `v6=this||self` @554797 | MUST |
| `sandbox.Math === realm.Math` (the real intrinsic) | goog.getGlobal @361937 walks `[globalThis,window,self,global]` and picks the first whose `["Math"]===Math`, else throws "Cannot find global object" | MUST — hard throw |
| top-level `this` (call target) is the global | IIFE is `(function(){…}).call(this)` | MUST (vm gives this for free) |
| All ES intrinsics are the realm's own (not Proxy-shadowed) | string-pool XOR decoder + protobuf readers need spec-exact `codePointAt`/typed arrays | MUST |

Inject every intrinsic explicitly onto `sandbox` (the Proxy shadows the
realm), exactly as `jsvm_probe.js` does: `Object Array Function String Number
Boolean Symbol BigInt Math JSON Date RegExp Error TypeError RangeError
Reflect Proxy Promise Map Set WeakMap WeakSet WeakRef ArrayBuffer
SharedArrayBuffer DataView Uint8Array Int8Array Uint8ClampedArray Uint16Array
Int16Array Uint32Array Int32Array Float32Array Float64Array BigInt64Array
BigUint64Array Intl structuredClone parseInt parseFloat isNaN isFinite
encodeURIComponent decodeURIComponent encodeURI decodeURI escape unescape
Infinity NaN`.

### 5.3 Worker globals — value table

Legend: **M** = MUST (bootstrap/ak reads it or throws without it), **R** =
recommended (BotGuard program likely reads), **O** = optional/no-op.

| Global | M/R/O | Concrete value (Chrome/Edge 149, Win10 x64) | Read site / note |
|---|---|---|---|
| `self` / `globalThis` | M | the proxy | @886958 `yKq=self` |
| `importScripts` | M | `()=>{}` (no-op; real load already done) | webworker.js entry |
| `postMessage(msg, transfer)` | M | capture `(d5,[port2])` → §5.7 | bare call @886958 hands the page the RPC port2 |
| `addEventListener` / `removeEventListener` | M | store `message`/`error` listeners | worker message pump |
| `onmessage` / `onerror` | R | settable, init `null` | |
| `close` | O | `()=>{}` | worker self-terminate |
| `MessageChannel` | M | hand-rolled (§5.7) — do NOT use `node:worker_threads` | @886958, microtask polyfill @241850 |
| `MessagePort` | M | hand-rolled ctor | transfer target |
| `location` | M | WorkerLocation object (§5.4) | `v6.location.origin` passed to `AE` |
| `navigator` | M | WorkerNavigator object (§5.5) | `navigator.deviceMemory` in `ak` |
| `performance` | M | object (§5.6) — dynamic | `performance.now`, `performance.memory.usedJSHeapSize` in `ak` |
| `Date` | M | realm `Date` | timestamps, telemetry |
| `setTimeout`/`clearTimeout` | M | realm timers | `v6.setTimeout`; AE.send 15s watchdog; nextTick fallback |
| `setInterval`/`clearInterval` | R | realm timers | token-mint poll (2s) |
| `queueMicrotask` | R | realm | generator engine scheduling |
| `TextEncoder` / `TextDecoder` | M | realm | `Sd=new TextEncoder` @886309; decoder ×7 read sites |
| `atob`/`btoa` | M | Buffer-based (§5.8) | base64 for telemetry/tokens |
| `crypto` | R | `require('crypto').webcrypto` | `crypto.subtle` ×2, `getRandomValues` ×1 |
| `URL` / `URLSearchParams` | M | realm | api2 URL builder `e[12]` parse `.L` |
| `console` | O | silent no-op object | error logging only |
| `Worker` | O | `function(){}` | worker doesn't spawn nested |
| `requestIdleCallback` | O | `(cb)=>setTimeout(cb,0)` | page-ish; harmless |
| `requestAnimationFrame` | O | absent (not a worker API) | leave undefined |
| `__recaptcha_api`, `___grecaptcha_cfg`, `trustedTypes` | O | absent → defaults taken | page config; worker ignores |
| `window`, `document`, `screen` | MUST be absent | — | forces DOM-less branch |

### 5.4 `location` (WorkerLocation)

The worker script is served from `www.google.com/recaptcha/api2/webworker.js`
(confirmed in headers.json):

```js
location: {
  href:'https://www.google.com/recaptcha/api2/webworker.js?hl=en&v=TnA7HacJFoBWt9hnlunBlYfK',
  origin:'https://www.google.com', protocol:'https:',
  host:'www.google.com', hostname:'www.google.com',
  port:'', pathname:'/recaptcha/api2/webworker.js',
  search:'?hl=en&v=TnA7HacJFoBWt9hnlunBlYfK', hash:'',
  toString(){ return this.href; }
}
```

`origin` is the only load-bearing field (passed as the `AE` origin arg
@886958). It must be `https://www.google.com`.

### 5.5 `navigator` (WorkerNavigator)

Only `deviceMemory` is read in the worker `ak` path (byte 886875:
`navigator.deviceMemory||0`). The rest are read by the downloaded BotGuard
program and must be mutually consistent with the UA the curl_cffi side
impersonates:

```js
navigator: {
  userAgent:'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
           +'(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0',
  deviceMemory: 8,            // Chrome caps at 8 — desktop reports exactly 8 (MUST)
  hardwareConcurrency: 8,     // match the real box's core count
  language:'en-US', languages:['en-US','en'],
  platform:'Win32',          // Chrome still reports Win32 on 64-bit
  vendor:'Google Inc.', product:'Gecko', appName:'Netscape', appCodeName:'Mozilla',
  onLine:true, webdriver:false,   // false is mandatory
  maxTouchPoints:0,          // read in page path (v6.navigator.maxTouchPoints>0)
  userAgentData:{
    brands:[{brand:'Chromium',version:'149'},
            {brand:'Microsoft Edge',version:'149'},
            {brand:'Not)A;Brand',version:'24'}],
    mobile:false, platform:'Windows',
    getHighEntropyValues:(h)=>Promise.resolve({
      platform:'Windows', platformVersion:'10.0.0', architecture:'x86', bitness:'64',
      model:'', uaFullVersion:'149.0.0.0', fullVersionList:[
        {brand:'Chromium',version:'149.0.0.0'},
        {brand:'Microsoft Edge',version:'149.0.0.0'},
        {brand:'Not)A;Brand',version:'24.0.0.0'}]}),
  },
  sendBeacon:()=>true,
  // mediaDevices is the page camera-iframe path — absent in worker is fine
}
```

`webdriver:false` is non-negotiable. UA / `userAgentData` / `platform` must
agree (version, "Windows", x64) — a mismatch is a cheap discriminator. Keep
the major version aligned with the live `recaptcha__en.js` release era and
the curl_cffi `impersonate` profile.

### 5.6 `performance` — dynamic, not static

The `ak` handler (bytes 886650–886900) does, around the BotGuard VM run
`B[27](1,1,24,2,3,v)`:

```
K = self.performance.memory.usedJSHeapSize     // before
A = performance.now()                          // before
…run VM…
N = self.performance.memory.usedJSHeapSize     // after
x = X3(performance.now() - A)                  // timing delta
U = (K!==undefined && N!==undefined) ? N - K : undefined   // heap delta
return new Xm(navigator.deviceMemory||0, U, x, R.P)
```

The attestation embeds (heapDelta U, timingDelta x, deviceMemory). A static
`performance.now` ⇒ `x≈0`; a constant `usedJSHeapSize` ⇒ `U===0`. Both are
tells. Build it self-consistent off the real clock and real heap:

```js
const T0 = process.hrtime.bigint();
function nowMs(){
  const ms = Number(process.hrtime.bigint() - T0) / 1e6;
  return Math.round(ms * 10) / 10;        // Chrome worker clamps to 100µs
}
const HEAP_BASE = 14_300_000;
performance = {
  now: nowMs,
  timeOrigin: Date.now() - nowMs(),
  memory: {
    get usedJSHeapSize(){
      // grow with real V8 heap so the pre/post-VM delta is positive & plausible
      const live = HEAP_BASE + process.memoryUsage().heapUsed % 5_000_000;
      return Math.round(live / 100000) * 100000;   // Chrome quantizes ~100KB
    },
    totalJSHeapSize: 35_700_000,
    jsHeapSizeLimit: 4_294_705_152,        // 64-bit desktop Chrome
  },
  getEntriesByType:(t)=> t==='resource' ? RESOURCE_ENTRIES : [],
  mark:()=>{}, measure:()=>{}, clearMarks:()=>{}, clearMeasures:()=>{},
};
```

Driving the heap getter off `process.memoryUsage().heapUsed` gives a positive
delta for free — the VM allocates during `B[27]`.

### 5.7 MessageChannel / MessagePort (the load-bearing primitive)

`node:worker_threads` MessageChannel will throw `DataCloneError`: AE messages
are in-realm objects (`Bp` wrappers, functions, prototypes) that are not
structured-cloneable. Pass references by identity and simulate transfer
manually — the loopback in §2 (code B) is the concrete implementation.
Requirements, all read by the bundle:

- `MessageEvent.ports[r]` yields the transferred reply port — the onmessage
  installer @341747 does `new Bp(f.data, AE-over f.ports[r])` (r is index 0).
  Transfer list → `ev.ports`. MUST.
- `AE.prototype.send` @794700 opens a fresh `MessageChannel`, transfers
  `port2`, listens on `port1`, waits ≤15000 ms. Delivery must be
  async-but-prompt (`setImmediate`/`queueMicrotask` ≈ a browser task). A
  missing/slow port = silent null token (the soft-block signature). MUST.
- Auto-start on `onmessage`/`addEventListener` (browser ports auto-start);
  the microtask polyfill @241850 relies on `onmessage`.
- `port.close()` (AE.X @795060 stores the port as `this.D`, calls
  `this.D.close()`).

Bootstrap capture — the bare `postMessage(d5,[Z$.port2])` @886958 is the
worker→page handshake. The global `postMessage` must record `(d5, [port2])`;
`PAGE_PORT` (the transferred `Z$.port2`) is the handle to the worker's AE RPC
server on `Z$.port1`. Opcode tokens `Qr/ak/d5` are factory-generated
(`t[41]`/`lZ`) — capture at runtime by instrumenting the `RPp` Map
construction, never hardcode.

### 5.8 atob / btoa

```js
atob: s => Buffer.from(String(s),'base64').toString('binary'),
btoa: s => Buffer.from(String(s),'binary').toString('base64'),
```

### 5.9 Validation checklist (matches `jsvm_probe.js` instrumentation)

1. Runs to completion, no throw.
2. Exactly one outgoing `postMessage` at load carrying the handshake sentinel
   + one transferred port → handshake/PAGE_PORT populated.
3. After sending captured `Qr` then `ak` over PAGE_PORT, the reply is an `Xm`
   with U (heapDelta) > 0, x (timing) > 0, deviceMemory = 8. If U or x is
   0/undefined, the stub is degenerate (§5.6).
4. No access to undefined `window`/`document` (the missing set contains
   neither).

## 6. Worker loader design

### 6.1 What happens at load (byte 886958, verified)

In worker mode there is no page: `webworker.js` is just
`importScripts(recaptcha__en.js)`, so the entire 895 KB IIFE re-runs in a
DedicatedWorkerGlobalScope. At the bottom of its var-init chain:

```js
yKq=self, Z$=new MessageChannel,
bLs=(new (postMessage(d5,[Z$.port2]),AE)(Z$.port1, RPp, yKq, v6.location.origin, Z$), YG)()
```

Decoded order of effects:

1. `yKq = self` (worker global).
2. `Z$ = new MessageChannel`.
3. The bare global `postMessage(d5, [Z$.port2])` fires first (it is the `new`
   operand's comma-expr) — DedicatedWorkerGlobalScope.postMessage handing
   `Z$.port2` to the spawning page, with `d5` the handshake sentinel.
4. `new AE(Z$.port1, RPp, yKq, origin, Z$)` wires the worker's RPC server
   onto `port1` with opcode map `RPp`.
5. `bLs = YG()` builds the BotGuard handle.

The harness plays the page. Everything flows from one event: capture the
`port2` transferred by that load-time postMessage → that port is the handle
to the worker's AE server. Then drive the two and only two RPp opcodes
(byte 886328):

- **`Qr`** = LOAD/INIT: `r=q.Oo` (program bytes) → `sd.Z().D = t[5](40,0,r)`,
  `aq.Z().init(ZS(q.D))`, `L[49](22,3,1,q.L)`.
- **`ak`** = RUN/COLLECT: builds VM `v=new bC(TP(q.D))`, runs it, returns
  `new Xm(deviceMemory, heapDelta, timing, R.P)` — the live attestation.

"Feed the server bg program over the port" = send a `Qr` message whose `.Oo`
is the bgdata program (reload-response field 3). "Read back the attestation"
= send `ak`, await the `Xm` reply. The catch: `Qr`/`ak`/`AE`/`d5` are
closure-local, runtime-generated tokens (they rotate per release) — hence the
source instrumentation below.

### 6.2 Source instrumentation

String replacement on the loaded text before `vm.runInContext` (§2 code A).
`__cap` is a plain object on the sandbox; after load it holds
`{Qr, ak, AE, RPp, d5}`. If AE framing fights you, `__cap.RPp.get(Qr)` and
`.get(ak)` are callable directly with a plain object exposing `.Oo/.D/.L`
(the handlers do plain property reads) — the bootstrap/debug path; the port
path is the faithful one.

### 6.3 Global + recursive logging ghost

`self === globalThis === ctx`, no-op `importScripts`, the MessageChannel
shim, and a recursive ghost for everything unstubbed so one run enumerates
the entire missing surface (deep chains like
`self.performance.memory.usedJSHeapSize` get logged at every hop instead of
throwing on the first miss):

```js
function ghost(path){
  const f = function(){ note('CALL '+path); return ghost(path+'()'); };
  return new Proxy(f, {
    get(t,k){
      if (k==='__isGhost') return true;
      if (typeof k==='symbol'){
        if (k===Symbol.toPrimitive) return ()=>0;       // numeric/string coercion -> 0/''
        if (k===Symbol.iterator) return undefined;       // not iterable
        return t[k];
      }
      if (k==='then') return undefined;                  // never look like a thenable
      const np = path+'.'+k; HARNESS.paths.add(np); note('GET '+np);
      return ghost(np);
    },
    apply(){ note('APPLY '+path); return ghost(path+'()'); },
    construct(){ note('NEW '+path); return ghost('new '+path); },
    has(){ return true }, set(){ return true },
  });
}
```

Guards that matter: `then` → undefined (else feature-detects treat the ghost
as a thenable and deadlock), `Symbol.iterator` → undefined, `Symbol.toPrimitive`
→ 0/''. Once enumeration stabilizes, promote frequently-hit ghost paths to
concrete stubs in `base` and turn the ghost into a hard throw to surface
anything still unstubbed.

### 6.4 Drive

```js
vm.runInContext(CODE, ctx, { filename:'recaptcha__en.js', timeout:20000 });
const { AE, Qr, ak, d5, workerPort } = __cap;
if (!workerPort) throw new Error('did not capture worker port2 — bootstrap path changed');

// Page-side AE over the captured worker port. Args mirror the page mirror @446226:
const pageAE = new AE(workerPort, new Map(), ctx, 'https://2captcha.com', null);

async function feedProgramAndAttest(bgProgramBytes, collectInput){
  await pageAE.send(Qr, { Oo: bgProgramBytes, D: collectInput.initD, L: collectInput.progL });
  heap += 180_000 + ((Math.random()*64)|0)*1024;          // advance heap so the delta is non-zero
  const xm = await pageAE.send(ak, { D: collectInput.runD });
  return xm;
}
```

`AE.prototype.send(opcode, payload, timeoutMs?)` (byte 794700) returns a
Promise resolving with the reply (default 15000 ms timeout). Inputs:
`Oo` = the BotGuard program from the /reload response bgdata field 3 (decode
with `poc/pb.js`, pass raw bytes). `D`/`L` = per-interaction collection
inputs — the genuinely under-specified shapes (see §6.5). Output: the `Xm`
jspb message; serialize with `.CE()` (byte 569083) or read accessors, then
place into reload field 16 via `B[18](88,16,…)` (byte 392015) and/or the
per-interaction field 4 `Nv` (byte 19600).

### 6.5 Enumeration loop + open risk

After a run, dump the ghost telemetry (top accesses, missing roots, ghost
paths). The ghost-path set is the deliverable of the enumeration pass: every
`a.b.c` BotGuard probed but unstubbed. Iterate until errors are empty and
`ak` returns a non-degenerate `Xm`.

Open risk: the exact byte-shape of the `Qr`/`ak` payloads and whether the
in-worker `bC` VM is self-contained at all versus needing the externally
delivered `window.botguard.bg` interpreter. The `Qr` handler does
`aq.Z().init(ZS(q.Oo))` — implying the worker's own embedded VM is initialized
from `q.Oo` — but `recaptcha__en.js` contains no downloaded-bytecode
interpreter (only the XOR string pool + protobuf readers), and the real token
math may live in `window.botguard.bg`, an external interpreter delivered via
reload field-1 URL / field-2 inline source. Even granting the worker path is
sufficient, the jspb field layout `Bp.Oo/.D/.L` expect is unknown until
captured: instrument the real browser worker (or `AE.prototype.send` / the
`Bp` ctor at byte 583829) to dump the actual `{opcode, payload}` bytes for
one genuine interaction, then replay that shape. First build step: the CDP
capture of Step 1b.

## 7. XHR shim + curl_cffi sidecar

### 7.1 Positioning — the layer under Google's hook

The bundle hooks XHR itself (byte 391012):

```
UF = XMLHttpRequest.prototype.open;  XMLHttpRequest.prototype.open = VH
gE = XMLHttpRequest.prototype.send;  XMLHttpRequest.prototype.send = Zf
```

It saves *our shim's* `open`/`send` as `UF`/`gE` and wraps them. By the time
control reaches the shim, the bundle's async send wrapper (byte 142822) has
already done `p.setRequestHeader(BV, v)` and then `gE.call(p, r)`. So when
`send(body)` runs, the attestation header (if this URL was registered in
`j5`) is already sitting in the shim's header map. The shim never computes,
names, or synthesizes it — it is a transparent forwarder. It must not assume
`X-Recaptcha-Token` is present (BV is attached only to j5-registered URLs;
`replaceimage` is not one of them). Contract: faithful pass-through of
method + url + body + headers, real Chrome-TLS egress, real response back.

The shim lives in the bframe/page-role context (where `Aq`, the XHR hook, and
`j5` live). The worker-role context does not get it — the worker only does
BotGuard over MessagePort, never HTTP.

### 7.2 Architecture

Node can't do Chrome-JA3, and curl_cffi is Python:

```
 ┌─ Node process ──────────────────────────────┐        ┌─ Python sidecar (1 per harness) ─┐
 │  vm context (bframe role)                    │        │  curl_cffi.requests.Session(     │
 │   recaptcha__en.js  ── Aq ──> XHRShim.send ──┼─ JSON ─┤    impersonate="chrome")          │
 │   (BotGuard hook injects BV into headers)    │  over  │  ONE session = 1 cookie jar +     │
 │  vm context (worker role): BotGuard/MsgPort  │  socket│  1 conn pool + 1 TLS fingerprint  │
 └──────────────────────────────────────────────┘        └───────────────────────────────────┘
```

Why a single persistent sidecar Session (not exec per call):

- `_GRECAPTCHA` is set via `Set-Cookie` and must ride forward on every
  subsequent reload/payload/replaceimage/userverify — one Session jar does it
  automatically.
- One consistent TLS/JA3 + connection reuse (HTTP/2 multiplexing), matching a
  browser keeping the bframe socket warm. One impersonation profile for the
  whole solve.

Bridge: newline-delimited JSON over a loopback TCP socket (or stdio pipe).
Request frame `{id, method, url, headers:[[k,v],...], bodyB64, sync}`;
response frame `{id, status, statusText, headers:[[k,v],...], bodyB64}`.
Headers travel as ordered arrays of pairs, never a dict — order and duplicate
`Set-Cookie` must survive.

### 7.3 The shim

Installed on the bframe-role sandbox as global `XMLHttpRequest`; defined with
prototype methods (plain assignments → `writable:true`, so the bundle's
`prototype.open = VH` swap works cleanly). Requirements the bundle reads:
Closure's `XhrIo` drives off `onreadystatechange` /
`addEventListener('readystatechange')`, at `readyState===4` reads `status`,
`responseText` (and `responseType`+`response` for typed responses), and calls
`getResponseHeader('Content-Type')` / `getAllResponseHeaders()`. The
HEADERS→LOADING→DONE transitions and `load`/`loadend` events are what unblock
the bundle's Promise/generator pipeline so the client logic continues to the
next reload/replaceimage and ultimately mints the userverify token.

Key behaviors:

- `open(method, url, async)` → stores method/url, resets header arrays,
  readyState=OPENED. This is `UF` from the bundle's POV — called by `VH`
  after it records `{url,fG}` in `PV`.
- `setRequestHeader(name, value)` → push `[name, value]` onto an ordered
  array; NOT hooked by the bundle; preserve order + duplicates per spec.
- `send(body)` → this is `gE` from the bundle's POV — invoked after
  `setRequestHeader(BV,...)` already ran. Body bytes preserved exactly:
  string → utf8 Buffer; ArrayBuffer / typed arrays → raw bytes; base64 across
  the bridge. Sync (`fG===false`) → blocking round-trip to the same sidecar;
  async → `bridge.send(frame).then(deliver)`.
- `_deliver(resp)` → sets status/statusText/headers, HEADERS→LOADING→DONE,
  builds `responseText` (utf8; the `)]}'` XSSI prefix stays — the client
  strips it), `response` per `responseType`, emits `load`/`loadend`.
- `abort()` → DONE silent + `abort`/`loadend` events. `addEventListener`/
  `removeEventListener` supported.

### 7.4 Sidecar core

```python
# one persistent Session => one cookie jar (_GRECAPTCHA) + one JA3 for the whole solve
import json, base64
from curl_cffi import requests
SESSION = requests.Session(impersonate="chrome")   # same as solve_tls.py

# per-endpoint browser defaults the network STACK adds (JS never sets these);
# merged UNDER the JS-set headers. Values from poc/headers.json.
DEFAULTS = {
  "reload":       {"accept":"*/*","sec-fetch-dest":"empty","sec-fetch-mode":"cors","sec-fetch-site":"same-origin","origin":"https://www.google.com"},
  "replaceimage": {"accept":"*/*","sec-fetch-dest":"empty","sec-fetch-mode":"cors","sec-fetch-site":"same-origin","origin":"https://www.google.com"},
  "userverify":   {"accept":"*/*","sec-fetch-dest":"empty","sec-fetch-mode":"cors","sec-fetch-site":"same-origin","origin":"https://www.google.com"},
  "payload":      {"accept":"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8","sec-fetch-dest":"image","sec-fetch-mode":"no-cors","sec-fetch-site":"same-origin"},
}
BFRAME_REFERER = "https://www.google.com/recaptcha/api2/bframe?hl=tr&v=TnA7HacJFoBWt9hnlunBlYfK&k=<SITEKEY>&bft=<LIVE_BFT>"

def endpoint(url): return url.split("?")[0].rstrip("/").split("/")[-1]

def handle(frame):
    js_headers = frame["headers"]                      # ORDERED [[k,v]...] incl Content-Type & maybe BV
    ep = endpoint(frame["url"])
    hdrs = dict(DEFAULTS.get(ep, {}))
    hdrs["referer"] = BFRAME_REFERER                   # forbidden header: stack-supplied, never by JS
    for k, v in js_headers:                            # overlay JS headers verbatim
        hdrs[k] = v
    body = base64.b64decode(frame["bodyB64"]) if frame.get("bodyB64") else None
    r = SESSION.request(frame["method"], frame["url"], headers=hdrs, data=body,
                        allow_redirects=False)
    return {"id": frame["id"], "status": r.status_code, "statusText": r.reason or "",
            "headers": [[k, v] for k, v in r.headers.multi_items()],   # keep dup Set-Cookie
            "bodyB64": base64.b64encode(r.content).decode()}            # curl_cffi auto-decodes gzip/br/zstd
```

### 7.5 Header policy (load-bearing)

| header class | who sets it | handling |
|---|---|---|
| `X-Recaptcha-Token` (BV) | bundle's hook, via `setRequestHeader` on registered URLs only | forward verbatim, in the position JS set it. Never synthesize, never drop. Absent on unregistered URLs — correct. |
| `Content-Type` | bundle JS (`x-protobuffer` for reload; `x-www-form-urlencoded` for replace/userverify) | forward verbatim |
| `Origin`, `Referer`, `Cookie`, `User-Agent`, `sec-ch-ua*`, `sec-fetch-*`, `accept*` | browser network stack, NOT JS (forbidden header names) | sidecar injects from the per-endpoint template + Session jar + impersonation profile |

The shim's header map holds only what JS set. Browser-equivalent defaults are
added at the sidecar so they mirror the captured wire (reload =
`origin: https://www.google.com`, `sec-fetch-site: same-origin`; payload =
`sec-fetch-dest: image`, `no-cors`). `_GRECAPTCHA` is HttpOnly — handled
entirely by the Session jar.

### 7.6 fetch twin

The bundle hooks `window.fetch` in lockstep (byte 277818) and injects the
same BV header onto `Request`/`Headers`/init. Provide a `fetch` shim on the
same sandbox that marshals `{method, url, headers, bodyB64}` into the
identical bridge frame and returns a `Response`-like object (`.status`,
`.text()`, `.arrayBuffer()`, `.json()`, `.headers.get()`). Critical: the
returned `Response.status` must be the true upstream status and never 431 —
the bundle's 431 path (`f.status===431 ? bu(D,w) : f`) silently retries
without the attestation header, manufacturing a false "it works
header-lessly" result.

### 7.7 Deliberate don'ts

- Don't strip the `)]}'` XSSI prefix (the client strips it).
- Don't reorder/normalize/lowercase the JS-set headers before the wire.
- Don't assume async vs sync (honor `open`'s 3rd arg; `fG` can be false).
- Don't collapse duplicate `Set-Cookie` (use `multi_items()`).
- Don't block the Node event loop on async sends — that's what advances the
  BotGuard Promise chain.

### 7.8 Open risk

The exact Chrome on-the-wire header ordering — specifically where
`X-Recaptcha-Token` sits relative to Chrome's canonical sequence — is
unverifiable with the captures held: `capture_hdr.js` saw no attestation
header on reload/replaceimage (those URLs aren't j5-registered), so no real
attested request exists to copy the order from. curl_cffi appends custom
headers onto its `impersonate="chrome"` template by its own merge logic; if
the gate includes HTTP/2 header order, the forwarder could still soft-block
with a valid live token. Mitigation: pin curl_cffi's `header_order` and, once
the live path mints a real token, A/B the wire bytes against a fresh
real-Chrome capture of the same registered URL.

## 8. Integrity shim layer

### 8.1 Threat model

The static `recaptcha__en.js` performs no hostile native-integrity check —
the lone `indexOf("native code")` is a benign goog.bind feature-detect that
passes for free because the realm runs the real `Function.prototype.bind`.
The real probe surface is (a) the `ak` attestation fields (§5.6), baked
verbatim into `Xm`, and (b) the downloaded BotGuard `bg` program (reload
field 3, not in the file), whose checks are unknown and rotate. This layer's
job: present every JS-implemented shim as indistinguishable-from-native, and
make `performance.memory` / `performance.now` / `navigator.deviceMemory`
mutually coherent Chrome values so `Xm` is statistically browser-like.

### 8.2 Two design decisions

**(a) No global Proxy over the final context.** `goog.getGlobal` (@361937)
hard-throws unless `global.Math === Math`. Use a real `vm.createContext`
(possibly fed through the logging Proxy only during enumeration) so the
worker global carries real `Math`, `Object`, `Function`, `Promise`,
TypedArrays, and run the IIFE so `this`, `self`, and `globalThis` are one
object. This also satisfies the bind check natively.

**(b) Don't freeze shims to look intrinsic — match descriptors.** Real
DOM/Worker prototype methods are not frozen:
`getOwnPropertyDescriptor(XMLHttpRequest.prototype,'open')` in Chrome =
`{writable:true, enumerable:false, configurable:true}`. `Object.freeze`
yields `configurable:false, writable:false` — a cheap, decisive tell. Never
blanket-freeze; replicate each property's real descriptor shape.

### 8.3 toString cloak

Replace `Function.prototype.toString` with a plain function (not a Proxy —
fewer invariant/stack tells) defined inside the vm context, closing over the
original and a `WeakSet` of present-as-native functions. It self-registers
so `Function.prototype.toString.toString()` also reads native:

```js
function installToStringCloak(ctx) {
  const FP = ctx.Function.prototype;
  const realToString = FP.toString;
  const native = new ctx.WeakSet();            // funcs to present as native
  const nameOf = new ctx.WeakMap();            // optional name override

  const fake = function toString() {
    if (typeof this !== 'function')
      return realToString.call(this);          // let V8 throw the real TypeError
    if (this === fake || native.has(this)) {
      const n = nameOf.get(this) || this.name || '';
      return 'function ' + n + '() { [native code] }';
    }
    return realToString.call(this);            // Google's own VH/Zf wrappers pass through
  }

  native.add(fake);                            // toString.toString() => native
  native.add(realToString);
  Object.defineProperty(FP, 'toString', {
    value: fake, writable: true, enumerable: false, configurable: true
  });
  Object.defineProperty(fake, 'name',   { value: 'toString', configurable: true });
  Object.defineProperty(fake, 'length', { value: 0, configurable: true });

  ctx.__markNative = (fn, name) => { native.add(fn); if (name) nameOf.set(fn, name); return fn; };
}
```

A `vm` context has two `Function.prototype`s: in-context literals (the
bundle + the bC-VM bytecode) inherit the context-internal FP; host-authored
stubs inherit the host FP. The override must patch both with one shared
WeakSet. Tagging is by object identity in a realm-resident WeakSet →
invisible to `getOwnPropertyNames` enumeration. Residual leak: the error
stack if `bg` calls `toString` on a non-function inside try/catch and
inspects `e.stack` — mitigations: keep the override one self-contained frame;
optionally filter `Error.prepareStackTrace` in-context; make the TypeError
path call the real `realToString` so the throw originates in native code.

### 8.4 defineNative helpers

Every shim installs through one helper so name/length/descriptor/native-mark
are always right. Methods on prototypes:
`{writable:true, enumerable:false, configurable:true}`; WebIDL attribute
getters (`navigator.deviceMemory`, `performance.memory`): accessor,
`enumerable:true`, `configurable:true`. Constructors (`XMLHttpRequest`,
`Worker`, `MessageChannel`, `Request`, `Headers`, `Response`, `MessagePort`,
`MessageEvent`): `__markNative`'d, correct `.name`/`.length`, a proper
`.prototype` whose `constructor` back-points, `instanceof` works,
`Symbol.toStringTag` on prototypes so
`Object.prototype.toString.call(xhr) === '[object XMLHttpRequest]'`.

Arity table (verify against a live Chrome before shipping; arity mismatch is
a one-line probe): `XMLHttpRequest.open`=2, `send`=0, `setRequestHeader`=2;
`addEventListener`/`removeEventListener`=2; worker `postMessage`=1,
`MessagePort.postMessage`=1, `close`=0; `performance.now`=0; `fetch`=1;
`Worker`=1; `MessageChannel`=0; `importScripts`=0 (variadic).

Note: recaptcha itself swaps `XMLHttpRequest.prototype.open/send` to `VH`/
`Zf` (@391012) and saves the originals (`UF`/`gE`). The cloak must mark the
originals native at install time (they're read then). After the swap, `VH`/
`Zf` are Google's own code and pass through `realToString` — exactly as the
file already self-cloaks its `el.click` patch (@814011), so `bg` tolerates
Google wrappers.

### 8.5 performance.now — clamped, monotonic, Date-coherent

Chrome (non-cross-origin-isolated) clamps `performance.now()` to 100 µs
(0.1 ms) with jitter, and `timeOrigin + now() ≈ Date.now()`. Node's clock is
higher-res — over-resolution is itself a tell:

```js
const NS = 1e6;
const t0 = process.hrtime.bigint();
const timeOrigin = Date.now();                 // ms epoch at "load"
let last = 0;
function perfNow() {
  let t = Number(process.hrtime.bigint() - t0) / NS;   // ms, high-res
  t = Math.floor(t / 0.1) * 0.1;               // clamp to Chrome 100us bucket
  if (t < last) t = last;                       // non-decreasing; Chrome MAY repeat -> allow equal
  last = t;
  return t;
}
```

Do not strictly increment by 0.1 each call (a tight-loop probe would see a
perfectly regular ladder); allow equal consecutive values like real clamped
Chrome. The `ak` timing field then reflects the VM's real Node execution
time, clamped to Chrome's grid — coherent by construction.

### 8.6 performance.memory — tied to real allocation, quantized

`performance.memory` is Chrome-only and absent in Node → without it,
`Xm.heapDelta` is `undefined` (a hard not-Chrome signature). Anchor it to
real `process.memoryUsage().heapUsed` so the before/after delta brackets
genuine VM allocation, mapped into a believable Chrome window and quantized
like Chrome's `QuantizeMemorySize`:

```js
const HEAP_LIMIT = 2172649472;                 // ~2.0GB, typical 64-bit Chrome tab
const Q = 100000;                              // ~100KB bucket
const baseUsed = 9 * 1048576;                  // ~9MB floor
let monoUsed = 0;                              // never go backward within a session
function quant(v){ return Math.round(v / Q) * Q; }
function memInfo() {
  const real = process.memoryUsage().heapUsed; // grows as the bg VM allocates
  let used = baseUsed + (real % (40 * 1048576));
  if (used < monoUsed) used = monoUsed + Q;    // monotone-ish across the bracket
  monoUsed = used;
  const usedQ  = quant(used);
  const totalQ = quant(usedQ + 8 * 1048576);   // total > used, < limit
  return { totalJSHeapSize: totalQ, usedJSHeapSize: usedQ, jsHeapSizeLimit: HEAP_LIMIT };
}
```

Result: `Xm.heapDelta = N − K` is a small positive value scaled to the VM
run, never `undefined` or 0/negative, and the three numbers obey
`used ≤ total ≤ limit` with Chrome-plausible magnitudes and bucket
quantization.

### 8.7 navigator

`deviceMemory` must be one of Chrome's quantized set {0.25, .5, 1, 2, 4, 8}
and non-zero (the `||0` fallback turns absence into a 0 that flags the
worker). Keep it consistent with the TLS/UA profile of the curl_cffi driver
and with `hardwareConcurrency`.

### 8.8 Install order (matters)

1. Create the vm context (real intrinsics, `self=globalThis=this`).
2. `installToStringCloak(ctx)` first — so every subsequent shim can be
   `__markNative`'d.
3. Install clock (`perfNow`, `timeOrigin`), `performance.memory`,
   `navigator.*`.
4. Install the worker surface (`postMessage`, `MessageChannel`/`MessagePort`
   with real `{data, ports}` transfer, `addEventListener`, no-op
   `importScripts`, `TextEncoder`) and the HTTP surface (`XMLHttpRequest`,
   `fetch`, `Request`, `Headers`, `Response`).
5. `runInContext(recaptcha__en.js)`. The bare `postMessage(d5,[port2])` at
   load (@886958) hits the native-looking shim; capture `d5` + `port2`.

### 8.9 Self-test gate (run before any live attempt)

Assert, inside the context, that none of these reveal the harness:

- `XMLHttpRequest.prototype.open.toString()` ends with `[native code]`; so do
  `''+XMLHttpRequest.prototype.send`, `performance.now`, worker `postMessage`,
  `fetch`.
- `Function.prototype.toString.toString()` and `(()=>{}).toString.toString()`
  → native.
- `getOwnPropertyDescriptor(XMLHttpRequest.prototype,'open')` deep-equals
  `{writable:true,enumerable:false,configurable:true}` (not frozen).
- `getOwnPropertyDescriptor(nav,'deviceMemory')` is an accessor,
  `enumerable:true`.
- `performance.memory.usedJSHeapSize < totalJSHeapSize < jsHeapSizeLimit`;
  two reads bracketing a `for`-loop allocation give a positive delta.
- `navigator.deviceMemory` ∈ {0.25,.5,1,2,4,8} and `!= 0`; arities match the
  §8.4 table.
- `Function.prototype.bind.toString().indexOf('native code') !== -1` (the
  goog.bind detect stays green).

### 8.10 Open risk

The live, server-delivered BotGuard `bg` program (reload field 3) is not in
`recaptcha__en.js`, runs unknown/rotating anti-tamper, and is the actual
scorer of `Xm` — this cloak is built blind against it. Specifically
unverifiable without the siteverify oracle: whether `bg` cross-checks the
faked values against each other or against a pristine cross-realm reference
(e.g. an un-cloaked `Function.prototype.toString` grabbed via a fresh realm/
MessageChannel and diffed); the exact Chrome quantizers for
`performance.memory`; and how `(heapDelta, execMs, deviceMemory)` are joined
against a server-side model. Two known mismatches even after bucketing:
`process.memoryUsage().heapUsed` is V8-process-wide and GC-noisy, not
Chrome's privacy-quantized renderer `usedJSHeapSize`; and Node interpreting
the ~336 KB program is slower than Chrome's JIT, inflating the timing delta.

## 9. Harvest wiring — let recaptcha__en.js build everything

### 9.1 The inversion

`solve.js` hand-builds every body (`pb.encode`, `ds=...&c=...`) and hand-fires
`fetch` — exactly why it soft-blocks: no live attestation rides along.
Harvest wiring flips it: the client builds 100% of bodies/headers; the
harness only supplies the runtime, injects the ONNX selection at the tile
layer, and ferries the client-built requests over curl_cffi. Nothing is
hand-encoded. The X-Recaptcha-Token header (the gate; `BV` @865232) is
produced by the client's own j5/F[32] hook and forwarded verbatim — never
reconstructed.

### 9.2 Topology — three roles, two in-process channels, one HTTP boundary

`recaptcha__en.js` is one IIFE that self-selects a role from `location`/cfg
(routing table @705690; installs `recaptcha.{anchor.Main.init,
frame.Main.init}`). The harness instantiates the file three times in three
`vm` contexts, one Node process:

```
 [anchor ctx]  recaptcha.anchor.Main.init   — holds g-recaptcha-response, exposes grecaptcha.getResponse
      |  cross-frame postMessage bus (shared dispatcher; no real iframes)
 [bframe ctx]  recaptcha.frame.Main.init    — renders tile grid, builds reload/replaceimage/userverify,
      |                                         hosts XHR/fetch hook (j5) + spawns worker
      |  REAL loopback MessageChannel (AE/RPp; @886958 / @446226)
 [worker ctx]  webworker.js role            — BotGuard: Qr=init, ak=run→Xm attestation
```

- anchor↔bframe: a shared bus — both contexts get `postMessage`/
  `addEventListener('message')` routed to a single dispatcher. This is how
  the anchor hands the bframe the `{sitekey, c, co}` init and how the bframe
  hands back the final token.
- bframe↔worker: a real loopback MessageChannel (§5.7), because
  `AE.prototype.send` (@794700) opens a fresh channel per call, transfers
  `port2`, and waits ≤15000 ms for the reply on `port1`. A fake port that
  doesn't deliver `{data, ports}` nulls the token — the exact soft-block.
- HTTP boundary: our own `fetch`/`XMLHttpRequest` on each context's global.
  The client patches them (j5 install @391012) and calls them; our
  implementation forwards the already-built request (including the stamped
  X-Recaptcha-Token) to www.google.com via curl_cffi and feeds the real
  Response back.

### 9.3 Bootstrap per context

1. Seed the cfg in the page contexts exactly as `api.js` does:
   ```js
   g.___grecaptcha_cfg = { fns:[], clients:{}, render:['onload'],
     'anchor-ms':[20000], 'execute-ms':[30000] };
   g.__recaptcha_api = 'https://www.google.com/recaptcha/api2/';
   g.__google_recaptcha_client = true;
   g.grecaptcha = {};                 // the file populates render/getResponse/etc.
   ```
2. `location` per role: anchor → `.../api2/anchor?...`, bframe →
   `.../api2/bframe?hl=en&v=VER&k=SITEKEY&bft=<carry-through>`, worker →
   `.../api2/webworker.js?...`. (`bft` is a free server token — just carry
   it; do not synthesize.)
3. Provide the env deps §5 enumerates (navigator, performance, TextEncoder,
   crypto.webcrypto, intrinsics).
4. `vm.runInContext(CODE, ctx)` for all three. The worker at load fires the
   bare `postMessage(d5,[port2])` (@886958) — capture `d5` + `port2`; that
   port is the bframe's handle to BotGuard.

### 9.4 HTTP bridge

§7 applies verbatim. To observe the attestation, tap `setRequestHeader`/
`Headers.set` for name === BV — confirms the live token is present before
forwarding. If it is absent on a replaceimage/userverify, the worker/
loopback is broken; forwarding bare is a guaranteed soft-block.

### 9.5 Answer injection — the centerpiece

Driving entrypoint (no hand-built reload): init anchor → synthesize the
checkbox click → anchor opens bframe → `frame.Main.init` itself issues
`/reload` through our fetch (body = client-built protobuf with field16 from
the live channel; reload tolerates empty field16 — the gate is later). The
reload `rresp` (see `capture.json`) gives `pmeta` (idx 4: target mid + grid
dims), payload token (idx 9), type (idx 5). The bframe then GETs `/payload`
and renders an N-cell grid.

Injection point: the tile-selection layer — between "grid rendered" and
"client builds `ds`/`response`". The client's own click handlers accumulate a
per-tile selected-set and, on Verify, serialize it to `ds=[[idx…]]`
(replaceimage, urlencoded) or `response` (userverify). Feed ONNX indices in
there so the client builds those bytes:

```js
// after the bframe renders the tiles and the model returns selected = [i,...]:
async function injectAnswer(bframeDoc, selected, grid) {
  // PRIMARY (faithful): synthesize trusted-shaped pointer events on the chosen tiles.
  // This also populates field20 behavioral telemetry (mouse path + timing).
  const tiles = bframeDoc.querySelectorAll('table td[role="button"], .rc-imageselect-tile');
  for (const i of selected) {
    const td = tiles[i]; const {x,y} = tileCenter(td, grid, i);
    fire(td, 'pointerover', x, y); fire(td, 'mousemove', x+2, y+1);
    fire(td, 'pointerdown', x, y); fire(td, 'mousedown', x, y);
    fire(td, 'pointerup',   x, y); fire(td, 'mouseup',   x, y);
    fire(td, 'click',       x, y);
    await jitter(120, 380);          // human-ish inter-click deltas -> non-degenerate variance
  }
  clickVerify(bframeDoc); // .rc-button-default / "Verify" -> client builds ds/response + POSTs (attested)
}
```

The client then emits `v=VER&c=<c>&ds=[[selected]]` (dynamic 3×3 loop) or
the userverify `response` (multicaptcha 4×4 one-shot) — byte-for-byte
client-authored, carrying X-Recaptcha-Token. Classify each replacement
payload and re-inject until the model returns no matches (mirrors solve.js's
loop, but the client drives the wire).

Fallback injection point (surgical, if jsdom won't render clickable tiles):
set the widget's selection model directly and invoke its verify handler —
locate the selection array from the widget instance (the `frame.Main` client
object in `___grecaptcha_cfg.clients`) and its verify method. This still
routes through the client's serializer + XHR hook (the header is stamped)
but loses the field20 mouse path.

`pb.js` stays read-only observability: decode the client's outgoing reload
field16/field20 and assert non-degenerate before forwarding. Never encode.

### 9.6 Reading the token

Three concentric reads, cross-checked:

```js
// authoritative wire read (in the fetch shim): uvresp[1] from the userverify Response
// canonical API read (anchor ctx):
const token = anchorCtx.grecaptcha.getResponse(widgetId);   // == uvresp[1]
// DOM read (anchor ctx): document.querySelector('textarea[name="g-recaptcha-response"]').value
```

`getResponse` returns '' until the bframe delivers; await the bus message (or
poll uvresp), then read. That token is the harvest output.

### 9.7 Continuous-attestation invariant (why this isn't replay)

The X-Recaptcha-Token / field4 stream is re-minted by `botguard.invoke` per
interaction. The worker (§9.2) and the reload-delivered `window.botguard`
interpreter (`ew.load` @680310; bgdata field 2 inline → `window.eval`, or
field 1 URL → fetch+eval) must stay live across the whole loop — one mint
per replaceimage and per userverify. A one-shot token will not advance the
grid.

### 9.8 Open risk

Whether `frame.Main.init` runs far enough under jsdom to expose the inject
seam at all. Everything above assumes the bframe role (a) installs the j5 XHR
hook, (b) renders clickable tile elements, and (c) accepts synthetic
(`isTrusted:false`) selection and then emits a client-built `ds`/`response`
carrying X-Recaptcha-Token. The challenge UI code depends on real `<img>`
decode, `getBoundingClientRect`, and CSS layout that jsdom lacks, and it may
weight `isTrusted`. If the bframe UI bails before rendering tiles, there is
no primary seam — regress to the selection-model poke, or accept that this
layer needs a real renderer.
