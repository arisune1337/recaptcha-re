# reCAPTCHA v2 pure-request PoC — findings (2026-06-30)

## Verdict: browserless reCAPTCHA v2 over HTTP alone = infeasible

The image model and the entire wire protocol work browserlessly, but
challenge progression is gated on live, per-interaction in-browser BotGuard
execution. No combination of transport, identity, and correct answers
completes a challenge over plain HTTP.

## What works browserless (pure Node / curl_cffi, no field16)

- `GET /anchor` → parse `#recaptcha-token` = `c` (session handle). Trivial.
- `POST /reload` (protobuf body; field16 may be **empty**) → `["rresp", challengeToken, …,
  pmeta(targets+grid), type, …, payloadToken(arr[9]), …]`. 200 every time.
  - protobuf fields: f1=v, f2=c, f5/f6=reason, f14=sitekey, f16=BotGuard (**ignored at reload**),
    f20=behavioral telemetry (b64), f25=`W10` (=[]).
- `GET /payload?p=arr[9]&k=sitekey` → real JPEG challenge grid (300×300 3×3 / 450×450 4×4).
- `POST /replaceimage` is `application/x-www-form-urlencoded`: `v=&c=&ds=[[tileIdx…]]`.
  No field16, no telemetry. Returns `["dresp", newC, …, newPayloadToken]`. 200.
- `POST /userverify` urlencoded `v=&c=` → `["uvresp", token, …]`. 200; the token is a
  valid g-recaptcha-response **only on a completed challenge**.
- Challenge type (`dynamic` 3×3 / `multicaptcha` 4×4) is reputation-driven; a pure-Node
  client (lowest trust) skews to the hard ones.

## The wall — the trust matrix (every cell: same image / null token)

| token minted with      | continued via         | answer        | result     |
|------------------------|-----------------------|---------------|------------|
| anchor (no field16)    | Node fetch            | model         | soft-block |
| browser (real field16) | Node fetch            | model         | soft-block |
| anchor (no field16)    | curl_cffi Chrome-TLS  | model         | soft-block |
| anchor (no field16)    | curl_cffi Chrome-TLS  | human-correct | soft-block |
| browser (real field16) | curl_cffi Chrome-TLS  | human-correct | soft-block |

Ruled out as the gate: TLS/JA3 (curl_cffi impersonates Chrome), IP (same
machine), cookies (`_GRECAPTCHA` forwarded), the c-token (browser
field16-minted token reused), answer correctness (human-verified tiles). The
server returns 200, a fresh chained `c`, and a new payload token — but the
payload image is byte-identical, so the challenge never advances and the
`userverify` token is always null.

The only remaining variable is **continuous client-side BotGuard execution**:
Google's `recaptcha__en.js` running in the bframe and webworker, attesting
each interaction. An HTTP-only client cannot reproduce it.

## Round 2 (2026-06-30) — two follow-up hypotheses, refuted by direct measurement

- **BV attestation request header → refuted.** Hypothesis: `recaptcha__en.js`'s
  XHR hook injects a large BotGuard attestation *request header* the captures
  never saw (they only read `Network.requestWillBeSent.request.headers`, not
  JS-set headers). `capture_hdr.js` subscribes to
  `Network.requestWillBeSentExtraInfo` and dumps the real on-wire headers of
  the browser's `/replaceimage`: only standard headers (sec-ch-ua,
  Content-Type, Referer, Origin, `_GRECAPTCHA`, UA). No large or opaque
  attestation header. The browser's replaceimage is header-identical to the
  PoC's.
- **bft-in-Referer → refuted.** The browser's reload/replaceimage Referer is
  the full `bframe?hl=tr&v=VER&k=SITEKEY&bft=<108B token>`; the PoC used
  `bframe?k=SITEKEY`. `handoff_curl.py` was given the exact browser Referer
  (with live bft), a browser-minted c, `_GRECAPTCHA`, and a human-correct
  tile — still a byte-identical image and a null token.

So body, headers, Referer(+bft), cookie, TLS, IP, token, and answer are all
identical or controlled, yet only the browser advances. The gate is the live
in-page/worker BotGuard *session state*, not any reproducible request field.

## Round 4 (JS-VM path) — the renderer risk measured away

- **`recaptcha__en.js` runs headless in a node `vm`** to completion
  (`harness/worker.js`): env surface ~15 globals. Source instrumentation
  captures the rotating tokens (`RPp` opcode map, `Qr`=init, `ak`=run→`Xm`
  attestation, `AE`=rpc, `d5`=handshake). A by-reference loopback MessagePort
  captures the worker `port2`; a page-side `AE` over it has `.send()`; driving
  `ak` returns a Promise (async attest).
- **Renderer dependency → refuted.** `step1c_fp.js` instrumented
  canvas/webgl/audio before load in anchor+bframe and clicked the checkbox
  (the field16-generation window): **zero** canvas/webgl/audio calls. Driving
  the opcode handlers touches no canvas/webgl either (only document→undefined
  and performance). field16 needs no renderer — the light BotGuard VM
  attestation (navigator/performance/timing/heap/integrity) is fakeable in
  node.
- **Worker protocol captured** (`capture_prog.js` → `prog_capture.json`): the
  BotGuard worker runs in the **anchor frame** (not the bframe). 40
  MessagePort frames: two ~336 KB (the bg program), one 10.5 KB, several
  1–3.5 KB (attestation I/O), and many 30-byte `["B<b64>","x","<callid>"]`
  RPC polls. AE-encoded and session-bound — it must be self-driven in one
  session, not replayed.
- **Remaining (multi-day):** run the anchor page role in-process (minimal
  document stub, no canvas) plus worker via loopback, wire XHR→node fetch,
  let `recaptcha__en.js` self-generate program→attest→field16→/reload, gate
  on own-key siteverify. Residual risk: Xm realism
  (performance.memory is Chrome-only), field20 mouse degeneracy, and
  native-toString integrity.

## Two untested levers that could still flip it

1. **Own easy key + siteverify oracle.** Every earlier test used the 2captcha
   demo key (pathologically hard, origin-bound) and only an md5(payload)
   proxy — never an authoritative accept. Register a free v2-checkbox key
   (default security, "verify origin" off), fill `own_key.json`, run
   `solve_own.py`: tests whether an easy key's soft-block is weaker and gives
   a ground-truth `POST /api/siteverify` verdict.
2. **Lightweight live JS-VM** — run the real `recaptcha__en.js` under
   node-vm/jsdom to keep a live BotGuard session emitting per-interaction
   attestations, then drive HTTP from inside it. Heavy, a maintenance
   treadmill, and tokens may still score low-trust.

## Salvage / recommendation

1. Kill the pure-request solver track (dead end, proven above).
2. Keep the existing headful-Chrome solver (runs the real JS → BotGuard
   executes → challenges complete). The trained model is good and deployed.
3. Reuse the browserless fetch pipeline (anchor→reload→payload) to harvest
   training tiles with no browser (cheap, fast) and keep improving the
   classifier.

## Files

`capture*.js` (CDP exact-byte capture), `pb.js` (protobuf), `flow_probe.js`,
`solve.js` (Node full flow), `mc_probe2.js`, `*handoff*` (trust-locus tests),
`tls_test.py` / `solve_tls.py` / `probe_known.py` / `handoff_curl.py`
(curl_cffi Chrome-TLS tests). Classifier: `models/recaptcha_cls_effv2s_128_single.onnx`.
