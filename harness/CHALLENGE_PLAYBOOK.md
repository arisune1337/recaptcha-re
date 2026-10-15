# reCAPTCHA v2 headless challenge-completion playbook (build TnA7HacJFoBWt9hnlunBlYfK)

Goal: once the headless bframe realm has fired /reload and received a
challenge, drive it to a token IN-REALM with LIVE BotGuard (required — the
trust-matrix runs proved a separate HTTP client freezes /replaceimage; see
poc/FINDINGS.md).

## The challenge instance
- `tS` (L1705) = bframe coordinator. `tS.H` renders a challenge; `tS.W` consumes verify results
  (status `q.EM()` 4/10/6…) and either re-renders the next image or, on terminal state, builds
  `new dh(60,q.D(),...)` and calls `this.D.D.Zr(token)` to postMessage the g-recaptcha-response.
- The live challenge object is an `mr` (L1558) subclass rendered by tS.H:
  - `B5` (L1577) = static image-select base (3x3 or 4x4 "select all")
  - `GG` (L1606) = DYNAMIC 3x3 (replaceimage, one tile at a time)
  - `oS` (L1603) = 4x4 MULTICAPTCHA carousel (select-all → Next, multiple rounds)

## Tile DOM (renderer L825-826)
- Table class: `rc-imageselect-table-44` / `-42` / `-33` (from rowSpan/colSpan).
- Each cell: `<td role="button" id="L[46](7, row*cols+col)" class="rc-imageselect-tile" ...>`
  → tile INDEX = reading order = row*colCount + col.
- Container: element with class `rc-imageselect-target`. Payload host: `rc-imageselect-payload`.
- Grid model on the challenge instance: **`challenge.P.VI.I$`** = `{rowSpan, colSpan, e_, PG}`
  - `e_[i]` = tile model `{selected:bool, element:td}` (index i = reading order)
  - `PG` = selected count.

## DRIVING IT HEADLESS — call the controller method directly (do NOT fire a bare 'click')
Binding is a `U$` TAP gesture (pointerdown `h6` + pointerup `GU` within 500ms) → `challenge.Dr(z)`.
A plain MouseEvent('click') will NOT fire it. So select tile i by calling `Dr` on its model:

    challenge.Dr(challenge.P.VI.I$.e_[i])

- **DYNAMIC 3x3 (GG.Dr, L1609):** `Dr(e_[i])` sets selected + calls `t[1](2,!0,this)` →
  POST /recaptcha/api2/replaceimage body `v=&c=<token>&ds=[[i]]`. Reply handled by `GG.Gn`
  (L1607-8): shifts next image, swaps into the faded slot, rebinds a fresh tap. RE-READ `e_`
  after each (its length grows). Loop: classify current image → if positive, Dr(that tile) →
  wait for replacement → reclassify the new tile → repeat until no positives remain → Verify.
- **STATIC 3x3/4x4 (B5.Dr, L1579-80):** `Dr(e_[i])` toggles selection, NO network per click.
  After selecting all positives, submit via the Verify button path:
  `H[31](17,!1,challenge)` (the handler bound to `challenge.u` via listener `Il`).
- **4x4 MULTICAPTCHA (oS, L1603-6):** `Dr(e_[i])` per round (toggles), then Verify/Next
  (`challenge.u` → `H[31]`). `oS.vS` pushes the round's selected indices into `challenge.V`
  (array-of-arrays). Repeat rounds until `tS.W` sees terminal `EM()` → token via `this.D.D.Zr`.

## Submit + read the token
- Verify button widget = `challenge.u`, bound at mr.Jb (L1560-1): listener `Il` →
  `H[31](17,!1,challenge)` reads `challenge.response` (each subclass's `zR` writes it) and POSTs
  userverify. Reload button = `challenge.wU`→`qP`.
- Wire sender = `pn.prototype.send` (L1600): `fetch(url,{method,headers:{Content-Type},body})`;
  api2 base assembled L203 `"https://www.google.com/recaptcha/api2/"+subpath`.
- **Token capture:** hook `Zr` (L1703/L1713 = RecaptchaEmbedder.verifyCallback(q.response)) — the
  final token (`["uvresp", <token>, ...]` → the g-recaptcha-response) is delivered there.

## Classification (own model)
- Model: `models/recaptcha_cls_effv2s_128_single.onnx` at the repo root
  (EfficientNetV2-S, 128px single tile, 14 classes alphabetical). Preprocessing follows the
  dataset-maker tooling it was trained with. Detector for segmentation if needed:
  `recaptcha_detect_yolov8s.onnx`.
- Map Google's target `/m/<id>`+human label (from reload pmeta) → our class index (see the
  reload-parse notes below and the training class order).

## Reload response parse (indices)
- `)]}'`-prefixed array: idx1 = challenge/session token `c`; a `["pmeta",["/m/<id>",...,"<label>"],...]`
  entry = target class; a `"dynamic"` | `"multicaptcha"` marker = mode; grid size from the table
  class / pmeta; idx9-area = payload token for `GET /recaptcha/api2/payload?p=<tok>&k=<sitekey>&c=<c>`.
  (Cross-check harness/reload_net.json.)

## Env realism (minimize BotGuard bot-scoring at siteverify)
- attestation `ak` reads performance.memory.usedJSHeapSize + navigator.deviceMemory + performance.now();
  field20 (~390-430B) = interaction telemetry. Present: UA Chrome/149 Edg/149, deviceMemory 8,
  hardwareConcurrency 8, monotonic 0.1ms-resolution performance.now, growing heap, plausible
  userAgentData, screen 1920x1080, Intl/timezone. (harness/realism.js implements this.)
  This is the residual ~8-12% trust risk — hardened last.
