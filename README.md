# recaptcha-re

Browserless reCAPTCHA v2 solver. Python drives the whole challenge flow over
Chrome-impersonated TLS (curl_cffi), a Node VM harness mints the BotGuard
field16 token by executing Google's own anchor script, and challenge tiles
are classified by a local ONNX EfficientNetV2-S model. Built to understand
the protocol — not to run a solving farm.

Demo run: https://www.youtube.com/watch?v=WRUv3rbeZL4

## Status

The pipeline runs end to end but does not pass siteverify yet. BotGuard token
out of the Node harness, anchor fetch, attested /reload, image challenge
(3x3; 4x4 is skipped), tile classification, replaceimage clicks accepted with
HTTP 200, userverify returns a token — and then siteverify answers:

    {"success": false, "error-codes": ["incorrect-captcha-sol"]}

Three runs out of three, including one with an empty selection.

The cause is understood and it is not a bug in the glue. The field16 token
solve_bg.js produces is the setup-phase token, about 1.1 KB. A real browser
attestation is around 5.4 KB (decoded from a captured reload body) and only
appears on reload #2, via the vy(ak) re-attest loop. The notes in
poc/DRIVER_INTEGRATION.md and poc/HARNESS_PLAN.md lay out both hypotheses for
what that larger artifact is — worker Xm versus the page-side botguard.bg
interpreter. The emp_run*.log experiments are where that chase stalled
(reCAPTCHA Timeout (D)/(E): the page never answers the worker in time).
Symptom-wise Google serves the challenge "dead": replaceimage hands back a
fresh ptok on every click but the image bytes never change. That is the wall.

The `node` and `capsolver` labelers need a funded CapSolver key for
ground-truth classification. Mine is out of balance, so everything runs
through the local model.

One thing worth knowing: userverify returns a token even when the selection
is wrong or empty. "TOKEN obtained" in the log means nothing by itself.
Siteverify is the only oracle.

## Requirements

Python 3.11 and Node 18 or newer. Development happens on Windows — paths and
the ANSI setup are win-tuned, and the examples use the `py` launcher. Other
platforms should work with minor adjustments; untested.

## Setup

    py -m pip install -r requirements.txt

Fetch Google's scripts (gitignored — Google's code, not shipped in this
repo; version pinned in the script, live release as of writing is
nY0xPItgwtlvjEjk2TqdwOQz):

    node scripts/fetch_google.js

Config:

    copy config.example.json config.json

Fill in site_key and secret_key. Any v2 keypair you control will do.

The classifier lives at models/recaptcha_cls_effv2s_128_single.onnx, about
78 MB, also not in the repo. `model_path` in config.json overrides the
location. No model and no CapSolver balance means no classification, so pick
one: model for the free path, CapSolver for ground truth.

## Usage

Free path, local model plus BotGuard:

    py solve_tls.py --attempts 1 --labeler model-bg

CapSolver ground truth (needs a funded key):

    py solve_tls.py --attempts 1 --labeler node

Smoke the BotGuard harness on its own:

    node solve_bg.js "https://www.google.com/recaptcha/api2/anchor?ar=1&k=<sitekey>&co=<b64-origin>&hl=en&v=<version>&size=normal&cb=p"

It prints a JSON line with the bg token plus some diagnostics; takes a few
seconds. For the full solver, successful output looks like a run of
"[OK] TOKEN obtained (...)" followed by "[ERR] TOKEN IS INVALID" from
siteverify — see Status for why.

## Documentation

- poc/FINDINGS.md — protocol research: what works browserless, the soft-block
  trust matrix, refuted hypotheses.
- poc/HARNESS_PLAN.md — build plan for the node-vm harness: worker environment
  spec, XHR/curl_cffi forwarding, integrity shims, harvest wiring.
- poc/DRIVER_INTEGRATION.md — driver bring-up: anchor interactivity, the
  page-RPC ack layer, solve loop, realism wiring.
- poc/RELOAD_ROUTES.md — the routes to a captured /reload body (bframe-direct,
  parent emulation, fire-and-capture).
- harness/CHALLENGE_PLAYBOOK.md — challenge object model and how the headless
  client drives tiles to a token.

## Repo layout

- solve_tls.py — the solver. Anchor, reload, click loop, userverify, siteverify.
- solve_bg.js — BotGuard field16 via a synthetic parent-message handshake in a Node VM.
- poc/ — protocol research. pb.js is required at runtime by solve_bg.js; the rest is archived experiments and captures.
- harness/ — VM realm builder. page.js, page_rpc.js and realism.js are runtime-required; the rest is archived.
- scripts/ — fetch_google.js, the Google script downloader.
- models/ — classifier weights, not committed.
- config.json — keys and knobs. Keep it out of any public push.

## Legal

Educational research. Test only against sitekeys you control. Automating
reCAPTCHA violates Google's Terms of Service, and this code will get keys and
IPs banned if pointed at other people's sites. No warranty. MIT — see LICENSE.
