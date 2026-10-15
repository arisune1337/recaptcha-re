#!/usr/bin/env python3
"""
solve_tls.py  —  end-to-end browserless reCAPTCHA v2 solver
  • Chrome-impersonated TLS  (curl_cffi)
  • Local ONNX classifier    (onnxruntime + EfficientNetV2-S)
  • Supports dynamic 3x3 / multicaptcha grids
  • Configurable via config.json (shares config with maker.py)
  • Multi-attempt with configurable concurrency
  • Full error handling + colored status output

Usage:
  py solve_tls.py                  # 3 attempts (default)
  py solve_tls.py --attempts 10
  py solve_tls.py --threads 4 --attempts 20
"""
import os, sys, json, re, base64, hashlib, io, time, argparse, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, quote as _urlquote

import numpy as np
from PIL import Image
from curl_cffi import requests as cffi_requests
import onnxruntime as ort

# capsolver uses stdlib urllib so it doesn't interfere with curl_cffi
import urllib.request as _urllib
import urllib.error   as _urllib_err

# ---- config -----------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
CFG  = json.load(open(ROOT / "config.json", encoding="utf-8"))

SITEKEY = CFG["site_key"]
VER     = CFG["version"]
SITE_URL = CFG["site_url"]
SECRET_KEY = CFG.get("secret_key", "")
MODEL   = CFG.get("model_path") or "models/recaptcha_cls_effv2s_128_single.onnx"
MODEL   = Path(MODEL) if Path(MODEL).is_absolute() else ROOT / MODEL

def make_co(site_url: str) -> str:
    """
    Compute reCAPTCHA co= parameter = base64(window.location.origin).
    JS 'origin' omits port for standard ports (443 for https, 80 for http).
    e.g. https://nopecha.com/page  →  base64('https://nopecha.com')
         http://site.com:8080/x   →  base64('http://site.com:8080')
    """
    p = urlparse(site_url)
    std = {"https": 443, "http": 80}.get(p.scheme, 443)
    explicit = p.port
    if explicit and explicit != std:
        origin = f"{p.scheme}://{p.hostname}:{explicit}"
    else:
        origin = f"{p.scheme}://{p.hostname}"
    return base64.b64encode(origin.encode()).decode().rstrip("=")

parsed = urlparse(SITE_URL)
CO     = make_co(SITE_URL)
REF    = f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"
UA     = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0")

# ---- ANSI -------------------------------------------------------------------
if sys.platform == "win32":
    os.system("")
RESET = "\033[0m"; GREEN = "\033[92m"; RED = "\033[91m"
CYAN  = "\033[96m"; YELLOW = "\033[93m"; GRAY = "\033[90m"; BOLD = "\033[1m"

def _tid():
    tid = getattr(_tl, 'task_id', None)
    return f"[{tid[:8]}] " if tid else ""

def ok(msg):  print(f"{_tid()}{GREEN}{BOLD}[OK]{RESET}  {msg}", flush=True)
def err(msg): print(f"{_tid()}{RED}{BOLD}[ERR]{RESET} {msg}", flush=True)
def inf(msg): print(f"{_tid()}{CYAN}[INF]{RESET} {msg}", flush=True)
def dbg(msg): print(f"{_tid()}{GRAY}[DBG]{RESET} {msg}", flush=True)

# ---- class map --------------------------------------------------------------
CLS = "bicycle bridge bus car chimney crosswalk hydrant motorcycle mountain other palm stairs tractor traffic_light".split()
MID2I = {
    "/m/0199g": 0, "/m/015kr": 1, "/m/01bjv": 2, "/m/0k4j": 3, "/m/0pg52": 3,
    "/m/01jk_4": 4, "/m/014xcs": 5, "/m/01pns0": 6, "/m/04_sv": 7, "/m/09d_r": 8,
    "/m/0cdl1": 10, "/m/01lynh": 11, "/m/013xlm": 12, "/m/015qff": 13,
}
HUM2I = {
    "bike": 0, "bicycle": 0, "bridge": 1, "bus": 2, "car": 3, "taxi": 3,
    "chimney": 4, "pedestrian crossing": 5, "crosswalk": 5,
    "fire hydrant": 6, "hydrant": 6, "motorcycle": 7, "mountain": 8,
    "palm tree": 10, "stairs": 11, "staircase": 11, "tractor": 12, "traffic light": 13,
}

# ---- thread-local context (for concurrent multi-site solving) ---------------
# Each API worker thread sets its own SITEKEY/CO/REF via thread_ctx().
# Falls back to module-level globals when no thread-local value is set.
_tl = threading.local()

def _sk():   return getattr(_tl, 'sitekey', SITEKEY)
def _co_():  return getattr(_tl, 'co',      CO)
def _ref_(): return getattr(_tl, 'ref',     REF)
def _ver_(): return getattr(_tl, 'ver',     VER)

class thread_ctx:
    """Context manager: override reCAPTCHA params per-thread.
    Usage:
        with solve_tls.thread_ctx(sitekey, site_url):
            token = solve_once(session, labeler='model')
    """
    __slots__ = ('_sk', '_co', '_ref', '_ver', '_tid')
    def __init__(self, sitekey: str, site_url: str, task_id: str = None):
        self._sk  = sitekey
        self._co  = make_co(site_url)
        self._ref = f"https://www.google.com/recaptcha/api2/bframe?k={sitekey}"
        self._ver = VER  # global version — same for all sites
        self._tid = task_id
    def __enter__(self):
        _tl.sitekey = self._sk
        _tl.co      = self._co
        _tl.ref     = self._ref
        _tl.ver     = self._ver
        if self._tid: _tl.task_id = self._tid
        return self
    def __exit__(self, *_):
        for a in ('sitekey', 'co', 'ref', 'ver', 'task_id'):
            _tl.__dict__.pop(a, None)

# ---- ONNX session (lazy, thread-safe) ---------------------------------------
_LOCK = threading.Lock()
_sess = None
def get_sess():
    global _sess
    if _sess is None:
        with _LOCK:
            if _sess is None:
                if not Path(MODEL).exists():
                    sys.exit(f"{RED}Model not found:{RESET} {MODEL}")
                so = ort.SessionOptions()
                so.intra_op_num_threads = 2   # cap per-process CPU (api_server runs many subprocesses)
                so.inter_op_num_threads = 1
                _sess = ort.InferenceSession(MODEL, sess_options=so, providers=["CPUExecutionProvider"])
                inf(f"Model loaded: {Path(MODEL).name}")
    return _sess

def classify_tile(pil_img, ci: int) -> float:
    sess = get_sess()
    inp  = sess.get_inputs()[0].name
    a = np.asarray(pil_img.convert("RGB").resize((128, 128)), dtype=np.float32) / 255.0
    a = np.transpose(a, (2, 0, 1))[None, ...]
    return float(sess.run(None, {inp: a})[0][0][ci])

# ---- protobuf (shared logic) ------------------------------------------------
def rv(b, p):
    sh = r = 0
    while True:
        x = b[p]; p += 1; r |= (x & 0x7f) << sh
        if not (x & 0x80): break
        sh += 7
    return r, p
def decode(b):
    o = []; p = 0
    while p < len(b):
        t, p = rv(b, p); fn = t >> 3; wt = t & 7
        if wt == 0: v, p = rv(b, p); o.append([fn, 0, v])
        elif wt == 2: ln, p = rv(b, p); o.append([fn, 2, b[p:p+ln]]); p += ln
        elif wt == 5: o.append([fn, 5, b[p:p+4]]); p += 4
        elif wt == 1: o.append([fn, 1, b[p:p+8]]); p += 8
        else: break
    return o
def ev(n):
    o = bytearray()
    while True:
        x = n & 0x7f; n >>= 7
        if n: o.append(x | 0x80)
        else: o.append(x); break
    return bytes(o)
def encode(fs):
    o = bytearray()
    for fn, wt, val in fs:
        o += ev((fn << 3) | wt)
        if wt == 0: o += ev(val)
        elif wt == 2: o += ev(len(val)) + val
        else: o += val
    return bytes(o)
def setf(fs, n, s):
    for f in fs:
        if f[0] == n: f[2] = s.encode("latin1")
    return fs

RELOAD_TEMPLATE = base64.b64decode((ROOT / "reload_template.b64").read_text().strip())

# ---- network helpers --------------------------------------------------------
def _dejson(t: str):
    t = re.sub(r"^\)\]\}'\n?", "", t.strip())
    if not t:
        raise ValueError("Empty response")
    return json.loads(t)

# ---- network helpers --------------------------------------------------------
def new_session(proxy: str = None):
    s = cffi_requests.Session(impersonate=CFG.get("impersonate", "chrome"))
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s

def anchor_token(s):
    """Return (c_token, html) or (None, None).
    Tries api2 first; falls back to enterprise endpoint for enterprise keys.
    """
    for endpoint in ("api2", "enterprise"):
        url = (f"https://www.google.com/recaptcha/{endpoint}/anchor?ar=1&k={_sk()}"
               f"&co={_co_()}&hl=en&v={_ver_()}&size=normal&cb=p")
        try:
            h = s.get(url, headers={"User-Agent": UA},
                      timeout=CFG.get("request_timeout", 25)).text
            m = re.search(r'value="([^"]+)"', h)
            if m:
                return m.group(1), h
            if endpoint == "api2":
                dbg(f"anchor api2 no value= (len={len(h)}) — trying enterprise endpoint")
                continue
        except Exception as e:
            dbg(f"anchor {endpoint} error: {e}")
    return None, None

def get_botguard_via_node(proxy: str = None, anchor_url: str = None) -> str:
    """
    Use Node.js (solve_bg.js) to generate a BotGuard field16 token via request-only
    JS execution. No Playwright, no Selenium — just Node.js running Google's reCAPTCHA
    JS in a VM with a synthetic parent-message handshake.
    Returns bg string or '' on failure.
    """
    import subprocess, json as _json
    bg_js = ROOT / "solve_bg.js"
    if not bg_js.exists():
        dbg("solve_bg.js not found next to solve_tls.py")
        return ""
    if not anchor_url:
        anchor_url = (f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={_sk()}"
                      f"&co={_co_()}&hl=en&v={_ver_()}&size=normal&cb=p")
    # Pass proxy as argv[3] (solve_bg.js reads it from process.argv[3])
    cmd = ["node", str(bg_js)]
    if anchor_url:
        cmd.append(anchor_url)
    if proxy:
        cmd.append(proxy)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=45,
            env=__import__("os").environ.copy()
        )
        out = result.stdout.strip()
        if not out:
            dbg(f"solve_bg.js produced no output. stderr={result.stderr[:200]}")
            return ""
        data = _json.loads(out)
        if "error" in data:
            dbg(f"solve_bg.js error: {data['error']}")
            return ""
        # Log diagnostic fields
        reloads  = data.get("reloads",  "?")
        clickable= data.get("clickable","?")
        handlers = data.get("msgHandlers","?")
        dbg(f"  bg diag: reloads={reloads} clickable={clickable} msgHandlers={handlers}")
        bg = data.get("bg", "")
        if bg:
            inf(f"BotGuard token from Node.js ({len(bg)} chars)")
        else:
            dbg("solve_bg.js returned empty bg token")
        return bg
    except subprocess.TimeoutExpired:
        dbg("solve_bg.js timed out (45s)")
        return ""
    except Exception as e:
        dbg(f"get_botguard_via_node error: {e}")
        return ""



def reload_arr(s, c, field16: str = ""):
    """Send /reload.  field16 = BotGuard attestation token (URL-safe b64, ~5KB)."""
    f = decode(RELOAD_TEMPLATE)
    setf(f, 2, c)                    # fresh anchor token
    setf(f, 14, _sk())             # SITEKEY must match URL ?k= param (field[14])
    setf(f, 16, field16 or "")       # BotGuard attestation (empty = unatested)
    setf(f, 6, "fi")                 # reason: fi (first)
    try:
        r = s.post(
            f"https://www.google.com/recaptcha/api2/reload?k={_sk()}",
            data=encode(f),
            headers={"User-Agent": UA,
                     "Content-Type": "application/x-protobuffer",
                     "Referer": _ref_(), "Origin": "https://www.google.com"},
            timeout=CFG.get("request_timeout", 25)
        )
        if r.status_code != 200:
            raise ValueError(f"HTTP {r.status_code}")
        return _dejson(r.text)
    except Exception as e:
        raw = getattr(r, 'text', '') if 'r' in dir() else ''
        raise RuntimeError(f"reload failed: {e} | raw={raw[:200]!r}")

def fetch_payload(s, ptok) -> bytes | None:
    r = s.get(f"https://www.google.com/recaptcha/api2/payload?p={ptok}&k={_sk()}",
              headers={"User-Agent": UA, "Referer": _ref_()},
              timeout=CFG.get("request_timeout", 25))
    ct = r.headers.get("content-type", "")
    return r.content if (r.status_code == 200 and "image" in ct) else None


# ---- CapSolver tile classification ------------------------------------------
CAP_KEY = CFG.get("capsolver_key", "")

def _capsolver_post(endpoint: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req  = _urllib.Request(
        f"https://api.capsolver.com/{endpoint}",
        data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        raw = _urllib.urlopen(req, timeout=CFG.get("capsolver_timeout", 30)).read()
    except _urllib_err.HTTPError as e:
        raw = e.read()
    resp = json.loads(raw)
    if resp.get("errorId"):
        raise RuntimeError(f"CapSolver [{resp.get('errorCode')}]: {resp.get('errorDescription')}")
    return resp

def capsolver_classify(img_bytes: bytes, mid: str) -> set:
    """
    ReCaptchaV2Classification — classify tiles synchronously.
    Returns set of positive tile indices.
    """
    resp = _capsolver_post("createTask", {
        "clientKey": CAP_KEY,
        "task": {
            "type": "ReCaptchaV2Classification",
            "websiteURL": SITE_URL, "websiteKey": SITEKEY,
            "image": base64.b64encode(img_bytes).decode(),
            "question": mid,
        }
    })
    sol = resp.get("solution") or {}
    return set(int(x) for x in (sol.get("objects") or []))

def capsolver_full_solve() -> str | None:
    """
    ReCaptchaV2Task+proxy fallback — full async solve by CapSolver.
    Returns the gRecaptchaResponse token, or raises on failure.
    """
    if not CAP_KEY:
        raise RuntimeError("capsolver_key not set in config.json")

    # Build proxy config for CapSolver if we have one
    proxies = [p for p in (CFG.get("proxies") or []) if p and p.strip()]
    proxy_url = proxies[0] if proxies else None

    task_types = []
    if proxy_url:
        # Parse proxy: http://user:pass@host:port
        import re as _re
        m = _re.match(r"(https?)://(?:([^:@]+):([^@]+)@)?([^:]+):(\d+)", proxy_url)
        if m:
            task_types.append({
                "type": "ReCaptchaV2Task",
                "websiteURL": SITE_URL, "websiteKey": SITEKEY,
                "proxyType": m.group(1), "proxyAddress": m.group(4),
                "proxyPort": int(m.group(5)), "proxyLogin": m.group(2) or "",
                "proxyPassword": m.group(3) or "",
            })
    task_types.append({
        "type": "ReCaptchaV2TaskProxyless",
        "websiteURL": SITE_URL, "websiteKey": SITEKEY,
    })

    last_err = None
    for task in task_types:
        try:
            resp = _capsolver_post("createTask", {"clientKey": CAP_KEY, "task": task})
        except RuntimeError as e:
            last_err = e
            inf(f"  {task['type']} failed: {e}, trying next…")
            continue
        task_id = resp["taskId"]
        inf(f"CapSolver task created ({task['type']}): {task_id}")
        for tick in range(120):
            time.sleep(1)
            r = _capsolver_post("getTaskResult", {"clientKey": CAP_KEY, "taskId": task_id})
            status = r.get("status", "")
            if status == "ready":
                return r["solution"]["gRecaptchaResponse"]
            if status == "failed":
                last_err = RuntimeError(f"task failed: {r}")
                break
            if tick % 5 == 0:
                dbg(f"  CapSolver waiting… {tick}s")
        break  # don't retry with proxyless if proxied task ran
    raise last_err or RuntimeError("CapSolver: all task types failed")

# ---- parse challenge ---------------------------------------------------------
def parse_challenge(arr):
    """Return (mid, rows, cols, human_label) or None."""
    if len(arr) < 6 or arr[4] is None:
        return None
    typ = arr[5]
    if typ not in ("dynamic", "multicaptcha", "tileselect"):
        return None
    pm = arr[4]
    try:
        if typ == "dynamic":
            t = pm[1]
            mid, rows, cols = t[0], t[2], t[3]
            human = str(t[6]) if len(t) > 6 else ""
            return mid, rows, cols, human
        # multicaptcha
        sub = pm[5][0][0]
        mid, rows, cols = sub[0], sub[3], sub[4]
        return mid, rows, cols, ""
    except Exception:
        try:
            t = pm[1]
            return t[0], t[2], t[3], ""
        except Exception:
            return None

# ---- core solver ------------------------------------------------------------
def solve_once(s, threshold: float = None, max_rounds: int = 12,
               verbose: bool = True, labeler: str = "capsolver",
               proxy: str = None) -> bool | None:
    """
    Returns True  -> got a token
             False -> completed but no token
             None  -> could not get a challenge
    """
    # ---- node: TLS solve with Node.js BotGuard generation -------------------
    # 'node' is same flow as 'capsolver'/'model' but fetches a real bg token
    # via solve_bg.js (Node.js VM execution of Google's BotGuard JS)
    use_node_bg = labeler in ("node", "model-bg")
    if labeler == "node":
        labeler = "capsolver"  # node    = BotGuard field16 + CapSolver classify
    elif labeler == "model-bg":
        labeler = "model"      # model-bg = BotGuard field16 + local ONNX classify (no CapSolver)

    # ---- capsolver-full: old API-only full solve ----------------------------
    if labeler == "capsolver-full":
        try:
            token = capsolver_full_solve()
            ok(f"TOKEN obtained ({token[:60]}...)")
            return True
        except Exception as e:
            err(f"CapSolver full solve failed: {e}")
            return False

    if threshold is None:
        threshold = float(CFG.get("model_threshold", 0.55))

    # 1. Fetch BotGuard field16 BEFORE first /reload (if node labeler)
    #    field16 is the BotGuard attestation token embedded in the /reload protobuf body.
    #    Without it Google returns a challenge whose replaceimage won't advance the image.
    bg = ""
    if use_node_bg:
        bg = get_botguard_via_node(proxy=proxy)
        if bg:
            inf(f"BotGuard field16 ready ({len(bg)} chars) — attested reload")
        else:
            inf("Node.js BotGuard unavailable (anchor didn't go interactive) — unatested reload")

    # 2. Get a fresh anchor token
    c, anchor_html = anchor_token(s)
    if not c:
        err("anchor failed"); return None

    # 3. Reload until we get an image challenge (max 8 tries), injecting field16
    arr = None
    for attempt in range(8):
        try:
            arr = reload_arr(s, c, field16=bg)
        except RuntimeError as e:
            err(str(e)); return None
        ch = parse_challenge(arr)
        if ch:
            break
        if verbose: dbg(f"  non-image challenge type={arr[5]!r}, retrying ({attempt+1}/8)...")
        c, anchor_html = anchor_token(s)
        if not c: err("anchor failed"); return None

    ch = parse_challenge(arr)
    if not ch:
        err(f"Could not get image challenge after 8 reloads (last type={arr[5]!r})")
        return None

    mid, rows, cols, human = ch
    ci = MID2I.get(mid) if mid in MID2I else HUM2I.get(human.lower())
    cls_name = CLS[ci] if ci is not None else "unknown"

    # -- skip 4x4 grids (model accuracy too low) — retry until 3x3 ---------------
    _grid_retries = 0
    while rows == 4 and _grid_retries < 8:
        if verbose: inf(f"  4x4 grid detected — skipping, requesting 3x3 (retry {_grid_retries+1}/8)")
        c, anchor_html = anchor_token(s)
        if not c: err("anchor failed on 4x4 skip"); return None
        try:
            arr = reload_arr(s, c, field16=bg)
        except RuntimeError as e:
            err(str(e)); return None
        ch2 = parse_challenge(arr)
        if ch2:
            mid, rows, cols, human = ch2
            ci = MID2I.get(mid) if mid in MID2I else HUM2I.get(human.lower())
            cls_name = CLS[ci] if ci is not None else "unknown"
        _grid_retries += 1

    if rows == 4:
        if verbose: err("Could not get 3x3 challenge after retries — skipping attempt")
        return None
    # -------------------------------------------------------------------------------

    if verbose:
        inf(f"Challenge: {human!r}/{mid} -> class={YELLOW}{cls_name}{RESET} ({rows}x{cols})")

    if ci is None:
        err(f"No model class for mid={mid!r} human={human!r}")
        return None

    c_tok = arr[1]
    ptok  = arr[9] if len(arr) > 9 else None
    if not ptok:
        err("No payload token"); return None

    img = fetch_payload(s, ptok)
    if not img:
        err("Payload fetch failed"); return None


    # 4. Click loop
    t_start = int(time.time() * 1000)
    prev_hash = None
    prev_ptok = ptok
    consecutive_same = 0   # track how many rounds in a row the image didn't change
    all_selected_tiles = []  # all tiles clicked across all rounds (for userverify response=)
    for rnd in range(max_rounds):
        cur_hash = hashlib.md5(img).hexdigest()[:8]

        # --- label tiles ---
        if labeler == "capsolver":
            try:
                sel = sorted(capsolver_classify(img, mid))
                confs = []  # no per-tile confs from capsolver
                if verbose:
                    print(f"  round {rnd:2d}: img={GRAY}{cur_hash}{RESET} "
                          f"sel={GREEN}{sel}{RESET} [CapSolver]")
            except Exception as e:
                err(f"CapSolver classify error: {e}"); break
        else:
            pil = Image.open(io.BytesIO(img)); W, H = pil.size
            cw, ch_ = W // cols, H // rows
            confs = []
            for i in range(rows * cols):
                r_, c_ = divmod(i, cols)
                tile = pil.crop((c_*cw, r_*ch_, c_*cw+cw, r_*ch_+ch_))
                confs.append(classify_tile(tile, ci))
            sel = sorted(i for i, v in enumerate(confs) if v >= threshold)
            if verbose:
                conf_str = " ".join(f"{v:.2f}" for v in confs)
                print(f"  round {rnd:2d}: img={GRAY}{cur_hash}{RESET} "
                      f"sel={GREEN}{sel}{RESET} max={max(confs):.3f}")
                dbg(f"  confs: [{conf_str}]")

        if not sel:
            if verbose: ok("  No targets found -- proceeding to verify")
            break

        prev_hash = cur_hash

        # Real browser sends tiles one-at-a-time: ds=[2], ds=[6], etc.
        ra = None
        for tile_idx in sel:
            all_selected_tiles.append(tile_idx)
            now_ms = int(time.time() * 1000)
            elapsed_ms = now_ms - t_start
            # ds=[N] URL-encoded: %5BN%5D
            tile_body = (f"v={_ver_()}&c={c_tok}"
                         f"&ds=%5B{tile_idx}%5D&t={elapsed_ms}&ct={elapsed_ms}")
            try:
                ri_resp = s.post(
                    f"https://www.google.com/recaptcha/api2/replaceimage?k={_sk()}",
                    data=tile_body,
                    headers={"User-Agent": UA,
                             "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                             "Referer": _ref_(), "Origin": "https://www.google.com"},
                    timeout=CFG.get("request_timeout", 25)
                )
                if verbose:
                    dbg(f"  replaceimage[tile={tile_idx}] HTTP {ri_resp.status_code}")
                tile_ra = _dejson(ri_resp.text)
                # update c_tok after each tile click (it grows with each call)
                if len(tile_ra) > 1 and tile_ra[1]:
                    c_tok = tile_ra[1]
                ra = tile_ra
                time.sleep(0.2)  # small delay between tile clicks
            except Exception as e:
                err(f"replaceimage[tile={tile_idx}] error: {e}")
                ra = None; break
        if ra is None:
            break

        c_tok = ra[1] if len(ra) > 1 else c_tok
        new_ptok = ra[5] if len(ra) > 5 else None

        # ra[4] can carry updated pmeta (mid/grid change mid-solve)
        if len(ra) > 4 and ra[4]:
            try:
                for entry in ra[4]:
                    if entry and entry[0] == "pmeta":
                        pm = entry[1]
                        new_mid = pm[0] if len(pm) > 0 else mid
                        if new_mid != mid:
                            mid = new_mid
                            new_ci = MID2I.get(mid) if mid in MID2I else ci
                            if new_ci is not None:
                                ci = new_ci
                            if verbose:
                                inf(f"  mid updated: {mid} -> class={CLS[ci] if ci < len(CLS) else '?'}")
            except Exception:
                pass

        if verbose:
            dbg(f"  ra structure: len={len(ra)} fields={[type(x).__name__ for x in ra]}")
            dbg(f"  old_ptok={str(prev_ptok)[:30]} | new_ptok={str(new_ptok)[:30]}")

        if new_ptok and new_ptok != prev_ptok:
            new_img = fetch_payload(s, new_ptok)
            if new_img is None:
                if verbose: err("  New payload fetch failed"); break
            if verbose: dbg(f"  old_img_size={len(img)} new_img_size={len(new_img)} same={img==new_img}")
            if img == new_img:
                consecutive_same += 1
                if consecutive_same >= 2:
                    # Image unchanged 2+ rounds: either tileselect (static) or wrong tiles.
                    # Stop looping — call userverify with current token.
                    if verbose: inf(f"  Image unchanged {consecutive_same} rounds — calling userverify")
                    break
            else:
                consecutive_same = 0
            img = new_img
            prev_ptok = new_ptok
        elif new_ptok and new_ptok == prev_ptok:
            if verbose: err("  same ptok returned — Google didn't advance (possible bot detection)"); break
        else:
            if verbose: dbg(f"  no new ptok in ra — challenge ended, calling userverify"); break

    # 5. userverify — match real browser fields:
    #    response= (selected tiles JSON), t=, ct=, oc= (BG token), pm= (mouse data)
    if verbose: inf(f"userverify c_tok=(len={len(c_tok)}) tiles={all_selected_tiles}")
    now_ms = int(time.time() * 1000)
    elapsed_ms = now_ms - t_start
    # response= field: base64url({"response":[...tiles...],"e":""})
    response_json = json.dumps({"response": all_selected_tiles, "e": ""}, separators=(',', ':'))
    response_b64 = base64.urlsafe_b64encode(response_json.encode()).decode().rstrip('=')
    # pm= field: 9-byte binary header + JSON interaction data, base64url-encoded
    # Header bytes (constant from real browser captures), followed by minimal mouse JSON
    _pm_hdr = b'\xe7\x56\xc6\xc2\xc6\xe7\x56\xc6\xc2'
    _pm_json = b'[null,null,[null,null,null,[5,1.5,0.0015,3],[1,0.4,0.00005,1],0,0,0]]'
    pm_b64 = base64.urlsafe_b64encode(_pm_hdr + _pm_json).decode().rstrip('=')
    uv_body = (f"v={_ver_()}&c={c_tok}"
               f"&response={_urlquote(response_b64, safe='')}"
               f"&t={elapsed_ms}&ct={elapsed_ms}")
    if bg:
        uv_body += f"&oc={bg}"   # BG token goes in oc= for userverify
    uv_body += f"&pm={pm_b64}"
    if verbose:
        dbg(f"  uv fields: response={response_json[:60]} oc={'yes' if bg else 'no'} pm=yes")
    try:
        uv_resp = s.post(
            f"https://www.google.com/recaptcha/api2/userverify?k={_sk()}",
            data=uv_body,
            headers={"User-Agent": UA,
                     "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                     "Referer": _ref_(), "Origin": "https://www.google.com"},
            timeout=CFG.get("request_timeout", 25)
        ).text
        if verbose: dbg(f"  userverify ok")
        ua_arr = _dejson(uv_resp)
    except Exception as e:
        err(f"userverify error: {e}"); return False

    token = ua_arr[1] if len(ua_arr) > 1 else None
    if token:
        ok(f"TOKEN obtained ({token[:64]}\u2026)")
        return token
    else:
        err(f"userverify null token | uvresp={json.dumps(ua_arr)}")
        return None

def check_token_validity(session, token: str) -> bool:
    """Check if the recaptcha token is valid using the secret key."""
    if not SECRET_KEY:
        inf("no secret_key in config.json — skipping siteverify")
        return False
    inf(f"Verifying token against Google siteverify API using secret key: {SECRET_KEY[:8]}...")
    try:
        r = session.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": SECRET_KEY, "response": token},
            timeout=15
        )
        res = r.json()
        if res.get("success"):
            ok(f"TOKEN IS VALID! [OK] | hostname={res.get('hostname')} challenge_ts={res.get('challenge_ts')}")
            return True
        else:
            err(f"TOKEN IS INVALID! [FAIL] | response={json.dumps(res)}")
            return False
    except Exception as e:
        err(f"Failed to verify token: {e}")
        return False

# ---- thread worker ---------------------------------------------------------
_print_lock = threading.Lock()

def _solve_worker(args, proxy, tid, wins_ref, tokens_list, stop_evt, t0, proxies_all):
    """Single worker thread — runs one solve attempt and reports result."""
    # Rotate proxies by thread id if multiple available
    if proxies_all:
        proxy = proxies_all[(tid - 1) % len(proxies_all)]
    s = new_session(proxy)
    # In multi-thread mode suppress per-round verbose to avoid interleaving
    multi = getattr(args, 'threads', 1) > 1
    verbose = (not args.quiet) and (not multi)
    try:
        result = solve_once(s, threshold=args.threshold, verbose=verbose,
                            labeler=args.labeler, proxy=proxy)
    except Exception as exc:
        with _print_lock:
            err(f"[T{tid:02d}] exception: {exc}")
        return None
    if result:
        with _print_lock:
            wins_ref[0] += 1
            n = wins_ref[0]
            elapsed = time.time() - t0
            ok(f"[T{tid:02d}] TOKEN #{n} in {elapsed:.1f}s")
            print(f"\n{GREEN}{BOLD}TOKEN:{RESET} {result}\n")
            tokens_list.append(result)
            check_token_validity(s, result)
        stop_evt.set()
    else:
        with _print_lock:
            err(f"[T{tid:02d}] No token")
    return result

# ---- main -------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Browserless reCAPTCHA v2 solver")
    parser.add_argument("--attempts", type=int, default=3, help="Number of solve attempts")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Confidence threshold for positive tiles (default: from config)")
    parser.add_argument("--labeler",
                        choices=["node", "model", "model-bg", "capsolver", "capsolver-full"],
                        default="node",
                        help=("node=Node.js BotGuard+CapSolver classify+TLS (default) | "
                              "model-bg=Node.js BotGuard+local ONNX classify+TLS (no CapSolver) | "
                              "capsolver=CapSolver classify+TLS (no BotGuard) | "
                              "model=local ONNX+TLS | "
                              "capsolver-full=full CapSolver API solve"))
    parser.add_argument("--quiet", action="store_true", help="Suppress per-round output")
    parser.add_argument("--threads", type=int, default=1,
                        help="Number of parallel solver threads (default: 1)")
    parser.add_argument("--collect", type=int, default=1,
                        help="Stop after collecting this many tokens (default: 1)")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy URL (overrides config)")
    parser.add_argument("--site-url", type=str, default=None,
                        help="Target site URL (overrides config.json site_url)")
    parser.add_argument("--site-key", type=str, default=None,
                        help="reCAPTCHA site key (overrides config.json site_key)")
    parser.add_argument("--verify", action="store_true",
                        help="Auto-verify token against site's demo endpoint after solving")
    args = parser.parse_args()

    # --- apply site-url / site-key overrides ---
    global SITEKEY, SITE_URL, CO, REF
    if args.site_url:  SITE_URL = args.site_url
    if args.site_key:  SITEKEY  = args.site_key
    if args.site_url or args.site_key:
        parsed2 = urlparse(SITE_URL)
        port2   = parsed2.port or (443 if parsed2.scheme == "https" else 80)
        CO  = make_co(SITE_URL)
        REF = f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"

    # --- proxy list for rotation ---
    proxies_cfg = [p for p in (CFG.get("proxies") or []) if p and p.strip()]
    if args.proxy:
        # explicit --proxy overrides: all threads use it
        proxies_all = [args.proxy]
        proxy = args.proxy
    elif proxies_cfg:
        proxies_all = proxies_cfg
        proxy = proxies_cfg[0]
    else:
        proxies_all = []
        proxy = None

    if proxy:
        inf(f"Using proxy: {proxy.split('@')[-1]}")  # hide credentials
        if len(proxies_all) > 1:
            inf(f"Proxy pool : {len(proxies_all)} proxies (round-robin)")
    else:
        inf("Direct connection (no proxy)")

    inf(f"Site key : {YELLOW}{SITEKEY[:20]}…{RESET}")
    inf(f"Site URL : {SITE_URL}")
    inf(f"Version  : {VER}")
    inf(f"Labeler  : {YELLOW}{args.labeler}{RESET}")
    if args.labeler == "model":
        inf(f"Threshold: {args.threshold or CFG.get('model_threshold', 0.55)}")
    if args.labeler == "capsolver-full" and not CAP_KEY:
        err("capsolver_key is empty in config.json — capsolver-full won't work!")
        sys.exit(1)
    n_threads = max(1, args.threads)
    n_collect = max(1, args.collect)
    inf(f"Threads  : {n_threads}  |  Collect: {n_collect}  |  Attempts: {args.attempts}")
    print()

    wins_ref   = [0]           # mutable counter shared across threads
    tokens_list = []           # collected token strings
    stop_evt   = threading.Event()
    t0         = time.time()

    if n_threads == 1:
        # ── single-thread mode (original behaviour) ──────────────────────────
        s = new_session(proxy)
        for i in range(args.attempts):
            print(f"{BOLD}{'='*55}{RESET}")
            print(f"{BOLD}Attempt {i+1}/{args.attempts}{RESET}")
            print(f"{BOLD}{'='*55}{RESET}")
            result = solve_once(s, threshold=args.threshold,
                                verbose=not args.quiet,
                                labeler=args.labeler, proxy=proxy)
            if result:
                wins_ref[0] += 1
                ok(f"SUCCESS  [{wins_ref[0]}/{i+1}]  ({time.time()-t0:.1f}s elapsed)")
                tokens_list.append(result)
                check_token_validity(s, result)
                # --- optional auto-verify ---
                do_verify = getattr(args, 'verify', False)
                verify_url = None
                if "2captcha.com" in SITE_URL:
                    verify_url = "https://2captcha.com/api/v1/captcha-demo/recaptcha/verify"
                if do_verify and verify_url:
                    vr = s.post(verify_url,
                                json={"siteKey": SITEKEY, "answer": result},
                                headers={"Content-Type": "application/json",
                                         "Origin": SITE_URL, "Referer": SITE_URL},
                                timeout=15)
                    vj = vr.json()
                    if vj.get("success"):
                        ok(f"VERIFY OK ✔ | {json.dumps(vj)}")
                    else:
                        err(f"VERIFY FAILED | {json.dumps(vj)}")
                if wins_ref[0] >= n_collect:
                    break
            elif result is None:
                err(f"No image challenge  [{wins_ref[0]}/{i+1}]")
            else:
                err(f"No token  [{wins_ref[0]}/{i+1}]")
            print()
    else:
        # ── multi-thread mode ────────────────────────────────────────────────
        inf(f"Starting {n_threads} parallel workers for {args.attempts} attempts …")
        print()
        total_submitted = 0
        with ThreadPoolExecutor(max_workers=n_threads) as ex:
            futures = []
            for tid in range(1, args.attempts + 1):
                if stop_evt.is_set() and wins_ref[0] >= n_collect:
                    break
                futures.append(
                    ex.submit(_solve_worker, args, proxy, tid,
                              wins_ref, tokens_list, stop_evt, t0, proxies_all)
                )
                total_submitted += 1
            # Wait — cancel remaining futures once collect target is reached
            for f in as_completed(futures):
                if wins_ref[0] >= n_collect:
                    # cancel pending futures (Python 3.9+ cancel_futures in shutdown)
                    for pf in futures:
                        pf.cancel()
                    break

    elapsed = time.time() - t0
    print(f"\n{BOLD}Result: {wins_ref[0]}/{args.attempts} tokens obtained in {elapsed:.1f}s{RESET}")
    if tokens_list and args.attempts > 1:
        print(f"{BOLD}All tokens:{RESET}")
        for i, tok in enumerate(tokens_list, 1):
            print(f"  [{i}] {tok}")

if __name__ == "__main__":
    main()
