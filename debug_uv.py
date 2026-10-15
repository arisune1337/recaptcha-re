#!/usr/bin/env python3
"""Debug userverify response to understand why tokens are rejected"""
import sys, json, re, base64, time, hashlib, io
from urllib.parse import quote as _urlquote
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import curl_cffi.requests as cffi_requests

# Load config
with open(ROOT / "config.json") as f:
    CFG = json.load(f)

SITEKEY = CFG["site_key"]
SITE_URL = CFG["site_url"]
VER = CFG["version"]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")

def make_co(site_url):
    from urllib.parse import urlparse
    p = urlparse(site_url)
    std = {"https": 443, "http": 80}.get(p.scheme, 443)
    explicit = p.port
    if explicit and explicit != std:
        origin = f"{p.scheme}://{p.hostname}:{explicit}"
    else:
        origin = f"{p.scheme}://{p.hostname}"
    return base64.b64encode(origin.encode()).decode().rstrip("=")

CO = make_co(SITE_URL)
REF = f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"

# Protobuf helpers
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
        if f[0] == n: f[2] = s.encode('latin1')
    return fs

def _dejson(t):
    # Google wraps responses in )]}'
    if t.startswith(")]}'"):
        t = t[4:]
    # Also handle )]}'\n variant
    if t.startswith(")]}'\n"):
        t = t[5:]
    t = t.strip()
    if not t:
        raise ValueError("Empty response")
    return json.loads(t)

RELOAD_TEMPLATE = base64.b64decode((ROOT / "reload_template.b64").read_text().strip())

def get_botguard_via_node():
    import subprocess
    bg_js = ROOT / "solve_bg.js"
    anchor_url = f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={SITEKEY}&co={CO}&hl=en&v={VER}&size=normal&cb=p"
    try:
        result = subprocess.run(
            ["node", str(bg_js), anchor_url],
            capture_output=True, text=True, timeout=45,
        )
        out = result.stdout.strip()
        if not out:
            print(f"  solve_bg.js no output: {result.stderr[:200]}")
            return ""
        data = json.loads(out)
        bg = data.get("bg", "")
        if bg:
            print(f"  BotGuard token: {len(bg)} chars")
        else:
            print(f"  No bg token in response")
        return bg
    except Exception as e:
        print(f"  BotGuard error: {e}")
        return ""

# Main flow
s = cffi_requests.Session(impersonate="chrome")

# 1. Get anchor
print("1. Getting anchor...")
h = s.get(f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={SITEKEY}&co={CO}&hl=en&v={VER}&size=normal&cb=p",
          headers={"User-Agent": UA}, timeout=25).text
m = re.search(r'value="([^"]+)"', h)
if not m:
    print("  No anchor token!")
    sys.exit(1)
c_token = m.group(1)
print(f"  Anchor token: {c_token[:40]}...")

# 2. Get BotGuard
print("\n2. Getting BotGuard token...")
bg = get_botguard_via_node()

# 3. Get challenge
print("\n3. Getting challenge...")
for attempt in range(8):
    f = decode(RELOAD_TEMPLATE)
    setf(f, 2, c_token)
    setf(f, 14, SITEKEY)
    setf(f, 16, bg or "")
    setf(f, 6, "fi")

    r = s.post(
        f"https://www.google.com/recaptcha/api2/reload?k={SITEKEY}",
        data=encode(f),
        headers={"User-Agent": UA, "Content-Type": "application/x-protobuffer",
                 "Referer": REF, "Origin": "https://www.google.com"},
        timeout=25
    )
    if r.status_code != 200:
        print(f"  HTTP {r.status_code}")
        sys.exit(1)
    arr = _dejson(r.text)
    if len(arr) >= 6 and arr[4] and arr[5] in ("dynamic", "multicaptcha", "tileselect"):
        break
    print(f"  Non-image challenge: {arr[5] if len(arr) > 5 else '?'}, retry {attempt+1}/8")
    # Get new anchor token
    h = s.get(f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={SITEKEY}&co={CO}&hl=en&v={VER}&size=normal&cb=p",
              headers={"User-Agent": UA}, timeout=25).text
    m = re.search(r'value="([^"]+)"', h)
    if m: c_token = m.group(1)

# Parse challenge
pm = arr[4]
typ = arr[5]
if typ == "dynamic":
    t = pm[1]
    mid, rows, cols = t[0], t[2], t[3]
    human = str(t[6]) if len(t) > 6 else ""
    print(f"  Challenge: mid={mid}, rows={rows}, cols={cols}, human={human!r}")

c_tok = arr[1]
ptok = arr[9] if len(arr) > 9 else None
print(f"  c_tok: {c_tok[:40]}...")
print(f"  ptok: {ptok[:40] if ptok else None}...")

# 4. Fetch image
img = s.get(f"https://www.google.com/recaptcha/api2/payload?p={ptok}&k={SITEKEY}",
            headers={"User-Agent": UA, "Referer": REF}, timeout=25).content
print(f"  Image: {len(img)} bytes")

# 5. Click simulation with multiple tiles
print("\n4. Simulating clicks (tiles 0, 2, 7)...")
t_start = int(time.time() * 1000)

tiles_to_click = [0, 2, 7]
for tile_idx in tiles_to_click:
    now_ms = int(time.time() * 1000)
    elapsed_ms = now_ms - t_start

    tile_body = f"v={VER}&c={c_tok}&ds=%5B{tile_idx}%5D&t={elapsed_ms}&ct={elapsed_ms}"
    ri_resp = s.post(
        f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",
        data=tile_body,
        headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                 "Referer": REF, "Origin": "https://www.google.com"},
        timeout=25
    )
    print(f"  replaceimage[{tile_idx}] HTTP {ri_resp.status_code}")
    tile_ra = _dejson(ri_resp.text)
    c_tok = tile_ra[1] if len(tile_ra) > 1 else c_tok
    time.sleep(0.2)

# 6. Userverify
print("\n5. Calling userverify...")
all_selected_tiles = tiles_to_click  # Use the tiles we clicked
response_json = json.dumps({"response": all_selected_tiles, "e": ""}, separators=(',', ':'))
response_b64 = base64.urlsafe_b64encode(response_json.encode()).decode().rstrip('=')
_pm_hdr = b'\xe7\x56\xc6\xc2\xc6\xe7\x56\xc6\xc2'
_pm_json = b'[null,null,[null,null,null,[5,1.5,0.0015,3],[1,0.4,0.00005,1],0,0,0]]'
pm_b64 = base64.urlsafe_b64encode(_pm_hdr + _pm_json).decode().rstrip('=')

uv_body = f"v={VER}&c={c_tok}&response={_urlquote(response_b64, safe='')}&t={elapsed_ms}&ct={elapsed_ms}"
if bg:
    uv_body += f"&oc={bg}"
uv_body += f"&pm={pm_b64}"

print(f"  uv_body length: {len(uv_body)}")
print(f"  response field: {response_json}")

uv_resp = s.post(
    f"https://www.google.com/recaptcha/api2/userverify?k={SITEKEY}",
    data=uv_body,
    headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
             "Referer": REF, "Origin": "https://www.google.com"},
    timeout=25
).text

print(f"\n6. Userverify response:")
print(f"  Raw (first 200 chars): {uv_resp[:200]}")

try:
    ua_arr = _dejson(uv_resp)
    print(f"  ua_arr length: {len(ua_arr)}")
    for i, v in enumerate(ua_arr):
        if isinstance(v, str) and len(v) > 80:
            print(f"    ua_arr[{i}]: str[len={len(v)}]")
        elif isinstance(v, list):
            print(f"    ua_arr[{i}]: list[len={len(v)}]")
            if i == 7 and len(v) > 0:
                # Print ua_arr[7] contents - diagnostic data
                print(f"      ua_arr[7] contents: {v[:5]}...")
        else:
            print(f"    ua_arr[{i}]: {v!r}")

    token = ua_arr[1] if len(ua_arr) > 1 else None
    if token:
        print(f"\n7. Token obtained: {token[:80]}...")

        # Verify with siteverify
        print("\n8. Verifying with siteverify API...")
        sv_resp = s.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": CFG.get("secret_key", ""), "response": token},
            timeout=15
        ).json()
        print(f"  siteverify response: {json.dumps(sv_resp, indent=2)}")
    else:
        print(f"\n7. No token in response!")
except Exception as e:
    print(f"  Error parsing: {e}")
    print(f"  Raw response: {repr(uv_resp[:500])}")
