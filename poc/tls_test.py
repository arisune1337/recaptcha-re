# DECISIVE TLS test: run the EXACT same pure-request reCAPTCHA flow that soft-blocked
# under Node, but through curl_cffi impersonating Chrome (real JA3/JA4 + HTTP2 fingerprint).
# If the challenge now ADVANCES (payload image changes after replaceimage), the gate was
# the TLS/transport fingerprint -> pure-request is FEASIBLE with TLS impersonation.
import json, re, base64, hashlib
from curl_cffi import requests

SITEKEY = "6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u"
VER = "TnA7HacJFoBWt9hnlunBlYfK"
CAP = json.load(open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\capture.json"))
UA = CAP["items"][0]["headers"]["User-Agent"]
md5 = lambda b: hashlib.md5(b).hexdigest()[:8]
dejson = lambda t: json.loads(re.sub(r"^\)\]\}'\n?", "", t))

# --- minimal protobuf wire parse/encode (port of pb.js) ---
def rv(buf, p):
    shift = 0; res = 0
    while True:
        b = buf[p]; p += 1; res |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return res, p
def decode(buf):
    out = []; p = 0
    while p < len(buf):
        tag, p = rv(buf, p); fn = tag >> 3; wt = tag & 7
        if wt == 0:
            v, p = rv(buf, p); out.append([fn, 0, v])
        elif wt == 2:
            ln, p = rv(buf, p); out.append([fn, 2, buf[p:p+ln]]); p += ln
        elif wt == 5: out.append([fn, 5, buf[p:p+4]]); p += 4
        elif wt == 1: out.append([fn, 1, buf[p:p+8]]); p += 8
        else: break
    return out
def ev(n):
    o = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: o.append(b | 0x80)
        else: o.append(b); break
    return bytes(o)
def encode(fields):
    o = bytearray()
    for fn, wt, val in fields:
        o += ev((fn << 3) | wt)
        if wt == 0: o += ev(val)
        elif wt == 2: o += ev(len(val)) + val
        else: o += val
    return bytes(o)
def setf(fields, n, s):
    for f in fields:
        if f[0] == n: f[2] = s.encode("latin1")
    return fields

base = base64.b64decode(CAP["items"][0]["bodyB64"])

s = requests.Session(impersonate="chrome")
REF = f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"

# 1) anchor -> c
au = f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v={VER}&size=normal&cb=p"
html = s.get(au, headers={"User-Agent": UA}).text
c = re.search(r'value="([^"]+)"', html).group(1)
print("anchor c:", c[:24], "…")

# 2) reload — retry until multicaptcha (NEXT advances regardless of answer correctness,
#    so advancement cleanly = not soft-blocked; dynamic would confound wrong-answer w/ block)
def reload_once():
    h2 = s.get(au, headers={"User-Agent": UA}).text
    cc = re.search(r'value="([^"]+)"', h2).group(1)
    f = decode(base); setf(f, 2, cc); setf(f, 16, ""); setf(f, 6, "fi")
    rr2 = s.post(f"https://www.google.com/recaptcha/api2/reload?k={SITEKEY}",
                 data=encode(f), headers={"User-Agent": UA, "Content-Type": "application/x-protobuffer", "Referer": REF, "Origin": "https://www.google.com"})
    return dejson(rr2.text)
arr = dejson(r.text) if False else reload_once()
tries = 1
while arr[5] != "multicaptcha" and tries < 8:
    arr = reload_once(); tries += 1
typ, token, ptok = arr[5], arr[1], arr[9]
print("type:", typ, "| token:", token[:20], "…")

# 3) payload image
img0 = s.get(f"https://www.google.com/recaptcha/api2/payload?p={ptok}&k={SITEKEY}", headers={"User-Agent": UA, "Referer": REF}).content
print("payload md5:", md5(img0), len(img0), "B")

# 4) replaceimage with an arbitrary selection; multicaptcha NEXT advances regardless,
#    dynamic replaces correct tiles. Either way: does the image CHANGE (= not soft-blocked)?
ds = [[0, 1, 2]]
body = f"v={VER}&c={token}&ds={json.dumps(ds, separators=(',',':'))}"
rr = s.post(f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",
            data=body, headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", "Referer": REF, "Origin": "https://www.google.com"})
ra = dejson(rr.text)
print("replaceimage:", rr.status_code, "-> newC(", len(str(ra[1])), ") payload:", "yes" if (len(ra) > 5 and ra[5]) else "NONE")
if len(ra) > 5 and ra[5]:
    img1 = s.get(f"https://www.google.com/recaptcha/api2/payload?p={ra[5]}&k={SITEKEY}", headers={"User-Agent": UA, "Referer": REF}).content
    same = md5(img1) == md5(img0)
    print("next payload md5:", md5(img1), "=>", "SAME — soft-block (TLS not the gate)" if same else "*** CHANGED — ADVANCED! TLS impersonation lifts the soft-block -> pure-request FEASIBLE ***")
    open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\tls_next.png", "wb").write(img1)
