# solve_hybrid.py — DECISIVE hybrid test.
#
# Reads capture_own.json (written by serve_and_capture.js: a REAL browser minted a valid
# field16 for the user's OWN reCAPTCHA v2 key on a local page). Then runs the ENTIRE solve
# pipeline PURE-HTTP (curl_cffi Chrome-TLS), seeded with that browser field16:
#     reload(seed field16) -> payload -> classify(own ONNX) -> replaceimage loop -> userverify -> siteverify
# Because the user OWNS the key+secret, siteverify is an AUTHORITATIVE accept oracle.
#
# KEY DIAGNOSTIC per round: md5(payload). If the image ADVANCES after replaceimage, HTTP
# progression works with a browser field16. If it is byte-identical => the FINDINGS.md wall
# (live per-interaction BotGuard) still stands. Verdict + all artifacts -> result.json.
import json, re, base64, hashlib, io, sys, time, traceback
import numpy as np
from PIL import Image
from curl_cffi import requests
import onnxruntime as ort

HYB   = r"C:\Users\user\Desktop\a\recaptcha-re\harness\hybrid"
CAPF  = HYB + r"\capture_own.json"
OUTF  = HYB + r"\result.json"
KEYF  = r"C:\Users\user\Desktop\a\recaptcha-re\poc\own_key.json"
MODEL = r"C:\Users\user\Desktop\a\cf-bypass\cf-bypasss\models\recaptcha_cls_effv2s_128_single.onnx"

K = json.load(open(KEYF))
SITEKEY = K["sitekey"]; SECRET = K["secret"]; DOMAIN = K["domain"]
CAP = json.load(open(CAPF))

UA  = CAP["meta"]["userAgent"]
VER = CAP.get("version") or "TnA7HacJFoBWt9hnlunBlYfK"
BFT = CAP.get("bft")
# Browser bframe Referer (carries live bft) — use verbatim for every continuation request.
REF = CAP.get("bframeUrl") or f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"
COOKIE = (CAP.get("reload") or {}).get("cookie") or (
    f"_GRECAPTCHA={CAP['grecaptcha']}" if CAP.get("grecaptcha") else None)

md5   = lambda b: hashlib.md5(b).hexdigest()[:8]
dejson = lambda t: json.loads(re.sub(r"^\)\]\}'\n?", "", t))

# class map (alphabetical == training ImageFolder order) — from solve_own.py
CLS = "bicycle bridge bus car chimney crosswalk hydrant motorcycle mountain other palm stairs tractor traffic_light".split()
MID2I = {"/m/0199g":0,"/m/0c9ph5":1,"/m/01bjv":2,"/m/0k4j":3,"/m/06bt6":4,"/m/079cl":5,"/m/014xcs":5,
         "/m/01pns0":6,"/m/04_sv":7,"/m/09d_r":8,"/m/0cdl1":10,"/m/01lynh":11,"/m/013xlm":12,"/m/015qff":13}
HUM2I = {"bike":0,"bicycle":0,"bridge":1,"bus":2,"car":3,"taxi":3,"chimney":4,"pedestrian crossing":5,
         "crosswalk":5,"fire hydrant":6,"hydrant":6,"motorcycle":7,"mountain":8,"palm tree":10,
         "stairs":11,"tractor":12,"traffic light":13}

ort_sess = ort.InferenceSession(MODEL, providers=["CPUExecutionProvider"]); IN = ort_sess.get_inputs()[0].name

def classify(pil, ci):
    a = np.asarray(pil.convert("RGB").resize((128,128)), dtype=np.float32)/255.0
    a = np.transpose(a,(2,0,1))[None,...]
    return float(ort_sess.run(None,{IN:a})[0][0][ci])

def siteverify(token):
    try:
        r = requests.post("https://www.google.com/recaptcha/api/siteverify",
                          data={"secret":SECRET,"response":token}, timeout=25)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def form_headers():
    h = {"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8",
         "Referer":REF,"Origin":"https://www.google.com"}
    if COOKIE: h["Cookie"] = COOKIE
    return h

def get_payload(s, tk):
    h = {"User-Agent":UA,"Referer":REF}
    if COOKIE: h["Cookie"] = COOKIE
    r = s.get(f"https://www.google.com/recaptcha/api2/payload?p={tk}&k={SITEKEY}", headers=h, timeout=25)
    ct = r.headers.get("content-type","")
    return r.content if (r.status_code==200 and "image" in ct) else None

def parse_target(arr):
    """Return (ci, rows, cols, human, mid) for the FIRST image challenge, or None."""
    typ = arr[5] if len(arr)>5 else None
    pm  = arr[4] if len(arr)>4 else None
    if not typ or pm is None: return None
    try:
        if typ == "dynamic":
            t = pm[1]; mid=t[0]; rows,cols=t[2],t[3]; human=str(t[6]) if len(t)>6 else ""
        else:  # multicaptcha / default: first sub descriptor
            sub = pm[5][0][0]; mid=sub[0]; rows,cols=sub[3],sub[4]; human=""
    except Exception:
        return None
    ci = MID2I.get(mid, HUM2I.get(human.lower()) if human else None)
    return ci, rows, cols, human, mid

def solve_from_reload(s, arr, tag, steps, thr=0.5):
    """Given a reload response array (a fresh challenge), solve it PURE-HTTP. Records into steps."""
    typ = arr[5] if len(arr)>5 else None
    c   = arr[1]
    ptok= arr[9] if len(arr)>9 else None
    rec = {"tag":tag, "reloadType":typ, "reloadC_len":len(str(c)) if c else 0}
    steps.append(rec)

    # AUTO-PASS: no challenge type, token sitting at arr[1]
    if not typ:
        rec["autopass"] = True
        if c and isinstance(c,str) and len(c) > 200:
            sv = siteverify(c)
            rec["siteverify"] = sv
            rec["token"] = c[:40]+"..."
            return ("AUTOPASS_TOKEN", c, sv)
        return ("AUTOPASS_NO_TOKEN", None, None)

    tgt = parse_target(arr)
    rec["target"] = None
    if tgt is None:
        rec["note"] = "could not parse target"
        return ("NO_TARGET", None, None)
    ci, rows, cols, human, mid = tgt
    rec["target"] = {"class": CLS[ci] if ci is not None else None, "human":human, "mid":mid, "grid":f"{rows}x{cols}"}
    if not ptok:
        rec["note"] = "no payload token"; return ("NO_PAYLOAD", None, None)
    if ci is None:
        rec["note"] = f"class not supported by model (mid={mid}, human={human})"

    img = get_payload(s, ptok)
    if img is None:
        rec["note"] = "initial payload fetch failed"; return ("PAYLOAD_FAIL", None, None)

    # ---- FREEZE PROBE (removes the answer-correctness confound) ----
    # Submit DELIBERATELY DIFFERENT tile sets over HTTP. If the payload image bytes NEVER
    # change in response to ANY input => image is frozen regardless of answer => soft-block
    # (the live-BotGuard wall). If ANY input yields a different image => progression is
    # responsive over HTTP and a null token is only a wrong-answer problem, not a wall.
    ntiles = rows*cols
    probe_sets = [[0], [ntiles-1], list(range(ntiles//2)), list(range(ntiles)), []]
    init_md = md5(img)
    probe = {"initial_img_md5": init_md, "submissions": [], "distinct_images": 1, "responsive": False}
    cprobe = c; pimg = img; seen = {init_md}
    for ds in probe_sets:
        body = f"v={VER}&c={cprobe}&ds={json.dumps([ds],separators=(',',':'))}"
        try:
            ra = dejson(s.post(f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",
                               data=body, headers=form_headers(), timeout=25).text)
        except Exception as e:
            probe["submissions"].append({"ds":ds,"err":str(e)}); break
        cprobe = ra[1]
        newmd = None
        if len(ra) > 5 and ra[5]:
            ni = get_payload(s, ra[5])
            if ni is not None: pimg = ni; newmd = md5(ni)
        probe["submissions"].append({"ds":ds,"got_new_token":bool(len(ra)>5 and ra[5]),"img_md5":newmd})
        if newmd: seen.add(newmd)
        print(f"  [{tag}] freeze-probe ds={ds} -> new_token={bool(len(ra)>5 and ra[5])} img={newmd}")
    probe["distinct_images"] = len(seen)
    probe["responsive"] = len(seen) > 1
    rec["freeze_probe"] = probe
    print(f"  [{tag}] FREEZE PROBE: distinct_images={len(seen)} responsive={probe['responsive']}")
    # continue the model-guided attempt from the probed token/image
    c = cprobe; img = pimg

    rounds = []
    prev_md = None
    advanced_any = probe["responsive"]
    for rnd in range(6):
        cur_md = md5(img)
        pil = Image.open(io.BytesIO(img)); W,H = pil.size; cw,ch = W//cols, H//rows
        if ci is not None:
            confs = [classify(pil.crop(((i%cols)*cw,(i//cols)*ch,(i%cols)*cw+cw,(i//cols)*ch+ch)), ci)
                     for i in range(rows*cols)]
            sel = sorted([i for i,v in enumerate(confs) if v>thr])
            mx = max(confs) if confs else 0.0
        else:
            confs=[]; sel=[]; mx=0.0
        advanced = (prev_md is not None and cur_md != prev_md)
        if advanced: advanced_any = True
        rounds.append({"round":rnd,"img_md5":cur_md,"sel":sel,"max_conf":round(mx,3),
                       "advanced_from_prev": advanced})
        print(f"  [{tag}] round {rnd}: img={cur_md} sel={sel} max={mx:.2f} advanced={advanced}")
        if not sel:
            break
        prev_md = cur_md
        body = f"v={VER}&c={c}&ds={json.dumps([sel],separators=(',',':'))}"
        try:
            ra = dejson(s.post(f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",
                               data=body, headers=form_headers(), timeout=25).text)
        except Exception as e:
            rounds[-1]["replaceimage_err"] = str(e); break
        c = ra[1]
        if len(ra) > 5 and ra[5]:
            ni = get_payload(s, ra[5])
            if ni is None:
                rounds[-1]["note"]="payload refetch failed"; break
            img = ni
        else:
            rounds[-1]["note"]="no new payload token (challenge may be complete)"; break
    rec["rounds"] = rounds
    rec["image_advanced_any_round"] = advanced_any

    # userverify
    try:
        uv = dejson(s.post(f"https://www.google.com/recaptcha/api2/userverify?k={SITEKEY}",
                           data=f"v={VER}&c={c}", headers=form_headers(), timeout=25).text)
    except Exception as e:
        rec["userverify_err"] = str(e); return ("USERVERIFY_ERR", None, None)
    tok = uv[1] if len(uv)>1 else None
    rec["userverify_raw"] = json.dumps(uv)[:120]
    rec["userverify_token"] = (tok[:40]+"...") if tok else None
    print(f"  [{tag}] userverify: {json.dumps(uv)[:90]} => {'TOKEN' if tok else 'NULL'}")
    if tok:
        sv = siteverify(tok)
        rec["siteverify"] = sv
        print(f"  [{tag}] *** siteverify: {sv} ***")
        return ("TOKEN", tok, sv)
    return ("NULL_TOKEN", None, None)

def main():
    result = {"meta":{"ranAt":time.strftime("%Y-%m-%dT%H:%M:%S"),
                      "captureAgeMs": int(time.time()*1000) - CAP["meta"].get("capturedAtMs",0),
                      "sitekey":SITEKEY,"domain":DOMAIN,"version":VER,
                      "bframeReferer":REF[:120],"cookiePresent":bool(COOKIE),
                      "grecaptchaPresent":bool(CAP.get("grecaptcha"))},
              "steps":[], "verdict":None}
    steps = result["steps"]
    s = requests.Session(impersonate="chrome")

    rel = CAP.get("reload") or {}
    if not rel.get("bodyB64"):
        result["verdict"] = "NO_FIELD16_CAPTURED — browser did not produce a reload with field16; cannot run hybrid test."
        json.dump(result, open(OUTF,"w"), indent=1); print(result["verdict"]); return
    result["meta"]["field16_len"] = rel.get("field16_len")
    result["meta"]["reload_body_len"] = rel.get("bodyLen")

    # ---------- PRIMARY: HTTP reload SEEDED with browser field16 -> full solve ----------
    body = base64.b64decode(rel["bodyB64"])
    rh = {"User-Agent":UA,"Content-Type": rel.get("contentType") or "application/x-protobuffer",
          "Referer": REF, "Origin":"https://www.google.com"}
    if COOKIE: rh["Cookie"] = COOKIE
    print("=== PRIMARY: field16-seeded HTTP reload -> solve ===")
    print(f"    field16_len={rel.get('field16_len')} body_len={len(body)} ver={VER} bft={'yes' if BFT else 'no'} cookie={'yes' if COOKIE else 'no'}")
    try:
        rr = s.post(rel["url"], data=body, headers=rh, timeout=25)
        arr = dejson(rr.text)
        print(f"    reload HTTP {rr.status_code} arrLen={len(arr)} type={arr[5] if len(arr)>5 else None} token1={'yes' if arr[1] else 'null'}")
        outcome, tok, sv = solve_from_reload(s, arr, "seeded", steps)
        result["primary_outcome"] = outcome
    except Exception as e:
        result["primary_outcome"] = "RELOAD_ERR"
        result["primary_error"] = traceback.format_exc()
        print("    PRIMARY reload error:", e)
        outcome = "RELOAD_ERR"; sv = None

    # ---------- DIAGNOSTIC: continue the browser's OWN issued challenge over HTTP ----------
    # (Uses the reload RESPONSE the browser already got — the "handoff" continuation cell.)
    br = rel.get("responseB64")
    if br and result.get("primary_outcome") not in ("TOKEN","AUTOPASS_TOKEN"):
        try:
            barr = dejson(base64.b64decode(br).decode("utf-8","replace"))
            print("=== DIAGNOSTIC: continue browser's OWN issued challenge over HTTP ===")
            outcome2, tok2, sv2 = solve_from_reload(s, barr, "browser_continue", steps)
            result["diagnostic_outcome"] = outcome2
        except Exception as e:
            result["diagnostic_outcome"] = "ERR"
            result["diagnostic_error"] = str(e)

    # ---------- VERDICT ----------
    def sv_ok(step):
        sv = step.get("siteverify") or {}
        return sv.get("success") is True
    any_token = any(st.get("userverify_token") or st.get("autopass") for st in steps)
    any_sv    = any(sv_ok(st) for st in steps)
    any_adv   = any(st.get("image_advanced_any_round") for st in steps)
    any_responsive = any((st.get("freeze_probe") or {}).get("responsive") for st in steps)
    seeded    = next((st for st in steps if st.get("tag")=="seeded"), {})

    if any_sv:
        verdict = "FULL SUCCESS — pure-HTTP solve with browser field16 yields a siteverify-accepted token. Hybrid is shippable."
    elif any_token:
        verdict = ("PROTOCOL PASSES but token rejected — userverify returned a NON-NULL token over HTTP, "
                   "but siteverify success=false (answer/classifier wrong or low-trust token). Progression is NOT the wall.")
    elif any_responsive or any_adv:
        verdict = ("PARTIAL — the payload image RESPONDED to HTTP input (freeze-probe saw distinct images), so progression "
                   "is NOT frozen; userverify token was null (answer wrong). Boundary is challenge-completion, not reload.")
    else:
        verdict = ("SOFT-BLOCK — field16-seeded reload issues a real challenge, but the payload image is FROZEN over HTTP: "
                   "it stays byte-identical regardless of which tiles are submitted (freeze-probe), and userverify is null. "
                   "Confirms the live per-interaction BotGuard wall; browser-mints-field16 hybrid is NOT shippable as-is.")
    result["verdict"] = verdict
    result["signals"] = {"any_siteverify_success":any_sv,"any_userverify_token":any_token,
                         "any_image_advanced":any_adv,"any_freeze_probe_responsive":any_responsive,
                         "seeded_reload_type": seeded.get("reloadType"),
                         "seeded_target": seeded.get("target")}
    json.dump(result, open(OUTF,"w"), indent=1)
    print("\n================ VERDICT ================")
    print(verdict)
    print("saved", OUTF)

if __name__ == "__main__":
    main()
