# Final cell of the trust matrix: browser-minted (field16-backed) token  +  curl_cffi
# Chrome-TLS continuation.  capture_handoff.js must have just written handoff.json.
#   python handoff_curl.py get          -> curl_cffi fetch payload(token), save image
#   python handoff_curl.py submit 1,2,4 -> curl_cffi replaceimage w/ human-correct tiles
# CHANGED => browser-token + Chrome-TLS is enough (harvest-token architecture viable).
# SAME    => the browser's per-step live BotGuard is required => pure-request infeasible.
import json, re, hashlib, sys
from curl_cffi import requests
SITEKEY="6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u"; VER="TnA7HacJFoBWt9hnlunBlYfK"
H=json.load(open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\handoff.json")); UA=H.get("userAgent") or "Mozilla/5.0"
# use the EXACT browser Referer (carries the live bft) instead of a bft-less one
REF=H.get("referer") or f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"
print("Referer (bft):", REF[:80])
md5=lambda b:hashlib.md5(b).hexdigest()[:8]; dejson=lambda t:json.loads(re.sub(r"^\)\]\}'\n?","",t))
COOK=H.get("cookieHeader","")
hdr={"User-Agent":UA,"Referer":REF}
if COOK: hdr["Cookie"]=COOK
fh={"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8","Referer":REF,"Origin":"https://www.google.com"}
if COOK: fh["Cookie"]=COOK
s=requests.Session(impersonate="chrome")
def getP(tk):
    r=s.get(f"https://www.google.com/recaptcha/api2/payload?p={tk}&k={SITEKEY}",headers=hdr); return r.content if r.status_code==200 else None
mode=sys.argv[1]
if mode=="get":
    img=getP(H["payloadToken"])
    if not img: print("payload fetch FAILED"); sys.exit()
    open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\handoff_challenge.png","wb").write(img)
    H["md5"]=md5(img); json.dump(H,open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\handoff.json","w"))
    print(f"type={H['type']} pmeta={json.dumps(H['pmeta'])[:90]} img_md5={md5(img)} saved handoff_challenge.png")
elif mode=="submit":
    tiles=[int(x) for x in sys.argv[2].split(",")]
    body=f"v={VER}&c={H['challengeToken']}&ds={json.dumps([tiles],separators=(',',':'))}"
    ra=dejson(s.post(f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",data=body,headers=fh).text)
    print("replaceimage newC", len(str(ra[1])), "payload", "yes" if len(ra)>5 and ra[5] else "NO")
    if len(ra)>5 and ra[5]:
        ni=getP(ra[5]); print("orig",H.get("md5"),"-> new",md5(ni),"=>","*** CHANGED — browser-token + Chrome-TLS ADVANCES! harvest-token architecture VIABLE ***" if md5(ni)!=H.get("md5") else "SAME — live per-step BotGuard required => pure-request INFEASIBLE")
    uv=dejson(s.post(f"https://www.google.com/recaptcha/api2/userverify?k={SITEKEY}",data=f"v={VER}&c={ra[1]}",headers=fh).text)
    print("userverify:", json.dumps(uv)[:80])
