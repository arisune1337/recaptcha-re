# DECISIVE end-to-end: pure-request reCAPTCHA v2 solve over Chrome-impersonated TLS
# (curl_cffi) + our own ONNX classifier (onnxruntime). Solves a DYNAMIC 3x3 correctly,
# loops replaceimage until no target tiles remain, then userverify. If the payload image
# ADVANCES on a correct click AND userverify returns a NON-NULL token -> pure-request works.
import json, re, base64, hashlib, io, sys
import numpy as np
from PIL import Image
from curl_cffi import requests
import onnxruntime as ort

SITEKEY = "6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u"
VER = "TnA7HacJFoBWt9hnlunBlYfK"
CAP = json.load(open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\capture.json"))
UA = CAP["items"][0]["headers"]["User-Agent"]
MODEL = r"C:\Users\user\Desktop\a\cf-bypass\cf-bypasss\models\recaptcha_cls_effv2s_128_single.onnx"
md5 = lambda b: hashlib.md5(b).hexdigest()[:8]
dejson = lambda t: json.loads(re.sub(r"^\)\]\}'\n?", "", t))
REF = f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"

# class map (alphabetical, == training ImageFolder order)
CLS = "bicycle bridge bus car chimney crosswalk hydrant motorcycle mountain other palm stairs tractor traffic_light".split()
MID2I = {"/m/0199g":0,"/m/0c9ph5":1,"/m/01bjv":2,"/m/0k4j":3,"/m/06bt6":4,"/m/079cl":5,"/m/01pns0":6,"/m/04_sv":7,"/m/014j1m":8,"/m/0cdl1":10,"/m/01lynh":11,"/m/013xlm":12,"/m/015qff":13}
HUM2I = {"bike":0,"bicycle":0,"bridge":1,"bus":2,"car":3,"taxi":3,"chimney":4,"pedestrian crossing":5,"crosswalk":5,"fire hydrant":6,"hydrant":6,"motorcycle":7,"mountain":8,"palm tree":10,"stairs":11,"tractor":12,"traffic light":13}

sess = ort.InferenceSession(MODEL, providers=["CPUExecutionProvider"])
IN = sess.get_inputs()[0].name

# --- protobuf (port of pb.js) ---
def rv(b,p):
    sh=0;r=0
    while True:
        x=b[p];p+=1;r|=(x&0x7f)<<sh
        if not (x&0x80):break
        sh+=7
    return r,p
def decode(b):
    o=[];p=0
    while p<len(b):
        t,p=rv(b,p);fn=t>>3;wt=t&7
        if wt==0: v,p=rv(b,p);o.append([fn,0,v])
        elif wt==2: ln,p=rv(b,p);o.append([fn,2,b[p:p+ln]]);p+=ln
        elif wt==5: o.append([fn,5,b[p:p+4]]);p+=4
        elif wt==1: o.append([fn,1,b[p:p+8]]);p+=8
        else: break
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
        if f[0]==n: f[2]=s.encode("latin1")
    return fs
BASE=base64.b64decode(CAP["items"][0]["bodyB64"])

def classify_tile(pil):
    a=np.asarray(pil.convert("RGB").resize((128,128)),dtype=np.float32)/255.0
    a=np.transpose(a,(2,0,1))[None,...]
    out=sess.run(None,{IN:a})[0][0]
    return out

def solve_once(s):
    au=f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v={VER}&size=normal&cb=p"
    def reload_once():
        h=s.get(au,headers={"User-Agent":UA}).text
        cc=re.search(r'value="([^"]+)"',h).group(1)
        f=decode(BASE);setf(f,2,cc);setf(f,16,"");setf(f,6,"fi")
        return dejson(s.post(f"https://www.google.com/recaptcha/api2/reload?k={SITEKEY}",data=encode(f),headers={"User-Agent":UA,"Content-Type":"application/x-protobuffer","Referer":REF,"Origin":"https://www.google.com"}).text)
    arr=reload_once();t=1
    while arr[5]!="dynamic" and t<8: arr=reload_once();t+=1
    if arr[5]!="dynamic": print("no dynamic challenge");return None
    pm=arr[4][1]; mid=pm[0]; rows,cols=pm[2],pm[3]; human=str(pm[6]) if len(pm)>6 else ""
    ci=MID2I.get(mid, HUM2I.get(human.lower()))
    print(f"target: {human}/{mid} -> class {CLS[ci] if ci is not None else '??'} ({rows}x{cols})")
    if ci is None: return None
    token=arr[1]; ptok=arr[9]
    def get_payload(tk):
        r=s.get(f"https://www.google.com/recaptcha/api2/payload?p={tk}&k={SITEKEY}",headers={"User-Agent":UA,"Referer":REF})
        return r.content if r.status_code==200 else None
    img=get_payload(ptok)
    c=token; prev_md=None; rounds=0
    while rounds<12:
        pil=Image.open(io.BytesIO(img)); W,H=pil.size; cw,ch=W//cols,H//rows
        confs=[]
        for i in range(rows*cols):
            r_,c_=divmod(i,cols); tile=pil.crop((c_*cw,r_*ch,c_*cw+cw,r_*ch+ch))
            confs.append(classify_tile(tile)[ci])
        sel=sorted([i for i,v in enumerate(confs) if v>0.55])
        cur_md=md5(img)
        print(f"  round {rounds}: img={cur_md} sel={sel} max={max(confs):.2f}")
        if cur_md==prev_md:
            print("  image unchanged after click -> soft-block OR wrong answer");
        if not sel:
            break
        prev_md=cur_md
        body=f"v={VER}&c={c}&ds={json.dumps([sel],separators=(',',':'))}"
        ra=dejson(s.post(f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",data=body,headers={"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8","Referer":REF,"Origin":"https://www.google.com"}).text)
        c=ra[1]
        if len(ra)>5 and ra[5]:
            ni=get_payload(ra[5])
            if ni is None: print("  payload fetch fail");break
            img=ni
        else:
            print("  no new payload");break
        rounds+=1
    uv=s.post(f"https://www.google.com/recaptcha/api2/userverify?k={SITEKEY}",data=f"v={VER}&c={c}",headers={"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8","Referer":REF,"Origin":"https://www.google.com"}).text
    ua=dejson(uv)
    tok=ua[1] if len(ua)>1 else None
    print("  userverify:", json.dumps(ua)[:90], "=>", "*** TOKEN! FEASIBLE ***" if tok else "null token")
    return bool(tok)

s=requests.Session(impersonate="chrome")
for attempt in range(int(sys.argv[1]) if len(sys.argv)>1 else 3):
    print(f"=== attempt {attempt+1} ===")
    if solve_once(s): break
