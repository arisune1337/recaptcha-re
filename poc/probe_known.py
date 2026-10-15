# Resolve the soft-block-vs-wrong-answer confound with a HUMAN-known answer.
#   python probe_known.py get          -> fetch a dynamic challenge over Chrome TLS,
#                                          save known_challenge.png + known.json
#   python probe_known.py submit 1,4,7 -> submit those EXACT tiles, report if image changed
# If a human-correct selection still leaves the image byte-identical -> soft-block confirmed
# (TLS impersonation does not lift it). If it changes -> the model was just wrong.
import json, re, base64, hashlib, sys
from curl_cffi import requests

SITEKEY="6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u"; VER="TnA7HacJFoBWt9hnlunBlYfK"
CAP=json.load(open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\capture.json")); UA=CAP["items"][0]["headers"]["User-Agent"]
REF=f"https://www.google.com/recaptcha/api2/bframe?k={SITEKEY}"
md5=lambda b:hashlib.md5(b).hexdigest()[:8]; dejson=lambda t:json.loads(re.sub(r"^\)\]\}'\n?","",t))
def rv(b,p):
    sh=0;r=0
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
def getP(s,tk):
    r=s.get(f"https://www.google.com/recaptcha/api2/payload?p={tk}&k={SITEKEY}",headers={"User-Agent":UA,"Referer":REF})
    return r.content if r.status_code==200 else None

mode=sys.argv[1]
s=requests.Session(impersonate="chrome")
if mode=="get":
    au=f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v={VER}&size=normal&cb=p"
    def reload_once():
        h=s.get(au,headers={"User-Agent":UA}).text;cc=re.search(r'value="([^"]+)"',h).group(1)
        f=decode(BASE);setf(f,2,cc);setf(f,16,"");setf(f,6,"fi")
        return dejson(s.post(f"https://www.google.com/recaptcha/api2/reload?k={SITEKEY}",data=encode(f),headers={"User-Agent":UA,"Content-Type":"application/x-protobuffer","Referer":REF,"Origin":"https://www.google.com"}).text)
    arr=reload_once();t=1
    while arr[5]!="dynamic" and t<8:arr=reload_once();t+=1
    pm=arr[4][1];img=getP(s,arr[9])
    open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\known_challenge.png","wb").write(img)
    json.dump({"c":arr[1],"token":arr[1],"target":str(pm[6]) if len(pm)>6 else pm[0],"grid":[pm[2],pm[3]],"md5":md5(img)},open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\known.json","w"))
    print(f"type={arr[5]} target={pm[6] if len(pm)>6 else pm[0]} grid={pm[2]}x{pm[3]} img_md5={md5(img)} saved known_challenge.png")
    print("Tiles index 0-8 row-major (top-left=0). View image, then: python probe_known.py submit a,b,c")
elif mode=="submit":
    K=json.load(open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\known.json"))
    tiles=[int(x) for x in sys.argv[2].split(",")] if len(sys.argv)>2 and sys.argv[2] else []
    body=f"v={VER}&c={K['c']}&ds={json.dumps([tiles],separators=(',',':'))}"
    ra=dejson(s.post(f"https://www.google.com/recaptcha/api2/replaceimage?k={SITEKEY}",data=body,headers={"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8","Referer":REF,"Origin":"https://www.google.com"}).text)
    print("replaceimage status ok, newC len", len(str(ra[1])), "payload", "yes" if len(ra)>5 and ra[5] else "NO")
    if len(ra)>5 and ra[5]:
        ni=getP(s,ra[5])
        print("orig md5", K["md5"], "-> new md5", md5(ni), "=>", "*** CHANGED — correct click advanced! TLS+answer WORKS ***" if md5(ni)!=K["md5"] else "SAME — SOFT-BLOCK CONFIRMED (TLS insufficient)")
        open(r"C:\Users\user\Desktop\a\recaptcha-re\poc\known_after.png","wb").write(ni)
    uv=dejson(s.post(f"https://www.google.com/recaptcha/api2/userverify?k={SITEKEY}",data=f"v={VER}&c={ra[1]}",headers={"User-Agent":UA,"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8","Referer":REF,"Origin":"https://www.google.com"}).text)
    print("userverify:", json.dumps(uv)[:80])
