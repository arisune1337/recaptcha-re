const { decode, encode } = require('./pb')
const CAP = require('./capture.json')
const SITEKEY='6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u', VER='TnA7HacJFoBWt9hnlunBlYfK', UA=CAP.items[0].headers['User-Agent']
const dejson=t=>JSON.parse(t.replace(/^\)\]\}'\n?/,''))
const setF=(f,n,s)=>{const x=f.find(y=>y.field===n);if(x)x.raw=Buffer.from(s,'latin1');return f}
;(async()=>{
  const a=await(await fetch(`https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=${VER}&size=normal&cb=p`,{headers:{'User-Agent':UA}})).text()
  const c=a.match(/id="recaptcha-token"[^>]*value="([^"]+)"/)[1]
  const f=decode(Buffer.from(CAP.items[0].bodyB64,'base64'));setF(f,2,c);setF(f,16,'');setF(f,6,'fi')
  const r=await fetch(`https://www.google.com/recaptcha/api2/reload?k=${SITEKEY}`,{method:'POST',headers:{'User-Agent':UA,'Content-Type':'application/x-protobuffer',Referer:`https://www.google.com/recaptcha/api2/bframe?k=${SITEKEY}`},body:encode(f)})
  const arr=dejson(await r.text())
  console.log('type:',arr[5])
  arr.forEach((v,i)=>{ console.log(`[${i}] ${typeof v==='string'?'str('+v.length+'): '+v.slice(0,30):JSON.stringify(v)}`) })
})().catch(e=>console.log('ERR',e.message))
