// DOM-surface probe: load recaptcha__en.js in PAGE mode, call anchor.Main.init(cfg),
// spawn the loopback worker, and RECORD every document/window/element property the
// init->BotGuard-attestation path dereferences. Flags noop-served vs real-value reads.
'use strict'
const fs = require('fs'); const vm = require('vm')
const ENJS = 'C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js'
const CODE = fs.readFileSync(ENJS, 'utf8')
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0'
process.on('unhandledRejection', () => {})

// ---- recorders -------------------------------------------------------------
const REC = {}                          // label -> Map(key->count)
function rec(label, key) { const m = REC[label] || (REC[label] = new Map()); m.set(key, (m.get(key) || 0) + 1) }
const DOC_KEYS = new Map(), ELEM_KEYS = new Map(), WIN_MISS = new Set(), WIN_HIT = new Map()
const WK_MISS = new Set(), WK_HIT = new Map(), WK_NAV = new Map(), WK_PERF = new Map()
const FRAMES = []   // {dir, kind, size}
function frameInfo(data){ try{ if(typeof data==='string') return {kind:'str', size:data.length, head:data.slice(0,40)}; if(Array.isArray(data)) return {kind:'arr['+data.length+']', size:JSON.stringify(data).length, head:String(data[0]).slice(0,30)}; return {kind:typeof data, size:0} }catch(e){return {kind:'?',size:0}} }
const HOT = ['canvas','getContext','toDataURL','getImageData','webgl','getParameter','toBlob','OffscreenCanvas','captureStream','AudioContext','OfflineAudioContext']
const HOTHITS = []
function hotCheck(k){ if (HOT.includes(k)) HOTHITS.push(k) }

const INTRINSICS = ['Object','Array','Function','String','Number','Boolean','Symbol','BigInt','Math','JSON','Date','RegExp','Error','TypeError','RangeError','EvalError','ReferenceError','SyntaxError','URIError','Reflect','Proxy','Promise','Map','Set','WeakMap','WeakSet','WeakRef','ArrayBuffer','SharedArrayBuffer','DataView','Uint8Array','Int8Array','Uint8ClampedArray','Uint16Array','Int16Array','Uint32Array','Int32Array','Float32Array','Float64Array','BigInt64Array','BigUint64Array','parseInt','parseFloat','decodeURIComponent','encodeURIComponent','decodeURI','encodeURI','escape','unescape','isNaN','isFinite','Intl','structuredClone','Infinity','NaN','undefined','globalThis']

// loopback MessagePort (by reference)
function makePort(){const p={__isPort:true,_peer:null,_started:false,_q:[],_on:null,_lis:[],get onmessage(){return this._on},set onmessage(f){this._on=f;this._started=true;this._flush()},addEventListener(t,f){if(t==='message'){this._lis.push(f);this._started=true;this._flush()}},removeEventListener(t,f){this._lis=this._lis.filter(x=>x!==f)},start(){this._started=true;this._flush()},close(){this._closed=true},dispatchEvent(){return true},postMessage(data,transfer){const ports=(transfer||[]).filter(x=>x&&x.__isPort);const ev={data,ports,type:'message',target:this._peer};queueMicrotask(()=>this._peer&&this._peer._deliver(ev))},_deliver(ev){if(this._closed)return;if(!this._started){this._q.push(ev);return}if(this._on)try{this._on(ev)}catch(e){}for(const f of this._lis)try{f(ev)}catch(e){}},_flush(){if(!this._started)return;const q=this._q;this._q=[];for(const ev of q)this._deliver(ev)}};return p}
function MessageChannelShim(){const a=makePort(),b=makePort();a._peer=b;b._peer=a;this.port1=a;this.port2=b}

const XHR_REQS=[]
function makeXHR(){return class XHR{constructor(){this._h={};this.readyState=0;this.status=0;this.responseText='';this.response=''}open(m,u){this._m=m;this._u=u}setRequestHeader(k,v){this._h[k]=v}addEventListener(t,f){this['on'+t]=f}getAllResponseHeaders(){return ''}abort(){}send(body){const self=this;const path=String(this._u).split('?')[0].replace(/^https?:\/\/[^/]+/,'');XHR_REQS.push({m:this._m,path,bodyLen:body?(body.byteLength||body.length||0):0});fetch(this._u,{method:this._m||'GET',headers:{'User-Agent':UA,...this._h},body:body||undefined}).then(async r=>{self.status=r.status;const buf=Buffer.from(await r.arrayBuffer());self.responseText=buf.toString('latin1');self.response=self.responseText;self.readyState=4;if(self.onreadystatechange)self.onreadystatechange();if(self.onload)self.onload()}).catch(e=>{self.status=0;self.readyState=4;if(self.onerror)self.onerror(e)})}}}

// recording noop element/proxy: every key accessed on a DOM node is logged
function makeNoop(){const f=function(){return P};const P=new Proxy(f,{get(t,k){if(typeof k==='symbol')return t[k];ELEM_KEYS.set(k,(ELEM_KEYS.get(k)||0)+1);hotCheck(k);if(k==='toString'||k==='valueOf')return ()=>'';if(k==='length')return 0;if(k==='nodeType')return 1;if(k==='style'||k==='dataset'||k==='classList')return P;if(k==='parentNode'||k==='ownerDocument'||k==='ownerSVGElement')return P;return P},apply(){return P},construct(){return P},set(){return true},has(){return true}});return P}

function recWrap(obj, sink){ return new Proxy(obj,{get(t,k){if(typeof k!=='symbol')sink.set(k,(sink.get(k)||0)+1);const v=t[k];if(v&&typeof v==='object'&&(k==='memory'||k==='userAgentData'))return recWrap(v,sink);return v},has(t,k){return k in t},set(t,k,v){t[k]=v;return true}}) }
function buildRealm(role, extra, pageWindow){
  let T0=Date.now(); let heap=12_000_000
  const isWk = role==='worker'
  const perfRaw={now:()=>Date.now()-T0+Math.random(),memory:{get usedJSHeapSize(){return heap},totalJSHeapSize:30_000_000,jsHeapSizeLimit:2_200_000_000},timeOrigin:0,getEntriesByType:()=>[],mark(){},measure(){},clearMarks(){},clearMeasures(){}}
  const navRaw={userAgent:UA,webdriver:false,deviceMemory:8,hardwareConcurrency:8,language:'en-US',languages:['en-US','en'],platform:'Win32',vendor:'Google Inc.',product:'Gecko',appName:'Netscape',onLine:true,userAgentData:{brands:[{brand:'Chromium',version:'149'}],mobile:false,platform:'Windows',getHighEntropyValues:()=>Promise.resolve({})},sendBeacon:()=>true,cookieEnabled:true,doNotTrack:null}
  const perf = isWk ? recWrap(perfRaw, WK_PERF) : perfRaw
  const base={importScripts:()=>{},postMessage:()=>{},addEventListener:()=>{},removeEventListener:()=>{},onmessage:null,onerror:null,close:()=>{},MessageChannel:MessageChannelShim,MessagePort:function(){},performance:perf,
    navigator: isWk ? recWrap(navRaw, WK_NAV) : navRaw,
    XMLHttpRequest:makeXHR(),location:{href:'https://www.google.com/recaptcha/api2/webworker.js',origin:'https://www.google.com',protocol:'https:',host:'www.google.com',hostname:'www.google.com',pathname:'/recaptcha/api2/webworker.js',search:'',hash:''},
    atob:s=>Buffer.from(s,'base64').toString('binary'),btoa:s=>Buffer.from(s,'binary').toString('base64'),setTimeout,clearTimeout,setInterval,clearInterval,queueMicrotask,requestAnimationFrame:f=>setTimeout(()=>f(Date.now()),16),cancelAnimationFrame:()=>{},requestIdleCallback:f=>setTimeout(()=>f({timeRemaining:()=>5,didTimeout:false}),1),cancelIdleCallback:()=>{},TextEncoder,TextDecoder,URL,URLSearchParams,crypto:require('crypto').webcrypto,fetch:(...a)=>fetch(...a),console:{log:()=>{},warn:()=>{},error:()=>{},info:()=>{},debug:()=>{}}}
  Object.assign(base, extra||{})
  for (const k of INTRINSICS) if (!(k in base)) try { base[k]=globalThis[k] } catch {}
  let globalRef
  const HITM = pageWindow?WIN_HIT:(isWk?WK_HIT:null), MISSS = pageWindow?WIN_MISS:(isWk?WK_MISS:null)
  const handler={get(t,k){if(typeof k==='symbol')return t[k];if(k==='self'||k==='globalThis')return globalRef;if(k==='window')return pageWindow?globalRef:undefined;if(k==='top'||k==='parent')return pageWindow?globalRef:undefined;if(k in t){if(HITM){HITM.set(k,(HITM.get(k)||0)+1);hotCheck(k)}return t[k]}if(MISSS){MISSS.add(k);hotCheck(k)}return undefined},has(){return true},set(t,k,v){t[k]=v;return true}}
  const sandbox=Object.assign(Object.create(null),base)
  const ctx=vm.createContext(new Proxy(sandbox,handler));globalRef=ctx
  let err=null
  try{vm.runInContext(CODE,ctx,{filename:`en[${role}]`,timeout:20000})}catch(e){err=e}
  return {ctx,sandbox,err,setHeap:v=>{heap=v}}
}

// ---- worker realm spawned on new Worker() ----
let workerRealm=null
function FakeWorker(url){
  const self_=this; self_._lis=[]; self_._on=null
  const wmsgListeners=[]; const toPageQ=[]
  function flushToPage(){if(!(self_._on||self_._lis.length))return;while(toPageQ.length){const ev=toPageQ.shift();if(self_._on)try{self_._on(ev)}catch(e){}for(const f of self_._lis)try{f(ev)}catch(e){}}}
  workerRealm=buildRealm('worker',{postMessage:(m,transfer)=>{FRAMES.push({dir:'W->P',...frameInfo(m)});toPageQ.push({data:m,ports:Array.isArray(transfer)?transfer.filter(x=>x&&x.__isPort):[]});flushToPage()},addEventListener:(t,f)=>{if(t==='message')wmsgListeners.push(f)}},false)
  function deliverToWorker(ev){const ws=workerRealm.sandbox;if(ws.onmessage)try{ws.onmessage(ev)}catch(e){}for(const f of wmsgListeners)try{f(ev)}catch(e){}}
  self_.postMessage=(m,t)=>{FRAMES.push({dir:'P->W',...frameInfo(m)});deliverToWorker({data:m,ports:(t||[]).filter(x=>x&&x.__isPort)})}
  self_.addEventListener=(t,f)=>{if(t==='message'){self_._lis.push(f);flushToPage()}}
  self_.removeEventListener=(t,f)=>{self_._lis=self_._lis.filter(x=>x!==f)}
  self_.terminate=()=>{}
  Object.defineProperty(self_,'onmessage',{get(){return self_._on},set(f){self_._on=f;flushToPage()}})
}

// ---- recording document ----
const docTarget={createElement:(t)=>{rec('createElementTag',String(t));return makeNoop()},createElementNS:(ns,t)=>{rec('createElementNS',String(t));return makeNoop()},getElementById:()=>null,getElementsByTagName:()=>[],getElementsByClassName:()=>[],querySelector:()=>null,querySelectorAll:()=>[],createTextNode:()=>makeNoop(),documentElement:makeNoop(),head:makeNoop(),body:makeNoop(),cookie:'',referrer:'https://www.google.com/',location:null,addEventListener(){},removeEventListener(){},createEvent:()=>makeNoop(),readyState:'complete',visibilityState:'visible',hidden:false,currentScript:null,scripts:[],title:'',implementation:{createHTMLDocument:()=>document}}
const document=new Proxy(docTarget,{get(t,k){if(typeof k==='symbol')return t[k];DOC_KEYS.set(k,(DOC_KEYS.get(k)||0)+1);hotCheck(k);if(k in t)return t[k];return makeNoop()},has(){return true},set(t,k,v){t[k]=v;return true}})

const windowExtra={Worker:FakeWorker,document,
  location:{href:'https://www.google.com/recaptcha/api2/anchor?k=SITEKEY&co=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDM&hl=en&v=VER&size=normal',origin:'https://www.google.com',protocol:'https:',host:'www.google.com',hostname:'www.google.com',pathname:'/recaptcha/api2/anchor',search:'?k=SITEKEY',hash:'',replace(){},assign(){},reload(){}},
  screen:{width:1920,height:1080,availWidth:1920,availHeight:1040,colorDepth:24,pixelDepth:24},
  history:{length:1,pushState(){},replaceState(){},back(){},forward(){}},
  localStorage:{getItem:()=>null,setItem(){},removeItem(){},clear(){}},sessionStorage:{getItem:()=>null,setItem(){},removeItem(){},clear(){}},
  devicePixelRatio:1,innerWidth:1920,innerHeight:1040,outerWidth:1920,outerHeight:1080,name:'',closed:false,
  matchMedia:()=>({matches:false,addListener(){},removeListener(){},addEventListener(){},removeEventListener(){}}),
  getComputedStyle:()=>makeNoop(),parent:null,top:null,frameElement:null,scrollTo(){},focus(){},blur(){},
  Image:function(){return makeNoop()},Event:function(){return makeNoop()},CustomEvent:function(){return makeNoop()},
  MutationObserver:function(){return{observe(){},disconnect(){},takeRecords:()=>[]}},IntersectionObserver:function(){return{observe(){},disconnect(){}}},ResizeObserver:function(){return{observe(){},disconnect(){}}},
  ___grecaptcha_cfg:{clients:{},count:0,fns:[]}}

function extractInitCall(html){const key='recaptcha.anchor.Main.init(';const i=html.indexOf(key);if(i<0)return null;let p=i+key.length,depth=1,inStr=false,q='';for(;p<html.length;p++){const c=html[p];if(inStr){if(c==='\\'){p++;continue}if(c===q)inStr=false;continue}if(c==='"'||c==="'"){inStr=true;q=c;continue}if(c==='(')depth++;else if(c===')'){depth--;if(depth===0){p++;break}}}return html.slice(i,p)}

;(async()=>{
  const SITEKEY=process.env.SITEKEY||'6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-', VER='TnA7HacJFoBWt9hnlunBlYfK'
  const page=buildRealm('page',windowExtra,true)
  console.log('[page] load:',page.err?'THREW '+page.err.message:'OK')
  if(!page.sandbox.recaptcha||!page.sandbox.recaptcha.anchor){console.log('NO anchor api');return}
  const aurl=`https://www.google.com/recaptcha/api2/anchor?ar=1&k=${SITEKEY}&co=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDM&hl=en&v=${VER}&size=normal&cb=p`
  const html=await(await fetch(aurl,{headers:{'User-Agent':UA}})).text()
  const initCall=extractInitCall(html)
  console.log('[page] initCall:',!!initCall,initCall?initCall.length+' chars':'')
  if(!initCall){console.log('NO init call');return}
  // mark a boundary: clear element/doc recorders so we measure only the init+ path
  DOC_KEYS.clear(); ELEM_KEYS.clear(); WIN_MISS.clear(); WIN_HIT.clear(); HOTHITS.length=0
  console.log('[page] === calling init(cfg) ===')
  try{vm.runInContext(initCall,page.ctx,{timeout:20000})}catch(e){console.log('[page] init threw:',e.message)}
  for(let s=0;s<14;s++){await new Promise(r=>setTimeout(r,1000));if(workerRealm)break}
  await new Promise(r=>setTimeout(r,4000))

  const dump=(label,m,n=60)=>{const a=[...m.entries()].sort((x,y)=>y[1]-x[1]).slice(0,n);console.log('\n## '+label+' ('+m.size+' distinct):');for(const[k,c]of a)console.log('   '+String(c).padStart(4)+'  '+String(k))}
  console.log('\n[page] worker spawned:',!!workerRealm,workerRealm?(workerRealm.err?'worker THREW '+workerRealm.err.message:'worker OK'):'')
  console.log('[page] HOT canvas/webgl/audio hits:',HOTHITS.length?[...new Set(HOTHITS)].join(' '):'NONE')
  console.log('[page] XHRs:',XHR_REQS.map(r=>r.m+' '+r.path+'#'+r.bodyLen).join(' | ')||'none')
  console.log('\n[loopback FRAMES] '+FRAMES.length+':')
  for(const f of FRAMES) console.log('   '+f.dir+'  '+f.kind+'  ~'+f.size+'B  '+(f.head||''))
  dump('PAGE document.<key> reads',DOC_KEYS)
  dump('PAGE element/node.<key> reads',ELEM_KEYS)
  dump('PAGE window MISSING (read->undefined)',new Map([...WIN_MISS].map(k=>[k,1])),120)
  dump('PAGE window HIT (provided & read)',WIN_HIT,80)
  dump('WORKER navigator.<key> reads',WK_NAV)
  dump('WORKER performance.<key> reads',WK_PERF)
  dump('WORKER window MISSING (read->undefined)',new Map([...WK_MISS].map(k=>[k,1])),120)
  dump('WORKER window HIT (provided & read)',WK_HIT,80)
  process.exit(0)
})()
