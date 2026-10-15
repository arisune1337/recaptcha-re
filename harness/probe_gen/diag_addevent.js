'use strict'
// Deep introspection: what does winMsgHandlers[0] expect?
// What methods does recaptcha.anchor.Main have?
// Does apiToAnchor port routing work?
const vm  = require('vm')
const PR  = require('C:/Users/user/Desktop/a/recaptcha-re/harness/page_rpc.js')
const fs  = require('fs')
const { MessageChannelShim } = require('C:/Users/user/Desktop/a/recaptcha-re/harness/page.js')

let CODE = PR.applyPatches(fs.readFileSync('C:/Users/user/Desktop/a/recaptcha-re/recaptcha__en.js', 'utf8'))
const INTRINSICS = ['Object','Array','Function','String','Number','Boolean','Symbol','BigInt','Math','JSON','Date','RegExp','Error','TypeError','RangeError','EvalError','ReferenceError','SyntaxError','URIError','Reflect','Proxy','Promise','Map','Set','WeakMap','WeakSet','WeakRef','ArrayBuffer','SharedArrayBuffer','DataView','Uint8Array','Int8Array','Uint8ClampedArray','Uint16Array','Int16Array','Uint32Array','Int32Array','Float32Array','Float64Array','BigInt64Array','BigUint64Array','parseInt','parseFloat','decodeURIComponent','encodeURIComponent','decodeURI','encodeURI','escape','unescape','isNaN','isFinite','Intl','structuredClone','Infinity','NaN','undefined','globalThis']
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36'
const sleep = ms => new Promise(r => setTimeout(r, ms))

function extractInitCall(html) {
  const key = 'recaptcha.anchor.Main.init('; const i = html.indexOf(key); if (i < 0) return { call: null, cfg: null }
  let p = i + key.length, depth = 1, inStr = false, q = ''
  for (; p < html.length; p++) { const c = html[p]; if (inStr) { if (c === '\\') { p++; continue } if (c === q) inStr = false; continue }; if (c === '"' || c === "'") { inStr = true; q = c; continue }; if (c === '(') depth++; else if (c === ')') { if (--depth === 0) { p++; break } } }
  const call = html.slice(i, p); let cfg = null
  try { const s = Function('return ' + call.slice(key.length, -1))(); cfg = JSON.parse(s) } catch {}
  return { call, cfg }
}

;(async () => {
  const PROXY_URL = process.argv[2]
  if (PROXY_URL) { try { const {ProxyAgent,setGlobalDispatcher}=require('undici');setGlobalDispatcher(new ProxyAgent(PROXY_URL)) } catch {} }
  const AURL = 'https://www.google.com/recaptcha/api2/anchor?ar=1&k=6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u&co=aHR0cHM6Ly8yY2FwdGNoYS5jb206NDQz&hl=en&v=TnA7HacJFoBWt9hnlunBlYfK&size=normal&cb=p'
  const html = await (await fetch(AURL, {headers:{'User-Agent':UA}})).text()
  const { call: initCall, cfg } = extractInitCall(html)
  console.log('cfg[24]:', cfg && cfg[24], '| cfg[30]:', cfg && cfg[30] && cfg[30].slice(0,20)+'...')

  const winListeners = {}
  const captureFn = (t, f) => { (winListeners[t] = winListeners[t] || []).push(f) }
  const removeFn = () => {}
  const parentMsgs = []
  const hostOrigin = 'https://2captcha.com'
  const parentSpy = { postMessage: (d,o) => { console.log('[parent.postMessage]', JSON.stringify(d).slice(0,80)); parentMsgs.push(d) }, origin: hostOrigin, closed: false, location: { href: hostOrigin+'/', origin: hostOrigin } }
  const allEls = []
  function makeEl(tag) {
    const lis = {}; const real = { tagName:(tag||'div').toUpperCase(),id:'',nodeType:1,value:'',checked:false,style:new Proxy({},{get:()=>'',set:()=>true}),dataset:{},classList:{add(){},remove(){},contains:()=>false,toggle(){}},addEventListener(t,f){(lis[t]=lis[t]||[]).push(f)},removeEventListener(){},setAttribute(){},getAttribute:()=>null,hasAttribute:()=>false,removeAttribute(){},appendChild:x=>x,removeChild:x=>x,insertBefore:x=>x,replaceChild:x=>x,remove(){},contains:()=>false,focus(){},blur(){},click(){},cloneNode(){return makeEl(tag)},getContext:()=>null,querySelector:()=>makeEl('div'),querySelectorAll:()=>[],getElementsByTagName:()=>[],getElementsByClassName:()=>[],getBoundingClientRect:()=>({x:0,y:0,width:28,height:28,top:0,left:0,right:28,bottom:28}),getClientRects:()=>[],children:[],childNodes:[],firstChild:null,lastChild:null,nextSibling:null,previousSibling:null,parentNode:null,ownerDocument:null,innerHTML:'',outerHTML:'',textContent:'',offsetWidth:28,offsetHeight:28,offsetParent:null,dispatchEvent(ev){(lis[ev&&ev.type]||[]).forEach(f=>{try{f(ev)}catch{}});return true},_lis:lis }
    const P = new Proxy(real, { get(t,k){if(k===Symbol.toPrimitive)return(h)=>h==='number'?0:'';if(k==='valueOf')return()=>0;if(k==='then')return undefined;if(k in t)return t[k];if(typeof k==='string'&&/^on/.test(k))return null;return new Proxy(function(){},{get:(_,k2)=>{if(k2===Symbol.toPrimitive)return()=>'';if(k2==='then')return undefined;return()=>{}},apply:()=>undefined,set:()=>true,has:()=>true})}, set(t,k,v){t[k]=v;return true},has:()=>true })
    allEls.push(real); return P
  }
  const ELS = {}
  const document = new Proxy({ createElement:t=>makeEl(t),createElementNS:(n,t)=>makeEl(t),createDocumentFragment:()=>makeEl('frag'),createTextNode:()=>makeEl('text'),createComment:()=>makeEl('cmt'),createEvent:()=>({initEvent(){},initCustomEvent(){}}),getElementById:id=>(ELS[id]=ELS[id]||makeEl('div')),querySelector:s=>(ELS['q:'+s]=ELS['q:'+s]||makeEl('div')),querySelectorAll:()=>[],getElementsByTagName:()=>[],getElementsByClassName:()=>[],getElementsByName:()=>[],documentElement:makeEl('html'),head:makeEl('head'),body:makeEl('body'),cookie:'',referrer:'https://www.google.com/',addEventListener(){},removeEventListener(){},dispatchEvent:()=>true,readyState:'complete',visibilityState:'visible',hidden:false,currentScript:null,scripts:[],title:'',defaultView:null,characterSet:'UTF-8',compatMode:'CSS1Compat' },{get(t,k){return k in t?t[k]:()=>{}},has:()=>true})
  const base = {__cap:{},addEventListener:captureFn,removeEventListener:removeFn,postMessage:()=>{},onmessage:null,onerror:null,close:()=>{},MessageChannel:MessageChannelShim,MessagePort:function(){},performance:{now:()=>Date.now(),timeOrigin:Date.now(),getEntriesByType:()=>[],mark(){},measure(){},clearMarks(){},clearMeasures(){},memory:{usedJSHeapSize:13e6,totalJSHeapSize:50e6,jsHeapSizeLimit:2190e6}},navigator:{userAgent:UA,webdriver:false,deviceMemory:8,hardwareConcurrency:8,language:'en-US',languages:['en-US'],platform:'Win32',vendor:'Google Inc.',onLine:true,userAgentData:{brands:[{brand:'Chromium',version:'149'}],mobile:false,platform:'Windows',getHighEntropyValues:()=>Promise.resolve({})},sendBeacon:()=>true,cookieEnabled:true,plugins:[],mimeTypes:[],permissions:{query:()=>Promise.resolve({state:'prompt'})}},location:{href:AURL,origin:'https://www.google.com',protocol:'https:',host:'www.google.com',hostname:'www.google.com',pathname:'/recaptcha/api2/anchor',search:'?ar=1',hash:'',replace(){},assign(){},reload(){}},screen:{width:1920,height:1080,availWidth:1920,availHeight:1040,colorDepth:24,pixelDepth:24},atob:s=>Buffer.from(s,'base64').toString('binary'),btoa:s=>Buffer.from(s,'binary').toString('base64'),setTimeout,clearTimeout,setInterval,clearInterval,queueMicrotask,requestAnimationFrame:f=>setTimeout(()=>f(Date.now()),16),cancelAnimationFrame:()=>{},requestIdleCallback:f=>setTimeout(()=>f({timeRemaining:()=>5,didTimeout:false}),1),cancelIdleCallback:()=>{},TextEncoder,TextDecoder,URL,URLSearchParams,crypto:require('crypto').webcrypto,fetch:(...a)=>fetch(...a),console:{log:()=>{},warn:()=>{},error:()=>{},info:()=>{},debug:()=>{}},history:{length:1,pushState(){},replaceState(){},back(){},forward(){}},localStorage:{getItem:()=>null,setItem(){},removeItem(){},clear(){}},sessionStorage:{getItem:()=>null,setItem(){},removeItem(){},clear(){}},devicePixelRatio:1,innerWidth:1920,innerHeight:1040,name:'',closed:false,frameElement:null,matchMedia:()=>({matches:false,addListener(){},removeListener(){},addEventListener(){},removeEventListener(){}}),getComputedStyle:()=>new Proxy({},{get:()=>'',set:()=>true}),scrollTo(){},focus(){},blur(){},MutationObserver:function(){return{observe(){},disconnect(){},takeRecords:()=>[]}},IntersectionObserver:function(){return{observe(){},disconnect(){}}},ResizeObserver:function(){return{observe(){},disconnect(){}}},Image:function(){return makeEl('img')},Event:function(t,o){return{type:t,isTrusted:true,bubbles:!!(o&&o.bubbles),cancelable:!!(o&&o.cancelable),preventDefault(){},stopPropagation(){}}},CustomEvent:function(t,o){return{type:t,detail:o&&o.detail,isTrusted:true,preventDefault(){},stopPropagation(){}}},Worker:function(url){console.log('[Worker]',String(url).slice(0,60));this.postMessage=()=>{};this.addEventListener=()=>{};this.terminate=()=>{};this.onmessage=null},Notification:Object.assign(function(){},{permission:'default',requestPermission:()=>Promise.resolve('default')}),chrome:{app:{isInstalled:false},runtime:{},loadTimes:()=>({wasFetchedViaSpdy:true,wasNpnNegotiated:true,npnNegotiatedProtocol:'h2'}),csi:()=>({onloadT:Date.now(),tran:15})},___grecaptcha_cfg:{clients:{},count:0,fns:[]},botguard:undefined,__onAE:()=>{},document}
  for (const k of INTRINSICS) if (!(k in base)) try { base[k] = globalThis[k] } catch {}

  let g
  const sandbox = Object.assign(Object.create(null), base)
  const hnd = { get(t,k){if(typeof k==='symbol')return t[k];if(k==='self'||k==='globalThis')return g;if(k==='window')return g;if(k==='top'||k==='parent')return parentSpy;if(k==='addEventListener')return captureFn;if(k==='removeEventListener')return removeFn;return t[k]},has:()=>true,set(t,k,v){t[k]=v;return true} }
  const ctx = vm.createContext(new Proxy(sandbox, hnd)); g = ctx
  vm.runInContext(CODE, ctx, {timeout:20000})
  const savedTest = [...(winListeners['test']||[])]
  console.log('\n=== recaptcha.anchor.Main methods ===')
  try { console.log(Object.keys(sandbox.recaptcha.anchor.Main).join(', ')) } catch(e) { console.log('err:', e.message) }

  // Fire test
  const mc = new MessageChannelShim()
  const name = cfg && cfg[24] || ''
  const cb = 'p'
  for (const dv of [name, cb]) {
    const ev = { data:dv, origin:hostOrigin, source:parentSpy, ports:[mc.port2], type:'test', isTrusted:true, preventDefault(){}, stopPropagation(){} }
    for (const fn of savedTest) { try { fn(ev) } catch(e) { console.log('testFire err:', e.message) } }
  }
  console.log('After test: parentMsgs:', parentMsgs.length)

  // Run init
  try { vm.runInContext(initCall, ctx, {timeout:20000}) } catch(e) { console.log('initErr:', e.message) }
  const nCl = sandbox.___grecaptcha_cfg && sandbox.___grecaptcha_cfg.clients ? Object.keys(sandbox.___grecaptcha_cfg.clients).length : 0
  console.log('After init: clients:', nCl, '| parentMsgs:', parentMsgs.length, '| msg handlers:', (winListeners.message||[]).length)

  // Inspect the message handler
  const msgH = winListeners.message || []
  if (msgH.length > 0) {
    const src = msgH[0].toString()
    console.log('\n=== winMsgHandlers[0] source (first 500 chars) ===')
    console.log(src.slice(0, 500))
  }

  // Check if mc.port2 (given to anchor) has onmessage or event listeners
  console.log('\n=== mc.port2 state ===')
  console.log('onmessage type:', typeof mc.port2.onmessage)
  console.log('_listeners:', mc.port2._listeners ? mc.port2._listeners.length : 0)

  // Try firing message via port1 → port2
  console.log('\n=== Testing port routing ===')
  mc.port1.onmessage = (ev) => { console.log('[port1.onmessage] got:', JSON.stringify(ev.data).slice(0,60)) }
  mc.port2.postMessage('test-port-routing')
  await sleep(100)
  console.log('port routing test done')

  // What happens after we post to port1 (api→anchor)?
  for (const dv of ['recaptcha-setup', name, [name, cfg && cfg[30] || '']]) {
    mc.port1.postMessage(dv)
    await sleep(100)
    const c = sandbox.___grecaptcha_cfg && sandbox.___grecaptcha_cfg.clients ? Object.keys(sandbox.___grecaptcha_cfg.clients).length : 0
    const cl = allEls.filter(e=>e._lis&&(e._lis.click||e._lis.mousedown)).length
    console.log(`port1.postMessage(${JSON.stringify(dv).slice(0,30)}): clients=${c} clickable=${cl}`)
  }
})()
