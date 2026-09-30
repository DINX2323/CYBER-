'use strict';
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {Lab,verifyBundle,experiment}=require('./lib');
const root=process.env.CANARYGRAPH_DATA || path.join(__dirname,'data');
const port=Number(process.env.PORT || 4317);
const host='127.0.0.1';
const origin=`http://${host}:${port}`;
const csrf=crypto.randomBytes(32).toString('hex');
const lab=new Lab(root);
const staticFiles={'/':['index.html','text/html'],'/app.js':['app.js','text/javascript'],'/style.css':['style.css','text/css']};
function send(res,status,data,type='application/json',extra={}) {
  res.writeHead(status,{'Content-Type':type+'; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",...extra});
  res.end(type==='application/json'?JSON.stringify(data):data);
}
async function body(req) {
  let data='';
  for await(const chunk of req){data+=chunk;if(data.length>16384)throw new Error('Request is too large.');}
  return data?JSON.parse(data):{};
}
const server=http.createServer(async(req,res)=>{
  try {
    if(req.headers.host!==`${host}:${port}`)return send(res,403,{error:'Use the loopback address shown by CanaryGraph.'});
    if(req.headers.origin && req.headers.origin!==origin)return send(res,403,{error:'Cross-origin requests are blocked.'});
    if(req.headers['sec-fetch-site']==='cross-site')return send(res,403,{error:'Cross-site requests are blocked.'});
    const url=new URL(req.url,origin);
    const route=url.pathname;
    if(req.method==='GET' && staticFiles[route]){
      const [file,type]=staticFiles[route];return send(res,200,fs.readFileSync(path.join(__dirname,'public',file)),type);
    }
    if(req.method==='GET'&&route==='/api/state')return send(res,200,{...lab.state(),csrf});
    if(req.method==='GET'&&route==='/api/export')return send(res,200,lab.ledger.assertIntegrity(),'application/json',{'Content-Disposition':'attachment; filename="canarygraph-evidence.json"'});
    if(req.method!=='POST')return send(res,404,{error:'Not found.'});
    if(req.headers['x-canarygraph-token']!==csrf)return send(res,403,{error:'Reload the lab page before running this action.'});
    if(!String(req.headers['content-type']||'').startsWith('application/json'))return send(res,415,{error:'JSON required.'});
    const input=await body(req);
    if(route==='/api/session')return send(res,200,{session:lab.newSession()});
    if(route==='/api/read')return send(res,200,lab.readAsset(input.session,input.asset));
    if(route==='/api/login')return send(res,200,lab.login(input.session,input.token));
    if(route==='/api/vault')return send(res,200,lab.vault(input.session));
    if(route==='/api/demo')return send(res,200,lab.demo(input.type));
    if(route==='/api/verify')return send(res,200,verifyBundle(lab.ledger.bundle(),lab.ledger.fingerprint));
    if(route==='/api/tamper-demo'){
      const bundle=lab.ledger.assertIntegrity();
      if(!bundle.events.length)throw new Error('Record at least one lab event first.');
      const original=verifyBundle(bundle,lab.ledger.fingerprint);
      const altered=structuredClone(bundle);altered.events[0].label='Changed by tamper demonstration';
      const truncated=structuredClone(bundle);truncated.events.pop();
      return send(res,200,{original,altered:verifyBundle(altered,lab.ledger.fingerprint),truncated:verifyBundle(truncated,lab.ledger.fingerprint),note:'Only in-memory copies were changed. The original evidence was preserved.'});
    }
    if(route==='/api/experiment'){
      const seed=input.seed??42;if(!Number.isInteger(seed)||seed<0||seed>1000000)throw new Error('Seed must be an integer from 0 to 1000000.');
      return send(res,200,experiment(seed));
    }
    return send(res,404,{error:'Not found.'});
  }catch(e){send(res,400,{error:e.message});}
});
server.on('error',e=>{console.error(e.code==='EADDRINUSE'?`Port ${port} is already in use. Check the existing lab or select another PORT.`:e.message);process.exitCode=1;});
server.listen(port,host,()=>console.log(`CanaryGraph running at ${origin}\nEvidence directory: ${root}\nTrusted key fingerprint: ${lab.ledger.fingerprint}\nPress Ctrl+C to stop.`));
