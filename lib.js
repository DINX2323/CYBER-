'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
const digest = value => crypto.createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
const fingerprint = pem => digest(crypto.createPublicKey(pem).export({type:'spki',format:'der'}).toString('base64'));
const GENESIS = '0'.repeat(64);
function verifyBundle(bundle, trustedFingerprint) {
  try {
    if (!trustedFingerprint) throw new Error('A separately trusted key fingerprint is required.');
    if (bundle.version !== 1 || !Array.isArray(bundle.events)) throw new Error('Unsupported evidence format.');
    if (fingerprint(bundle.publicKey) !== trustedFingerprint) throw new Error('Signing key does not match the trusted fingerprint.');
    const cp = bundle.checkpoint;
    if (!cp || !crypto.verify(null, Buffer.from(canonical(cp.payload)), bundle.publicKey, Buffer.from(cp.signature, 'base64'))) throw new Error('Checkpoint signature is invalid.');
    if (cp.payload.count !== bundle.events.length) throw new Error('Event count differs from the signed checkpoint (missing or extra records).');
    let previous = GENESIS;
    for (let i=0;i<bundle.events.length;i++) {
      const {hash,...event} = bundle.events[i];
      if (event.seq !== i+1 || event.previous !== previous) throw new Error(`Broken sequence at event ${i+1}.`);
      if (digest(event) !== hash) throw new Error(`Content changed at event ${i+1}.`);
      previous = hash;
    }
    if (cp.payload.head !== previous) throw new Error('Chain head does not match signed checkpoint.');
    return {ok:true, count:bundle.events.length, head:previous, fingerprint:trustedFingerprint, message:'All records match the signed checkpoint and trusted key.'};
  } catch (e) { return {ok:false,message:e.message}; }
}

class Ledger {
  constructor(root) {
    this.root = root;
    fs.mkdirSync(root,{recursive:true});
    this.file = path.join(root,'events.jsonl');
    this.checkpointFile = path.join(root,'checkpoint.json');
    const keyDir = path.join(root,'keys');
    fs.mkdirSync(keyDir,{recursive:true});
    const privateFile = path.join(keyDir,'private.pem');
    const publicFile = path.join(keyDir,'public.pem');
    const existing = [this.file,this.checkpointFile,privateFile,publicFile].map(f=>fs.existsSync(f));
    if (existing.some(Boolean) && !existing.every(Boolean)) throw new Error('Incomplete evidence store. Preserve it for inspection; use a new data directory to start a new lab.');
    if (!existing.some(Boolean)) {
      const keys = crypto.generateKeyPairSync('ed25519');
      fs.writeFileSync(privateFile,keys.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
      fs.writeFileSync(publicFile,keys.publicKey.export({type:'spki',format:'pem'}),{flag:'wx'});
      fs.writeFileSync(this.file,'',{flag:'wx'});
      this.privateKey = fs.readFileSync(privateFile,'utf8');
      this.publicKey = fs.readFileSync(publicFile,'utf8');
      this.writeCheckpoint([]);
    } else {
      this.privateKey = fs.readFileSync(privateFile,'utf8');
      this.publicKey = fs.readFileSync(publicFile,'utf8');
    }
    this.fingerprint = fingerprint(this.publicKey);
    if (fingerprint(crypto.createPublicKey(this.privateKey).export({type:'spki',format:'pem'})) !== this.fingerprint) throw new Error('Signing key pair does not match.');
    this.assertIntegrity();
  }
  read() {
    const raw = fs.readFileSync(this.file,'utf8');
    if (raw && !raw.endsWith('\n')) throw new Error('Incomplete ledger record.');
    return raw.trim() ? raw.trim().split('\n').map(line=>JSON.parse(line)) : [];
  }
  writeCheckpoint(events) {
    const payload = {count:events.length,head:events.at(-1)?.hash || GENESIS,createdAt:new Date().toISOString()};
    const checkpoint = {payload,signature:crypto.sign(null,Buffer.from(canonical(payload)),this.privateKey).toString('base64')};
    const temp = this.checkpointFile+'.tmp';
    fs.writeFileSync(temp,JSON.stringify(checkpoint,null,2));
    fs.renameSync(temp,this.checkpointFile);
  }
  bundle() { return {version:1,publicKey:this.publicKey,checkpoint:JSON.parse(fs.readFileSync(this.checkpointFile,'utf8')),events:this.read()}; }
  assertIntegrity() {
    const bundle = this.bundle();
    const result = verifyBundle(bundle,this.fingerprint);
    if (!result.ok) throw new Error('Evidence integrity failure: '+result.message);
    return bundle;
  }
  append(fields) {
    const bundle = this.assertIntegrity();
    const events = bundle.events;
    const event = {...fields,seq:events.length+1,timestamp:new Date().toISOString(),previous:events.at(-1)?.hash || GENESIS};
    const record = {...event,hash:digest(event)};
    fs.appendFileSync(this.file,JSON.stringify(record)+'\n');
    this.writeCheckpoint([...events,record]);
    return record;
  }
}

const ASSETS = [
  {id:'welcome',name:'Welcome.txt',kind:'ordinary',zone:'Public',description:'Ordinary onboarding instructions.',content:'CanaryGraph research lab. All documents and identities are synthetic.\n'},
  {id:'handbook',name:'Team-handbook.txt',kind:'ordinary',zone:'Public',description:'Ordinary internal handbook.',content:'Synthetic handbook: read the welcome file, review meeting notes, then close your session.\n'},
  {id:'notes',name:'Meeting-notes.txt',kind:'ordinary',zone:'Shared',description:'Ordinary meeting notes.',content:'Synthetic meeting: review security lab results on Friday.\n'},
  {id:'credentials',name:'Service-credentials.txt',kind:'decoy',zone:'Engineering',description:'Credential bait for the local decoy service.',content:'SYNTHETIC LAB ONLY — not a real credential\nService: CanaryGraph local vault\nUsername: lab-operator\nToken: CG-DECOY-ONLY-7F3A\n'},
  {id:'backup',name:'Backup-index.txt',kind:'decoy',zone:'Operations',description:'A synthetic backup manifest.',content:'SYNTHETIC DECOY: quarterly-backup.zip / finance-archive.zip. These archives do not exist.\n'},
  {id:'payroll',name:'Payroll-preview.csv',kind:'decoy',zone:'Finance',description:'Synthetic payroll bait; no real personal information.',content:'synthetic_id,department,amount\nDEMO-001,Research,1000\nDEMO-002,Design,1200\n'},
  {id:'vault',name:'Vault-export.txt',kind:'decoy',zone:'Restricted',description:'Local service document; requires a lab session token.',content:'SYNTHETIC VAULT EXPORT\nThis is a decoy document with no production data.\n'}
];
const LAB_TOKEN='CG-DECOY-ONLY-7F3A';
class Lab {
  constructor(root) {
    this.ledger = new Ledger(root);
    this.assetsDir = path.join(root,'assets');
    fs.mkdirSync(this.assetsDir,{recursive:true});
    for (const a of ASSETS) if (!fs.existsSync(path.join(this.assetsDir,a.name))) fs.writeFileSync(path.join(this.assetsDir,a.name),a.content);
    this.sessions = new Map();
  }
  newSession(source='manual') {
    const id = crypto.randomUUID();
    this.sessions.set(id,{source,authorized:false,createdAt:Date.now()});
    for (const [sid,s] of this.sessions) if (Date.now()-s.createdAt>86400000) this.sessions.delete(sid);
    return id;
  }
  session(id) {
    const s = this.sessions.get(id);
    if (!s || Date.now()-s.createdAt>86400000) throw new Error('Session expired. Start a new lab session.');
    return s;
  }
  log(id,fields) {
    const s = this.session(id);
    return this.ledger.append({session:id,source:s.source,...fields});
  }
  readAsset(id,assetId) {
    this.session(id);
    const asset = ASSETS.find(a=>a.id===assetId);
    if (!asset || asset.id==='vault') throw new Error('Choose an available lab document.');
    const content = fs.readFileSync(path.join(this.assetsDir,asset.name),'utf8');
    this.log(id,{action:'file_read',asset:asset.id,label:asset.name,severity:asset.kind==='decoy'?'medium':'info',reason:asset.kind==='decoy'?'Instrumented read of a synthetic decoy file.':'Ordinary lab document read.'});
    return {asset:asset.name,content};
  }
  login(id,token) {
    const s=this.session(id);
    const success = token===LAB_TOKEN;
    this.log(id,{action:'service_login',asset:'vault-service',label:'Decoy vault login',severity:success?'high':'low',outcome:success?'accepted':'rejected',reason:success?'Known synthetic bait credential used against the local decoy service.':'Login attempt to a decoy service; no submitted credential retained.'});
    if (success) s.authorized=true;
    return {accepted:success};
  }
  vault(id) {
    const s=this.session(id);
    if (!s.authorized) {
      this.log(id,{action:'access_denied',asset:'vault',label:'Vault access denied',severity:'low',reason:'Local decoy document requested without a successful lab login.'});
      throw new Error('Log into the local decoy service first.');
    }
    const content=fs.readFileSync(path.join(this.assetsDir,'Vault-export.txt'),'utf8');
    this.log(id,{action:'vault_read',asset:'vault',label:'Vault-export.txt',severity:'high',reason:'Synthetic restricted document read following a bait-credential login.'});
    return {asset:'Vault-export.txt',content};
  }
  demo(type) {
    if (!['intrusion','benign'].includes(type)) throw new Error('Unknown scenario.');
    const session=this.newSession('scripted-'+type);
    if (type==='benign') for (const id of ['welcome','handbook','notes']) this.readAsset(session,id);
    else {this.readAsset(session,'welcome');this.readAsset(session,'credentials');this.login(session,LAB_TOKEN);this.vault(session);}
    return {session,type};
  }
  state() {
    const bundle=this.ledger.assertIntegrity();
    const events=bundle.events;
    const sessions = [...new Set(events.map(e=>e.session))].map(id=>{
      const list=events.filter(e=>e.session===id);
      const readsBait=list.some(e=>e.asset==='credentials'&&e.action==='file_read');
      const login=list.find(e=>e.action==='service_login'&&e.outcome==='accepted');
      const vault=list.find(e=>e.action==='vault_read');
      const credentialRead=list.find(e=>e.asset==='credentials'&&e.action==='file_read');
      const chain=readsBait&&login&&vault&&credentialRead.seq<login.seq&&login.seq<vault.seq;
      return {id,source:list[0].source,count:list.length,first:list[0].timestamp,last:list.at(-1).timestamp,alerts:list.filter(e=>e.severity!=='info').length,chain,events:list};
    }).reverse();
    return {events:events.slice(-500),total:events.length,sessions:sessions.slice(0,100),fingerprint:this.ledger.fingerprint,checkpoint:bundle.checkpoint.payload,assets:ASSETS.map(({content,...a})=>a),alerts:events.filter(e=>e.severity!=='info').length,chains:sessions.filter(s=>s.chain).length};
  }
}

function rng(seed) { let t=seed>>>0;return ()=>{t+=0x6D2B79F5;let z=t;z=Math.imul(z^(z>>>15),z|1);z^=z+Math.imul(z^(z>>>7),z|61);return ((z^(z>>>14))>>>0)/4294967296;}; }
const CANDIDATES=['public','shared','engineering','finance','backup','vault'];
function scenarios(seed,n) {
  const random=rng(seed);
  const malicious=[['public','engineering','vault'],['shared','backup','vault'],['public','finance','backup'],['engineering','backup'],['shared','finance','vault'],['public','shared','engineering']];
  const benign=[['public','shared'],['public'],['shared','engineering'],['public','finance'],['shared'],['public','shared','backup']];
  return Array.from({length:n},(_,i)=>{
    const attack=i%2===0, templates=attack?malicious:benign;
    const route=[...templates[Math.floor(random()*templates.length)]];
    if(random()<0.2) route.splice(1,0,CANDIDATES[Math.floor(random()*CANDIDATES.length)]);
    return {attack,route};
  });
}
function measure(placement,trials) {
  let attacks=0,detected=0,benign=0,falseAlerts=0,steps=0;
  for (const trial of trials) {
    const first=trial.route.findIndex(a=>placement.includes(a));
    if(trial.attack){attacks++;if(first>=0){detected++;steps+=first+1;}}
    else {benign++;if(first>=0)falseAlerts++;}
  }
  return {attacks,detected,benign,falseAlerts,detectionRate:detected/attacks,falsePositiveRate:falseAlerts/benign,meanSteps:detected?steps/detected:null};
}
function experiment(seed=42) {
  const training=scenarios(seed,120), heldout=scenarios(seed+10000,240);
  const choices=[];
  for(let i=0;i<CANDIDATES.length;i++) for(let j=i+1;j<CANDIDATES.length;j++)choices.push([CANDIDATES[i],CANDIDATES[j]]);
  const scored=choices.map(p=>{const m=measure(p,training);return {p,score:m.detectionRate-m.falsePositiveRate};}).sort((a,b)=>b.score-a.score);
  const random=rng(seed+999);
  const selected=choices[Math.floor(random()*choices.length)];
  return {seed,budget:2,training:120,heldout:240,objective:'Training detection rate minus training false-positive rate; ties keep deterministic candidate order.',disclaimer:'Synthetic route replay, not a real-world efficacy benchmark. All policies are evaluated on identical held-out routes. Detection means a route touches a decoy location; benign touches count as false alerts. A single seeded random placement is a baseline, not a statistical estimate over all random placements.',rows:[['Seeded random',selected],['Fixed sensitive areas',['finance','backup']],['Training-selected',scored[0].p]].map(([name,placement])=>({name,placement,training:measure(placement,training),test:measure(placement,heldout)}))};
}
module.exports={canonical,digest,fingerprint,verifyBundle,Ledger,Lab,ASSETS,experiment,GENESIS};
