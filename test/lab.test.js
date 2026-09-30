'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const {Lab,Ledger,verifyBundle,digest,canonical,experiment}=require('../lib');
function temporary(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'canarygraph-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));return dir;}
test('instrumented file reads, rejected login, authorized vault, and ordered correlation',t=>{
  const lab=new Lab(temporary(t));const session=lab.newSession();
  assert.throws(()=>lab.vault(session),/Log into/);
  assert.equal(lab.login(session,'NOT-A-REAL-PASSWORD').accepted,false);
  const file=lab.readAsset(session,'credentials');assert.match(file.content,/CG-DECOY-ONLY/);
  assert.equal(lab.login(session,'CG-DECOY-ONLY-7F3A').accepted,true);
  assert.match(lab.vault(session).content,/SYNTHETIC/);
  const state=lab.state();assert.equal(state.chains,1);assert.equal(state.total,5);
  assert.ok(!JSON.stringify(state.events).includes('NOT-A-REAL-PASSWORD'));
  assert.throws(()=>lab.readAsset(session,'../../private.pem'),/available/);
  assert.throws(()=>lab.readAsset(session,'vault'),/available/);
  assert.throws(()=>lab.readAsset('missing','welcome'),/expired/);
});
test('ordinary and intrusion demos perform separate, correctly labelled operations',t=>{
  const lab=new Lab(temporary(t));lab.demo('benign');lab.demo('intrusion');
  const state=lab.state();assert.equal(state.total,7);assert.equal(state.alerts,3);assert.equal(state.chains,1);
  const ordinary=state.sessions.find(s=>s.source==='scripted-benign');assert.equal(ordinary.alerts,0);
  assert.throws(()=>lab.demo('unknown'),/Unknown/);
});
test('live filesystem is read rather than a canned preview',t=>{
  const root=temporary(t);const lab=new Lab(root);const s=lab.newSession();
  fs.writeFileSync(path.join(root,'assets','Welcome.txt'),'Edited synthetic file');
  assert.equal(lab.readAsset(s,'welcome').content,'Edited synthetic file');
});
test('signed evidence rejects edits, rehashing, deletions, reordering, key substitution, and missing trust',t=>{
  const lab=new Lab(temporary(t));lab.demo('intrusion');const good=lab.ledger.bundle(),fp=lab.ledger.fingerprint;
  assert.equal(verifyBundle(good,fp).ok,true);
  assert.equal(verifyBundle(good).ok,false);
  for(const mutate of [b=>b.events[0].label='forged',b=>b.events.pop(),b=>b.events.reverse(),b=>b.checkpoint.payload.count=0]){
    const bad=structuredClone(good);mutate(bad);assert.equal(verifyBundle(bad,fp).ok,false);
  }
  const rehashed=structuredClone(good);rehashed.events[0].label='forged';
  let prev='0'.repeat(64);for(const event of rehashed.events){event.previous=prev;const {hash,...payload}=event;event.hash=digest(payload);prev=event.hash;}
  assert.equal(verifyBundle(rehashed,fp).ok,false);
  const forged=structuredClone(good);const keys=crypto.generateKeyPairSync('ed25519');
  forged.publicKey=keys.publicKey.export({type:'spki',format:'pem'});
  forged.checkpoint.signature=crypto.sign(null,Buffer.from(canonical(forged.checkpoint.payload)),keys.privateKey).toString('base64');
  assert.equal(verifyBundle(forged,fp).ok,false);
});
test('ledger survives restart; corrupt or incomplete stores fail closed',t=>{
  const root=temporary(t);const lab=new Lab(root);lab.demo('intrusion');const restarted=new Ledger(root);
  assert.equal(restarted.bundle().events.length,4);
  const events=restarted.read();events[0].label='disk tampering';
  fs.writeFileSync(path.join(root,'events.jsonl'),events.map(e=>JSON.stringify(e)).join('\n')+'\n');
  assert.throws(()=>restarted.append({action:'test'}),/integrity failure/);
  assert.throws(()=>new Ledger(root),/integrity failure/);
  fs.unlinkSync(path.join(root,'keys','private.pem'));
  assert.throws(()=>new Ledger(root),/Incomplete/);
});
test('evidence verifier exits successfully only with valid independently trusted evidence',t=>{
  const root=temporary(t);const lab=new Lab(path.join(root,'store'));lab.demo('benign');
  const file=path.join(root,'export.json');fs.writeFileSync(file,JSON.stringify(lab.ledger.bundle()));
  const cli=path.resolve(__dirname,'../verify.js');
  assert.equal(spawnSync(process.execPath,[cli,file,lab.ledger.fingerprint]).status,0);
  assert.equal(spawnSync(process.execPath,[cli,file,'incorrect-fingerprint']).status,1);
  assert.equal(spawnSync(process.execPath,[cli,file]).status,2);
});
test('placement replay is deterministic and reports balanced held-out denominators',()=>{
  const a=experiment(42);assert.deepEqual(a,experiment(42));assert.equal(a.heldout,240);
  for(const row of a.rows){assert.equal(new Set(row.placement).size,2);assert.equal(row.training.attacks,60);assert.equal(row.test.attacks,120);assert.equal(row.test.benign,120);assert.ok(row.test.detectionRate>=0&&row.test.detectionRate<=1);}
  assert.ok(a.rows[2].training.detectionRate-a.rows[2].training.falsePositiveRate>=a.rows[0].training.detectionRate-a.rows[0].training.falsePositiveRate);
});
