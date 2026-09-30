'use strict';
const fs=require('node:fs');
const {verifyBundle}=require('./lib');
const [file,trustedFingerprint]=process.argv.slice(2);
if(!file||!trustedFingerprint){console.error('Usage: node verify.js <evidence.json> <separately-saved-trusted-fingerprint>');process.exitCode=2;}
else{try{const result=verifyBundle(JSON.parse(fs.readFileSync(file,'utf8')),trustedFingerprint);console.log(JSON.stringify(result,null,2));process.exitCode=result.ok?0:1;}catch(e){console.error(e.message);process.exitCode=1;}}
