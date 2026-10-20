import test from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import https from 'node:https';
import {EventEmitter} from 'node:events';
import {assessmentInput} from '../lib/assessment/input';
import {scannerFor,runAssessment} from '../lib/assessment/registry';
import {compareAssessments} from '../lib/assessment/compare';
import {peMetadata,apkMetadata} from '../lib/assessment/binary-modules';
import {trafficSignals} from '../lib/assessment/store';
import {body} from '../lib/request';
import type {AssessmentContext} from '../lib/assessment/types';
const context=():AssessmentContext=>({locale:'ko',signal:AbortSignal.timeout(20000)});
const ssh=(text:string)=>assessmentInput({moduleId:'linux.ssh',label:'router lab',text,authorized:true});
const safe='PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\nMaxAuthTries 4';
function pe(){const b=Buffer.alloc(1024);b.write('MZ');b.writeUInt32LE(64,60);b.writeUInt32LE(0x4550,64);b.writeUInt16LE(0x8664,68);b.writeUInt16LE(1,70);b.writeUInt16LE(240,84);const o=88;b.writeUInt16LE(0x20b,o);b.writeUInt16LE(0x140,o+70);b.writeUInt32LE(16,o+108);b.writeUInt32LE(512,o+240+16);b.writeUInt32LE(512,o+240+20);b.writeUInt32LE(0x60000020,o+240+36);return b;}
function apk(){const name=Buffer.from('AndroidManifest.xml'),data=Buffer.alloc(4),local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(name.length,26);local.writeUInt32LE(4,18);local.writeUInt32LE(4,22);const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(name.length,28);central.writeUInt32LE(4,20);central.writeUInt32LE(4,24);const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+name.length,12);end.writeUInt32LE(local.length+name.length+data.length,16);return Buffer.concat([local,name,data,central,name,end]);}
test('module catalog is allowlisted; permission, target type and size validation cannot be bypassed',()=>{
 assert.throws(()=>scannerFor('../../evil'));
 assert.throws(()=>assessmentInput({moduleId:'linux.ssh',label:'lab',text:safe,authorized:false}));
 assert.throws(()=>assessmentInput({moduleId:'linux.ssh',label:'lab',text:safe,url:'https://example.com',authorized:true}));
 assert.throws(()=>ssh('PermitRootLogin no\n'+'#'.repeat(65536)));
 assert.throws(()=>assessmentInput({moduleId:'linux.ssh',label:'<script>',text:safe,authorized:true}));
 assert.throws(()=>assessmentInput({moduleId:'web.compare',label:'lab',url:'https://127.0.0.1',authorized:true}));
 assert.throws(()=>assessmentInput({moduleId:'linux.ssh',label:'lab',text:safe,userId:'other',authorized:true}));
});
test('SSH snapshots use explicit first values, report Include/Match as unassessed and never retain secrets',async()=>{
 const report=await runAssessment(ssh(safe+'\n# secret-token-123\nHostKey /private/secret-key'),context());assert(report.findings.every(f=>f.status==='pass'));assert(!JSON.stringify(report).includes('secret'));
 const duplicate=await runAssessment(ssh('PermitRootLogin yes\n'+safe),context());assert.equal(duplicate.findings[0].status,'warning');
 for(const extra of ['Include /etc/ssh/*.conf','Match User private-user']){const conditional=await runAssessment(ssh(safe+'\n'+extra),context());assert(conditional.findings.every(f=>f.status==='not_assessed'));assert(!JSON.stringify(conditional).includes('private-user'));}
});
test('Windows snapshot distinguishes unknowns, disabled states and RDP NLA and ignores extra private values',async()=>{
 const a=await runAssessment(assessmentInput({moduleId:'windows.policy',label:'pc',authorized:true,text:JSON.stringify({schemaVersion:1,firewall:{public:false},rdp:{enabled:false},password:'never-persist-this'})}),context());
 assert.equal(a.findings.find(f=>f.id==='firewall.public')?.status,'warning');assert.equal(a.findings.find(f=>f.id==='firewall.domain')?.status,'not_assessed');assert.equal(a.findings.find(f=>f.id==='rdp.nla')?.status,'info');assert(!JSON.stringify(a).includes('never-persist'));
});
test('PE parser validates offsets and bounds; certificate presence never becomes a signature trust verdict',async()=>{
 const valid=pe();assert.equal(peMetadata(valid).flags,0x140);const r=await runAssessment(assessmentInput({moduleId:'application.pe',label:'app',authorized:true,base64:valid.toString('base64')}),context());assert.equal(r.findings.find(f=>f.id==='authenticode')?.status,'not_assessed');
 for(const cut of [0,10,64,90,300])assert.throws(()=>peMetadata(valid.subarray(0,cut)));
 const bad=Buffer.from(valid);bad.writeUInt32LE(0xffffffff,60);assert.throws(()=>peMetadata(bad));
});
test('APK inventory is bounded, rejects corrupt/encrypted/ZIP64 containers and never claims permission or signature inspection',async()=>{
 const valid=apk();assert.equal(apkMetadata(valid).entries,1);const r=await runAssessment(assessmentInput({moduleId:'application.apk',label:'apk',authorized:true,base64:valid.toString('base64')}),context());assert(r.findings.filter(f=>f.id!=='package-structure').every(f=>f.status==='not_assessed'));
 const encrypted=Buffer.from(valid);encrypted.writeUInt16LE(1,6);assert.throws(()=>apkMetadata(encrypted));
 const central=30+Buffer.byteLength('AndroidManifest.xml')+4;
 const split=Buffer.from(valid);split.writeUInt16LE(1,central+34);assert.throws(()=>apkMetadata(split));
 const zip64=Buffer.from(valid);zip64.writeUInt32LE(0xffffffff,central+24);assert.throws(()=>apkMetadata(zip64));
 const bad=Buffer.from(valid);bad.writeUInt32LE(0xffffffff,bad.length-6);assert.throws(()=>apkMetadata(bad));assert.throws(()=>apkMetadata(valid.subarray(0,valid.length-1)));
});
test('retest comparison never treats missing/unassessed evidence or incompatible rule versions as remediation',async()=>{
 const a=await runAssessment(ssh('PermitRootLogin yes'),context()),b=await runAssessment(ssh(safe),context());
 assert.equal(compareAssessments(a,b).changes.find(c=>c.id==='permitrootlogin')?.transition,'improved');
 const c=await runAssessment(ssh('Include extra.conf\n'+safe),context());assert(compareAssessments(b,c).changes.every(v=>v.transition==='unknown'));
 assert.equal(compareAssessments(a,{...b,ruleVersion:'next'}).compatible,false);
});
test('deadline cancellation stops even offline modules and opt-in request body size never weakens ordinary JSON limits',async()=>{
 const c=new AbortController();c.abort();await assert.rejects(runAssessment(ssh(safe),{locale:'ko',signal:c.signal}));
 const request=()=>new Request('https://hub.example/api/assessments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:'a'.repeat(5000)})});
 await assert.rejects(body(request()),{status:413});assert.equal((await body(request(),8192)).text.length,5000);
});
test('aggregate-only detection applies documented thresholds without an identity or blocking verdict',()=>{
 assert.deepEqual(trafficSignals({requests:999,login_failures:4,probes:2,server_errors:4}),{loginFailures:false,probes:false,serverErrors:false,highVolume:false});assert(Object.values(trafficSignals({requests:1000,login_failures:5,probes:3,server_errors:5})).every(Boolean));
});
test('web module performs exactly two pinned HEAD requests with separate User-Agents, no credentials and redacted evidence',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);const agents:string[]=[];
 const transport=t.mock.method(https,'request',(_url:URL,options:any,callback:Function)=>{assert.equal(options.method,'HEAD');assert.equal(options.rejectUnauthorized,true);assert.equal(options.headers.Cookie,undefined);assert.equal(options.headers.Authorization,undefined);agents.push(options.headers['User-Agent']);const req=new EventEmitter() as any;req.end=()=>{callback({statusCode:200,headers:{'set-cookie':['private=SECRET; Secure; SameSite=Lax']},socket:{authorized:true,getProtocol:()=> 'TLSv1.3',getPeerCertificate:()=>({valid_to:'Jan 1 00:00:00 2030 GMT'})},destroy(){}});req.emit('close');};req.destroy=(e:Error)=>{req.emit('error',e);req.emit('close');};return req;});
 const before=process.env.SCAN_TARGET_POLICY;process.env.SCAN_TARGET_POLICY='public';try{const r=await runAssessment(assessmentInput({moduleId:'web.compare',label:'web',url:'https://owned.example',authorized:true}),context());assert.equal(transport.mock.callCount(),2);assert.equal(agents.filter(a=>a.includes('Mobile')).length,1);assert(!JSON.stringify(r).includes('SECRET'));assert(r.findings.some(f=>f.id==='profile-comparison'));}finally{if(before===undefined)delete process.env.SCAN_TARGET_POLICY;else process.env.SCAN_TARGET_POLICY=before;}
});
