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
import {explainFinding,orderedFindings,statusCopy} from '../lib/assessment/explanation';
import type {Finding} from '../lib/assessment/types';

test('readable findings prioritize warnings without changing stored verdicts or evidence',()=>{
 const make=(id:string,status:Finding['status'],severity:Finding['severity']):Finding=>Object.freeze({id,title:id,status,severity,evidence:['explicit=true'],remediation:'Original guidance'});
 const original=Object.freeze([make('pass','pass','info'),make('medium-a','warning','medium'),make('unknown','not_assessed','info'),make('high','warning','high'),make('medium-b','warning','medium'),make('observed','info','info')]);
 const before=JSON.stringify(original),sorted=orderedFindings(original);
 assert.deepEqual(sorted.map(f=>f.id),['high','medium-a','medium-b','unknown','observed','pass']);
 assert.equal(JSON.stringify(original),before);assert.equal(sorted[0],original[3]);assert.equal(sorted[3].status,'not_assessed');
});
test('plain explanations preserve profile and architecture identity with original fallback',()=>{
 const f:Finding={id:'arch-2:nx',title:'DEP/NX',status:'warning',severity:'medium',evidence:['declared=false'],remediation:'Original next step'};
 assert.match(explainFinding(f,'application.pe','ko').title,/실행 형식 2/);
 assert.match(explainFinding(f,'application.pe','ko').action,/제작자/);
 assert.match(explainFinding({...f,id:'mobile:content-security-policy'},'web.compare','ko').title,/^모바일/);
 const unknown={...f,id:'future-check',title:'Future check'};
 assert.equal(explainFinding(unknown,'application.pe','en').action,unknown.remediation);
 assert.equal(f.status,'warning');assert.deepEqual(f.evidence,['declared=false']);
});
test('unverified advisory presentation does not claim a confirmed vulnerability or pass',()=>{
 const f:Finding={id:'desktop:technology:PHP:CVE-2026-109618',title:'Advisory',status:'not_assessed',severity:'info',evidence:['versionRangeMatch=unknown'],remediation:'Check provider guidance'};
 const copy=explainFinding(f,'web.compare','ko');
 assert.match(copy.why,/확정된 것은 아닙니다/);assert.match(copy.action,/실제 설치 버전/);
 assert.equal(statusCopy[f.status].ko,'아직 확인하지 못함');assert.equal(f.status,'not_assessed');
});

test('GNS3 version gate rejects unsupported majors and malformed versions before analysis',async()=>{
 const context={locale:'en' as const,signal:new AbortController().signal},input=(version:unknown)=>({moduleId:'network.gns3',label:'Version boundary',authorized:true,text:JSON.stringify({type:'topology',version,topology:{nodes:[],links:[]}})});
 for(const version of ['999.0','3.0.0','1.5','2','2.x','2.2.61<script>',null])assert.throws(()=>assessmentInput(input(version)));
 for(const version of ['2.2','2.2.61','2.2.61-beta.1'])assert.equal((await runAssessment(assessmentInput(input(version)),context)).moduleId,'network.gns3');
});
import {protectedRequest} from '../lib/protected-request';
import {parseVmx,parseGns3} from '../lib/assessment/infrastructure-modules';

test('VMX explicit unsafe flags warn; missing values remain unassessed and private fields never enter reports',async()=>{
 const text='config.version = "8"\nvirtualHW.version = "21"\nisolation.tools.copy.disable = "FALSE"\nisolation.tools.paste.disable = "TRUE"\nethernet0.connectionType = "bridged"\nRemoteDisplay.vnc.enabled = "TRUE"\ndisplayName = "PRIVATE_VM_NAME"\nsharedFolder0.hostPath = "PRIVATE_HOST_PATH"';
 const input=assessmentInput({moduleId:'virtualization.vmx',label:'VMX check',authorized:true,text});
 const result=await runAssessment(input,{locale:'ko',signal:new AbortController().signal});
 assert.equal(result.findings.find(f=>f.id==='copy')?.status,'warning');assert.equal(result.findings.find(f=>f.id==='paste')?.status,'pass');
 assert.equal(result.findings.find(f=>f.id==='dragDrop')?.status,'not_assessed');assert.equal(result.findings.find(f=>f.id==='networkBoundary')?.status,'warning');
 assert.equal(result.findings.find(f=>f.id==='remoteConsole')?.status,'warning');
 assert(!JSON.stringify(result).includes('PRIVATE_'));assert.throws(()=>parseVmx({...input,text:text+'\nCONFIG.VERSION = "9"'}));
 assert.throws(()=>parseVmx({...input,text:'something = "not a VMX"'}));assert.throws(()=>parseVmx({...input,text:'x'.repeat(65537)}));
});

test('GNS3 topology flags explicit external boundaries and non-loopback consoles without claiming device security',async()=>{
 const topology={type:'topology',version:'2.2.61',name:'PRIVATE_LAB',topology:{nodes:[{node_id:'a',node_type:'vpcs',console_host:'127.0.0.1',name:'PRIVATE_NODE'},{node_id:'b',node_type:'cloud',console_host:'0.0.0.0',properties:{password:'PRIVATE_SECRET'}}],links:[{nodes:[{node_id:'a'},{node_id:'b'}]}]}};
 const input=assessmentInput({moduleId:'network.gns3',label:'Lab check',authorized:true,text:JSON.stringify(topology)});
 const result=await runAssessment(input,{locale:'en',signal:new AbortController().signal});
 assert.equal(result.findings.find(f=>f.id==='externalBoundary')?.status,'warning');assert.equal(result.findings.find(f=>f.id==='consoleBinding')?.status,'warning');
 assert.equal(result.findings.find(f=>f.id==='devicePolicy')?.status,'not_assessed');assert(!JSON.stringify(result).includes('PRIVATE_'));
 delete (topology.topology.nodes[1] as any).console_host;
 const missing=await runAssessment({...input,text:JSON.stringify(topology)},{locale:'en',signal:new AbortController().signal});assert.equal(missing.findings.find(f=>f.id==='consoleBinding')?.status,'not_assessed');
 topology.topology.links[0].nodes[1].node_id='missing';assert.throws(()=>parseGns3({...input,text:JSON.stringify(topology)}));
 assert.throws(()=>parseGns3({...input,text:JSON.stringify({type:'not-topology',topology:{nodes:[],links:[]}})}));
});

test('infrastructure inspection remains bounded and rejects cancellation before parsing',async()=>{
 const stop=new AbortController();stop.abort();
 await assert.rejects(runAssessment({moduleId:'network.gns3',label:'lab',text:'{}'},{locale:'en',signal:stop.signal}));
 assert.throws(()=>assessmentInput({moduleId:'virtualization.vmx',label:'lab',authorized:false,text:'config.version = "8"'}));
 assert.throws(()=>assessmentInput({moduleId:'network.gns3',label:'lab',authorized:true,snapshot:{}}));
});
import type {AssessmentContext} from '../lib/assessment/types';
const context=():AssessmentContext=>({locale:'ko',signal:AbortSignal.timeout(20000)});
const ssh=(text:string)=>assessmentInput({moduleId:'linux.ssh',label:'router lab',text,authorized:true});
const safe='PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\nMaxAuthTries 4';
test('assessment retry only replays an explicit pre-handler protection failure, once',async()=>{
 const payload=JSON.stringify({moduleId:'linux.ssh',authorized:true});let calls=0;
 const response=await protectedRequest('/api/assessments',{method:'POST',body:payload},async(_url,init)=>{
  calls++;assert.equal(init?.body,payload);
  return calls===1?Response.json({errorCode:'PROTECTION_UNAVAILABLE'},{status:503}):Response.json({saved:true});
 });
 assert.equal(calls,2);assert.deepEqual(await response.json(),{saved:true});
 calls=0;const unavailable=await protectedRequest('/api/assessments',{},async()=>{calls++;return Response.json({errorCode:'PROTECTION_UNAVAILABLE'},{status:503});});
 assert.equal(calls,2);assert.equal(unavailable.status,503);
 for(const [status,errorCode]of [[503,'SERVICE_UNAVAILABLE'],[403,'IP_BLACKLISTED'],[429,'THREAT_BLOCKED'],[400,'INPUT_INVALID'],[200,'PROTECTION_UNAVAILABLE']] as const){
  calls=0;await protectedRequest('/api/assessments',{},async()=>{calls++;return Response.json({errorCode},{status});});assert.equal(calls,1);
 }
 calls=0;await assert.rejects(protectedRequest('/api/assessments',{},async()=>{calls++;throw new Error('AMBIGUOUS_NETWORK_FAILURE');}),/AMBIGUOUS_NETWORK_FAILURE/);assert.equal(calls,1);
 calls=0;await protectedRequest('/api/assessments',{},async()=>{calls++;return new Response('not JSON',{status:503});});assert.equal(calls,1);
});
test('cancelled assessments never replay during the protection retry wait',async()=>{
 const controller=new AbortController();let calls=0;
 const pending=protectedRequest('/api/assessments',{signal:controller.signal},async()=>{calls++;return Response.json({errorCode:'PROTECTION_UNAVAILABLE'},{status:503});});
 setTimeout(()=>controller.abort(),30);
 await assert.rejects(pending,{name:'AbortError'});assert.equal(calls,1);
});
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
