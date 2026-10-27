import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {inspectExecutable} from '../public/tools/executable-inspector.mjs';
import {inspectPackage} from '../public/tools/package-inspector.mjs';
import {assessmentInput} from '../lib/assessment/input';
import {runAssessment} from '../lib/assessment/registry';
import type {AssessmentReport} from '../lib/assessment/types';
import {createHash} from 'node:crypto';
import {compareAssessments} from '../lib/assessment/compare';

test('original verification recomputes from bytes and refuses mixed or forged claims',async()=>{
 for(const [moduleId,name] of [['application.pe','windows-pe-vulnerable.exe'],['application.macho','macos-macho-vulnerable.macho'],['application.package','android-vulnerable.apk']] as const){
  const bytes=await readFile('tests/fixtures/phase2/'+name);
  const data={moduleId,label:'Original verification',authorized:true,originalUpload:true,base64:bytes.toString('base64')};
  const report=await runAssessment(assessmentInput(data),{locale:'en',signal:AbortSignal.timeout(5000)});
  assert.equal(report.integrity?.status,'server-recomputed');
  assert.equal(report.integrity?.sha256,createHash('sha256').update(bytes).digest('hex'));
  assert.equal(report.integrity?.bytes,bytes.length);
  assert(report.findings.some(f=>f.status==='warning'));
  assert(!report.findings.some(f=>f.id==='provenance'));
  assert.throws(()=>assessmentInput({...data,snapshot:{}}));
  assert.throws(()=>assessmentInput({...data,integrity:{status:'server-recomputed'}}));
  assert.throws(()=>assessmentInput({...data,originalUpload:false}));
  assert.throws(()=>assessmentInput({...data,base64:42}));
  assert.throws(()=>assessmentInput({...data,userId:'another-account'}));
  assert.throws(()=>assessmentInput({...data,base64:Buffer.alloc(2097153).toString('base64')}));
  await assert.rejects(runAssessment(assessmentInput({...data,base64:Buffer.from('not an executable or package').toString('base64')}),{locale:'en',signal:AbortSignal.timeout(5000)}));
 }
 const bytes=await readFile('tests/fixtures/phase2/windows-pe-remediated.exe');
 const snapshot=await inspectExecutable({size:bytes.length,read:async(o:number,n:number)=>bytes.subarray(o,o+n)},'pe');
 const report=await runAssessment(assessmentInput({moduleId:'application.pe',label:'Self report',authorized:true,snapshot}),{locale:'en',signal:AbortSignal.timeout(5000)});
 assert.deepEqual(report.integrity,{status:'unverified-summary'});
 assert.equal(compareAssessments(report,{...report,integrity:{status:'server-recomputed',basis:'received-file-bytes'}}).compatible,false);
});
const cases=[['linux','linux.ssh','sshd_config',5],['windows','windows.policy','json',6],['vmware','virtualization.vmx','vmx',6],['gns3','network.gns3','gns3',2],['windows-pe','application.pe','exe',3],['macos-macho','application.macho','macho',3],['android','application.package','apk',3],['ios','application.package','ipa',1]] as const;
for(const [name,moduleId,extension,warnings]of cases)test(`paired synthetic ${name}: warnings change; unknown checks stay unknown`,async()=>{
 const results:AssessmentReport[]=[];
 for(const variant of ['vulnerable','remediated']){
  const bytes=await readFile(`tests/fixtures/phase2/${name}-${variant}.${extension}`),source={size:bytes.length,read:async(o:number,n:number)=>bytes.subarray(o,o+n)};
  const payload=moduleId==='application.package'?{snapshot:await inspectPackage(source)}:moduleId==='application.pe'||moduleId==='application.macho'?{snapshot:await inspectExecutable(source,moduleId==='application.pe'?'pe':'macho')}:{text:bytes.toString()};
  results.push(await runAssessment(assessmentInput({moduleId,label:'Synthetic review',authorized:true,...payload}),{locale:'ko',signal:AbortSignal.timeout(5000)}));
 }
 assert.equal(results[0].findings.filter(f=>f.status==='warning').length,warnings);
 if(!moduleId.startsWith('application.'))for(let i=0;i<2;i++){
  assert.equal(results[i].integrity?.status,'server-recomputed');
  assert.equal(results[i].integrity?.basis,'received-utf8-text');
  const bytes=await readFile(`tests/fixtures/phase2/${name}-${i===0?'vulnerable':'remediated'}.${extension}`);
  assert.equal(results[i].integrity?.sha256,createHash('sha256').update(bytes).digest('hex'));
 }
 assert.equal(results[1].findings.filter(f=>f.status==='warning').length,0);
 const unknown=(n:number)=>results[n].findings.filter(f=>f.status==='not_assessed').map(f=>f.id);
 assert.deepEqual(unknown(1),unknown(0));
 if(moduleId.startsWith('application.')){assert(unknown(1).length>0);assert.equal(results[1].findings.filter(f=>f.status==='pass').length,0);}
});
