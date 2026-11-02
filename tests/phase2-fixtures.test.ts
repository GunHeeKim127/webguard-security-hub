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

test('original verification recomputes from bytes and refuses mixed or forged claims',/** test 콜백: 테스트: original verification recomputes from bytes and refuses mixed or forged claims 주요 호출: readFile·toString·runAssessment. */ async()=>{
 for(const [moduleId,name] of [['application.pe','windows-pe-vulnerable.exe'],['application.macho','macos-macho-vulnerable.macho'],['application.package','android-vulnerable.apk']] as const){
  const bytes=await readFile('tests/fixtures/phase2/'+name);
  const data={moduleId,label:'Original verification',authorized:true,originalUpload:true,base64:bytes.toString('base64')};
  const report=await runAssessment(assessmentInput(data),{locale:'en',signal:AbortSignal.timeout(5000)});
  assert.equal(report.integrity?.status,'server-recomputed');
  assert.equal(report.integrity?.sha256,createHash('sha256').update(bytes).digest('hex'));
  assert.equal(report.integrity?.bytes,bytes.length);
  assert(report.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.status==='warning'));
  assert(!report.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.id==='provenance'));
  assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({...data,snapshot:{}}));
  assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({...data,integrity:{status:'server-recomputed'}}));
  assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({...data,originalUpload:false}));
  assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({...data,base64:42}));
  assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({...data,userId:'another-account'}));
  assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput·toString·alloc. */ ()=>assessmentInput({...data,base64:Buffer.alloc(2097153).toString('base64')}));
  await assert.rejects(runAssessment(assessmentInput({...data,base64:Buffer.from('not an executable or package').toString('base64')}),{locale:'en',signal:AbortSignal.timeout(5000)}));
 }
 const bytes=await readFile('tests/fixtures/phase2/windows-pe-remediated.exe');
 const snapshot=await inspectExecutable({size:bytes.length,read:/** inspectExecutable 콜백: inspectExecutable에서 전달한 값을 처리하는 콜백입니다 주요 호출: subarray. */ async(o:number,n:number)=>bytes.subarray(o,o+n)},'pe');
 const report=await runAssessment(assessmentInput({moduleId:'application.pe',label:'Self report',authorized:true,snapshot}),{locale:'en',signal:AbortSignal.timeout(5000)});
 assert.deepEqual(report.integrity,{status:'unverified-summary'});
 assert.equal(compareAssessments(report,{...report,integrity:{status:'server-recomputed',basis:'received-file-bytes'}}).compatible,false);
});
const cases=[['linux','linux.ssh','sshd_config',5],['windows','windows.policy','json',6],['vmware','virtualization.vmx','vmx',6],['gns3','network.gns3','gns3',2],['windows-pe','application.pe','exe',3],['macos-macho','application.macho','macho',3],['android','application.package','apk',3],['ios','application.package','ipa',1]] as const;
for(const [name,moduleId,extension,warnings]of cases)test(`paired synthetic ${name}: warnings change; unknown checks stay unknown`,/** test 콜백: 지정된 검증 시나리오의 기대 결과를 확인합니다 주요 호출: readFile·inspectPackage·inspectExecutable. */ async()=>{
 const results:AssessmentReport[]=[];
 for(const variant of ['vulnerable','remediated']){
  const bytes=await readFile(`tests/fixtures/phase2/${name}-${variant}.${extension}`),source={size:bytes.length,read:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: subarray. */ async(o:number,n:number)=>bytes.subarray(o,o+n)};
  const payload=moduleId==='application.package'?{snapshot:await inspectPackage(source)}:moduleId==='application.pe'||moduleId==='application.macho'?{snapshot:await inspectExecutable(source,moduleId==='application.pe'?'pe':'macho')}:{text:bytes.toString()};
  results.push(await runAssessment(assessmentInput({moduleId,label:'Synthetic review',authorized:true,...payload}),{locale:'ko',signal:AbortSignal.timeout(5000)}));
 }
 assert.equal(results[0].findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning').length,warnings);
 if(!moduleId.startsWith('application.'))for(let i=0;i<2;i++){
  assert.equal(results[i].integrity?.status,'server-recomputed');
  assert.equal(results[i].integrity?.basis,'received-utf8-text');
  const bytes=await readFile(`tests/fixtures/phase2/${name}-${i===0?'vulnerable':'remediated'}.${extension}`);
  assert.equal(results[i].integrity?.sha256,createHash('sha256').update(bytes).digest('hex'));
 }
 assert.equal(results[1].findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning').length,0);
 const unknown=/** unknown: 검증 시나리오에서 unknown에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: map·filter. */ (n:number)=>results[n].findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='not_assessed').map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ f=>f.id);
 assert.deepEqual(unknown(1),unknown(0));
 if(moduleId.startsWith('application.')){assert(unknown(1).length>0);assert.equal(results[1].findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='pass').length,0);}
});
