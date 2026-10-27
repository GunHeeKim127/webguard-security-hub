import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {inspectExecutable} from '../public/tools/executable-inspector.mjs';
import {inspectPackage} from '../public/tools/package-inspector.mjs';
import {assessmentInput} from '../lib/assessment/input';
import {runAssessment} from '../lib/assessment/registry';
import type {AssessmentReport} from '../lib/assessment/types';
const cases=[['linux','linux.ssh','sshd_config',5],['windows','windows.policy','json',6],['vmware','virtualization.vmx','vmx',6],['gns3','network.gns3','gns3',2],['windows-pe','application.pe','exe',3],['macos-macho','application.macho','macho',3],['android','application.package','apk',3],['ios','application.package','ipa',1]] as const;
for(const [name,moduleId,extension,warnings]of cases)test(`paired synthetic ${name}: warnings change; unknown checks stay unknown`,async()=>{
 const results:AssessmentReport[]=[];
 for(const variant of ['vulnerable','remediated']){
  const bytes=await readFile(`tests/fixtures/phase2/${name}-${variant}.${extension}`),source={size:bytes.length,read:async(o:number,n:number)=>bytes.subarray(o,o+n)};
  const payload=moduleId==='application.package'?{snapshot:await inspectPackage(source)}:moduleId==='application.pe'||moduleId==='application.macho'?{snapshot:await inspectExecutable(source,moduleId==='application.pe'?'pe':'macho')}:{text:bytes.toString()};
  results.push(await runAssessment(assessmentInput({moduleId,label:'Synthetic review',authorized:true,...payload}),{locale:'ko',signal:AbortSignal.timeout(5000)}));
 }
 assert.equal(results[0].findings.filter(f=>f.status==='warning').length,warnings);
 assert.equal(results[1].findings.filter(f=>f.status==='warning').length,0);
 const unknown=(n:number)=>results[n].findings.filter(f=>f.status==='not_assessed').map(f=>f.id);
 assert.deepEqual(unknown(1),unknown(0));
 if(moduleId.startsWith('application.')){assert(unknown(1).length>0);assert.equal(results[1].findings.filter(f=>f.status==='pass').length,0);}
});
