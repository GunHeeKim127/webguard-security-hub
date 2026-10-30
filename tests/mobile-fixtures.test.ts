import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {inspectPackage} from '../public/tools/package-inspector.mjs';
import {assessmentInput} from '../lib/assessment/input';
import {runAssessment} from '../lib/assessment/registry';
const root='tests/fixtures/mobile-2026-10-30';
async function inspect(name:string){const bytes=await readFile(`${root}/${name}`);return inspectPackage({size:bytes.length,read:async(o:number,n:number)=>bytes.subarray(o,o+n)});}
for(const format of ['ipa','aab','apks','xapk'] as const)test(`synthetic ${format}: supported declarations change; unsupported checks remain unknown`,async()=>{
 const findings=[];
 for(const variant of ['vulnerable','remediated']){
  const snapshot=await inspect(`${format}-${variant}.${format}`);assert.equal(snapshot.format,format);
  const report=await runAssessment(assessmentInput({moduleId:'application.package',label:'Synthetic package',authorized:true,snapshot}),{locale:'en',signal:AbortSignal.timeout(5000)});
  if(format==='ipa'){assert.equal(snapshot.settings.arbitraryLoads,variant==='vulnerable');assert.equal(report.findings.find(f=>f.id==='arbitraryLoads')?.status,variant==='vulnerable'?'warning':'info');}
  else{assert.equal(snapshot.settings.decoded,false);for(const [key,value]of Object.entries(snapshot.settings))if(key!=='decoded')assert.equal(value,null);assert.equal(report.findings.filter(f=>f.status==='warning').length,0);assert.equal(report.findings.filter(f=>f.status==='not_assessed').length,6);}
  assert.equal(report.findings.filter(f=>f.status==='pass').length,0);
  for(const id of ['signature-trust','code-vulnerabilities','nested-packages'])assert.equal(report.findings.find(f=>f.id===id)?.status,'not_assessed');
  findings.push(report.findings.filter(f=>f.status==='not_assessed').map(f=>f.id));
 }
 assert.deepEqual(findings[0],findings[1]);
});
test('malformed and traversal mobile dummy inputs are rejected before any result can be assessed',async()=>{for(const name of ['reject-traversal.ipa','reject-not-a-package.ipa'])await assert.rejects(inspect(name));});
test('mobile dummy manifest hashes describe the on-disk fixture bytes',async()=>{const manifest=JSON.parse(await readFile(`${root}/manifest.json`,'utf8'));assert.equal(manifest.synthetic,true);assert.equal(manifest.originalsExecuted,false);for(const f of manifest.fixtures){const bytes=await readFile(`${root}/${f.name}`);assert.equal(createHash('sha256').update(bytes).digest('hex'),f.sha256);assert.equal(bytes.length,f.size);assert.equal(f.installable,false);}});
