import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {inspectJavaRuntime,javaRuntimeInput,type JavaRuntimeInput} from '../lib/java-runtime-review';
import JavaReview from '../app/workbench/java/java-client';
import {observeTechnology,technologyFindings} from '../lib/web-technology';
const base:JavaRuntimeInput={version:'17.0.21.0.3',vendor:'oracle',architecture:'x64',cpuFeatures:'supported',intrinsic:'enabled',untrustedBase64:'yes',performancePack:'no'};
test('Java4Shell distinguishes affected security suffixes from November fixed releases',()=>{
 for(const [before,after]of [['17.0.21.0.3','17.0.21.1+4'],['21.0.13.0.3','21.0.13.1'],['25.0.5.0.3','25.0.5.1'],['27.0.1.0.3','27.0.1.1']]){
  assert.equal(inspectJavaRuntime({...base,version:before}).summary.code,'update_recommended');
  const report=inspectJavaRuntime({...base,version:after});assert.equal(report.summary.code,'baseline_met');assert(report.checks.every(c=>c.status!=='warning'));assert(!JSON.stringify(report).includes('"status":"pass"'));
 }
});
test('hardware, missing evidence and mitigations never erase an old-runtime update recommendation',()=>{
 for(const fields of [{architecture:'arm64'},{cpuFeatures:'unknown'},{intrinsic:'disabled'},{untrustedBase64:'no'}]){
  const report=inspectJavaRuntime({...base,...fields});assert.equal(report.summary.code,'update_recommended');assert(report.checks.some(c=>c.id==='version'&&c.status==='warning'));
 }
 assert.equal(inspectJavaRuntime({...base,version:'17.0'}).summary.code,'needs_evidence');
 for(const vendor of ['graalvm','other','unknown'])assert.equal(inspectJavaRuntime({...base,vendor}).summary.code,'needs_evidence');
 assert.equal(inspectJavaRuntime({...base,version:'17.0.5'}).checks[0].status,'info');
});
test('Oracle performance builds are distinct from ordinary Java 8 and unsupported versions',()=>{
 assert.equal(inspectJavaRuntime({...base,version:'8u511b33-perf',performancePack:'yes'}).summary.code,'update_recommended');
 assert.equal(inspectJavaRuntime({...base,version:'1.8.0_513-b04',performancePack:'yes'}).summary.code,'baseline_met');
 assert.equal(inspectJavaRuntime({...base,version:'8u511',performancePack:'unknown'}).summary.code,'needs_evidence');
 assert.equal(inspectJavaRuntime({...base,version:'8u511',performancePack:'no'}).checks[0].status,'info');
 assert.equal(inspectJavaRuntime({...base,version:'22.0.1'}).summary.code,'needs_evidence');
});
test('structured runtime input rejects extra fields, control data and invalid enums',()=>{
 for(const input of [null,[],{...base,url:'https://example.invalid'},{...base,version:'x'.repeat(81)},{...base,version:'17\nsecret'},{...base,intrinsic:'false'},{version:'17.0.21'}])assert.throws(()=>javaRuntimeInput(input));
 assert.equal(javaRuntimeInput({...base,version:' 17.0.21.1 '}).version,'17.0.21.1');
 const unknown=inspectJavaRuntime({...base,version:'',cpuFeatures:'unknown',intrinsic:'unknown',architecture:'unknown',untrustedBase64:'unknown'});
 assert.equal(unknown.summary.code,'needs_evidence');assert(unknown.checks.some(c=>c.status==='not_assessed'));
});
test('Tomcat and Spring banners request JVM evidence rather than establishing Java4Shell',()=>{
 const findings=technologyFindings(observeTechnology({'x-powered-by':'Spring/5.3.17','server':'Apache Tomcat/9.0.0'},200),'ko');
 const java=findings.filter(f=>f.id.includes('CVE-2026-114938'));assert.equal(java.length,2);assert(java.every(f=>f.status==='not_assessed'));assert(java.every(f=>f.evidence.includes('jvmVersionVerified=false')));
 assert(!technologyFindings(observeTechnology({server:'nginx'},200),'en').some(f=>f.id.includes('CVE-2026-114938')));
});
test('runtime screen is categorized as Endpoint and exposes consent and unknown defaults',()=>{
 const html=renderToStaticMarkup(createElement(JavaReview,{locale:'ko'}));assert(html.includes('ENDPOINT'));assert(html.includes('Java4Shell'));assert(html.includes('확인하지 못함'));assert(html.includes('실제 기기에 접속하거나 변경하지 않는 점'));assert(html.includes('Log4Shell과는 다른'));assert(html.includes('disabled'));
});
