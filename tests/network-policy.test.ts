import test from 'node:test';
import assert from 'node:assert/strict';
import {assessmentInput} from '../lib/assessment/input';
import {runAssessment} from '../lib/assessment/registry';
import {compareAssessments} from '../lib/assessment/compare';
import {findingContext} from '../lib/assessment/finding-context';
const scan=/** scan: 검증 시나리오에서 scan에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: runAssessment·assessmentInput·stringify. */ (format:'bind9'|'cisco-ios',configuration:string)=>runAssessment(assessmentInput({moduleId:'network.gns3',label:'Network policy local test',authorized:true,text:JSON.stringify({type:'network-security-config',schemaVersion:1,format,configuration})}),{locale:'ko',signal:AbortSignal.timeout(5000)});
test('BIND explicit broad access/disabled validation versus restricted declarations, never safe verdict',/** test 콜백: 테스트: BIND explicit broad access/disabled validation versus restricted declarations, never safe verdict 주요 호출: scan·equal·filter. */ async()=>{
 const risky=await scan('bind9','options { recursion yes; allow-recursion { any; }; allow-transfer { any; }; dnssec-validation no; };');
 assert.equal(risky.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning').length,3);
 const restricted=await scan('bind9','options { recursion yes; allow-recursion { localhost; }; allow-transfer { none; }; dnssec-validation auto; };');
 assert.equal(restricted.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning'||f.status==='pass').length,0);
 assert.equal(restricted.integrity?.basis,'received-utf8-text');
});
test('BIND comments/strings cannot manufacture declarations or leak secrets',/** test 콜백: 테스트: BIND comments/strings cannot manufacture declarations or leak secrets 주요 호출: scan·assert·every. */ async()=>{
 const r=await scan('bind9','// allow-transfer { any; };\noptions { /* recursion yes; */ directory "SECRET_PATH allow-transfer { any; }"; }; key "SECRET_KEY" { secret "SECRET_VALUE"; };');
 assert(r.findings.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));
 assert(!JSON.stringify(r).includes('SECRET'));
});
test('BIND includes/views/duplicate scopes and missing values remain unknown',/** test 콜백: 테스트: BIND includes/views/duplicate scopes and missing values remain unknown 주요 호출: scan·assert·every. */ async()=>{
 for(const s of ['include "private.conf"; options { recursion yes; allow-recursion { any; }; };','view "private" { options { recursion yes; }; };','options { recursion yes; }; options { recursion no; };']){
  const r=await scan('bind9',s);assert(r.findings.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));
 }
 const r=await scan('bind9','options { recursion yes; recursion no; allow-recursion { any; }; };');assert.equal(r.findings[0].status,'not_assessed');
 await assert.rejects(scan('bind9','options { recursion yes;'));
});
test('authoritative DNS does not require recursive validation',/** test 콜백: 테스트: authoritative DNS does not require recursive validation 주요 호출: scan·equal. */ async()=>{
 const r=await scan('bind9','options { recursion no; dnssec-validation no; };');assert.equal(r.findings[2].status,'info');
});
test('IOS routes distinguish explicit weak auth from absent data and digest declarations',/** test 콜백: 테스트: IOS routes distinguish explicit weak auth from absent data and digest declarations 주요 호출: scan·equal·filter. */ async()=>{
 const r=await scan('cisco-ios','router rip\n version 1\n!\nrouter eigrp 100\n!\nrouter isis LAB\n authentication mode text\n!\ninterface Ethernet0\n ip rip authentication mode text\n no ip authentication mode eigrp 100 md5\n');
 assert.equal(r.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning').length,4);
 const protectedR=await scan('cisco-ios','router rip\n version 2\n!\nrouter eigrp 100\n!\nrouter isis LAB\n authentication mode md5\n!\ninterface Ethernet0\n ip rip authentication mode md5\n ip authentication mode eigrp 100 md5\n ip authentication key-chain eigrp 100 SECRET_CHAIN\n');
 assert.equal(protectedR.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning'||f.status==='pass').length,0);assert.equal(protectedR.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='info').length,3);assert(!JSON.stringify(protectedR).includes('SECRET_CHAIN'));
 const missing=await scan('cisco-ios','router rip\n network 10.0.0.0\n');assert(missing.findings.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));
});
test('IOS unrelated process versions, comments and named EIGRP do not become false safe results',/** test 콜백: 테스트: IOS unrelated process versions, comments and named EIGRP do not become false safe results 주요 호출: scan·assert·every. */ async()=>{
 const r=await scan('cisco-ios','router ospf 1\n version 1\n!\nrouter rip\n version 2\n!\nrouter eigrp NAMED\n address-family ipv4 unicast autonomous-system 100\n authentication mode hmac-sha-256 SECRET\n!\n! ip rip authentication mode text\n');
 assert(r.findings.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));assert(!JSON.stringify(r).includes('SECRET'));
});
test('network envelope rejects unknown fields, unsupported vendor, empty/missing configuration',/** test 콜백: 테스트: network envelope rejects unknown fields, unsupported vendor, empty/missing configuration 주요 호출: throws. */ ()=>{
 for(const extra of [{format:'junos'},{configuration:''},{configuration:42},{schemaVersion:2},{secret:'SECRET'}])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput·stringify. */ ()=>assessmentInput({moduleId:'network.gns3',label:'Invalid',authorized:true,text:JSON.stringify({type:'network-security-config',schemaVersion:1,format:'bind9',configuration:'options {};',...extra})}));
});
test('network report context is specific and different evidence formats cannot be compared',/** test 콜백: 테스트: network report context is specific and different evidence formats cannot be compared 주요 호출: scan·match·findingContext. */ async()=>{
 const dns=await scan('bind9','options { recursion yes; allow-recursion { any; }; };'),ios=await scan('cisco-ios','router rip\n version 1\n');
 assert.match(findingContext(dns.findings[0],dns,'ko').observed,/any/);
 assert.equal(compareAssessments(dns,ios).compatible,false);
});
