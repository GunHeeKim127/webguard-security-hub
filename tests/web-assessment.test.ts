import test from 'node:test';
import assert from 'node:assert/strict';
import {assessWeb,corsProbeOrigin} from '../lib/web-assessment';
import {assessmentText} from '../lib/assessment-copy';
import {locales} from '../lib/locale';
import {scan} from '../lib/scanner';
import dns from 'node:dns/promises';
import https from 'node:https';
import {EventEmitter} from 'node:events';
const now=Date.parse('2026-10-16T00:00:00Z');
const by=/** by: 검증 시나리오에서 by에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: find·assessWeb. */ (headers:Record<string,string|string[]>,id:string)=>assessWeb(headers).find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id===id)!;
test('present but insecure header values produce review findings',/** test 콜백: 테스트: present but insecure header values produce review findings 주요 호출: equal·by·assert. */ ()=>{
 const headers={'content-security-policy':"default-src * 'unsafe-inline'; script-src https: 'unsafe-eval'",'strict-transport-security':'max-age=0','x-content-type-options':'sniff','referrer-policy':'unsafe-url'};
 for(const id of ['csp','hsts','nosniff','referrer'])assert.equal(by(headers,id).status,'warning');
 assert(by(headers,'csp').issues.includes('csp_broad'));
 assert(by(headers,'hsts').issues.includes('hsts_short'));
});
test('baseline header policies pass only their limited static checks',/** test 콜백: 테스트: baseline header policies pass only their limited static checks 주요 호출: equal·by. */ ()=>{
 const headers={'content-security-policy':"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",'strict-transport-security':'max-age=31536000; includeSubDomains','x-content-type-options':'NoSniff','referrer-policy':'invalid, strict-origin-when-cross-origin'};
 for(const id of ['csp','hsts','nosniff','referrer'])assert.equal(by(headers,id).status,'pass');
 assert.equal(by({'content-security-policy-report-only':headers['content-security-policy']},'csp').status,'warning');
});
test('HSTS malformed, duplicate and negative max-age cannot pass',/** test 콜백: 테스트: HSTS malformed, duplicate and negative max-age cannot pass 주요 호출: equal·by. */ ()=>{
 for(const v of ['max-age=-1','max-age=31536000; max-age=31536000','max-age=31536000x','max-age="31536000','nonsense'])assert.equal(by({'strict-transport-security':v},'hsts').status,'warning',v);
 assert.equal(by({'strict-transport-security':'max-age="31536000"'},'hsts').status,'pass');
});
test('certificate assessment covers expiry boundaries without claiming protocol enumeration',/** test 콜백: 테스트: certificate assessment covers expiry boundaries without claiming protocol enumeration 주요 호출: equal·tls·assert. */ ()=>{
 const tls=/** tls: 검증 시나리오에서 tls에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: find·assessWeb. */ (validTo:string|null,protocol='TLSv1.3')=>assessWeb({},{authorized:true,protocol,validTo},now).find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='tls')!;
 assert.equal(tls('2027-01-01').status,'pass');assert(tls('2026-10-16').issues.includes('tls_expired'));
 assert(tls('2026-11-01').issues.includes('tls_expiring'));assert(tls(null).issues.includes('tls_expiry_unknown'));
 assert(tls('2027-01-01','TLSv1.1').issues.includes('tls_protocol'));
 assert.equal(assessWeb({}).find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='tls')!.status,'not_assessed');
});
test('cookie observations redact names, values, domains and paths from all findings',/** test 콜백: 테스트: cookie observations redact names, values, domains and paths from all findings 주요 호출: assessWeb·stringify·assert. */ ()=>{
 const result=assessWeb({'set-cookie':['secret-session=top-secret-value; Domain=private.example; Path=/private-path','__Host-other=another-secret; Secure; HttpOnly; SameSite=Lax; Path=/']});
 const encoded=JSON.stringify(result);for(const secret of ['secret-session','top-secret-value','private.example','private-path','another-secret','__Host-other'])assert(!encoded.includes(secret));
 assert.equal(result.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='cookie-1')!.status,'warning');assert.equal(result.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='cookie-2')!.status,'pass');
 assert.equal(by({},'cookies').status,'not_assessed');
});
test('cookie prefix, None, partition and duplicate attribute requirements are checked',/** test 콜백: 테스트: cookie prefix, None, partition and duplicate attribute requirements are checked 주요 호출: equal·by·filter. */ ()=>{
 for(const v of ['__Host-session=v; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com','__Secure-session=v; HttpOnly; SameSite=Lax','session=v; HttpOnly; SameSite=None','session=v; HttpOnly; SameSite=Lax; Partitioned','session=v; Secure; Secure; HttpOnly; SameSite=Lax'])assert.equal(by({'set-cookie':v},'cookie-1').status,'warning',v);
 assert.equal(assessWeb({'set-cookie':Array.from({length:100},/** from 콜백: from에서 전달한 값을 처리하는 콜백입니다 */ ()=>`a=value; Secure; HttpOnly; SameSite=Lax`)}).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.group==='cookies').length,33);
});
test('CORS separates public wildcard, invalid combinations and credentialed probe allowance',/** test 콜백: 테스트: CORS separates public wildcard, invalid combinations and credentialed probe allowance 주요 호출: equal·by·assert. */ ()=>{
 assert.equal(by({'access-control-allow-origin':'*'},'cors').status,'info');
 assert(by({'access-control-allow-origin':'*','access-control-allow-credentials':'true'},'cors').issues.includes('cors_invalid'));
 const probe=by({'access-control-allow-origin':corsProbeOrigin,'access-control-allow-credentials':'true'},'cors');assert(probe.issues.includes('cors_credentials'));assert(probe.issues.includes('cors_vary'));
 assert(!by({'access-control-allow-origin':corsProbeOrigin,vary:'Accept-Encoding, Origin'},'cors').issues.includes('cors_vary'));
 assert.equal(by({},'cors').status,'not_assessed');
 assert(by({'access-control-allow-origin':'null'},'cors').issues.includes('cors_null'));
 for(const v of ['https://a.example https://b.example','https://a.example/path'])assert(by({'access-control-allow-origin':v},'cors').issues.includes('cors_invalid'));
});
test('server version values are not persisted or labelled proven vulnerabilities',/** test 콜백: 테스트: server version values are not persisted or labelled proven vulnerabilities 주요 호출: by·equal·assert. */ ()=>{
 const item=by({'server':'private-product/1.2.3'},'exposure');assert.equal(item.status,'info');assert(!JSON.stringify(item).includes('private-product'));
});
test('every emitted finding and issue has text in all six locales',/** test 콜백: 테스트: every emitted finding and issue has text in all six locales 주요 호출: assessWeb·map·notEqual. */ ()=>{
 const headers={'content-security-policy':"default-src *",'strict-transport-security':'max-age=0','x-content-type-options':'x','referrer-policy':'unsafe-url','set-cookie':['__Host-secret=value; SameSite=None; Partitioned; Secure; Secure; Domain=x','foo=bar'],'access-control-allow-origin':corsProbeOrigin,'access-control-allow-credentials':'true',server:'x'};
 const findings=assessWeb(headers,{authorized:false,protocol:'TLSv1.1',validTo:null});
 for(const locale of locales)for(const item of findings){for(const key of [item.group,item.status,`${item.group}_fix`,...item.issues.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ i=>i==='exposure'?'exposure_note':i)])assert.notEqual(assessmentText(locale,key),key,`${locale}:${key}`);}
});
test('transport uses one bounded pinned HEAD with certificate verification and redacted observations',/** test 콜백: 테스트: transport uses one bounded pinned HEAD with certificate verification and redacted observations 주요 호출: method·scan·equal. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4}]);
 const transport=t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: equal. */ (_url:URL,options:any,callback:Function)=>{
  assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,'TLSv1.2');assert.equal(options.maxHeaderSize,16384);assert.equal(options.headers.Origin,corsProbeOrigin);assert.equal(options.headers.Cookie,undefined);assert.equal(options.headers.Authorization,undefined);
  const req=new EventEmitter() as any;req.end=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: callback·emit. */ ()=>{callback({statusCode:200,headers:{'x-powered-by':'PHP/8.4.26','set-cookie':['secret=hidden; Secure; HttpOnly; SameSite=Lax']},socket:{authorized:true,getProtocol:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=> 'TLSv1.3',getPeerCertificate:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=>({valid_to:'Jan 1 00:00:00 2030 GMT'})},/** destroy: 검증 시나리오에서 destroy에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ destroy(){}});req.emit('close');};req.destroy=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: emit. */ (e:Error)=>{req.emit('error',e);req.emit('close');};return req;
 });
 const result=await scan('https://owned.example',['owned.example']);assert.equal(result.assessmentVersion,2);assert.equal(result.assessment?.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='tls')?.status,'pass');assert(!JSON.stringify(result).includes('hidden'));assert.equal(transport.mock.callCount(),1);
});
test('TLS connection failure rejects scan without insecure retry',/** test 콜백: 테스트: TLS connection failure rejects scan without insecure retry 주요 호출: method·rejects·scan. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4}]);
 const transport=t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ ()=>{const req=new EventEmitter() as any;req.end=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: queueMicrotask. */ ()=>{queueMicrotask(/** queueMicrotask 콜백: queueMicrotask에서 전달한 값을 처리하는 콜백입니다 주요 호출: emit. */ ()=>{req.emit('error',new Error('CERT_HAS_EXPIRED'));req.emit('close');});};return req;});
 await assert.rejects(scan('https://owned.example',['owned.example']),/CERT_HAS_EXPIRED/);assert.equal(transport.mock.callCount(),1);
});
import {observeTechnology,technologyFindings} from '../lib/web-technology';
import {webCompare} from '../lib/assessment/web-module';

test('React server-only advisories request exact deployed packages instead of guessing versions',/** test 콜백: 테스트: React server-only advisories request exact deployed packages instead of guessing versions 주요 호출: technologyFindings·observeTechnology·filter. */ ()=>{
 const found=technologyFindings(observeTechnology({'x-powered-by':'Next.js','vary':'RSC'},200),'ko');
 for(const id of ['CVE-2026-23864','CVE-2025-55183','GHSA-xqc2-xf4c-x3h3','GHSA-h3gv-c5rc-p453']){
  const rows=found.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: endsWith. */ f=>f.id.endsWith(id));assert.equal(rows.length,2);assert(rows.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 주요 호출: includes. */ f=>f.status==='not_assessed'&&f.evidence.includes('exploitTested=false')&&!!f.reference));
 }
 assert(!technologyFindings(observeTechnology({},200),'en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('CVE-2026-23864')));
});
test('Node runtime advisory comparisons handle minor boundaries, unsupported branches and Express separately',/** test 콜백: 테스트: Node runtime advisory comparisons handle minor boundaries, unsupported branches and Express separately 주요 호출: technologyFindings·observeTechnology·equal. */ ()=>{
 for(const [version,expected] of [['22.23.3','warning'],['22.23.4','info'],['24.22.0','warning'],['24.22.1','info'],['24.23.0','info'],['26.12.0','warning'],['26.12.1','info'],['21.7.0','not_assessed']] as const){
  const rows=technologyFindings(observeTechnology({'server':'Node.js/v'+version},200),'en');
  assert.equal(rows.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2026-111497'))?.status,expected);assert(rows.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status!=='pass'));
 }
 for(const banner of ['Express/4.21.0','Node.js/v24.22.1-vendor1','Node.js/v24.22.1, Node.js/v24.21.0']){
  const rows=technologyFindings(observeTechnology({'x-powered-by':banner},200),'en');
  assert(rows.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes. */ f=>f.id.includes('CVE-')).every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));
 }
 for(const [version,status] of [['20.19.9','warning'],['20.20.0','info'],['22.21.9','warning'],['22.22.0','info'],['24.12.9','warning'],['24.13.0','info'],['25.2.9','warning'],['25.3.0','info']] as const){
  assert.equal(technologyFindings(observeTechnology({'server':'Node.js/'+version},200),'en').find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2025-55131'))?.status,status);
 }
});

test('PHP2Shell version hints respect each fixed branch and never certify a banner',/** test 콜백: 테스트: PHP2Shell version hints respect each fixed branch and never certify a banner 주요 호출: technologyFindings·observeTechnology·filter. */ ()=>{
 for(const [version,vulnerable] of [['8.2.34',true],['8.2.35',false],['8.3.35',true],['8.3.36',false],['8.4.26',true],['8.4.27',false],['8.5.11',true],['8.5.12',false]] as const){
  const result=technologyFindings(observeTechnology({'x-powered-by':'PHP/'+version},200),'en');
  const cves=result.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes. */ f=>f.id.includes('CVE-2026-10961'));assert.equal(cves.length,2);assert(cves.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status===(vulnerable?'warning':'info')));assert(result.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status!=='pass'));
 }
 for(const banner of ['PHP','PHP/8.4.27-vendor1','PHP/7.4.33','PHP/8.6.0'])assert(technologyFindings(observeTechnology({'x-powered-by':banner},200),'ko').filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes. */ f=>f.id.includes('CVE-')).every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));
});
test('technology observation keeps fixed hints only and treats hidden/error pages as unknown',/** test 콜백: 테스트: technology observation keeps fixed hints only and treats hidden/error pages as unknown 주요 호출: observeTechnology·equal·assert. */ ()=>{
 const headers={'x-powered-by':'PHP/8.4.26 private-token-example','set-cookie':['PRIVATE_SESSION=secret; HttpOnly'],'server':'private-host-name'};
 const data=observeTechnology(headers,200);assert.equal(data.products[0].product,'PHP');assert(!JSON.stringify(data).includes('private'));assert(!JSON.stringify(data).includes('secret'));
 assert.equal(observeTechnology(headers,302).products.length,0);assert.equal(observeTechnology(headers,500).products.length,0);
 const hidden=technologyFindings(observeTechnology({},200),'en');assert.equal(hidden.length,1);assert.equal(hidden[0].status,'not_assessed');
 assert.equal(observeTechnology({'x-powered-by':'PHP/8.4.27','server':'PHP/8.4.26'},200).products[0].version,null);
 const next=technologyFindings(observeTechnology({'x-powered-by':'Next.js','vary':'RSC, Accept-Encoding'},200),'en');assert(next.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('CVE-2025-55182')&&f.status==='not_assessed'));
});
test('framework rules distinguish PHP, Django, Spring and incomplete language coverage',/** test 콜백: 테스트: framework rules distinguish PHP, Django, Spring and incomplete language coverage 주요 호출: assert·some·technologyFindings. */ ()=>{
 const cases=[['Django/5.2.7','CVE-2025-64459','warning'],['Django/5.2.8','CVE-2025-64459','info'],['Spring/5.3.17','CVE-2022-22965','warning'],['Spring/5.3.18','CVE-2022-22965','info']] as const;
 for(const [banner,cve,status]of cases)assert(technologyFindings(observeTechnology({'x-powered-by':banner},200),'en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes(cve)&&f.status===status));
 for(const banner of ['ASP.NET','Express','Rails','Go'])assert(technologyFindings(observeTechnology({'x-powered-by':banner},200),'en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('advisory:')&&f.status==='not_assessed'));
});

test('desktop/mobile comparison includes differing technology hints',/** test 콜백: 테스트: desktop/mobile comparison includes differing technology hints 주요 호출: method·scan·timeout. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4}]);
 t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ (_url:URL,options:any,callback:Function)=>{
  const req=new EventEmitter() as any;req.end=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: callback·includes·emit. */ ()=>{callback({statusCode:200,headers:{'x-powered-by':options.headers['User-Agent'].includes('Mobile')?'Django/5.2.7':'PHP/8.4.26'},socket:{authorized:true,getProtocol:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=> 'TLSv1.3',getPeerCertificate:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=>({valid_to:'Jan 1 00:00:00 2030 GMT'})},/** destroy: 검증 시나리오에서 destroy에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ destroy(){}});req.emit('close');};req.destroy=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: emit. */ (e:Error)=>{req.emit('error',e);req.emit('close');};return req;
 });
 const report=await webCompare.scan({moduleId:'web.compare',label:'Mock profile comparison',url:'https://owned.example'},{locale:'en',signal:AbortSignal.timeout(2000)});
 assert(report.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='profile-comparison')?.evidence.includes('check=technology'));
});

test('legitimate delayed HEAD headers within the bounded budget can complete',/** test 콜백: 테스트: legitimate delayed HEAD headers within the bounded budget can complete 주요 호출: method·scan·timeout. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4}]);
 t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ (_url:URL,_options:any,callback:Function)=>{
  const req=new EventEmitter() as any;let responseTimer:ReturnType<typeof setTimeout>;
  req.end=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: setTimeout. */ ()=>{responseTimer=setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: callback·emit. */ ()=>{callback({statusCode:200,headers:{},socket:{authorized:true,getProtocol:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=> 'TLSv1.3',getPeerCertificate:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=>({valid_to:'Jan 1 00:00:00 2030 GMT'})},/** destroy: 검증 시나리오에서 destroy에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ destroy(){}});req.emit('close');},6500);};
  req.destroy=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: clearTimeout·emit. */ (error:Error)=>{clearTimeout(responseTimer);req.emit('error',error);req.emit('close');};return req;
 });
 const result=await scan('https://owned.example',['owned.example'],/** scan 콜백: scan에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},AbortSignal.timeout(15000));assert.equal(result.status,200);
});
