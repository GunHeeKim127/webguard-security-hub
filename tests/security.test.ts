import test from 'node:test';
import {webTargetInput,webTargetReason} from '../lib/web-target-input';
import {scanTarget} from '../lib/scan-policy';

test('domain input rejects detailed pages without silently changing the requested scope',/** test: 클라이언트 안내가 서버의 HTTPS 기본 주소 계약을 유지하고 비밀값을 재표시하지 않는지 검증합니다. */ ()=>{
 for(const raw of ['example.com',' https://example.com/ ','https://example.com:443']){
  const parsed=webTargetInput(raw);assert.equal(parsed.issue,null);assert.equal(parsed.normalized,'https://example.com');assert.doesNotThrow(/** doesNotThrow: 허용된 주소를 기존 서버 정책으로 교차 확인합니다. */ ()=>scanTarget(parsed.normalized));
 }
 for(const raw of ['example.com/login','https://example.com/?token=PRIVATE_QUERY','https://example.com/#account']){
  const parsed=webTargetInput(raw);assert.equal(parsed.issue,'detail');assert.equal(parsed.domain,'https://example.com');assert(!webTargetReason(parsed.issue,'ko').includes('PRIVATE_QUERY'));assert.throws(/** throws: 상세 주소는 서버에서도 거절되어야 합니다. */ ()=>scanTarget(parsed.normalized));
 }
 for(const raw of ['https://127.0.0.1','https://[::1]','https://user:PRIVATE_PASSWORD@example.com/path','https://example.com:8443','not a domain','https://'+ 'a'.repeat(301)]){
  const parsed=webTargetInput(raw);assert.equal(parsed.issue,'invalid');assert.equal(parsed.domain,undefined);
 }
 assert.equal(webTargetInput('http://example.com').issue,'https');assert.equal(webTargetInput('').issue,'empty');
});
import assert from 'node:assert/strict';
import { publicAddress,target,findings,scan } from '../lib/scanner';
import dns from 'node:dns/promises';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { hashPassword,verifyPassword,tokenHash,canScan } from '../lib/password';
import { sameOrigin,body,roleAllowed } from '../lib/request';
import { suspiciousPath } from '../lib/traffic';
import { projectDatabase } from '../lib/project-database';
test('project database and runtime identity guard rejects cross-project URLs',/** test 콜백: 테스트: project database and runtime identity guard rejects cross-project URLs 주요 호출: assert·projectDatabase·throws. */ ()=>{
 const original={...process.env};try{
 process.env.PROJECT_DATABASE='webguard_hub_dev';process.env.PROJECT_RUNTIME_ROLE='webguard_hub_dev_app';
 process.env.DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/webguard_hub_dev';assert(projectDatabase('runtime'));
 process.env.DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/webguard_hub_dev?database=another_project';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/query/);
 process.env.DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/another_project';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/mismatch/);
 process.env.DATABASE_URL='postgresql://postgres@localhost/webguard_hub_dev';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/dedicated/);
 process.env.MIGRATION_DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/webguard_hub_dev';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('migration'),/separate/);
 delete process.env.DATABASE_URL;assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/Set/);
 }finally{process.env=original;}
});
test('SSRF blocks private, loopback, mapped, link-local, reserved ranges',/** test 콜백: 테스트: SSRF blocks private, loopback, mapped, link-local, reserved ranges 주요 호출: equal·publicAddress. */ ()=>{for(const ip of ['127.0.0.1','10.0.0.1','172.16.1.1','192.168.1.1','169.254.169.254','0.0.0.0','100.64.0.1','224.0.0.1','::1','::','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1'])assert.equal(publicAddress(ip),false,ip);assert.equal(publicAddress('8.8.8.8'),true);});
test('URL policy rejects bypasses and unapproved targets',/** test 콜백: 테스트: URL policy rejects bypasses and unapproved targets 주요 호출: throws·equal·target. */ ()=>{for(const u of ['http://owned.example','https://owned.example:444','https://owned.example/path','https://owned.example?x=1','https://u:p@owned.example','https://owned.example.evil.com','https://127.1','https://2130706433','file:///etc/passwd','https://[::1]','https://owned.example#x'])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: target. */ ()=>target(u,['owned.example']));assert.equal(target('https://owned.example',['owned.example']).hostname,'owned.example');});
test('password hashing uses unique salts and rejects incorrect passwords',/** test 콜백: 테스트: password hashing uses unique salts and rejects incorrect passwords 주요 호출: hashPassword·notEqual·equal. */ ()=>{const p='a-long-local-password';const a=hashPassword(p),b=hashPassword(p);assert.notEqual(a,b);assert.equal(verifyPassword(p,a),true);assert.equal(verifyPassword('incorrect',a),false);assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: hashPassword. */ ()=>hashPassword('short'));assert.notEqual(tokenHash('token'),'token');});
test('registered members can scan and unknown roles fail closed',/** test 콜백: 테스트: registered members can scan and unknown roles fail closed 주요 호출: equal·canScan. */ ()=>{assert.equal(canScan('viewer'),true);assert.equal(canScan('other'),false);assert.equal(canScan('analyst'),true);assert.equal(canScan('admin'),true);});

test('malformed password hashes fail closed without ignoring trailing fields',/** test 콜백: 테스트: malformed password hashes fail closed without ignoring trailing fields 주요 호출: hashPassword·slice·repeat. */ ()=>{
 const password='a-long-local-password',valid=hashPassword(password);
 for(const stored of ['',valid+':ignored',valid.slice(1),'invalid:hash','x'.repeat(4000)])assert.equal(verifyPassword(password,stored),false);
 assert.equal(verifyPassword(password,valid),true);
});
test('missing security headers are reported without treating presence as a guarantee',/** test 콜백: 테스트: missing security headers are reported without treating presence as a guarantee 주요 호출: equal·filter·findings. */ ()=>{assert.equal(findings({}).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ x=>!x.present).length,4);assert.equal(findings({'content-security-policy':'anything'})[0].present,true);});
test('CSRF exact origin and missing origin rejection',/** test 콜백: 테스트: CSRF exact origin and missing origin rejection 주요 호출: throws·sameOrigin. */ ()=>{process.env.APP_ORIGIN='http://localhost:3000';for(const origin of ['https://evil.example','null','http://localhost:3000.evil.example',''])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: sameOrigin. */ ()=>sameOrigin(new Request('http://localhost:3000',{headers:origin?{origin}:{}})));sameOrigin(new Request('http://localhost:3000',{headers:{origin:'http://localhost:3000'}}));});
test('RBAC actual authorization policy fails closed',/** test 콜백: 테스트: RBAC actual authorization policy fails closed 주요 호출: equal·roleAllowed. */ ()=>{assert.equal(roleAllowed('viewer',['admin','analyst']),false);assert.equal(roleAllowed('admin',['admin','analyst']),true);assert.equal(roleAllowed('unknown',['admin','analyst','viewer']),false);});
test('JSON limit enforces actual streamed size and parsing',/** test 콜백: 테스트: JSON limit enforces actual streamed size and parsing 주요 호출: rejects·body·request. */ async()=>{const request=/** request: 검증 시나리오에서 request에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ (value:string,type='application/json')=>new Request('http://localhost',{method:'POST',body:value,headers:{'Content-Type':type}});await assert.rejects(body(request('x'.repeat(4097))),{status:413});await assert.rejects(body(request('{broken')),{status:400});await assert.rejects(body(request('{}','text/plain')),{status:415});assert.deepEqual(await body(request('{"ok":true}')),{ok:true});});

test('JSON upload rejects invalid UTF-8 and cancels a stalled request stream',/** test 콜백: 테스트: JSON upload rejects invalid UTF-8 and cancels a stalled request stream 주요 호출: rejects·body·assert. */ async()=>{
 const malformed=new Request('http://localhost',{method:'POST',headers:{'Content-Type':'application/json'},body:new Uint8Array([123,34,120,34,58,34,255,34,125])});
 await assert.rejects(body(malformed),{status:400});
 let cancelled=false;const stream=new ReadableStream<Uint8Array>({/** start: 검증 시나리오에서 start에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: enqueue·encode. */ start(c){c.enqueue(new TextEncoder().encode('{'));},/** cancel: 검증 시나리오에서 cancel에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ cancel(){cancelled=true;}});
 const request=new Request('http://localhost',{method:'POST',headers:{'Content-Type':'application/json'},body:stream,duplex:'half'} as RequestInit);
 await assert.rejects(body(request,4096,20),{status:408});assert(cancelled);
});
test('honeypot paths detect probes without classifying normal users',/** test 콜백: 테스트: honeypot paths detect probes without classifying normal users 주요 호출: equal·suspiciousPath. */ ()=>{for(const p of ['/.env','/.git/config','/wp-admin','/wp-login.php'])assert.equal(suspiciousPath(p),true);assert.equal(suspiciousPath('/dashboard'),false);});

test('JSON media type is exact, case-insensitive and permits charset parameters',/** test 콜백: 테스트: JSON media type is exact, case-insensitive and permits charset parameters 주요 호출: rejects·body·request. */ async()=>{
 const request=/** request: 검증 시나리오에서 request에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ (type:string)=>new Request('http://localhost',{method:'POST',body:'{}',headers:{'Content-Type':type}});
 for(const type of ['application/jsonp','application/json-malformed','text/application/json'])await assert.rejects(body(request(type)),{status:415});
 for(const type of ['application/json; charset=utf-8','Application/JSON'])assert.deepEqual(await body(request(type)),{});
});

test('cancelling pending DNS rejects promptly and never opens HTTPS',/** test 콜백: 테스트: cancelling pending DNS rejects promptly and never opens HTTPS 주요 호출: method·scan·abort. */ async t=>{
 let started!:()=>void;const ready=new Promise<void>(/** test 콜백: 테스트: cancelling pending DNS rejects promptly and never opens HTTPS */ resolve=>{started=resolve;});
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: started. */ ()=>{started();return new Promise(/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ ()=>{});});
 const transport=t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ ()=>{throw new Error('Must not connect');});
 const abort=new AbortController(),pending=scan('https://owned.example',undefined,/** scan 콜백: scan에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},abort.signal);await ready;abort.abort();
 await assert.rejects(pending,/cancelled/);assert.equal(transport.mock.callCount(),0);
});
test('scanner rejects a mixed public/private DNS answer before connecting',/** test 콜백: 테스트: scanner rejects a mixed public/private DNS answer before connecting 주요 호출: method·rejects·scan. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]);
 const transport=t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ ()=>{throw new Error('Must never connect');});
 await assert.rejects(scan('https://owned.example',['owned.example']),/Non-public/);assert.equal(transport.mock.callCount(),0);
});
test('scanner pins validated DNS, preserves hostname and does not follow redirects',/** test 콜백: 테스트: scanner pins validated DNS, preserves hostname and does not follow redirects 주요 호출: method·scan·deepEqual. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4}]);let destroyed=false;
 const transport=t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: equal·lookup. */ (url:URL,options:{method:string,agent:boolean,family:number,lookup:Function},callback:Function)=>{
  assert.equal(url.hostname,'owned.example');assert.equal(options.method,'HEAD');assert.equal(options.agent,false);
  assert.equal(options.family,4);
  options.lookup('owned.example',{},/** lookup 콜백: lookup에서 전달한 값을 처리하는 콜백입니다 주요 호출: equal. */ (error:unknown,address:string,family:number)=>{assert.equal(error,null);assert.equal(address,'8.8.8.8');assert.equal(family,4);});
  const request=new EventEmitter() as EventEmitter&{end:Function,destroy:Function};
  request.end=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: callback·emit. */ ()=>{callback({statusCode:302,headers:{location:'http://127.0.0.1'},/** destroy: 검증 시나리오에서 destroy에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ destroy(){destroyed=true;}});request.emit('close');};request.destroy=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: emit. */ ()=>request.emit('close');return request;
 });
 const steps:string[]=[];const result=await scan('https://owned.example',['owned.example'],/** scan 콜백: scan에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ (stage,state)=>steps.push(stage+':'+state));assert.deepEqual(steps,['target:running','target:success','network:running','network:success','headers:running','headers:success']);assert.equal(result.status,302);assert.equal(transport.mock.callCount(),1);assert.equal(destroyed,true);assert(result.assessment?.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.group!=='tls').every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 주요 호출: includes. */ f=>f.status==='not_assessed'&&f.issues.includes('response_scope')));
});

test('cancelled scan never opens a connection or reports completed stages',/** test 콜백: 테스트: cancelled scan never opens a connection or reports completed stages 주요 호출: method·rejects·scan. */ async t=>{
 const transport=t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ ()=>{throw new Error('Unexpected connection');});
 const steps:string[]=[];await assert.rejects(scan('https://owned.example',['owned.example'],/** scan 콜백: scan에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ stage=>steps.push(stage),AbortSignal.abort()),/cancelled/);assert.equal(transport.mock.callCount(),0);assert.deepEqual(steps,[]);
});

test('cancelling an in-flight HEAD destroys transport and cannot complete header checks',/** test 콜백: 테스트: cancelling an in-flight HEAD destroys transport and cannot complete header checks 주요 호출: method·scan·abort. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4}]);
 let opened!:()=>void;const ready=new Promise<void>(/** test 콜백: 테스트: cancelling an in-flight HEAD destroys transport and cannot complete header checks */ resolve=>{opened=resolve;});let destroyed=false;const steps:string[]=[];
 t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ ()=>{
  const request=new EventEmitter() as EventEmitter&{end:Function,destroy:Function};request.end=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: opened. */ ()=>opened();request.destroy=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: emit. */ (error:Error)=>{destroyed=true;request.emit('error',error);request.emit('close');return request;};return request;
 });
 const abort=new AbortController();const pending=scan('https://owned.example',['owned.example'],/** scan 콜백: scan에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ (stage,state)=>steps.push(stage+':'+state),abort.signal);await ready;abort.abort();await assert.rejects(pending,/cancelled/);assert(destroyed);assert.deepEqual(steps,['target:running','target:success','network:running']);
});
