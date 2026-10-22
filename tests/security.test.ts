import test from 'node:test';
import assert from 'node:assert/strict';
import { publicAddress,target,findings,scan } from '../lib/scanner';
import dns from 'node:dns/promises';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { hashPassword,verifyPassword,tokenHash,canScan } from '../lib/password';
import { sameOrigin,body,roleAllowed } from '../lib/request';
import { suspiciousPath } from '../lib/traffic';
import { projectDatabase } from '../lib/project-database';
test('project database and runtime identity guard rejects cross-project URLs',()=>{
 const original={...process.env};try{
 process.env.PROJECT_DATABASE='webguard_hub_dev';process.env.PROJECT_RUNTIME_ROLE='webguard_hub_dev_app';
 process.env.DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/webguard_hub_dev';assert(projectDatabase('runtime'));
 process.env.DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/webguard_hub_dev?database=another_project';assert.throws(()=>projectDatabase('runtime'),/query/);
 process.env.DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/another_project';assert.throws(()=>projectDatabase('runtime'),/mismatch/);
 process.env.DATABASE_URL='postgresql://postgres@localhost/webguard_hub_dev';assert.throws(()=>projectDatabase('runtime'),/dedicated/);
 process.env.MIGRATION_DATABASE_URL='postgresql://webguard_hub_dev_app@localhost/webguard_hub_dev';assert.throws(()=>projectDatabase('migration'),/separate/);
 delete process.env.DATABASE_URL;assert.throws(()=>projectDatabase('runtime'),/Set/);
 }finally{process.env=original;}
});
test('SSRF blocks private, loopback, mapped, link-local, reserved ranges',()=>{for(const ip of ['127.0.0.1','10.0.0.1','172.16.1.1','192.168.1.1','169.254.169.254','0.0.0.0','100.64.0.1','224.0.0.1','::1','::','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1'])assert.equal(publicAddress(ip),false,ip);assert.equal(publicAddress('8.8.8.8'),true);});
test('URL policy rejects bypasses and unapproved targets',()=>{for(const u of ['http://owned.example','https://owned.example:444','https://owned.example/path','https://owned.example?x=1','https://u:p@owned.example','https://owned.example.evil.com','https://127.1','https://2130706433','file:///etc/passwd','https://[::1]','https://owned.example#x'])assert.throws(()=>target(u,['owned.example']));assert.equal(target('https://owned.example',['owned.example']).hostname,'owned.example');});
test('password hashing uses unique salts and rejects incorrect passwords',()=>{const p='a-long-local-password';const a=hashPassword(p),b=hashPassword(p);assert.notEqual(a,b);assert.equal(verifyPassword(p,a),true);assert.equal(verifyPassword('incorrect',a),false);assert.throws(()=>hashPassword('short'));assert.notEqual(tokenHash('token'),'token');});
test('registered members can scan and unknown roles fail closed',()=>{assert.equal(canScan('viewer'),true);assert.equal(canScan('other'),false);assert.equal(canScan('analyst'),true);assert.equal(canScan('admin'),true);});

test('malformed password hashes fail closed without ignoring trailing fields',()=>{
 const password='a-long-local-password',valid=hashPassword(password);
 for(const stored of ['',valid+':ignored',valid.slice(1),'invalid:hash','x'.repeat(4000)])assert.equal(verifyPassword(password,stored),false);
 assert.equal(verifyPassword(password,valid),true);
});
test('missing security headers are reported without treating presence as a guarantee',()=>{assert.equal(findings({}).filter(x=>!x.present).length,4);assert.equal(findings({'content-security-policy':'anything'})[0].present,true);});
test('CSRF exact origin and missing origin rejection',()=>{process.env.APP_ORIGIN='http://localhost:3000';for(const origin of ['https://evil.example','null','http://localhost:3000.evil.example',''])assert.throws(()=>sameOrigin(new Request('http://localhost:3000',{headers:origin?{origin}:{}})));sameOrigin(new Request('http://localhost:3000',{headers:{origin:'http://localhost:3000'}}));});
test('RBAC actual authorization policy fails closed',()=>{assert.equal(roleAllowed('viewer',['admin','analyst']),false);assert.equal(roleAllowed('admin',['admin','analyst']),true);assert.equal(roleAllowed('unknown',['admin','analyst','viewer']),false);});
test('JSON limit enforces actual streamed size and parsing',async()=>{const request=(value:string,type='application/json')=>new Request('http://localhost',{method:'POST',body:value,headers:{'Content-Type':type}});await assert.rejects(body(request('x'.repeat(4097))),{status:413});await assert.rejects(body(request('{broken')),{status:400});await assert.rejects(body(request('{}','text/plain')),{status:415});assert.deepEqual(await body(request('{"ok":true}')),{ok:true});});
test('honeypot paths detect probes without classifying normal users',()=>{for(const p of ['/.env','/.git/config','/wp-admin','/wp-login.php'])assert.equal(suspiciousPath(p),true);assert.equal(suspiciousPath('/dashboard'),false);});

test('JSON media type is exact, case-insensitive and permits charset parameters',async()=>{
 const request=(type:string)=>new Request('http://localhost',{method:'POST',body:'{}',headers:{'Content-Type':type}});
 for(const type of ['application/jsonp','application/json-malformed','text/application/json'])await assert.rejects(body(request(type)),{status:415});
 for(const type of ['application/json; charset=utf-8','Application/JSON'])assert.deepEqual(await body(request(type)),{});
});

test('cancelling pending DNS rejects promptly and never opens HTTPS',async t=>{
 let started!:()=>void;const ready=new Promise<void>(resolve=>{started=resolve;});
 t.mock.method(dns,'lookup',()=>{started();return new Promise(()=>{});});
 const transport=t.mock.method(https,'request',()=>{throw new Error('Must not connect');});
 const abort=new AbortController(),pending=scan('https://owned.example',undefined,()=>{},abort.signal);await ready;abort.abort();
 await assert.rejects(pending,/cancelled/);assert.equal(transport.mock.callCount(),0);
});
test('scanner rejects a mixed public/private DNS answer before connecting',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]);
 const transport=t.mock.method(https,'request',()=>{throw new Error('Must never connect');});
 await assert.rejects(scan('https://owned.example',['owned.example']),/Non-public/);assert.equal(transport.mock.callCount(),0);
});
test('scanner pins validated DNS, preserves hostname and does not follow redirects',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);let destroyed=false;
 const transport=t.mock.method(https,'request',(url:URL,options:{method:string,agent:boolean,family:number,lookup:Function},callback:Function)=>{
  assert.equal(url.hostname,'owned.example');assert.equal(options.method,'HEAD');assert.equal(options.agent,false);
  assert.equal(options.family,4);
  options.lookup('owned.example',{},(error:unknown,address:string,family:number)=>{assert.equal(error,null);assert.equal(address,'8.8.8.8');assert.equal(family,4);});
  const request=new EventEmitter() as EventEmitter&{end:Function,destroy:Function};
  request.end=()=>{callback({statusCode:302,headers:{location:'http://127.0.0.1'},destroy(){destroyed=true;}});request.emit('close');};request.destroy=()=>request.emit('close');return request;
 });
 const steps:string[]=[];const result=await scan('https://owned.example',['owned.example'],(stage,state)=>steps.push(stage+':'+state));assert.deepEqual(steps,['target:running','target:success','network:running','network:success','headers:running','headers:success']);assert.equal(result.status,302);assert.equal(transport.mock.callCount(),1);assert.equal(destroyed,true);assert(result.assessment?.filter(f=>f.group!=='tls').every(f=>f.status==='not_assessed'&&f.issues.includes('response_scope')));
});

test('cancelled scan never opens a connection or reports completed stages',async t=>{
 const transport=t.mock.method(https,'request',()=>{throw new Error('Unexpected connection');});
 const steps:string[]=[];await assert.rejects(scan('https://owned.example',['owned.example'],stage=>steps.push(stage),AbortSignal.abort()),/cancelled/);assert.equal(transport.mock.callCount(),0);assert.deepEqual(steps,[]);
});

test('cancelling an in-flight HEAD destroys transport and cannot complete header checks',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);
 let opened!:()=>void;const ready=new Promise<void>(resolve=>{opened=resolve;});let destroyed=false;const steps:string[]=[];
 t.mock.method(https,'request',()=>{
  const request=new EventEmitter() as EventEmitter&{end:Function,destroy:Function};request.end=()=>opened();request.destroy=(error:Error)=>{destroyed=true;request.emit('error',error);request.emit('close');return request;};return request;
 });
 const abort=new AbortController();const pending=scan('https://owned.example',['owned.example'],(stage,state)=>steps.push(stage+':'+state),abort.signal);await ready;abort.abort();await assert.rejects(pending,/cancelled/);assert(destroyed);assert.deepEqual(steps,['target:running','target:success','network:running']);
});
