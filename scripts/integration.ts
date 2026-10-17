// Disposable local cluster only. Never connects to the user's existing database.
import {createServer} from 'node:http';
import { execFile,spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp,mkdir } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes,randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import assert from 'node:assert/strict';
import {cachedAdvice,adviceKey} from '../lib/advice-cache';
import {withAiBudget} from '../lib/ai-budget';
import {saveScan} from '../lib/scan-store';
import {assertManagedRuntimeSql} from '../lib/runtime-sql';
import {hashPassword,verifyPassword,tokenHash} from '../lib/password';
import {resetAccountPassword} from './support/reset-account-password';
const exec=promisify(execFile),bin=process.env.PG_BIN??'C:/Program Files/PostgreSQL/15/bin';
await mkdir('work',{recursive:true});const dir=await mkdtemp(path.resolve('work/isolated-pg-'));
const pgPort=45000+Math.floor(Math.random()*5000),webPort=50000+Math.floor(Math.random()*5000),base=`http://127.0.0.1:${webPort}`;
const database=`postgresql://postgres@127.0.0.1:${pgPort}/postgres`;
const env={...process.env,PROJECT_DATABASE:'webguard_hub_dev',PROJECT_RUNTIME_ROLE:'webguard_hub_dev_app',DATABASE_URL:`postgresql://webguard_hub_dev_app@127.0.0.1:${pgPort}/webguard_hub_dev`,MIGRATION_DATABASE_URL:`postgresql://webguard_hub_dev_migrator@127.0.0.1:${pgPort}/webguard_hub_dev`,APP_ORIGIN:base,APP_ADDITIONAL_ORIGINS:`http://localhost:${webPort}`,AI_ENABLED:'false',AI_PROVIDER:'openai',OPENAI_API_KEY:'',ALLOWED_SCAN_HOSTS:'owned.example',SCAN_TARGET_POLICY:'public',TRUSTED_PROXY_IPS:'',WEBGUARD_PROXY_SECRET:''};
const pool=new Pool({connectionString:database,connectionTimeoutMillis:1000});let pgStarted=false;let server:ReturnType<typeof spawn>|undefined;
const projectPools:Pool[]=[];
// Never inherit the real production DB profile or platform-IP mode from env files.
Object.assign(env,{DATABASE_PROVIDER:'postgresql',VERCEL:'',PUBLIC_REGISTRATION_ENABLED:'true',GROQ_API_KEY:'',GEMINI_API_KEY:'',GEOIP_PROXY_SECRET:''});
async function control(args:string[]){await new Promise<void>((resolve,reject)=>{const p=spawn(path.join(bin,'pg_ctl.exe'),args,{windowsHide:true,stdio:'ignore'});p.on('error',reject);p.on('exit',code=>code===0?resolve():reject(new Error('pg_ctl failed: '+code)));});}
async function script(name:string,extra:Partial<NodeJS.ProcessEnv>={}){return exec(process.execPath,['node_modules/tsx/dist/cli.mjs',name],{env:{...env,...extra},windowsHide:true});}
async function call(route:string,method='GET',payload?:unknown,cookie?:string){return fetch(base+route,{method,headers:{origin:base,...(payload===undefined?{}:{'Content-Type':'application/json'}),...(cookie?{cookie}:{})},body:payload===undefined?undefined:JSON.stringify(payload),signal:AbortSignal.timeout(10000)});}
try{
 await exec(path.join(bin,'initdb.exe'),['-D',dir,'-A','trust','-U','postgres','--encoding=UTF8','--locale=C'],{windowsHide:true});
 await control(['-D',dir,'-l',path.join(dir,'server.log'),'-o',`-h 127.0.0.1 -p ${pgPort}`,'-w','start']);pgStarted=true;
 console.log('PASS disposable PostgreSQL cluster started on loopback; existing DB untouched');
 const {readFile}=await import('node:fs/promises');
 for(const file of ['00_create_roles.sql','01_create_database.sql','02_restrict_database.sql'])await pool.query(await readFile('sql/setup/'+file,'utf8'));
 const projectAdmin=new Pool({connectionString:`postgresql://postgres@127.0.0.1:${pgPort}/webguard_hub_dev`});
 projectPools.push(projectAdmin);
 await script('scripts/migrate.ts');await script('scripts/migrate.ts');await script('scripts/grant-runtime.ts');
 assert.equal((await projectAdmin.query('SELECT count(*) FROM schema_migrations')).rows[0].count,'6');console.log('PASS per-project setup, migrations, grants and idempotent rerun');
 const runtime=new Pool({connectionString:env.DATABASE_URL});
 await assert.rejects(runtime.query('CREATE TABLE should_not_exist(id int)'),{code:'42501'});
 await assert.rejects(runtime.query('SELECT * FROM schema_migrations'),{code:'42501'});
 await assert.rejects(runtime.query("INSERT INTO users(id,email,password_hash,role) VALUES(gen_random_uuid(),'blocked@test','blocked','admin')"),{code:'42501'});
 await pool.query('CREATE ROLE other_project_app LOGIN');
 const other=new Pool({connectionString:`postgresql://other_project_app@127.0.0.1:${pgPort}/webguard_hub_dev`});
 await assert.rejects(other.query('SELECT 1'),{code:'42501'});await other.end();await runtime.end();console.log('PASS runtime DDL/user creation/history denied; other project role cannot connect');

 await assert.rejects(projectAdmin.query("SET ROLE other_project_app; SELECT public.register_viewer(gen_random_uuid(),'blocked@example.test',repeat('a',32)||':'||repeat('b',128))"),{code:'42501'});await projectAdmin.query('RESET ROLE');
 const password=randomBytes(24).toString('hex');
 for(const role of ['admin','viewer','analyst'])await script('scripts/create-user.ts',{BOOTSTRAP_EMAIL:role+'@example.test',BOOTSTRAP_PASSWORD:password,BOOTSTRAP_ROLE:role});
 let log='';server=spawn(process.execPath,['node_modules/tsx/dist/cli.mjs','scripts/serve.ts','--hostname','127.0.0.1','--port',String(webPort)],{env,windowsHide:true,stdio:['ignore','pipe','pipe']});server.stdout?.on('data',d=>log+=d);server.stderr?.on('data',d=>log+=d);
 let ready=false;for(let i=0;i<60;i++){if(server.exitCode!==null)throw new Error(log);try{if((await call('/api/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,500));}assert(ready,log);
 async function login(role:string){const r=await call('/api/login','POST',{email:role+'@example.test',password});assert.equal(r.status,200,await r.clone().text());const cookie=r.headers.get('set-cookie')!;assert(cookie.includes('HttpOnly'));assert(cookie.includes('SameSite=Strict'));return cookie.split(';')[0];}
 const admin=await login('admin'),viewer=await login('viewer');
 const deviceBase=`http://localhost:${webPort}`;
 const deviceLogin=await fetch(deviceBase+'/api/login',{method:'POST',headers:{origin:deviceBase,'Content-Type':'application/json','User-Agent':'WebGuard-Test-Device-B'},body:JSON.stringify({email:'admin@example.test',password})});
 assert.equal(deviceLogin.status,200);const deviceCookie=deviceLogin.headers.get('set-cookie')!.split(';')[0];assert.notEqual(deviceCookie,admin);
 assert.equal((await fetch(deviceBase+'/api/dashboard',{headers:{cookie:deviceCookie,'User-Agent':'WebGuard-Test-Device-B'}})).status,200);
 assert.equal((await call('/api/dashboard','GET',undefined,admin)).status,200);
 assert.equal((await fetch(deviceBase+'/api/logout',{method:'POST',headers:{origin:deviceBase,cookie:deviceCookie,'Content-Type':'application/json'},body:'{}'})).status,200);
 assert.equal((await fetch(deviceBase+'/api/dashboard',{headers:{cookie:deviceCookie}})).status,401);assert.equal((await call('/api/dashboard','GET',undefined,admin)).status,200);
 console.log('PASS independent same-account device sessions, alternate entry address, and logout isolation');
 const signupPassword=randomBytes(24).toString('hex');
 assert.equal((await fetch(base+'/api/register',{method:'POST',headers:{origin:'https://evil.example','Content-Type':'application/json'},body:JSON.stringify({email:'new@example.test',password:signupPassword})})).status,403);
 assert.equal((await call('/api/register','POST',{email:'new@example.test',password:'short'})).status,400);
 assert.equal((await call('/api/register','POST',{email:'new@example.test',password:signupPassword,role:'admin'})).status,400);
 assert.equal((await call('/api/register','POST',{email:' New@Example.Test ',password:signupPassword})).status,202);
 const newAccount=(await projectAdmin.query("SELECT role,password_hash FROM users WHERE email='new@example.test'")).rows[0];assert.equal(newAccount.role,'viewer');assert.notEqual(newAccount.password_hash,signupPassword);
 assert.equal((await call('/api/register','POST',{email:'new@example.test',password:signupPassword+'different'})).status,202);
 assert.equal((await projectAdmin.query("SELECT password_hash FROM users WHERE email='new@example.test'")).rows[0].password_hash,newAccount.password_hash);
 const newLogin=await call('/api/login','POST',{email:'new@example.test',password:signupPassword});assert.equal(newLogin.status,200);const newCookie=newLogin.headers.get('set-cookie')!.split(';')[0];
 assert.equal((await call('/api/scans','POST',{url:'https://owned.example',authorized:true},newCookie)).status,403);
 assert.equal((await call('/api/register','POST',{email:'new@example.test',password:signupPassword})).status,202);
 assert.equal((await call('/api/register','POST',{email:'new@example.test',password:signupPassword})).status,429);
 console.log('PASS registration, normalization, hashed password, viewer-only role, duplicate safety, sign-in, CSRF and rate limits');

 const token=admin.split('=')[1];assert.equal((await projectAdmin.query('SELECT count(*) FROM sessions WHERE token_hash=$1',[token])).rows[0].count,'0');
 const overviewResponse=await call('/api/dashboard','GET',undefined,admin);assert.equal(overviewResponse.status,200);const overviewData=await overviewResponse.json();assert.equal(overviewData.overview.approvedCount,1);assert(Array.isArray(overviewData.recentEvents));const viewerData=await (await call('/api/dashboard','GET',undefined,viewer)).json();assert.deepEqual(viewerData.overview.approvedHosts,[]);console.log('PASS account bootstrap, login, hashed sessions, dashboard');
 assert.equal((await call('/api/scans','POST',{url:'https://owned.example',authorized:true},viewer)).status,403);
 assert.equal((await call('/api/ai','POST',{scanId:'00000000-0000-0000-0000-000000000000'},viewer)).status,403);console.log('PASS viewer denied scan and AI');
 assert.equal((await call('/api/scans','POST',{url:'https://169.254.169.254',authorized:true},admin)).status,400);console.log('PASS metadata SSRF attempt denied by live API');
 const streamed=await fetch(base+'/api/scans',{method:'POST',headers:{origin:base,cookie:admin,'Content-Type':'application/json',accept:'application/x-ndjson'},body:JSON.stringify({url:'https://169.254.169.254',authorized:true})});
 assert.equal(streamed.status,200);assert(streamed.headers.get('content-type')?.includes('application/x-ndjson'));const scanEvents=(await streamed.text()).trim().split('\n').map(line=>JSON.parse(line));
 assert.deepEqual(scanEvents.map(e=>e.type),['progress','error']);assert.equal(scanEvents[0].stage,'target');assert.equal(scanEvents[1].errorCode,'TARGET_REJECTED');assert.equal((await projectAdmin.query('SELECT count(*) FROM scans')).rows[0].count,'0');console.log('PASS streamed SSRF rejection, real stage event and no saved result');


 // Verify both legacy de-duplication and the exact production save path without external traffic.
 const actor=(await projectAdmin.query("SELECT id FROM users WHERE email='admin@example.test'")).rows[0].id;
 await projectAdmin.query('BEGIN');
 try{
  await projectAdmin.query('ALTER TABLE public.scans DROP CONSTRAINT scans_user_hostname_unique');
  await projectAdmin.query(`INSERT INTO public.scans(id,user_id,hostname,result,created_at) VALUES
   (gen_random_uuid(),$1,'legacy.example','{"status":201,"checks":[]}','2026-01-01'),
   (gen_random_uuid(),$1,'legacy.example','{"status":202,"checks":[]}','2026-01-02')`,[actor]);
  await projectAdmin.query(await readFile('sql/migrations/003_latest_scan.sql','utf8'));
  assert.equal((await projectAdmin.query("SELECT result FROM scans WHERE hostname='legacy.example'")).rows[0].result.status,202);
  assert.equal((await projectAdmin.query("SELECT count(*) FROM scans WHERE hostname='legacy.example'")).rows[0].count,'1');
  assert.equal((await projectAdmin.query("SELECT result FROM scan_duplicate_archive WHERE hostname='legacy.example'")).rows[0].result.status,201);
 }finally{await projectAdmin.query('ROLLBACK');}
 const writer=new Pool({connectionString:env.DATABASE_URL});
 try{
  const query=(sql:string,values:unknown[])=>writer.query(sql,values);

  let generated=0;const key=adviceKey('test-model','ko',[]);
  const make=async()=>{generated++;return {advice:'Test advice',inputTokens:20,outputTokens:30};};
  assert.equal((await cachedAdvice(query,key,make)).source,'ai');assert.equal((await cachedAdvice(query,key,make)).source,'cache');assert.equal(generated,1);
  const fresh=adviceKey('test-model','en',[]);let unblock!:()=>void;let started!:()=>void;
  const waiting=new Promise<void>(resolve=>{unblock=resolve;}),ready=new Promise<void>(resolve=>{started=resolve;});
  const firstAdvice=cachedAdvice(query,fresh,async()=>{started();await waiting;return make();});await ready;
  assert.equal((await cachedAdvice(query,fresh,make)).source,'busy');unblock();await firstAdvice;assert.equal(generated,2);
  const failureKey=adviceKey('fail-model','ko',[]);await assert.rejects(cachedAdvice(query,failureKey,async()=>{throw new Error('provider quota');}));
  assert.equal((await cachedAdvice(query,failureKey,make)).source,'ai');
  await writer.query("UPDATE ai_advice_cache SET expires_at=now()-interval '1 second' WHERE cache_key=$1",[key]);
  assert.equal((await cachedAdvice(query,key,make)).source,'ai');
  console.log('PASS persistent advice reuse, token usage storage, concurrent generation exclusion, failed lease release and cache expiry');
  const bucket='ai:test-refund';
  await assert.rejects(withAiBudget(query,bucket,async()=>{throw new Error('Simulated provider failure');}));
  assert.equal((await writer.query('SELECT hits FROM rate_limits WHERE bucket=$1',[bucket])).rows[0].hits,0);
  await Promise.all([1,2,3].map(()=>withAiBudget(query,bucket,async()=>true)));
  await assert.rejects(withAiBudget(query,bucket,async()=>true),{status:429,message:'AI_LOCAL_RATE_LIMITED'});
  assert.equal((await writer.query('SELECT hits FROM rate_limits WHERE bucket=$1',[bucket])).rows[0].hits,3);
  await assert.rejects(withAiBudget(query,'ai:rollover',async()=>{await writer.query("UPDATE rate_limits SET hits=2,reset_at=now()+interval '2 hours' WHERE bucket='ai:rollover'");throw new Error('Old window failure');}));
  assert.equal((await writer.query("SELECT hits FROM rate_limits WHERE bucket='ai:rollover'")).rows[0].hits,2);
  console.log('PASS failed AI request refund, concurrent budget limit, non-inflating rejections and reset-window isolation');

  const first=await saveScan(query,actor,'owned.example',{status:200,checks:[]});
  await projectAdmin.query("UPDATE scans SET created_at='2026-01-01' WHERE id=$1",[first]);
  const second=await saveScan(query,actor,'owned.example',{status:204,checks:[{header:'content-security-policy',present:true}]});assert.equal(second,first);
  const latest=(await projectAdmin.query("SELECT result,created_at FROM scans WHERE hostname='owned.example'")).rows;
  assert.equal(latest.length,1);assert.equal(latest[0].result.status,204);assert.equal(latest[0].result.checks[0].present,true);assert(latest[0].created_at.getTime()>new Date('2026-01-01').getTime());
  await saveScan(query,actor,'different.example',{status:200,checks:[]});
  const concurrent=await Promise.all([200,201,202].map(status=>saveScan(query,actor,'concurrent.example',{status,checks:[]})));
  assert.equal(new Set(concurrent).size,1);assert.equal((await projectAdmin.query("SELECT count(*) FROM scans WHERE hostname='concurrent.example'")).rows[0].count,'1');
  await assert.rejects(saveScan(query,'00000000-0000-0000-0000-000000000000','owned.example',{status:500,checks:[]}));
  assert.equal((await projectAdmin.query("SELECT result FROM scans WHERE hostname='owned.example'")).rows[0].result.status,204);
  await assert.rejects(writer.query('SELECT * FROM public.scan_duplicate_archive'),{code:'42501'});
  await assert.rejects(writer.query("UPDATE scans SET hostname='changed.example'"),{code:'42501'});
 }finally{await writer.end();}
 console.log('PASS duplicate migration archive, stable-ID overwrite, updated timestamp, concurrent writes, failed-write preservation and archive isolation');
 const otherActor=(await projectAdmin.query("SELECT id FROM users WHERE email='analyst@example.test'")).rows[0].id,analyst=await login('analyst');
 const isolatedWriter=new Pool({connectionString:env.DATABASE_URL});
 let otherScanId:string;
 try{
  const query=(sql:string,values:unknown[])=>isolatedWriter.query(sql,values);
  const identicalChecks=[{header:'content-security-policy',present:true}];
  otherScanId=await saveScan(query,otherActor,'owned.example',{status:201,checks:identicalChecks});
  assert.notEqual(otherScanId,(await projectAdmin.query("SELECT id FROM scans WHERE user_id=$1 AND hostname='owned.example'",[actor])).rows[0].id);
  assert.equal(await saveScan(query,otherActor,'owned.example',{status:202,checks:identicalChecks}),otherScanId);
  await saveScan(query,otherActor,'private-only.example',{status:200,checks:[]});
  assert.equal((await projectAdmin.query("SELECT result FROM scans WHERE user_id=$1 AND hostname='owned.example'",[actor])).rows[0].result.status,204);
  await assert.rejects(isolatedWriter.query('UPDATE scans SET user_id=$1 WHERE id=$2',[actor,otherScanId]),{code:'42501'});
 }finally{await isolatedWriter.end();}
 await projectAdmin.query("INSERT INTO events(category,user_id) VALUES('private_a',$1),('private_b',$2),('legacy_unknown',NULL)",[actor,otherActor]);
 const aData=await (await call('/api/dashboard','GET',undefined,admin)).json(),bData=await (await call('/api/dashboard','GET',undefined,analyst)).json(),vData=await (await call('/api/dashboard','GET',undefined,viewer)).json();
 assert.equal(aData.scans.length,3);assert.equal(aData.overview.savedCount,3);assert(!aData.scans.some((s:any)=>s.id===otherScanId||s.hostname==='private-only.example'));
 assert.equal(bData.scans.length,2);assert.equal(bData.overview.savedCount,2);assert(bData.scans.some((s:any)=>s.id===otherScanId));assert.equal(vData.scans.length,0);assert.equal(vData.overview.savedCount,0);
 assert(aData.events.some((e:any)=>e.category==='private_a'));assert(!aData.events.some((e:any)=>['private_b','legacy_unknown'].includes(e.category)));
 assert(bData.events.some((e:any)=>e.category==='private_b'));assert(!bData.events.some((e:any)=>['private_a','legacy_unknown'].includes(e.category)));
 assert(!aData.recentEvents.some((e:any)=>['private_b','legacy_unknown'].includes(e.category)));assert(!bData.recentEvents.some((e:any)=>['private_a','legacy_unknown'].includes(e.category)));
 assert.equal((await call('/api/ai','POST',{scanId:otherScanId},admin)).status,404);
 const foreignAdminScan=(await projectAdmin.query("SELECT id FROM scans WHERE user_id=$1 AND hostname='owned.example'",[actor])).rows[0].id;
 assert.equal((await call('/api/ai','POST',{scanId:foreignAdminScan},analyst)).status,404);
 console.log('PASS account-scoped results/counts/events, same-host independent overwrite, no owner reassignment, and cross-account AI ID rejection even for admin');
 const ownScanId=(await projectAdmin.query("SELECT id FROM scans WHERE user_id=$1 AND hostname='owned.example'",[actor])).rows[0].id;
 assert.equal((await call('/api/ai','POST',{scanId:ownScanId},admin)).status,503);console.log('PASS AI disabled without key; no external API call');
 // A local fake OpenAI server proves the complete route never repeats a cached/quota-blocked request.
 let providerCalls=0,quotaMode=false;
 const provider=createServer((request,response)=>{
  providerCalls++;assert.equal(request.url,'/v1/responses');response.setHeader('Content-Type','application/json');
  if(quotaMode){response.statusCode=429;response.end(JSON.stringify({error:{code:'insufficient_quota',type:'insufficient_quota',message:'Test quota exhausted'}}));return;}
  response.end(JSON.stringify({id:'resp_test',object:'response',created_at:1,status:'completed',model:'mock-advice-model',output:[{id:'msg_test',type:'message',status:'completed',role:'assistant',content:[{type:'output_text',text:'Test defensive advice',annotations:[]}]}],usage:{input_tokens:20,output_tokens:30,total_tokens:50}}));
 });
 await new Promise<void>(resolve=>provider.listen(0,'127.0.0.1',resolve));
 const providerPort=(provider.address() as {port:number}).port,adviceBase=`http://127.0.0.1:${webPort+1}`;
 const adviceServer=spawn(process.execPath,['node_modules/tsx/dist/cli.mjs','scripts/serve.ts','--hostname','127.0.0.1','--port',String(webPort+1)],{env:{...env,APP_ORIGIN:adviceBase,PUBLIC_REGISTRATION_ENABLED:'false',AI_ENABLED:'true',OPENAI_API_KEY:'fake-key-for-local-test-only',OPENAI_MODEL:'mock-advice-model',OPENAI_BASE_URL:`http://127.0.0.1:${providerPort}/v1`},windowsHide:true,stdio:'ignore'});
 try{
  let adviceReady=false;for(let i=0;i<60;i++){if(adviceServer.exitCode!==null)throw new Error('Advice test server exited');try{if((await fetch(adviceBase+'/api/health')).ok){adviceReady=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,250));}assert(adviceReady);
  assert.equal((await fetch(adviceBase+'/api/register',{method:'POST',headers:{origin:adviceBase,'Content-Type':'application/json'},body:JSON.stringify({email:'public-blocked@example.test',password})})).status,403);
  assert.equal((await projectAdmin.query("SELECT count(*) FROM users WHERE email='public-blocked@example.test'")).rows[0].count,'0');
  console.log('PASS public-sharing profile blocks self-registration before account creation');
  const scanId=(await projectAdmin.query("SELECT id FROM scans WHERE user_id=$1 AND hostname='owned.example'",[actor])).rows[0].id;
  const requestAdvice=(locale:string)=>fetch(adviceBase+'/api/ai',{method:'POST',headers:{origin:adviceBase,cookie:admin+`; wg_locale=${locale}`,'Content-Type':'application/json'},body:JSON.stringify({scanId})});
  const live=await requestAdvice('ko');assert.equal(live.status,200);const generated=await live.json();assert.equal(generated.source,'ai');assert.equal(generated.inputTokens,20);assert.equal(generated.outputTokens,30);
  const cached=await (await requestAdvice('ko')).json();assert.equal(cached.source,'cache');assert.equal(providerCalls,1);
  const foreign=await fetch(adviceBase+'/api/ai',{method:'POST',headers:{origin:adviceBase,cookie:admin,'Content-Type':'application/json'},body:JSON.stringify({scanId:otherScanId})});assert.equal(foreign.status,404);assert.equal(providerCalls,1);
  const otherAdvice=await fetch(adviceBase+'/api/ai',{method:'POST',headers:{origin:adviceBase,cookie:analyst+'; wg_locale=ko','Content-Type':'application/json'},body:JSON.stringify({scanId:otherScanId})});assert.equal(otherAdvice.status,200);assert.equal((await otherAdvice.json()).source,'ai');assert.equal(providerCalls,2);
  quotaMode=true;const fallback=await (await requestAdvice('ja')).json();assert.equal(fallback.source,'local');assert.equal(fallback.reasonCode,'AI_QUOTA_EXCEEDED');assert(fallback.advice.length>0);assert.equal(providerCalls,3);
  const cooldown=await (await requestAdvice('es')).json();assert.equal(cooldown.source,'local');assert.equal(cooldown.reasonCode,'AI_QUOTA_EXCEEDED');assert.equal(providerCalls,3);
  console.log('PASS complete AI route with local-only provider: token usage, cache avoids calls, quota fallback and cross-language cooldown');
 }finally{adviceServer.kill();provider.closeAllConnections();await new Promise<void>(resolve=>provider.close(()=>resolve()));}

 assert.equal((await call('/decoy')).status,404);
 assert.equal((await projectAdmin.query("SELECT count(*) FROM events WHERE category='decoy_visit'")).rows[0].count,'1');console.log('PASS bounded decoy event persisted');
 for(let i=0;i<6;i++){const r=await call('/api/login','POST',{email:'absent@example.test',password:'incorrect'});assert.equal(r.status,i===5?429:401);}console.log('PASS account login rate limit');
 await projectAdmin.query("UPDATE sessions SET expires_at=now()-interval '1 second' WHERE token_hash<>$1",['none']);assert.equal((await call('/api/dashboard','GET',undefined,viewer)).status,401);console.log('PASS session expiry enforced');
 const fresh=await login('admin');assert.equal((await call('/api/logout','POST',{},fresh)).status,200);assert.equal((await call('/api/dashboard','GET',undefined,fresh)).status,401);console.log('PASS logout revokes session');
 const attacked=await fetch(base+'/.env',{headers:{'x-forwarded-for':'8.8.8.8','x-webguard-client-ip':'8.8.8.8','Accept-Language':'ko'}});
 assert.equal(attacked.status,429);assert.equal((await attacked.json()).errorCode,'THREAT_BLOCKED');assert(Number(attacked.headers.get('retry-after'))>=295&&Number(attacked.headers.get('retry-after'))<=300);
 assert.equal((await projectAdmin.query("SELECT strikes FROM ip_blocks WHERE address='127.0.0.1'")).rows[0].strikes,1);
 assert.equal((await projectAdmin.query("SELECT count(*) FROM ip_blocks WHERE address='8.8.8.8'")).rows[0].count,'0');
 await Promise.all(Array.from({length:8},async()=>assert.equal((await call('/.git/config')).status,429)));
 assert.equal((await projectAdmin.query("SELECT strikes FROM ip_blocks WHERE address='127.0.0.1'")).rows[0].strikes,1);
 assert.equal((await call('/api/dashboard')).status,429);assert.equal((await call('/api/health')).status,200);
 console.log('PASS actual peer IP blocks, forged IP headers ignored, Retry-After and no strike inflation during block');
 for(let strike=2;strike<=6;strike++){
  await projectAdmin.query("UPDATE ip_blocks SET blocked_until=now()-interval '1 second' WHERE address='127.0.0.1'");
  assert.equal((await call('/')).status,200);
  const responses=await Promise.all(Array.from({length:4},()=>call('/wp-admin')));assert(responses.every(r=>r.status===(strike===6?403:429)));
  const state=(await projectAdmin.query("SELECT strikes,blacklisted FROM ip_blocks WHERE address='127.0.0.1'")).rows[0];assert.equal(state.strikes,strike);assert.equal(state.blacklisted,strike===6);
 }
 assert.equal((await call('/')).status,403);assert.equal((await (await call('/api/dashboard')).json()).errorCode,'IP_BLACKLISTED');
 console.log('PASS expiry unlock, concurrent violations count once per cycle, five temporary blocks and sixth-offense persistent blacklist');
 await exec(process.execPath,['node_modules/tsx/dist/cli.mjs','scripts/unblock-ip.ts','127.0.0.1'],{env,windowsHide:true});
 assert.equal((await call('/')).status,200);assert.equal((await projectAdmin.query("SELECT strikes FROM ip_blocks WHERE address='127.0.0.1'")).rows[0].strikes,0);
 assert.equal((await projectAdmin.query("SELECT count(*) FROM events WHERE category='ip_unblocked'")).rows[0].count,'1');
 console.log('PASS local administrator recovery and audited unblock');
 await projectAdmin.query('ALTER ROLE webguard_hub_dev_app REPLICATION');
 assert.equal((await (await call('/api/ready')).json()).code,'DATABASE_RUNTIME_ROLE_UNSAFE');
 await assert.rejects(script('scripts/grant-runtime.ts'));
 await projectAdmin.query('ALTER ROLE webguard_hub_dev_app NOREPLICATION');
 await projectAdmin.query('ALTER ROLE webguard_hub_dev_app BYPASSRLS');
 await assert.rejects(script('scripts/grant-runtime.ts'));
 await projectAdmin.query('ALTER ROLE webguard_hub_dev_app NOBYPASSRLS');
 console.log('PASS replication/RLS-bypass runtime privileges are rejected by readiness/grant checks');
 await projectAdmin.query("INSERT INTO ip_blocks(address,strikes,blacklisted,blocked_until,last_reason) VALUES('198.51.100.99',1,false,now()+interval '5 minutes','probe')");
 const newAdmin=await login('admin'),newViewer=await login('viewer');
 const adminDefense=await (await call('/api/dashboard','GET',undefined,newAdmin)).json(),viewerDefense=await (await call('/api/dashboard','GET',undefined,newViewer)).json();
 assert.equal(adminDefense.overview.targetPolicy,'public');assert(adminDefense.ipBlocks.some((block:any)=>block.address==='198.51.100.99'));
 assert.equal(Object.hasOwn(viewerDefense,'ipBlocks'),false);console.log('PASS public-target metadata and administrator-only IP disclosure');
 assert.equal((await call('/api/ready')).status,200);console.log('PASS readiness confirms migrated least-privilege runtime');
 await pool.query('CREATE DATABASE webguard_copy_fixture');
 const targetUrl=`postgresql://postgres@127.0.0.1:${pgPort}/webguard_copy_fixture`;
 const cloudEnv={PROJECT_DATABASE:'webguard_copy_fixture',PROJECT_RUNTIME_ROLE:'webguard_fixture_app',MIGRATION_DATABASE_URL:targetUrl};
 const output=path.join(dir,'generated-production.env');
 await assert.rejects(exec(process.execPath,['node_modules/tsx/dist/cli.mjs','scripts/setup-production.ts','--output','unignored-credentials.txt'],{env:{...env,...cloudEnv},windowsHide:true}));
 await exec(process.execPath,['node_modules/tsx/dist/cli.mjs','scripts/setup-production.ts','--output',output],{env:{...env,...cloudEnv},windowsHide:true});
 const generated=await readFile(output,'utf8');assert(generated.includes('DATABASE_URL='));assert(generated.includes('PUBLIC_REGISTRATION_ENABLED=true'));assert(!generated.includes('MIGRATION_DATABASE_URL'));
 const roleState=(await pool.query("SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls FROM pg_roles WHERE rolname='webguard_fixture_app'")).rows[0];assert(Object.values(roleState).every(value=>value===false));
 await assert.rejects(exec(process.execPath,['node_modules/tsx/dist/cli.mjs','scripts/setup-production.ts','--output',output],{env:{...env,...cloudEnv},windowsHide:true}));assert.equal(await readFile(output,'utf8'),generated);
 await script('scripts/migrate.ts',cloudEnv);await script('scripts/grant-runtime.ts',cloudEnv);
 await script('scripts/copy-production-data.ts',cloudEnv);
 const copied=new Pool({connectionString:targetUrl});
 assert.deepEqual((await copied.query('SELECT id,password_hash,role FROM users ORDER BY id')).rows,(await projectAdmin.query('SELECT id,password_hash,role FROM users ORDER BY id')).rows);
 assert.equal((await copied.query('SELECT count(*) FROM scans')).rows[0].count,(await projectAdmin.query('SELECT count(*) FROM scans')).rows[0].count);
 assert.equal((await copied.query('SELECT count(*) FROM sessions')).rows[0].count,'0');
 await assert.rejects(script('scripts/copy-production-data.ts',cloudEnv));
 assert.equal((await copied.query("SELECT count(*) FROM events WHERE category='production_data_imported'")).rows[0].count,'1');
 await copied.end();console.log('PASS production role setup, existing-file protection, account hash/result copy, no copied sessions and non-empty target rejection');
 await pool.query('CREATE DATABASE webguard_managed_fixture');
 const managed=new Pool({connectionString:`postgresql://postgres@127.0.0.1:${pgPort}/webguard_managed_fixture`});
 try{
  await managed.query(await readFile('sql/migrations/prisma-postgres/001_initial.sql','utf8'));
  const legacyUser=randomUUID(),legacyScan=randomUUID();
  await managed.query('INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,$4)',[legacyUser,'legacy-managed@example.test',newAccount.password_hash,'viewer']);
  await managed.query("INSERT INTO scans(id,user_id,hostname,result) VALUES($1,$2,'legacy-managed.example','{\"status\":200,\"checks\":[]}')",[legacyScan,legacyUser]);
  await managed.query("INSERT INTO events(category) VALUES('legacy_actor_unknown')");
  await managed.query(await readFile('sql/migrations/prisma-postgres/002_account_isolation.sql','utf8'));
  assert.equal((await managed.query('SELECT user_id FROM scans WHERE id=$1',[legacyScan])).rows[0].user_id,legacyUser);
  assert.equal((await managed.query("SELECT user_id FROM events WHERE category='legacy_actor_unknown'")).rows[0].user_id,null);
  const managedQuery=(sql:string,values:unknown[])=>{assertManagedRuntimeSql(sql);return managed.query(sql,values);};
  const managedId=randomUUID();await managedQuery('SELECT public.register_viewer($1,$2,$3)',[managedId,'managed@example.test',newAccount.password_hash]);
  assert.equal((await managedQuery('SELECT role FROM users WHERE id=$1',[managedId])).rows[0].role,'viewer');
  const saved=await saveScan(managedQuery,managedId,'managed.example',{status:200,checks:[]});
  assert.equal(await saveScan(managedQuery,managedId,'managed.example',{status:204,checks:[]}),saved);
  await cachedAdvice(managedQuery,adviceKey('managed-test','ko',[]),async()=>({advice:'Local test only',inputTokens:1,outputTokens:1}));
  const beforeRecovery=(await managed.query('SELECT id,user_id,hostname,result,created_at FROM scans WHERE id=$1',[saved])).rows;
  await managed.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '1 hour')",[tokenHash('recovery-test-only-token'),managedId]);
  await managed.query("INSERT INTO rate_limits(bucket,hits,reset_at) VALUES($1,5,now()+interval '5 minutes')",['login:'+tokenHash('managed@example.test')]);
  const client=await managed.connect();try{
   const hash=hashPassword('local-recovery-test-only#2026');
   await assert.rejects(resetAccountPassword(client,'missing@example.test',hash,tokenHash('missing@example.test')),/ACCOUNT_NOT_FOUND/);
   const broken={async query(sql:string,values?:unknown[]){if(sql.startsWith('DELETE FROM public.sessions'))throw new Error('SIMULATED_FAILURE');return client.query(sql,values);}};
   await assert.rejects(resetAccountPassword(broken,'managed@example.test',hash,tokenHash('managed@example.test')),/SIMULATED_FAILURE/);
   assert.equal((await client.query('SELECT password_hash FROM users WHERE id=$1',[managedId])).rows[0].password_hash,newAccount.password_hash);
   assert.equal((await client.query('SELECT count(*) FROM sessions WHERE user_id=$1',[managedId])).rows[0].count,'1');
   await resetAccountPassword(client,'managed@example.test',hash,tokenHash('managed@example.test'));
  }finally{client.release();}
  const recovered=(await managed.query('SELECT password_hash,role FROM users WHERE id=$1',[managedId])).rows[0];assert(verifyPassword('local-recovery-test-only#2026',recovered.password_hash));assert.equal(recovered.role,'viewer');
  assert.deepEqual((await managed.query('SELECT id,user_id,hostname,result,created_at FROM scans WHERE id=$1',[saved])).rows,beforeRecovery);
  assert.equal((await managed.query('SELECT count(*) FROM sessions WHERE user_id=$1',[managedId])).rows[0].count,'0');
  assert.equal((await managed.query('SELECT count(*) FROM rate_limits WHERE bucket=$1',['login:'+tokenHash('managed@example.test')])).rows[0].count,'0');
  assert.equal((await managed.query("SELECT count(*) FROM events WHERE user_id=$1 AND category='password_reset_admin'",[managedId])).rows[0].count,'1');
  console.log('PASS administrative password recovery, rollback on partial failure, missing-user refusal, role/result preservation, session and login-limit invalidation');
  console.log('PASS managed-provider schema, forced-viewer registration, guarded upsert and cache SQL on disposable DB (provider ACL limitations remain)');
 }finally{await managed.end();}
 await projectAdmin.end();
}finally{server?.kill();await Promise.allSettled(projectPools.map(project=>project.end()));await pool.end();if(pgStarted)await control(['-D',dir,'-m','fast','-w','stop']);console.log('Disposable cluster stopped; test data remains in ignored work/ for inspection.');}
