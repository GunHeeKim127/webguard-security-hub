// Disposable local cluster only. Never connects to the user's existing database.
import {createServer} from 'node:http';
import { execFile,spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp,mkdir } from 'node:fs/promises';
import path from 'node:path';
import {tmpdir} from 'node:os';
import { randomBytes,randomUUID,createHash } from 'node:crypto';
import { Pool } from 'pg';
import assert from 'node:assert/strict';
import {cachedAdvice,adviceKey} from '../lib/advice-cache';
import {withAiBudget} from '../lib/ai-budget';
import {saveScan} from '../lib/scan-store';
import {assertManagedRuntimeSql} from '../lib/runtime-sql';
import {hashPassword,verifyPassword,tokenHash} from '../lib/password';
import {resetAccountPassword} from './support/reset-account-password';
import {saveAssessment} from '../lib/assessment/store';
import {protectionQuery} from '../lib/protection-query';
import {ACTIVE_BLOCK_SQL} from '../lib/ingress-guard';
import {vercelProtection} from '../lib/vercel-protection';
const exec=promisify(execFile),bin=process.env.PG_BIN??'C:/Program Files/PostgreSQL/15/bin';
// Windows PostgreSQL can reject non-ASCII checkout paths during initdb.
// Keep disposable cluster data in the OS temp directory, separate from real DBs.
const clusterRoot=process.env.PG_TEST_ROOT??(process.platform==='win32'?path.join(tmpdir(),'webguard-tests'):path.resolve('work'));
await mkdir(clusterRoot,{recursive:true});const dir=await mkdtemp(path.join(clusterRoot,'isolated-pg-'));
const pgPort=45000+Math.floor(Math.random()*5000),webPort=50000+Math.floor(Math.random()*5000),base=`http://127.0.0.1:${webPort}`;
const database=`postgresql://postgres@127.0.0.1:${pgPort}/postgres`;
const env={...process.env,PROJECT_DATABASE:'webguard_hub_dev',PROJECT_RUNTIME_ROLE:'webguard_hub_dev_app',DATABASE_URL:`postgresql://webguard_hub_dev_app@127.0.0.1:${pgPort}/webguard_hub_dev`,MIGRATION_DATABASE_URL:`postgresql://webguard_hub_dev_migrator@127.0.0.1:${pgPort}/webguard_hub_dev`,APP_ORIGIN:base,APP_ADDITIONAL_ORIGINS:`http://localhost:${webPort}`,AI_ENABLED:'false',AI_PROVIDER:'openai',OPENAI_API_KEY:'',ALLOWED_SCAN_HOSTS:'owned.example',SCAN_TARGET_POLICY:'public',TRUSTED_PROXY_IPS:'',WEBGUARD_PROXY_SECRET:''};
const pool=new Pool({connectionString:database,connectionTimeoutMillis:1000});let pgStarted=false;let server:ReturnType<typeof spawn>|undefined;
const projectPools:Pool[]=[];
// Never inherit the real production DB profile or platform-IP mode from env files.
const archiveSecret=randomBytes(32).toString('hex');
Object.assign(env,{WEBGUARD_VERIFY:'true',DATABASE_PROVIDER:'postgresql',VERCEL:'',PUBLIC_REGISTRATION_ENABLED:'true',GROQ_API_KEY:'',GEMINI_API_KEY:'',GEOIP_PROXY_SECRET:'',CRON_SECRET:archiveSecret});
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
 assert.equal((await projectAdmin.query('SELECT count(*) FROM schema_migrations')).rows[0].count,'12');console.log('PASS per-project setup, migrations, grants and idempotent rerun');
 const runtime=new Pool({connectionString:env.DATABASE_URL});
 // Reproduce an upstream read lasting over the general 5s client deadline.
 // Locks exist only in this disposable DB; no production writes or traffic.
 const guardPool=new Pool({connectionString:env.DATABASE_URL,query_timeout:5000});projectPools.push(guardPool);
 for(const adjusted of [false,true]){
  const blocker=await projectAdmin.connect();let unlock:Promise<unknown>|undefined;
  try{
   await blocker.query('BEGIN');await blocker.query('LOCK public.ip_blocks IN ACCESS EXCLUSIVE MODE');
   const timer=setTimeout(()=>{unlock=blocker.query('COMMIT');},6000);
   try{
    if(adjusted)assert.deepEqual((await protectionQuery(guardPool,ACTIVE_BLOCK_SQL,['192.0.2.199'],true)).rows,[]);
    else await assert.rejects(guardPool.query(ACTIVE_BLOCK_SQL,['192.0.2.199']),/Query read timeout/);
   }finally{await new Promise(resolve=>setTimeout(resolve,1100));clearTimeout(timer);if(unlock)await unlock;else await blocker.query('ROLLBACK');}
  }finally{blocker.release();}
 }
 console.log('PASS real PostgreSQL delayed protection read: old 5s deadline fails, scoped 10s deadline succeeds; no production DB used');
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
 assert.equal((await call('/api/scans','POST',{url:'https://127.0.0.1',authorized:true},newCookie)).status,400);
 const memberInput={moduleId:'linux.ssh',label:'Member owned asset',text:'PermitRootLogin yes',authorized:true};
 const memberFirst=await call('/api/assessments','POST',memberInput,newCookie);assert.equal(memberFirst.status,200);const memberSaved=await memberFirst.json();
 const memberRetest=await call('/api/assessments','POST',{...memberInput,text:'PermitRootLogin no'},newCookie);assert.equal(memberRetest.status,200);assert.equal((await memberRetest.json()).asset_id,memberSaved.asset_id);
 const memberHistory=await (await call('/api/assessments?assetId='+memberSaved.asset_id,'GET',undefined,newCookie)).json();assert.equal(memberHistory.runs.length,2);
 assert.equal((await call('/api/assessments?assetId='+memberSaved.asset_id,'GET',undefined,admin)).status,404);
 assert.equal(Object.hasOwn(await (await call('/api/dashboard','GET',undefined,newCookie)).json(),'ipBlocks'),false);
 const memberPage=await (await call('/workbench/endpoint','GET',undefined,newCookie+'; wg_locale=ko')).text();assert(memberPage.includes('일반 회원'));assert(memberPage.includes('최근 30일'));assert(!memberPage.includes('진단은 admin/analyst'));
 assert.equal((await call('/api/register','POST',{email:'new@example.test',password:signupPassword})).status,202);
 assert.equal((await call('/api/register','POST',{email:'new@example.test',password:signupPassword})).status,429);
 console.log('PASS public signup member assessment/retest/history, admin isolation, SSRF protection, role injection rejection, hashed password, duplicate safety and rate limits');

 const token=admin.split('=')[1];assert.equal((await projectAdmin.query('SELECT count(*) FROM sessions WHERE token_hash=$1',[token])).rows[0].count,'0');
 const overviewResponse=await call('/api/dashboard','GET',undefined,admin);assert.equal(overviewResponse.status,200);const overviewData=await overviewResponse.json();assert.equal(overviewData.overview.approvedCount,1);assert(Array.isArray(overviewData.recentEvents));const viewerData=await (await call('/api/dashboard','GET',undefined,viewer)).json();assert.deepEqual(viewerData.overview.approvedHosts,['owned.example']);console.log('PASS account bootstrap, login, hashed sessions, dashboard');
 assert.equal((await call('/api/scans','POST',{url:'https://127.0.0.1',authorized:true},viewer)).status,400);
 assert.equal((await call('/api/ai','POST',{scanId:'00000000-0000-0000-0000-000000000000'},viewer)).status,404);console.log('PASS general member scan input validation and AI ownership enforcement');
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

 const eventBaselineA=await (await call('/api/dashboard','GET',undefined,admin)).json(),eventBaselineB=await (await call('/api/dashboard','GET',undefined,analyst)).json();
 const otherCount=(value:any)=>value.events.find((e:any)=>e.category==='other')?.count??0;
 const eventTimeA=new Date(Date.now()+1000).toISOString(),eventTimeB=new Date(Date.now()+2000).toISOString(),eventTimeNull=new Date(Date.now()+3000).toISOString();
 await projectAdmin.query("INSERT INTO events(category,user_id,created_at) VALUES('private_a',$1,$3),('private_b',$2,$4),('private_b',$2,$4),('legacy_unknown',NULL,$5)",[actor,otherActor,eventTimeA,eventTimeB,eventTimeNull]);
 const aData=await (await call('/api/dashboard','GET',undefined,admin)).json(),bData=await (await call('/api/dashboard','GET',undefined,analyst)).json(),vData=await (await call('/api/dashboard','GET',undefined,viewer)).json();
 assert.equal(aData.scans.length,3);assert.equal(aData.overview.savedCount,3);assert(!aData.scans.some((s:any)=>s.id===otherScanId||s.hostname==='private-only.example'));
 assert.equal(bData.scans.length,2);assert.equal(bData.overview.savedCount,2);assert(bData.scans.some((s:any)=>s.id===otherScanId));assert.equal(vData.scans.length,0);assert.equal(vData.overview.savedCount,0);
 assert.equal(otherCount(aData),otherCount(eventBaselineA)+1);assert.equal(otherCount(bData),otherCount(eventBaselineB)+2);
 for(const data of [aData,bData,vData])for(const value of ['private_a','private_b','legacy_unknown'])assert(!JSON.stringify(data).includes(value));
 assert(aData.recentEvents.some((e:any)=>e.category==='other'&&e.created_at===eventTimeA));assert(!aData.recentEvents.some((e:any)=>[eventTimeB,eventTimeNull].includes(e.created_at)));
 assert(bData.recentEvents.some((e:any)=>e.category==='other'&&e.created_at===eventTimeB));assert(!bData.recentEvents.some((e:any)=>[eventTimeA,eventTimeNull].includes(e.created_at)));
 assert(!vData.recentEvents.some((e:any)=>[eventTimeA,eventTimeB,eventTimeNull].includes(e.created_at)));
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
  const memberAiId=(await projectAdmin.query("SELECT id FROM users WHERE email='new@example.test'")).rows[0].id;
  const memberAiScan=await saveScan((sql,values)=>projectAdmin.query(sql,values),memberAiId,'member-ai.example',{status:200,checks:[{header:'content-security-policy',present:true}]});
  const memberAdvice=()=>fetch(adviceBase+'/api/ai',{method:'POST',headers:{origin:adviceBase,cookie:newCookie+'; wg_locale=ko','Content-Type':'application/json'},body:JSON.stringify({scanId:memberAiScan})});
  const memberAdviceFirst=await memberAdvice();assert.equal(memberAdviceFirst.status,200);assert.equal((await memberAdviceFirst.json()).source,'ai');assert.equal(providerCalls,3);
  assert.equal((await (await memberAdvice()).json()).source,'cache');assert.equal(providerCalls,3);
  assert.equal((await fetch(adviceBase+'/api/ai',{method:'POST',headers:{origin:adviceBase,cookie:newCookie,'Content-Type':'application/json'},body:JSON.stringify({scanId})})).status,404);
  console.log('PASS registered general member configured AI advice/cache and denial of another account scan; local provider only');
  quotaMode=true;const fallback=await (await requestAdvice('ja')).json();assert.equal(fallback.source,'local');assert.equal(fallback.reasonCode,'AI_QUOTA_EXCEEDED');assert(fallback.advice.length>0);assert.equal(providerCalls,4);
  const cooldown=await (await requestAdvice('es')).json();assert.equal(cooldown.source,'local');assert.equal(cooldown.reasonCode,'AI_QUOTA_EXCEEDED');assert.equal(providerCalls,4);
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
 const unsafeReady=await call('/api/ready');assert.equal(unsafeReady.status,503);
 assert.deepEqual(await unsafeReady.json(),{status:'not_ready',code:'NOT_READY'});
 await assert.rejects(script('scripts/grant-runtime.ts'));
 await projectAdmin.query('ALTER ROLE webguard_hub_dev_app NOREPLICATION');
 await projectAdmin.query('ALTER ROLE webguard_hub_dev_app BYPASSRLS');
 await assert.rejects(script('scripts/grant-runtime.ts'));
 await projectAdmin.query('ALTER ROLE webguard_hub_dev_app NOBYPASSRLS');
 console.log('PASS replication/RLS-bypass runtime privileges are rejected by readiness/grant checks');
 await projectAdmin.query("INSERT INTO ip_blocks(address,strikes,blacklisted,blocked_until,last_reason) VALUES('198.51.100.99',1,false,now()+interval '5 minutes','probe')");
 const newAdmin=await login('admin'),newViewer=await login('viewer');
 const adminDefense=await (await call('/api/dashboard','GET',undefined,newAdmin)).json(),viewerDefense=await (await call('/api/dashboard','GET',undefined,newViewer)).json();
 assert.equal(adminDefense.overview.targetPolicy,'public');assert(!JSON.stringify(adminDefense).includes('198.51.100.99'));assert(!JSON.stringify(adminDefense).includes('admin@example.test'));assert(!Object.hasOwn(adminDefense.user,'id'));assert(adminDefense.ipBlocks.every((block:any)=>block.blockId&&block.address==='***.***.***.***'));
 assert.equal(Object.hasOwn(viewerDefense,'ipBlocks'),false);console.log('PASS public-target metadata and administrator-only IP disclosure');
 const ipReference=(await projectAdmin.query("SELECT management_id FROM ip_blocks WHERE address='198.51.100.99'")).rows[0].management_id;
 const releaseBody={action:'release',blockId:ipReference};
 assert.equal((await call('/api/admin/ip-blocks','POST',releaseBody)).status,401);
 assert.equal((await call('/api/admin/ip-blocks','POST',releaseBody,newViewer)).status,403);
 assert.equal((await fetch(base+'/api/admin/ip-blocks',{method:'POST',headers:{origin:'https://evil.example','Content-Type':'application/json',cookie:newAdmin},body:JSON.stringify(releaseBody)})).status,403);
 assert.equal((await call('/api/admin/ip-blocks','POST',{...releaseBody,actorId:'forged'},newAdmin)).status,400);
 assert.equal((await call('/api/admin/ip-blocks','POST',releaseBody,newAdmin)).status,200);
 const releasedBlock=(await projectAdmin.query("SELECT strikes,blacklisted,blocked_until,last_reason FROM ip_blocks WHERE address='198.51.100.99'")).rows[0];
 assert.deepEqual(releasedBlock,{strikes:0,blacklisted:false,blocked_until:null,last_reason:'manual_reset'});
 const audit=(await projectAdmin.query("SELECT category,user_id,created_at FROM events WHERE category LIKE 'ip_unblocked_target:%'")).rows;assert.equal(audit.length,1);assert.equal(audit[0].user_id,actor);assert(audit[0].created_at);assert(/^ip_unblocked_target:[a-f0-9]{64}$/.test(audit[0].category));
 assert.equal((await call('/api/admin/ip-blocks','POST',releaseBody,newAdmin)).status,404);
 assert.equal((await projectAdmin.query("SELECT count(*) FROM events WHERE category LIKE 'ip_unblocked_target:%'")).rows[0].count,'1');
 await projectAdmin.query("INSERT INTO ip_blocks(address,strikes,blacklisted,blocked_until,last_reason) VALUES('203.0.113.55',6,true,NULL,'probe')");
 const permanentIpReference=(await projectAdmin.query("SELECT management_id FROM ip_blocks WHERE address='203.0.113.55'")).rows[0].management_id;
 // An audit-write failure must roll back the reset, in this disposable DB only.
 await projectAdmin.query('REVOKE INSERT ON public.events FROM webguard_hub_dev_app');
 try{assert.equal((await call('/api/admin/ip-blocks','POST',{action:'release',blockId:permanentIpReference},newAdmin)).status,503);}finally{await projectAdmin.query('GRANT INSERT ON public.events TO webguard_hub_dev_app');}
 assert.equal((await projectAdmin.query("SELECT blacklisted FROM ip_blocks WHERE address='203.0.113.55'")).rows[0].blacklisted,true);
 assert.equal((await call('/api/admin/ip-blocks','POST',{action:'release',blockId:permanentIpReference},newAdmin)).status,200);
 assert.equal((await projectAdmin.query("SELECT blacklisted FROM ip_blocks WHERE address='203.0.113.55'")).rows[0].blacklisted,false);
 assert.equal((await call('/api/admin/ip-blocks','POST',{action:'release',address:'198.51.100.99'},newAdmin)).status,400);
 console.log('PASS administrator-only IP release: guest/member/cross-Origin/actor-injection rejection, atomic reset, actor/time/target-hash audit and duplicate safety');
 await script('scripts/create-user.ts',{BOOTSTRAP_EMAIL:'blockedaccount@example.test',BOOTSTRAP_PASSWORD:password,BOOTSTRAP_ROLE:'viewer'});
 const accountCookie=await login('blockedaccount');const blockedId=(await projectAdmin.query("SELECT id FROM users WHERE email='blockedaccount@example.test'")).rows[0].id;
 assert.equal((await call('/api/dashboard','GET',undefined,accountCookie+'; '+accountCookie)).status,401);
 const threatPool=new Pool({connectionString:env.DATABASE_URL});projectPools.push(threatPool);
 const simulatedThreat=(address:string,cookie?:string)=>vercelProtection(new Request('https://owned.example/.env?userId='+blockedId,{headers:{'x-real-ip':address,...(cookie?{cookie}:{})}}),(sql,values)=>threatPool.query(sql,values),{VERCEL:'1'});
 await simulatedThreat('192.0.2.101','wg_session='+'f'.repeat(64));
 assert.equal((await projectAdmin.query('SELECT count(*) FROM account_blocks WHERE user_id=$1',[blockedId])).rows[0].count,'0');
 await projectAdmin.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()-interval '1 minute')",[tokenHash('e'.repeat(64)),blockedId]);
 await simulatedThreat('192.0.2.102','wg_session='+'e'.repeat(64));
 assert.equal((await projectAdmin.query('SELECT count(*) FROM account_blocks WHERE user_id=$1',[blockedId])).rows[0].count,'0');
 await Promise.all(Array.from({length:4},()=>simulatedThreat('192.0.2.110',accountCookie)));
 assert.equal((await projectAdmin.query('SELECT strikes FROM account_blocks WHERE user_id=$1',[blockedId])).rows[0].strikes,1);
 for(let strike=2;strike<=6;strike++){
  assert.equal((await simulatedThreat('192.0.2.'+(110+strike),accountCookie))?.status,429);
  const row=(await projectAdmin.query('SELECT strikes,blacklisted FROM account_blocks WHERE user_id=$1',[blockedId])).rows[0];assert.equal(row.strikes,strike);assert.equal(row.blacklisted,strike===6);
 }
 assert.equal((await projectAdmin.query('SELECT count(*) FROM sessions WHERE user_id=$1',[blockedId])).rows[0].count,'0');
 assert.equal((await call('/api/dashboard','GET',undefined,accountCookie)).status,401);
 assert.equal((await call('/api/login','POST',{email:'blockedaccount@example.test',password})).status,401);
 const accountReference=(await projectAdmin.query('SELECT management_id FROM account_blocks WHERE user_id=$1',[blockedId])).rows[0].management_id;
 const accountAdmin=(await (await call('/api/dashboard','GET',undefined,newAdmin)).json()).accountBlocks;assert(accountAdmin.some((row:any)=>row.blockId===accountReference&&row.blacklisted));assert(!JSON.stringify(accountAdmin).includes(blockedId));assert(!JSON.stringify(accountAdmin).includes('blockedaccount@example.test'));
 assert.equal(Object.hasOwn(await (await call('/api/dashboard','GET',undefined,newViewer)).json(),'accountBlocks'),false);
 const accountRelease={action:'release',blockId:accountReference};
 assert.equal((await call('/api/admin/account-blocks','POST',accountRelease)).status,401);
 assert.equal((await call('/api/admin/account-blocks','POST',accountRelease,newViewer)).status,403);
 assert.equal((await call('/api/admin/account-blocks','POST',{...accountRelease,actorId:'forged'},newAdmin)).status,400);
 assert.equal((await fetch(base+'/api/admin/account-blocks',{method:'POST',headers:{origin:'https://evil.example','Content-Type':'application/json',cookie:newAdmin},body:JSON.stringify(accountRelease)})).status,403);
 await projectAdmin.query('REVOKE INSERT ON public.events FROM webguard_hub_dev_app');
 try{assert.equal((await call('/api/admin/account-blocks','POST',accountRelease,newAdmin)).status,503);}finally{await projectAdmin.query('GRANT INSERT ON public.events TO webguard_hub_dev_app');}
 assert.equal((await projectAdmin.query('SELECT blacklisted FROM account_blocks WHERE user_id=$1',[blockedId])).rows[0].blacklisted,true);
 assert.equal((await call('/api/admin/account-blocks','POST',accountRelease,newAdmin)).status,200);
 assert.equal((await call('/api/dashboard','GET',undefined,accountCookie)).status,401);
 const accountFresh=await login('blockedaccount');assert.equal((await call('/api/dashboard','GET',undefined,accountFresh)).status,200);
 assert.equal((await projectAdmin.query('SELECT strikes FROM account_blocks WHERE user_id=$1',[blockedId])).rows[0].strikes,0);
 const accountAudit=(await projectAdmin.query("SELECT user_id,created_at FROM events WHERE category LIKE 'account_unblocked_target:%'")).rows;assert.equal(accountAudit.length,1);assert.equal(accountAudit[0].user_id,actor);assert(accountAudit[0].created_at);
 assert.equal((await call('/api/admin/account-blocks','POST',accountRelease,newAdmin)).status,404);
 assert.equal((await call('/api/admin/account-blocks','POST',{action:'release',userId:blockedId},newAdmin)).status,400);
 console.log('PASS real-DB account attribution: forged/expired/duplicate identity rejected, concurrent strikes, sixth-offense ban, session revocation, login denial, admin-only release/audit/rollback and fresh-login recovery');
 assert.equal((await call('/api/ready')).status,200);console.log('PASS readiness confirms migrated least-privilege runtime');
 assert.equal((await call('/workbench','GET',undefined,newAdmin)).status,200);
 async function assertPageRedirect(response:Response,destination:string){
  if(response.status===307){assert.equal(response.headers.get('location'),destination);return;}
  assert.equal(response.status,200);const html=await response.text();
  assert(html.includes('id="__next-page-redirect" http-equiv="refresh" content="1;url='+destination+'"'));
  assert(!html.includes('id="asset-inspector"'));assert(!html.includes('id="assessment-results"'));
 }
 const homeEntry=await fetch(base+'/',{headers:{cookie:newAdmin},redirect:'manual'});await assertPageRedirect(homeEntry,'/workbench');
 const classicEntry=await call('/?view=web','GET',undefined,newAdmin);assert.equal(classicEntry.status,200);
 const platformHtml=await (await call('/workbench','GET',undefined,newAdmin)).text();assert(!platformHtml.includes('admin@example.test'));assert(!platformHtml.includes(actor));for(const section of ['VELTHARA','Unified Asset Security Assessment Platform','Virtualization','Container','Endpoint'])assert(platformHtml.includes(section));
 assert(!platformHtml.includes('id="asset-inspector"'));assert(!platformHtml.includes('id="assessment-results"'));
 for(const href of ['/?view=web','/workbench/mobile','/workbench/endpoint','/workbench/results'])assert(platformHtml.includes('href="'+href+'"'));
 for(const [page,module] of [['mobile','application.package'],['endpoint','application.pe'],['web','web.compare'],['virtualization','virtualization.vmx'],['network','network.gns3']] as const){const pageResponse=await call('/workbench/'+page,'GET',undefined,newViewer);assert.equal(pageResponse.status,200);const html=await pageResponse.text();assert(html.includes('id="asset-inspector"'));assert(html.includes('value="'+module+'"'));assert(!html.includes('Unified Asset Security Assessment Platform'));const guest=await fetch(base+'/workbench/'+page,{redirect:'manual'});await assertPageRedirect(guest,'/');}
 const resultsPage=await (await call('/workbench/results','GET',undefined,newAdmin)).text();assert(resultsPage.includes('id="assessment-results"'));assert(!resultsPage.includes('id="asset-inspector"'));
 const missingPage=await call('/workbench/not-a-module','GET',undefined,newAdmin);if(missingPage.status!==404){assert.equal(missingPage.status,200);const missingHtml=await missingPage.text();assert(missingHtml.includes('name="robots" content="noindex"'));assert(!missingHtml.includes('id="asset-inspector"'));}
 console.log('PASS button-only landing, dedicated category pages, direct-link authentication, results page, unknown route 404 and preserved classic web entry');
 assert.equal((await call('/api/assessments','POST',{moduleId:'linux.ssh',label:'lab',text:'PermitRootLogin yes',authorized:true},newViewer)).status,200);
 const phaseInput={moduleId:'linux.ssh',label:'integration lab',text:'PermitRootLogin yes\n# PRIVATE_CONFIG_TOKEN',authorized:true};
 const phaseFirst=await call('/api/assessments','POST',phaseInput,newAdmin);assert.equal(phaseFirst.status,200);const phaseA=await phaseFirst.json();assert(!JSON.stringify(phaseA).includes('PRIVATE_CONFIG_TOKEN'));
 const phaseSecond=await call('/api/assessments','POST',{...phaseInput,text:'PermitRootLogin no'},newAdmin);assert.equal(phaseSecond.status,200);const phaseB=await phaseSecond.json();assert.equal(phaseA.asset_id,phaseB.asset_id);assert.notEqual(phaseA.id,phaseB.id);
 const phaseAnalyst=await login('analyst');
 const phaseOther=await call('/api/assessments','POST',phaseInput,phaseAnalyst);assert.equal(phaseOther.status,200);assert.notEqual((await phaseOther.json()).asset_id,phaseA.asset_id);
 assert.equal((await call('/api/assessments?assetId='+phaseA.asset_id,'GET',undefined,phaseAnalyst)).status,404);
 const phaseHistory=await (await call('/api/assessments?assetId='+phaseA.asset_id,'GET',undefined,newAdmin)).json();assert.equal(phaseHistory.runs.length,2);assert.equal(phaseHistory.runs[0].report.findings[0].status,'pass');assert.equal(phaseHistory.runs[1].report.findings[0].status,'warning');
 const ownAssets=await (await call('/api/assessments','GET',undefined,phaseAnalyst)).json();
 const ownId=ownAssets.assets[0].id,ownHistory=await (await call('/api/assessments?assetId='+ownId,'GET',undefined,phaseAnalyst)).json();
 const initialResponse=await call('/api/assessments?initial=1&category=endpoint','GET',undefined,phaseAnalyst);assert.equal(initialResponse.status,200);const initialData=await initialResponse.json();
 assert.equal(initialData.selectedAssetId,ownId);assert.deepEqual(initialData.runs,ownHistory.runs);assert(initialData.assets.every((asset:any)=>['linux.ssh','windows.policy','application.pe','application.macho'].includes(asset.module_id)));assert(!JSON.stringify(initialData).includes(phaseA.asset_id));
 const emptyCategory=await (await call('/api/assessments?initial=1&category=network','GET',undefined,phaseAnalyst)).json();assert.equal(emptyCategory.selectedAssetId,null);assert.deepEqual(emptyCategory.runs,[]);assert.deepEqual(emptyCategory.assets,[]);
 for(const path of ['/api/assessments?initial=2','/api/assessments?initial=1&category=admin','/api/assessments?initial=1&category=endpoint&category=web','/api/assessments?initial=1&assetId='+phaseA.asset_id])assert.equal((await call(path,'GET',undefined,phaseAnalyst)).status,400);
 assert.equal((await call('/api/assessments?initial=1&category=endpoint')).status,401);console.log('PASS single initial assessment GET includes own category asset/history, empty state and strict request/tenant boundaries');
 const invalidConfig=await call('/api/assessments','POST',{...phaseInput,text:'UnrelatedDirective invalid-fixture'},phaseAnalyst);assert.equal(invalidConfig.status,400);assert.equal((await invalidConfig.json()).errorCode,'ASSESSMENT_INPUT_INVALID');
 const afterInvalid=await (await call('/api/assessments?assetId='+ownId,'GET',undefined,phaseAnalyst)).json();assert.deepEqual(afterInvalid.runs,ownHistory.runs);
 console.log('PASS invalid offline configuration gives input-specific guidance and preserves the previous successful run');
 assert.equal((await (await call('/api/assessments','GET',undefined,newViewer)).json()).assets.length,1);
 const webAsset=await saveAssessment((sql,values)=>projectAdmin.query(sql,values),actor,'aggregate-fixture.example','Aggregate test',{...phaseA.report,moduleId:'web.compare',targetKind:'public-https'});
 const issueKey=async()=>{const r=await call('/api/assessments','POST',{action:'rotateTelemetryToken',assetId:webAsset.asset_id},newAdmin);assert.equal(r.status,200);return (await r.json()).token as string;};
 const key1=await issueKey(),telemetryBody={assetId:webAsset.asset_id,requests:10,loginFailures:5,probes:3,serverErrors:5};
 const ingest=(token:string,payload:unknown=telemetryBody)=>fetch(base+'/api/telemetry',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(payload)});
 assert.equal((await ingest(key1)).status,202);assert.equal((await ingest('0'.repeat(64))).status,401);assert.equal((await ingest(key1,{...telemetryBody,rawIp:'PRIVATE_IP'})).status,400);
 const signalData=await (await call('/api/assessments?assetId='+webAsset.asset_id,'GET',undefined,newAdmin)).json();assert.equal(Number(signalData.traffic.requests),10);assert.equal(signalData.signals.loginFailures,true);assert.equal(signalData.signals.probes,true);assert(!JSON.stringify(signalData).includes(key1));
 const key2=await issueKey();assert.notEqual(key1,key2);assert.equal((await ingest(key1)).status,401);assert.equal((await ingest(key2)).status,202);
 const machInput={moduleId:'application.macho',label:'Mac summary test',authorized:true,snapshot:{schemaVersion:1,source:'browser',format:'macho',size:4000000000,architectures:[{bits:64,fileType:2,flags:0x200000,writableExecutable:0,certificateTable:false}]}};
 const mach=await call('/api/assessments','POST',machInput,newAdmin);assert.equal(mach.status,200);const machSaved=await mach.json();assert(machSaved.report.findings.every((f:any)=>f.status!=='pass'));assert.equal((await call('/api/assessments?assetId='+machSaved.asset_id,'GET',undefined,phaseAnalyst)).status,404);
 const mobileInput={moduleId:'application.package',label:'IPA summary test',authorized:true,snapshot:{schemaVersion:1,source:'browser',format:'ipa',size:3000000000,entries:100,nestedPackages:0,settings:{decoded:true,arbitraryLoads:true,debuggable:null,allowBackup:null,cleartext:null,permissionCount:null}}};
 const mobile=await call('/api/assessments','POST',mobileInput,phaseAnalyst);assert.equal(mobile.status,200);assert((await mobile.json()).report.findings.some((f:any)=>f.id==='arbitraryLoads'&&f.status==='warning'));
 assert.equal((await call('/api/assessments','POST',{...mobileInput,snapshot:{...mobileInput.snapshot,path:'PRIVATE_PATH'}},phaseAnalyst)).status,400);
 console.log('PASS macOS/mobile summary API persistence, self-report labels, owner isolation and raw-field rejection');
 assert.equal((await call('/api/assessments','POST',{action:'rotateTelemetryToken',assetId:webAsset.asset_id},phaseAnalyst)).status,404);
 const phaseWriter=new Pool({connectionString:env.DATABASE_URL});try{await assert.rejects(phaseWriter.query('UPDATE assessment_assets SET user_id=$1 WHERE id=$2',[otherActor,phaseA.asset_id]),{code:'42501'});await assert.rejects(phaseWriter.query("UPDATE assessment_runs SET report='{}'"),{code:'42501'});}finally{await phaseWriter.end();}
 const memberMach=await call('/api/assessments','POST',machInput,newViewer);assert.equal(memberMach.status,200);const memberMachSaved=await memberMach.json();assert.equal((await call('/api/assessments?assetId='+memberMachSaved.asset_id,'GET',undefined,newAdmin)).status,404);
 assert.equal((await call('/api/assessments','POST',{action:'rotateTelemetryToken',assetId:webAsset.asset_id},newViewer)).status,404);
 assert.equal((await call('/api/assessments','POST',{...machInput,authorized:false},newViewer)).status,400);
 assert.equal((await call('/api/assessments','POST',machInput)).status,401);
 console.log('PASS modular HTTP assessments: general member config/file summary assessment, required consent, guest denial, owner-only assets/history/keys, redaction and immutable results');
 await script('scripts/create-user.ts',{BOOTSTRAP_EMAIL:'integrity@example.test',BOOTSTRAP_PASSWORD:password,BOOTSTRAP_ROLE:'viewer'});const integrityUser=await login('integrity');
 const originalBytes=await readFile('tests/fixtures/phase2/windows-pe-vulnerable.exe');
 const originalBody={moduleId:'application.pe',label:'Original integrity',authorized:true,originalUpload:true,base64:originalBytes.toString('base64')};
 const originalResponse=await call('/api/assessments','POST',originalBody,integrityUser);assert.equal(originalResponse.status,200);const originalSaved=await originalResponse.json();
 assert.equal(originalSaved.report.integrity.status,'server-recomputed');assert.equal(originalSaved.report.integrity.bytes,originalBytes.length);
 assert.equal(originalSaved.report.integrity.sha256,(await import('node:crypto')).createHash('sha256').update(originalBytes).digest('hex'));
 assert.equal((await call('/api/assessments','POST',{...originalBody,snapshot:{source:'local',native:{signature:'valid'}}},integrityUser)).status,400);
 assert.equal((await call('/api/assessments','POST',{...originalBody,integrity:{status:'server-recomputed'}},integrityUser)).status,400);
 const originalHistory=await (await call('/api/assessments?assetId='+originalSaved.asset_id,'GET',undefined,integrityUser)).json();assert.equal(originalHistory.runs.length,1);assert.deepEqual(originalHistory.runs[0].report.integrity,originalSaved.report.integrity);
 assert.equal((await call('/api/assessments?assetId='+originalSaved.asset_id,'GET',undefined,newAdmin)).status,404);
 assert(!JSON.stringify(originalHistory).includes(originalBody.base64));
 console.log('PASS original upload server recomputation/hash, forged summary rejection, unchanged history, no raw persistence and account isolation');
 await script('scripts/create-user.ts',{BOOTSTRAP_EMAIL:'infra@example.test',BOOTSTRAP_PASSWORD:password,BOOTSTRAP_ROLE:'viewer'});const infraUser=await login('infra');
 const vmxText='config.version = "8"\nvirtualHW.version = "21"\nisolation.tools.copy.disable = "FALSE"\ndisplayName = "PRIVATE_VM_LABEL"';
 const vmxSaved=await call('/api/assessments','POST',{moduleId:'virtualization.vmx',label:'VM settings',text:vmxText,authorized:true},infraUser);assert.equal(vmxSaved.status,200);const vmx=await vmxSaved.json();assert(!JSON.stringify(vmx).includes('PRIVATE_VM_LABEL'));assert(vmx.report.findings.some((f:any)=>f.id==='copy'&&f.status==='warning'));
 const vmxRetest=await call('/api/assessments','POST',{moduleId:'virtualization.vmx',label:'VM settings',text:vmxText.replace('FALSE','TRUE'),authorized:true},infraUser);assert.equal(vmxRetest.status,200);assert.equal((await vmxRetest.json()).asset_id,vmx.asset_id);
 assert.equal((await call('/api/assessments?assetId='+vmx.asset_id,'GET',undefined,newAdmin)).status,404);
 const topology={type:'topology',version:'2.2.61',topology:{nodes:[{node_id:'a',node_type:'vpcs'},{node_id:'b',node_type:'nat'}],links:[{nodes:[{node_id:'a'},{node_id:'b'}]}]}};
 const labSaved=await call('/api/assessments','POST',{moduleId:'network.gns3',label:'Network lab',text:JSON.stringify(topology),authorized:true},infraUser);assert.equal(labSaved.status,200);assert((await labSaved.json()).report.findings.some((f:any)=>f.id==='externalBoundary'&&f.status==='warning'));
 assert.equal((await call('/api/assessments','POST',{moduleId:'network.gns3',label:'bad',text:'{}',authorized:true},infraUser)).status,400);
 const vmxHistory=await (await call('/api/assessments?assetId='+vmx.asset_id,'GET',undefined,infraUser)).json();assert.equal(vmxHistory.runs.length,2);
 console.log('PASS general customer VMware/GNS3 pages, assessment APIs, warning-to-pass retest, private-field redaction and owner isolation');
 const memberMatrixLogin=await call('/api/login','POST',{email:'new@example.test',password:signupPassword});assert.equal(memberMatrixLogin.status,200);const memberMatrixCookie=memberMatrixLogin.headers.get('set-cookie')!.split(';')[0];
 async function memberMatrixPost(payload:Record<string,unknown>){
  for(let attempt=0;attempt<3;attempt++){
   const response=await call('/api/assessments','POST',payload,memberMatrixCookie);
   if(response.status===429){assert.equal((await response.json()).errorCode,'RATE_LIMITED');console.log('INFO general-member configured request budget reached; waiting one minute without changing limits');await new Promise(resolve=>setTimeout(resolve,60000));continue;}
   assert.equal(response.status,200,await response.clone().text());return response.json();
  }throw new Error('General member did not recover after request-limit window');
 }
 const memberCases=[['linux.ssh','linux','sshd_config',5],['windows.policy','windows','json',6],['application.pe','windows-pe','exe',3],['application.macho','macos-macho','macho',3],['application.package','android','apk',3],['application.package','ios','ipa',1],['application.apk','android','apk',0],['virtualization.vmx','vmware','vmx',6],['network.gns3','gns3','gns3',2]] as const;
 for(const [moduleId,name,extension,warnings] of memberCases){
  let memberAsset='';
  for(const variant of ['vulnerable','remediated']){
   const bytes=await readFile(`tests/fixtures/phase2/${name}-${variant}.${extension}`),payload:Record<string,unknown>={moduleId,label:'Member matrix '+moduleId+' '+name,authorized:true};
   if(moduleId.startsWith('application.')){payload.base64=bytes.toString('base64');if(moduleId!=='application.apk')payload.originalUpload=true;}else payload.text=bytes.toString('utf8');
   const saved=await memberMatrixPost(payload);assert.equal(saved.report.integrity.status,'server-recomputed');assert.equal(saved.report.integrity.sha256,createHash('sha256').update(bytes).digest('hex'));
   assert.equal(saved.report.findings.filter((f:any)=>f.status==='warning').length,variant==='vulnerable'?warnings:0);
   if(memberAsset)assert.equal(saved.asset_id,memberAsset);memberAsset=saved.asset_id;
  }
  const history=await (await call('/api/assessments?assetId='+memberAsset,'GET',undefined,memberMatrixCookie)).json();assert.equal(history.runs.length,2);assert.equal(history.runs[0].report.findings.filter((f:any)=>f.status==='warning').length,0);
  assert(!Object.hasOwn(history.user,'id'));assert(!JSON.stringify(history.user).includes('new@example.test'));
  assert.equal((await call('/api/assessments?assetId='+memberAsset,'GET',undefined,newAdmin)).status,404);assert.equal((await call('/api/assessments?assetId='+memberAsset,'GET',undefined,newViewer)).status,404);
  console.log('PASS registered general member '+moduleId+' '+name+': original/config assessment, hash, same-asset retest, own history and cross-account denial');
 }
 // Archive validation touches only this disposable database. Backdate fixture
 // records, verify API filtering BEFORE maintenance, then prove atomic moves.
 const oldScan=randomUUID(),failedScan=randomUUID(),recentScan=randomUUID();
 for(const [id,host,age] of [[oldScan,'retention-old.example',33],[failedScan,'retention-fail.example',32],[recentScan,'retention-recent.example',29]] as const)await projectAdmin.query("INSERT INTO scans(id,user_id,hostname,result,created_at) VALUES($1,$2,$3,'{\"status\":200,\"checks\":[]}',now()-$4*interval '1 day')",[id,actor,host,age]);
 const oldAssessment=await saveAssessment((sql,values)=>projectAdmin.query(sql,values),actor,'retention-only','Retention only',phaseA.report);
 await projectAdmin.query("UPDATE assessment_runs SET created_at=now()-interval '31 days' WHERE id=$1",[oldAssessment.id]);
 await projectAdmin.query("UPDATE assessment_assets SET updated_at=now()-interval '31 days' WHERE id=$1",[oldAssessment.asset_id]);
 await projectAdmin.query("INSERT INTO assessment_traffic(user_id,asset_id,window_at,requests,login_failures,probes,server_errors) VALUES($1,$2,now()-interval '31 days',1,0,0,0)",[actor,oldAssessment.asset_id]);
 const filtered=await (await call('/api/dashboard','GET',undefined,newAdmin)).json();assert(!filtered.scans.some((s:any)=>s.id===oldScan||s.id===failedScan));assert(filtered.scans.some((s:any)=>s.id===recentScan));
 assert.equal((await call('/api/assessments?assetId='+oldAssessment.asset_id,'GET',undefined,newAdmin)).status,404);
 assert.equal((await call('/api/ai','POST',{scanId:oldScan},newAdmin)).status,404);
 assert.equal((await call('/api/maintenance/archive')).status,401);
 assert.equal((await fetch(base+'/api/maintenance/archive',{headers:{authorization:'Bearer wrong'}})).status,401);
 const archiveRole=new Pool({connectionString:env.DATABASE_URL});
 try{await assert.rejects(archiveRole.query('SELECT * FROM webguard_archive.diagnostic_records'),{code:'42501'});}finally{await archiveRole.end();}
 await projectAdmin.query("CREATE FUNCTION public.retention_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.payload->>'hostname'='retention-fail.example' THEN RAISE EXCEPTION 'simulated archive failure'; END IF; RETURN NEW; END $$");
 await projectAdmin.query('CREATE TRIGGER retention_test_failure BEFORE INSERT ON webguard_archive.diagnostic_records FOR EACH ROW EXECUTE FUNCTION public.retention_test_failure()');
 await assert.rejects(projectAdmin.query('SELECT public.archive_diagnostics_30d()'));
 assert.equal((await projectAdmin.query('SELECT count(*) FROM scans WHERE id=ANY($1::uuid[])',[[oldScan,failedScan]])).rows[0].count,'2');
 assert.equal((await projectAdmin.query('SELECT count(*) FROM webguard_archive.diagnostic_records')).rows[0].count,'0');
 await projectAdmin.query('DROP TRIGGER retention_test_failure ON webguard_archive.diagnostic_records');await projectAdmin.query('DROP FUNCTION public.retention_test_failure()');
 const maintenance=await fetch(base+'/api/maintenance/archive',{headers:{authorization:'Bearer '+archiveSecret}});assert.equal(maintenance.status,200);assert((await maintenance.json()).result.moved>=4);
 assert.equal((await projectAdmin.query('SELECT count(*) FROM scans WHERE id=ANY($1::uuid[])',[[oldScan,failedScan]])).rows[0].count,'0');
 assert.equal((await projectAdmin.query('SELECT count(*) FROM webguard_archive.diagnostic_records WHERE source_id=ANY($1::text[])',[[oldScan,failedScan,oldAssessment.id]])).rows[0].count,'3');
 assert.equal((await projectAdmin.query('SELECT count(*) FROM scans WHERE id=$1',[recentScan])).rows[0].count,'1');
 assert.equal((await projectAdmin.query('SELECT public.archive_diagnostics_30d() AS result')).rows[0].result.moved,0);
 const revived=await saveAssessment((sql,values)=>projectAdmin.query(sql,values),actor,'retention-only','Retention only',phaseA.report);assert.equal(revived.asset_id,oldAssessment.asset_id);
 const revivedHistory=await (await call('/api/assessments?assetId='+revived.asset_id,'GET',undefined,newAdmin)).json();assert.equal(revivedHistory.runs.length,1);assert.equal(revivedHistory.runs[0].id,revived.id);
 assert.equal((await call('/api/assessments?assetId='+revived.asset_id,'GET',undefined,newViewer)).status,404);
 console.log('PASS 30-day API filtering, private backup, authenticated maintenance, atomic rollback, idempotent archive, owner isolation and stable asset revival');
 await pool.query('CREATE DATABASE webguard_copy_fixture');
 const targetUrl=`postgresql://postgres@127.0.0.1:${pgPort}/webguard_copy_fixture`;
 const cloudEnv={PROJECT_DATABASE:'webguard_copy_fixture',PROJECT_RUNTIME_ROLE:'webguard_fixture_app',MIGRATION_DATABASE_URL:targetUrl};
 await mkdir('work',{recursive:true});
 const fixtureDir=await mkdtemp(path.resolve('work/integration-fixtures-'));
 const output=path.join(fixtureDir,'generated-production.env');
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
  await managed.query(await readFile('sql/migrations/prisma-postgres/003_modular_assessments.sql','utf8'));
  await managed.query(await readFile('sql/migrations/prisma-postgres/004_local_file_inspection.sql','utf8'));
  await managed.query(await readFile('sql/migrations/prisma-postgres/005_diagnostic_retention.sql','utf8'));
  await managed.query(await readFile('sql/migrations/prisma-postgres/006_infrastructure_modules.sql','utf8'));
  await managed.query(await readFile('sql/migrations/prisma-postgres/007_account_blocks.sql','utf8'));
  await managed.query(await readFile('sql/migrations/prisma-postgres/008_private_management_references.sql','utf8'));
  await managed.query("UPDATE scans SET created_at=now()-interval '31 days' WHERE id=$1",[legacyScan]);
  assert.equal((await managed.query('SELECT public.archive_diagnostics_30d() AS result')).rows[0].result.moved,1);
  assert.equal((await managed.query('SELECT count(*) FROM webguard_archive.diagnostic_records WHERE source_id=$1',[legacyScan])).rows[0].count,'1');
  assert.equal((await managed.query('SELECT user_id FROM webguard_archive.diagnostic_records WHERE source_id=$1',[legacyScan])).rows[0].user_id,legacyUser);
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
}finally{server?.kill();await Promise.allSettled(projectPools.map(project=>project.end()));await pool.end();if(pgStarted)await control(['-D',dir,'-m','fast','-w','stop']);console.log('Disposable cluster stopped; test data remains in the isolated test directory for inspection.');}
