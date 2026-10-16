// Disposable local cluster only. Never connects to the user's existing database.
import { execFile,spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp,mkdir } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { Pool } from 'pg';
import assert from 'node:assert/strict';
const exec=promisify(execFile),bin=process.env.PG_BIN??'C:/Program Files/PostgreSQL/15/bin';
await mkdir('work',{recursive:true});const dir=await mkdtemp(path.resolve('work/isolated-pg-'));
const pgPort=45000+Math.floor(Math.random()*5000),webPort=50000+Math.floor(Math.random()*5000),base=`http://127.0.0.1:${webPort}`;
const database=`postgresql://postgres@127.0.0.1:${pgPort}/postgres`;
const env={...process.env,DATABASE_URL:database,APP_ORIGIN:base,AI_ENABLED:'false',OPENAI_API_KEY:'',ALLOWED_SCAN_HOSTS:'owned.example'};
const pool=new Pool({connectionString:database,connectionTimeoutMillis:1000});let pgStarted=false;let server:ReturnType<typeof spawn>|undefined;
async function control(args:string[]){await new Promise<void>((resolve,reject)=>{const p=spawn(path.join(bin,'pg_ctl.exe'),args,{windowsHide:true,stdio:'ignore'});p.on('error',reject);p.on('exit',code=>code===0?resolve():reject(new Error('pg_ctl failed: '+code)));});}
async function script(name:string,extra:Partial<NodeJS.ProcessEnv>={}){return exec(process.execPath,['node_modules/tsx/dist/cli.mjs',name],{env:{...env,...extra},windowsHide:true});}
async function call(route:string,method='GET',payload?:unknown,cookie?:string){return fetch(base+route,{method,headers:{origin:base,...(payload===undefined?{}:{'Content-Type':'application/json'}),...(cookie?{cookie}:{})},body:payload===undefined?undefined:JSON.stringify(payload),signal:AbortSignal.timeout(10000)});}
try{
 await exec(path.join(bin,'initdb.exe'),['-D',dir,'-A','trust','-U','postgres','--encoding=UTF8','--locale=C'],{windowsHide:true});
 await control(['-D',dir,'-l',path.join(dir,'server.log'),'-o',`-h 127.0.0.1 -p ${pgPort}`,'-w','start']);pgStarted=true;
 console.log('PASS disposable PostgreSQL cluster started on loopback; existing DB untouched');
 await script('scripts/migrate.ts');await script('scripts/migrate.ts');assert.equal((await pool.query('SELECT count(*) FROM schema_migrations')).rows[0].count,'1');console.log('PASS migrations and idempotent rerun');
 const password=randomBytes(24).toString('hex');
 for(const role of ['admin','viewer'])await script('scripts/create-user.ts',{BOOTSTRAP_EMAIL:role+'@example.test',BOOTSTRAP_PASSWORD:password,BOOTSTRAP_ROLE:role});
 let log='';server=spawn(process.execPath,['node_modules/next/dist/bin/next','start','--hostname','127.0.0.1','--port',String(webPort)],{env,windowsHide:true,stdio:['ignore','pipe','pipe']});server.stdout?.on('data',d=>log+=d);server.stderr?.on('data',d=>log+=d);
 let ready=false;for(let i=0;i<60;i++){if(server.exitCode!==null)throw new Error(log);try{if((await call('/api/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,500));}assert(ready,log);
 async function login(role:string){const r=await call('/api/login','POST',{email:role+'@example.test',password});assert.equal(r.status,200,await r.clone().text());const cookie=r.headers.get('set-cookie')!;assert(cookie.includes('HttpOnly'));assert(cookie.includes('SameSite=Strict'));return cookie.split(';')[0];}
 const admin=await login('admin'),viewer=await login('viewer');
 const token=admin.split('=')[1];assert.equal((await pool.query('SELECT count(*) FROM sessions WHERE token_hash=$1',[token])).rows[0].count,'0');
 assert.equal((await call('/api/dashboard','GET',undefined,admin)).status,200);console.log('PASS account bootstrap, login, hashed sessions, dashboard');
 assert.equal((await call('/api/scans','POST',{url:'https://owned.example',authorized:true},viewer)).status,403);
 assert.equal((await call('/api/ai','POST',{scanId:'00000000-0000-0000-0000-000000000000'},viewer)).status,403);console.log('PASS viewer denied scan and AI');
 assert.equal((await call('/api/scans','POST',{url:'https://169.254.169.254',authorized:true},admin)).status,400);console.log('PASS metadata SSRF attempt denied by live API');
 assert.equal((await call('/api/ai','POST',{},admin)).status,503);console.log('PASS AI disabled without key; no external API call');
 assert.equal((await call('/decoy')).status,404);assert.equal((await call('/wp-admin')).status,404);
 assert.equal((await pool.query("SELECT count(*) FROM events WHERE category IN ('decoy_visit','suspicious_path')")).rows[0].count,'2');console.log('PASS bounded honeypot and probe events persisted');
 for(let i=0;i<6;i++){const r=await call('/api/login','POST',{email:'absent@example.test',password:'incorrect'});assert.equal(r.status,i===5?429:401);}console.log('PASS account login rate limit');
 await pool.query("UPDATE sessions SET expires_at=now()-interval '1 second' WHERE token_hash<>$1",['none']);assert.equal((await call('/api/dashboard','GET',undefined,viewer)).status,401);console.log('PASS session expiry enforced');
 const fresh=await login('admin');assert.equal((await call('/api/logout','POST',{},fresh)).status,200);assert.equal((await call('/api/dashboard','GET',undefined,fresh)).status,401);console.log('PASS logout revokes session');
}finally{server?.kill();await pool.end();if(pgStarted)await control(['-D',dir,'-m','fast','-w','stop']);console.log('Disposable cluster stopped; test data remains in ignored work/ for inspection.');}
