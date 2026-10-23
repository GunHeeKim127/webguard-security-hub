import test from 'node:test';
import assert from 'node:assert/strict';
import {projectDatabase} from '../lib/project-database';
import {deploymentReadiness} from '../lib/deployment-readiness';
import {vercelClientAddress,vercelProtection} from '../lib/vercel-protection';
import {accessOrigins,secureOriginCookie} from '../lib/access-origins';
import {assertManagedRuntimeSql} from '../lib/runtime-sql';
import {runtimePoolConfig} from '../lib/runtime-pool-config';
import {protectionQuery,PROTECTION_READ_TIMEOUT_MS} from '../lib/protection-query';
import {ACTIVE_BLOCK_SQL} from '../lib/ingress-guard';
import type {Pool} from 'pg';
import {maintenanceAuthorized} from '../lib/retention';
import {migrationChecksums} from '../scripts/support/migration-checksum';

test('migration checksums accept only LF/CRLF equivalents and reject changed SQL',()=>{
 const lf='SELECT 1;\nSELECT 2;\n',crlf=lf.replace(/\n/g,'\r\n');
 assert.equal(migrationChecksums(lf).canonical,migrationChecksums(crlf).canonical);
 assert(migrationChecksums(crlf).accepted.has(migrationChecksums(lf).canonical));
 assert(!migrationChecksums(lf.replace('SELECT 2','SELECT 3')).accepted.has(migrationChecksums(lf).canonical));
});

test('archive maintenance is inaccessible without the exact configured secret',()=>{
 const secret='a'.repeat(64);
 assert.equal(maintenanceAuthorized('Bearer '+secret,secret),true);
 for(const value of [null,'Bearer wrong',secret,'bearer '+secret,'Bearer '+secret+'x'])assert.equal(maintenanceAuthorized(value,secret),false);
 assert.equal(maintenanceAuthorized('Bearer '+secret,undefined),false);
 assert.equal(maintenanceAuthorized('Bearer x','x'),false);
});

test('protection query gives only the exact managed block read a longer deadline and releases clients',async()=>{
 const configs:any[]=[],releases:unknown[]=[];
 const pool={connect:async()=>({query:async(config:unknown)=>{configs.push(config);return {rows:[]};},release:(failed:unknown)=>releases.push(failed)})} as unknown as Pick<Pool,'connect'>;
 for(const [sql,managed] of [[ACTIVE_BLOCK_SQL,true],[ACTIVE_BLOCK_SQL,false],['WITH changed AS (INSERT INTO events(category) VALUES($1) RETURNING id) SELECT * FROM changed',true],['SELECT 1',true]] as const)await protectionQuery(pool,sql,['private-ip'],managed);
 assert.equal(configs[0].query_timeout,PROTECTION_READ_TIMEOUT_MS);
 for(const config of configs.slice(1))assert.equal(config.query_timeout,undefined);
 assert.deepEqual(releases,[false,false,false,false]);
});

test('protection database failures discard clients without replay and keep credentials out of logs',async()=>{
 const logs:unknown[][]=[],warn=console.warn;console.warn=(...args:unknown[])=>logs.push(args);
 try{
  let calls=0;const releases:unknown[]=[];
  const pool={connect:async()=>({query:async()=>{calls++;throw new Error('Query read timeout');},release:(failed:unknown)=>releases.push(failed)})} as unknown as Pick<Pool,'connect'>;
  await assert.rejects(protectionQuery(pool,ACTIVE_BLOCK_SQL,['private-ip'],true),/Query read timeout/);
  assert.equal(calls,1);assert.deepEqual(releases,[true]);
  const failed={connect:async()=>{throw Object.assign(new Error('secret-password private-ip'),{code:'ECONNRESET'});}} as unknown as Pick<Pool,'connect'>;
  await assert.rejects(protectionQuery(failed,ACTIVE_BLOCK_SQL,['private-ip'],true));
  assert.equal((logs[0][1] as any).phase,'block_read');assert.equal((logs[1][1] as any).phase,'acquire');
  assert(!JSON.stringify(logs).includes('secret-password'));assert(!JSON.stringify(logs).includes('private-ip'));
 }finally{console.warn=warn;}
});

test('runtime and local guard use provider-compatible timeout options',()=>{
 const before={...process.env};try{
  cloudEnv();const ordinary=runtimePoolConfig();assert.equal(ordinary.statement_timeout,5000);assert.equal(ordinary.query_timeout,undefined);
  process.env.DATABASE_PROVIDER='prisma-postgres';process.env.PROJECT_DATABASE='postgres';process.env.DATABASE_URL='postgres://test:test@pooled.db.prisma.io/postgres';
  const managed=runtimePoolConfig();assert.equal(managed.statement_timeout,undefined);assert.equal(managed.query_timeout,5000);assert.equal(managed.connectionTimeoutMillis,10000);assert.deepEqual(managed.ssl,{rejectUnauthorized:true});
 }finally{process.env=before;}
});

function cloudEnv(){process.env.DATABASE_PROVIDER='postgresql';process.env.PROJECT_DATABASE='neondb';process.env.PROJECT_RUNTIME_ROLE='webguard_hub_prod_app';process.env.DATABASE_URL='postgresql://webguard_hub_prod_app:dummy-password@db.example/neondb?sslmode=require&channel_binding=require';}
test('Prisma managed profile accepts provider credentials only on the matching pooled/direct hosts',()=>{
 const before={...process.env};try{
  process.env.DATABASE_PROVIDER='prisma-postgres';process.env.PROJECT_DATABASE='postgres';delete process.env.PROJECT_RUNTIME_ROLE;
  process.env.DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io:5432/?sslmode=require';
  assert.equal(new URL(projectDatabase('runtime').connectionString).pathname,'/postgres');assert.deepEqual(projectDatabase('runtime').ssl,{rejectUnauthorized:true});
  process.env.MIGRATION_DATABASE_URL='postgres://provider-user:provider-password@db.prisma.io:5432/postgres?sslmode=require';assert(projectDatabase('migration'));
  process.env.DATABASE_URL=process.env.MIGRATION_DATABASE_URL;assert.throws(()=>projectDatabase('runtime'),/pooled/);
  process.env.MIGRATION_DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io/postgres';assert.throws(()=>projectDatabase('migration'),/direct/);
  process.env.DATABASE_URL='postgres://provider-user:provider-password@evil.example/postgres';assert.throws(()=>projectDatabase('runtime'));
  process.env.DATABASE_PROVIDER='postgresql';process.env.DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io/postgres';assert.throws(()=>projectDatabase('runtime'),/DATABASE_PROVIDER/);
 }finally{process.env=before;}
});
test('Prisma managed runtime client rejects DDL, multi-statements, direct account writes and migration archives',()=>{
 assert.doesNotThrow(()=>assertManagedRuntimeSql('INSERT INTO scans(id) VALUES($1) ON CONFLICT(id) DO UPDATE SET result=$2'));
 assert.throws(()=>assertManagedRuntimeSql('DO $$ BEGIN NULL; END $$'));
 for(const sql of ['SELECT id FROM users WHERE email=$1','SELECT public.register_viewer($1,$2,$3)',"WITH changed AS (INSERT INTO events(category) VALUES('scan_success') RETURNING id) SELECT id FROM changed",'UPDATE scans SET result=$1 WHERE id=$2','DELETE FROM sessions WHERE token_hash=$1',"SELECT 'DROP' AS label"])assert.doesNotThrow(()=>assertManagedRuntimeSql(sql));
 for(const sql of ['DROP TABLE users','SELECT 1; DROP TABLE users','CREATE TABLE bad(id int)','TRUNCATE scans','GRANT ALL ON users TO PUBLIC','SELECT * FROM schema_migrations','SELECT * FROM public.scan_duplicate_archive','UPDATE users SET role=$1','INSERT INTO public.users(id) VALUES($1)','DELETE FROM "users"','SELECT set_config($1,$2,true)','SELECT 1 -- hidden'])assert.throws(()=>assertManagedRuntimeSql(sql));
 assert.throws(()=>assertManagedRuntimeSql('SELECT payload FROM webguard_archive.diagnostic_records'));
 assert.doesNotThrow(()=>assertManagedRuntimeSql('SELECT public.archive_diagnostics_30d() AS result'));
});
test('Prisma readiness reports provider-managed permissions without asserting separate SQL role isolation',async()=>{
 const before={...process.env};try{
  process.env.DATABASE_PROVIDER='prisma-postgres';process.env.PROJECT_DATABASE='postgres';process.env.DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io/postgres';
  const queries:string[]=[];const ready=await deploymentReadiness(async sql=>{queries.push(sql);return {rows:[{schema_ready:true,writes_ready:true}]};});
  assert.deepEqual(ready,{ready:true,code:'READY',permissionModel:'provider-managed'});assert(!queries.some(sql=>sql.includes('rolsuper')));
 }finally{process.env=before;}
});
test('cloud PostgreSQL URL preserves project identity and enforces verified TLS',()=>{
 const before={...process.env};try{
  cloudEnv();const c=projectDatabase('runtime');assert.deepEqual(c.ssl,{rejectUnauthorized:true});assert.equal(c.enableChannelBinding,true);assert.equal(new URL(c.connectionString).search,'');
  for(const query of ['user=postgres','database=other','host=evil.example','password=evil','sslcert=secret','sslmode=no-verify','sslmode=disable','sslmode=require&sslmode=verify-full','channel_binding=disable']){
   process.env.DATABASE_URL='postgresql://webguard_hub_prod_app@db.example/neondb?'+query;assert.throws(()=>projectDatabase('runtime'));
  }
  process.env.DATABASE_URL='postgresql://postgres@db.example/neondb?sslmode=require';assert.throws(()=>projectDatabase('runtime'),/dedicated/);
  process.env.DATABASE_URL='postgresql://webguard_hub_prod_app@db.example/other';assert.throws(()=>projectDatabase('runtime'),/mismatch/);
 }finally{process.env=before;}
});
test('localhost database works locally and is refused explicitly on Vercel',()=>{
 const before={...process.env};try{
  cloudEnv();delete process.env.VERCEL;process.env.DATABASE_URL='postgresql://webguard_hub_prod_app@localhost/neondb';assert.equal(projectDatabase('runtime').ssl,undefined);
  process.env.VERCEL='1';
  for(const host of ['localhost','other.localhost','127.0.0.1','127.9.8.7','[::1]','[::ffff:127.0.0.1]']){
   process.env.DATABASE_URL=`postgresql://webguard_hub_prod_app@${host}/neondb`;assert.throws(()=>projectDatabase('runtime'),e=>typeof e==='object'&&e!==null&&'code' in e&&e.code==='DATABASE_LOCALHOST_ON_VERCEL');
  }
 }finally{process.env=before;}
});
test('Vercel production keeps the official HTTPS origin and Secure session cookies',()=>{
 const before={...process.env};try{
  delete process.env.APP_ORIGIN;delete process.env.APP_ADDITIONAL_ORIGINS;process.env.VERCEL='1';process.env.VERCEL_ENV='production';
  assert.deepEqual(accessOrigins(),['https://webguard-security-hub.vercel.app']);
  assert.equal(secureOriginCookie(new Request('https://webguard-security-hub.vercel.app/api/login',{headers:{origin:'https://webguard-security-hub.vercel.app'}})),true);
  assert.throws(()=>secureOriginCookie(new Request('https://evil.vercel.app',{headers:{origin:'https://evil.vercel.app'}})));
 }finally{process.env=before;}
});
test('readiness distinguishes missing configuration, schema, unsafe role and connectivity without exposing credentials',async()=>{
 const before={...process.env};try{
  delete process.env.DATABASE_URL;assert.deepEqual(await deploymentReadiness(async()=>{throw new Error('must not query');}),{ready:false,code:'DATABASE_NOT_CONFIGURED'});
  cloudEnv();assert.equal((await deploymentReadiness(async()=>({rows:[{schema_ready:false}]}))).code,'DATABASE_SCHEMA_NOT_READY');
  assert.equal((await deploymentReadiness(async sql=>({rows:[sql.includes('to_regclass')?{schema_ready:true}:{role_safe:false}]}))).code,'DATABASE_RUNTIME_ROLE_UNSAFE');
  assert.equal((await deploymentReadiness(async()=>({rows:[{schema_ready:true,role_safe:true,writes_ready:false}]}))).code,'DATABASE_PERMISSIONS_NOT_READY');
  const ready=await deploymentReadiness(async()=>({rows:[{schema_ready:true,role_safe:true,writes_ready:true}]}));assert.deepEqual(ready,{ready:true,code:'READY'});
  const failed=await deploymentReadiness(async()=>{throw new Error('private-provider-host secret-password');});assert.equal(failed.code,'DATABASE_CONNECTION_OR_PERMISSIONS_FAILED');assert(!JSON.stringify(failed).includes('secret-password'));
 }finally{process.env=before;}
});
test('Vercel client identity uses only the official platform header and is disabled on raw servers',()=>{
 const h=new Headers({'x-real-ip':'::ffff:203.0.113.2','x-forwarded-for':'8.8.8.8','x-webguard-client-ip':'1.1.1.1'});
 assert.equal(vercelClientAddress(h,{VERCEL:'1'}),'203.0.113.2');assert.equal(vercelClientAddress(h,{}),null);
 assert.equal(vercelClientAddress(new Headers({'x-real-ip':'1.1.1.1,8.8.8.8'}),{VERCEL:'1'}),null);
});
test('Vercel protection checks persistent blocks and never runs twice on local guarded server',async()=>{
 let calls=0;const query=async(_sql:string,values:unknown[])=>{calls++;assert.equal(values[0],'203.0.113.2');return {rows:[]};};
 const req=new Request('https://webguard-security-hub.vercel.app/',{headers:{'x-real-ip':'203.0.113.2'}});
 assert.equal(await vercelProtection(req,query,{}),null);assert.equal(calls,0);
 assert.equal(await vercelProtection(req,query,{VERCEL:'1'}),null);assert.equal(calls,1);
 const blocked=await vercelProtection(req,async()=>({rows:[{blacklisted:false,strikes:2,retry_after:123}]}),{VERCEL:'1'});assert.equal(blocked?.status,429);assert.equal(blocked?.headers.get('retry-after'),'123');
 const blacklisted=await vercelProtection(req,async()=>({rows:[{blacklisted:true,strikes:6}]}),{VERCEL:'1'});assert.equal(blacklisted?.status,403);
});
test('Vercel protection detects probes, fails closed, and leaves readiness reachable',async()=>{
 let calls=0;const attacked=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/.env',{headers:{'x-real-ip':'203.0.113.2'}}),async sql=>{calls++;return {rows:sql.startsWith('SELECT')?[]:[{blacklisted:false,strikes:1,retry_after:300}]};},{VERCEL:'1'});
 assert.equal(calls,2);assert.equal(attacked?.status,429);
 const failed=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/',{headers:{'x-real-ip':'203.0.113.2'}}),async()=>{throw new Error('private database secret');},{VERCEL:'1'});assert.equal(failed?.status,503);assert(!(await failed!.text()).includes('secret'));
 const missing=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/'),async()=>{throw new Error('not called');},{VERCEL:'1'});assert.equal(missing?.status,503);
 for(const path of ['/api/ready','/api/health'])assert.equal(await vercelProtection(new Request('https://webguard-security-hub.vercel.app'+path),async()=>{throw new Error('not called');},{VERCEL:'1'}),null);
});

test('Vercel protection retries a transient block read once and still enforces the recovered block',async()=>{
 const req=new Request('https://webguard-security-hub.vercel.app/api/scans',{method:'POST',headers:{'x-real-ip':'2001:db8::2'}});
 let reads=0;const query=async(sql:string,values:unknown[])=>{assert(sql.startsWith('SELECT'));assert.equal(values[0],'2001:db8::2');if(++reads===1)throw new Error('Query read timeout');return {rows:[]};};
 assert.equal(await vercelProtection(req,query,{VERCEL:'1'}),null);assert.equal(reads,2);
 reads=0;const blocked=await vercelProtection(req,async()=>{if(++reads===1)throw Object.assign(new Error('private connection text'),{code:'ECONNRESET'});return {rows:[{blacklisted:true,strikes:6}]};},{VERCEL:'1'});
 assert.equal(blocked?.status,403);assert.equal(reads,2);
});

test('Vercel protection stops after a failed retry, rejects permanent errors immediately, and logs no secrets',async()=>{
 const req=new Request('https://webguard-security-hub.vercel.app/api/scans',{headers:{'x-real-ip':'203.0.113.2'}});
 let calls=0;const logs:unknown[][]=[],warn=console.warn;console.warn=(...args:unknown[])=>{logs.push(args);};
 try{
  const unavailable=await vercelProtection(req,async()=>{calls++;throw Object.assign(new Error('secret-db-password'),{code:'ECONNRESET'});},{VERCEL:'1'});
  assert.equal(calls,2);assert.equal(unavailable?.status,503);assert.equal((await unavailable!.json()).errorCode,'PROTECTION_UNAVAILABLE');
  calls=0;const denied=await vercelProtection(req,async()=>{calls++;throw Object.assign(new Error('secret-db-password'),{code:'42501'});},{VERCEL:'1'});
  assert.equal(calls,1);assert.equal(denied?.status,503);assert(!JSON.stringify(logs).includes('secret-db-password'));assert(!JSON.stringify(logs).includes('203.0.113.2'));
 }finally{console.warn=warn;}
});

test('Vercel protection never retries a threat write after an ambiguous connection error',async()=>{
 let calls=0;const response=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/.env',{headers:{'x-real-ip':'203.0.113.2'}}),async sql=>{calls++;if(sql.startsWith('SELECT'))return {rows:[]};throw Object.assign(new Error('write connection interrupted'),{code:'ECONNRESET'});},{VERCEL:'1'});
 assert.equal(calls,2);assert.equal(response?.status,503);
});
