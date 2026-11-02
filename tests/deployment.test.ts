import test from 'node:test';
import {httpQueryAdapter,prismaHttp,managedHttpConfig,coalescedReadProbe} from '../lib/prisma-http';

test('slow HTTP operations keep their original request alive and share one fixed read recovery',/** test 콜백: 테스트: slow HTTP operations keep their original request alive and share one fixed read recovery 주요 호출: coalescedReadProbe·httpQueryAdapter·all. */ async()=>{
 let probes=0,queries=0;const complete:Array<()=>void>=[];let probeDone!:(v:any)=>void;
 const driver={query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: forEach. */ async(sql:string)=>{if(sql==='SELECT 1 AS webguard_read_probe'){probes++;complete.forEach(/** forEach 콜백: 각 항목의 처리를 순서대로 실행합니다 주요 호출: done. */ done=>done());return await new Promise(/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ resolve=>{probeDone=resolve;});}queries++;await new Promise<void>(/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ resolve=>complete.push(resolve));return {columns:[],rows:{collect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>[]}};},exec:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>0} as any;
 const recovery=coalescedReadProbe(driver),pending:Promise<unknown>[]=[],db=httpQueryAdapter(driver,/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ p=>pending.push(p),recovery,1);
 await Promise.all([db.query('SELECT id FROM scans'),db.query('SELECT id FROM events')]);assert.equal(queries,2);assert.equal(probes,1);
 probeDone({columns:[],rows:{collect:/** probeDone 콜백: probeDone에서 전달한 값을 처리하는 콜백입니다 */ async()=>[]}});await Promise.all(pending);assert.equal(probes,1);
});
test('fixed read recovery never replays a slow write and normal queries schedule no recovery',/** test 콜백: 테스트: fixed read recovery never replays a slow write and normal queries schedule no recovery 주요 호출: httpQueryAdapter·coalescedReadProbe·equal. */ async()=>{
 let writes=0,probes=0,complete!:(n:number)=>void;
 const driver={exec:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>{writes++;return await new Promise<number>(/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ resolve=>{complete=resolve;});},query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: complete. */ async()=>{probes++;complete(1);return {columns:[],rows:{collect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>[]}};}} as any;
 const db=httpQueryAdapter(driver,/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},coalescedReadProbe(driver),1);assert.equal((await db.query('INSERT INTO events(category) VALUES($1)',['audit'])).rowCount,1);assert.equal(writes,1);assert.equal(probes,1);
 let recoveries=0;await httpQueryAdapter({query:/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ async()=>({columns:[],rows:{collect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>[]}}),exec:/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ async()=>0} as any,/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ async()=>{recoveries++;},1).query('SELECT 1');assert.equal(recoveries,0);
});

test('managed HTTPS always targets the documented HTTP host while retaining runtime credentials',/** test 콜백: 테스트: managed HTTPS always targets the documented HTTP host while retaining runtime credentials 주요 호출: managedHttpConfig·toString·equal. */ ()=>{
 const input=new URL('postgres://runtime-user:runtime-test-password@pooled.db.prisma.io:5432/postgres?sslmode=require'),output=new URL(managedHttpConfig(input.toString()).connectionString);
 assert.equal(output.hostname,'db.prisma.io');assert.equal(output.username,input.username);assert.equal(output.password,input.password);assert.equal(output.pathname,input.pathname);assert.equal(output.search,input.search);
 assert.equal(new URL(managedHttpConfig('postgres://test:test@db.prisma.io/postgres').connectionString).hostname,'db.prisma.io');
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: managedHttpConfig. */ ()=>managedHttpConfig('postgres://test:test@db.prisma.io.evil.invalid/postgres'));
});

test('readiness retries only an interrupted read once, without exposing database error text',/** test 콜백: 테스트: readiness retries only an interrupted read once, without exposing database error text 주요 호출: assign·deploymentReadiness·equal. */ async()=>{
 const envBefore={...process.env};Object.assign(process.env,{DATABASE_PROVIDER:'prisma-postgres',DATABASE_URL:'postgres://test:test@pooled.db.prisma.io/postgres',PROJECT_DATABASE:'postgres'});
 try{let attempts=0;const recovered=await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 */ async()=>{attempts++;if(attempts===1)throw new Error('Query read timeout');return {rows:[{schema_ready:false}]};});assert.equal(attempts,2);assert.equal(recovered.code,'DATABASE_SCHEMA_NOT_READY');
 attempts=0;const failed=await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 */ async()=>{attempts++;throw new Error('Query read timeout');});assert.equal(attempts,2);assert.equal(failed.ready,false);
 attempts=0;await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 주요 호출: assign. */ async()=>{attempts++;throw Object.assign(new Error('private credential'),{code:'42501'});});assert.equal(attempts,1);
 }finally{for(const k of Object.keys(process.env))if(!(k in envBefore))delete process.env[k];Object.assign(process.env,envBefore);}
});
import {releaseIpBlock} from '../lib/ip-block-management';
import {releaseAccountBlock} from '../lib/account-block-management';

test('admin release CTEs pass the same runtime SQL boundary as normal requests',/** test 콜백: 테스트: admin release CTEs pass the same runtime SQL boundary as normal requests 주요 호출: equal·releaseIpBlock·releaseAccountBlock. */ async()=>{
 let calls=0;const guarded=/** guarded: 검증 시나리오에서 guarded에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: assertManagedRuntimeSql. */ async(sql:string)=>{assertManagedRuntimeSql(sql);calls++;return {rows:[{audit_count:2}]};};
 const id='00000000-0000-4000-8000-000000000001';
 assert.equal(await releaseIpBlock(guarded,'192.0.2.1',id,id),true);
 assert.equal(await releaseAccountBlock(guarded,id,id,id),true);assert.equal(calls,2);
});

test('runtime SQL rejects side-effectful SELECT and alternate SQL literals before transport',/** test 콜백: 테스트: runtime SQL rejects side-effectful SELECT and alternate SQL literals before transport 주요 호출: throws·doesNotThrow. */ ()=>{
 for(const sql of ['SELECT pg_sleep(5)','SELECT pg_terminate_backend(1)','SELECT pg_notify($1,$2)','SELECT lo_get(1)','SELECT query_to_xml($1,true,false,$2)','SELECT $$hidden$$','SELECT 1 INTO TEMP TABLE leaked'])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql(sql));
 for(const sql of ["SELECT 'pg_sleep(5)' AS label",'SELECT id FROM public.scans WHERE user_id=$1','INSERT INTO public.events(category,user_id) VALUES($1,$2)'])assert.doesNotThrow(/** doesNotThrow 콜백: doesNotThrow에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql(sql));
});

test('HTTP adapter preserves named rows, bound values and row counts without reissuing SQL',/** test 콜백: 테스트: HTTP adapter preserves named rows, bound values and row counts without reissuing SQL 주요 호출: httpQueryAdapter·query·deepEqual. */ async()=>{
 const calls:any[]=[];const driver={query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ async(sql:string,...values:unknown[])=>{calls.push({kind:'query',sql,values});return {columns:[{name:'id',oid:23}],rows:{collect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{values:[7]}]}};},exec:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ async(sql:string,...values:unknown[])=>{calls.push({kind:'exec',sql,values});return 2;}} as any;
 const db=httpQueryAdapter(driver),payload="'); DROP TABLE users; --";
 const result=await db.query('UPDATE scans SET result=$1 RETURNING id',[payload]);assert.deepEqual(result.rows,[{id:7}]);assert.equal(result.rowCount,1);assert(!calls[0].sql.includes(payload));assert.deepEqual(calls[0].values,[payload]);
 const updated=await db.query("UPDATE events SET category='RETURNING' WHERE false");assert.equal(updated.rowCount,2);assert.deepEqual(updated.rows,[]);assert.equal(calls[1].kind,'exec');assert.equal(calls.length,2);
});
test('HTTP adapter serializes JSON/arrays safely and rejects non-provider credential destinations',/** test 콜백: 테스트: HTTP adapter serializes JSON/arrays safely and rejects non-provider credential destinations 주요 호출: httpQueryAdapter·query·deepEqual. */ async()=>{
 let args:unknown[]=[];const db=httpQueryAdapter({exec:/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ async(_sql:string,...values:unknown[])=>{args=values;return 1;},query:/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('unexpected query');}} as any);
 await db.query('INSERT INTO events(category) VALUES($1)',[{a:1},['a','NULL',null]]);assert.deepEqual(args,['{"a":1}','{"a","NULL",NULL}']);
 for(const url of ['https://db.prisma.io','postgres://test:test@evil.invalid/postgres','postgres://test@db.prisma.io/postgres'])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: prismaHttp. */ ()=>prismaHttp(url));
});
test('HTTP write timeout never replays an operation and tracks its unknown outcome for draining',/** test 콜백: 테스트: HTTP write timeout never replays an operation and tracks its unknown outcome for draining 주요 호출: httpQueryAdapter·rejects·query. */ async()=>{
 let complete!:(n:number)=>void,calls=0,draining:Promise<unknown>|undefined;
 const db=httpQueryAdapter({exec:/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ async()=>{calls++;return await new Promise<number>(/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ resolve=>{complete=resolve;});},query:/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('unexpected query');}} as any,/** httpQueryAdapter 콜백: httpQueryAdapter에서 전달한 값을 처리하는 콜백입니다 */ task=>{draining=task;});
 await assert.rejects(db.query('DELETE FROM sessions WHERE false',[],1),/Query read timeout/);assert.equal(calls,1);assert(draining);complete(0);await draining;assert.equal(calls,1);
});
import {freshConnector,leaseQuery,MAX_IDLE_LEASE_MS} from '../lib/fresh-pool';

test('suspended idle sockets are discarded before a query even when idle timers never ran',/** test 콜백: 테스트: suspended idle sockets are discarded before a query even when idle timers never ran 주요 호출: freshConnector·releaseListener·leaseQuery. */ async()=>{
 let clock=1000,releaseListener:Function=/** releaseListener: 검증 시나리오에서 releaseListener에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ ()=>{};const released:unknown[]=[],queries:string[]=[];
 const stale={query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('stale socket must not execute');},release:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ (drop:unknown)=>released.push(drop)};
 const fresh={query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ async(sql:string)=>{queries.push(sql);return {rows:[]};},release:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ (drop:unknown)=>released.push(drop)};
 const queue=[stale,fresh];const pool={on:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ (_event:string,fn:Function)=>{releaseListener=fn;},connect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: shift. */ async()=>queue.shift()!} as unknown as Pick<Pool,'connect'|'on'>;
 const connector=freshConnector(pool,/** freshConnector 콜백: freshConnector에서 전달한 값을 처리하는 콜백입니다 */ ()=>clock);releaseListener(undefined,stale);clock+=MAX_IDLE_LEASE_MS;
 await leaseQuery(connector,'SELECT 1');assert.deepEqual(released,[true,false]);assert.deepEqual(queries,['SELECT 1']);
});
test('fresh leases preserve concurrent borrowers and never replay failed writes',/** test 콜백: 테스트: fresh leases preserve concurrent borrowers and never replay failed writes 주요 호출: freshConnector·releaseListener·rejects. */ async()=>{
 let releaseListener:Function=/** releaseListener: 검증 시나리오에서 releaseListener에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ ()=>{};const released:unknown[]=[],calls:string[]=[];let connects=0;
 const client={query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ async(sql:string)=>{calls.push(sql);throw new Error('write outcome unknown');},release:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ (drop:unknown)=>released.push(drop)};
 const pool={on:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ (_event:string,fn:Function)=>{releaseListener=fn;},connect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>{connects++;return client;}} as unknown as Pick<Pool,'connect'|'on'>;
 const connector=freshConnector(pool,/** freshConnector 콜백: freshConnector에서 전달한 값을 처리하는 콜백입니다 */ ()=>1000);releaseListener(undefined,client);
 await assert.rejects(leaseQuery(connector,'INSERT INTO events(category) VALUES($1)',['test']),/write outcome unknown/);
 assert.equal(connects,1);assert.equal(calls.length,1);assert.deepEqual(released,[true]);
});
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
import {scannerCatalog} from '../lib/assessment/registry';
import {contentSecurityPolicy} from '../lib/content-security-policy';
import {authSourceBucket,localAuthIdentity} from '../lib/auth-rate-identity';
const moduleSchema={validated:true,module_constraint:'CHECK (module_id IN ('+scannerCatalog.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ m=>"'"+m.id+"'").join(',')+'))'};

test('readiness refuses old or unvalidated module constraints even when base schema and grants exist',/** test 콜백: 테스트: readiness refuses old or unvalidated module constraints even when base schema and grants exist 주요 호출: cloudEnv·replace·deploymentReadiness. */ async()=>{
 const before={...process.env};try{cloudEnv();for(const row of [{},{...moduleSchema,validated:false},{...moduleSchema,module_constraint:moduleSchema.module_constraint.replace("'network.gns3'","'older.module'")}]){const r=await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 주요 호출: includes. */ async sql=>({rows:[sql.includes('module_constraint')?row:{schema_ready:true,role_safe:true,writes_ready:true}]}));assert.equal(r.code,'DATABASE_MODULE_SCHEMA_NOT_READY');}}finally{process.env=before;}
});
test('production CSP permits only nonced scripts and retains worker and frame boundaries',/** test 콜백: 테스트: production CSP permits only nonced scripts and retains worker and frame boundaries 주요 호출: contentSecurityPolicy·repeat·find. */ ()=>{
 const policy=contentSecurityPolicy('a'.repeat(32));const script=policy.split(';').find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: includes. */ v=>v.includes('script-src'))!;assert(script.includes("'nonce-"));assert(!script.includes('unsafe-inline'));assert(!script.includes('unsafe-eval'));assert(policy.includes("worker-src 'self' blob:"));assert(policy.includes("frame-ancestors 'none'"));assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: contentSecurityPolicy. */ ()=>contentSecurityPolicy("bad';unsafe-inline"));assert(contentSecurityPolicy('b'.repeat(32),true).includes('unsafe-eval'));
});
test('authentication source limits isolate trusted peers and ignore forged identity headers',/** test 콜백: 테스트: authentication source limits isolate trusted peers and ignore forged identity headers 주요 호출: repeat·localAuthIdentity·notEqual. */ ()=>{
 const secret='x'.repeat(64),env={WEBGUARD_LOCAL_AUTH_SECRET:secret},a=new Request('http://localhost',{headers:localAuthIdentity('192.0.2.1',secret)}),b=new Request('http://localhost',{headers:localAuthIdentity('192.0.2.2',secret)});assert.notEqual(authSourceBucket('login',a,env),authSourceBucket('login',b,env));assert.equal(authSourceBucket('login',a,{}),authSourceBucket('login',new Request('http://localhost',{headers:{'x-real-ip':'198.51.100.3'}}),{}));assert(!authSourceBucket('login',a,env).includes('192.0.2.1'));
 const forged=new Request('http://localhost',{headers:{...localAuthIdentity('192.0.2.1',secret),'x-webguard-auth-peer':'192.0.2.2'}});assert.equal(authSourceBucket('login',forged,env),authSourceBucket('login',new Request('http://localhost'),env));
 assert.notEqual(authSourceBucket('login',new Request('https://example.test',{headers:{'x-real-ip':'192.0.2.1'}}),{VERCEL:'1'}),authSourceBucket('login',new Request('https://example.test',{headers:{'x-real-ip':'192.0.2.2'}}),{VERCEL:'1'}));
});

test('migration checksums accept only LF/CRLF equivalents and reject changed SQL',/** test 콜백: 테스트: migration checksums accept only LF/CRLF equivalents and reject changed SQL 주요 호출: replace·equal·migrationChecksums. */ ()=>{
 const lf='SELECT 1;\nSELECT 2;\n',crlf=lf.replace(/\n/g,'\r\n');
 assert.equal(migrationChecksums(lf).canonical,migrationChecksums(crlf).canonical);
 assert(migrationChecksums(crlf).accepted.has(migrationChecksums(lf).canonical));
 assert(!migrationChecksums(lf.replace('SELECT 2','SELECT 3')).accepted.has(migrationChecksums(lf).canonical));
});

test('archive maintenance is inaccessible without the exact configured secret',/** test 콜백: 테스트: archive maintenance is inaccessible without the exact configured secret 주요 호출: repeat·equal·maintenanceAuthorized. */ ()=>{
 const secret='a'.repeat(64);
 assert.equal(maintenanceAuthorized('Bearer '+secret,secret),true);
 for(const value of [null,'Bearer wrong',secret,'bearer '+secret,'Bearer '+secret+'x'])assert.equal(maintenanceAuthorized(value,secret),false);
 assert.equal(maintenanceAuthorized('Bearer '+secret,undefined),false);
 assert.equal(maintenanceAuthorized('Bearer x','x'),false);
});

test('protection query gives only the exact managed block read a longer deadline and releases clients',/** test 콜백: 테스트: protection query gives only the exact managed block read a longer deadline and releases clients 주요 호출: protectionQuery·equal·slice. */ async()=>{
 const configs:any[]=[],releases:unknown[]=[];
 const pool={connect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>({query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ async(config:unknown)=>{configs.push(config);return {rows:[]};},release:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ (failed:unknown)=>releases.push(failed)})} as unknown as Pick<Pool,'connect'>;
 for(const [sql,managed] of [[ACTIVE_BLOCK_SQL,true],[ACTIVE_BLOCK_SQL,false],['WITH changed AS (INSERT INTO events(category) VALUES($1) RETURNING id) SELECT * FROM changed',true],['SELECT 1',true]] as const)await protectionQuery(pool,sql,['private-ip'],managed);
 assert.equal(configs[0].query_timeout,PROTECTION_READ_TIMEOUT_MS);
 for(const config of configs.slice(1))assert.equal(config.query_timeout,undefined);
 assert.deepEqual(releases,[false,false,false,false]);
});

test('protection database failures discard clients without replay and keep credentials out of logs',/** test 콜백: 테스트: protection database failures discard clients without replay and keep credentials out of logs 주요 호출: rejects·protectionQuery·equal. */ async()=>{
 const logs:unknown[][]=[],warn=console.warn;console.warn=/** test 콜백: 테스트: protection database failures discard clients without replay and keep credentials out of logs 주요 호출: push. */ (...args:unknown[])=>logs.push(args);
 try{
  let calls=0;const releases:unknown[]=[];
  const pool={connect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>({query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ async()=>{calls++;throw new Error('Query read timeout');},release:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ (failed:unknown)=>releases.push(failed)})} as unknown as Pick<Pool,'connect'>;
  await assert.rejects(protectionQuery(pool,ACTIVE_BLOCK_SQL,['private-ip'],true),/Query read timeout/);
  assert.equal(calls,1);assert.deepEqual(releases,[true]);
  const failed={connect:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: assign. */ async()=>{throw Object.assign(new Error('secret-password private-ip'),{code:'ECONNRESET'});}} as unknown as Pick<Pool,'connect'>;
  await assert.rejects(protectionQuery(failed,ACTIVE_BLOCK_SQL,['private-ip'],true));
  assert.equal((logs[0][1] as any).phase,'block_read');assert.equal((logs[1][1] as any).phase,'acquire');
  assert(!JSON.stringify(logs).includes('secret-password'));assert(!JSON.stringify(logs).includes('private-ip'));
 }finally{console.warn=warn;}
});

test('runtime and local guard use provider-compatible timeout options',/** test 콜백: 테스트: runtime and local guard use provider-compatible timeout options 주요 호출: cloudEnv·runtimePoolConfig·equal. */ ()=>{
 const before={...process.env};try{
  cloudEnv();const ordinary=runtimePoolConfig();assert.equal(ordinary.statement_timeout,5000);assert.equal(ordinary.query_timeout,undefined);
  process.env.DATABASE_PROVIDER='prisma-postgres';process.env.PROJECT_DATABASE='postgres';process.env.DATABASE_URL='postgres://test:test@pooled.db.prisma.io/postgres';
  const managed=runtimePoolConfig();assert.equal(managed.statement_timeout,undefined);assert.equal(managed.query_timeout,5000);assert.equal(managed.connectionTimeoutMillis,10000);assert.deepEqual(managed.ssl,{rejectUnauthorized:true});
 }finally{process.env=before;}
});

/** cloudEnv: 검증 시나리오에서 cloudEnv에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ function cloudEnv(){process.env.DATABASE_PROVIDER='postgresql';process.env.PROJECT_DATABASE='neondb';process.env.PROJECT_RUNTIME_ROLE='webguard_hub_prod_app';process.env.DATABASE_URL='postgresql://webguard_hub_prod_app:dummy-password@db.example/neondb?sslmode=require&channel_binding=require';}
test('Prisma managed profile accepts provider credentials only on the matching pooled/direct hosts',/** test 콜백: 테스트: Prisma managed profile accepts provider credentials only on the matching pooled/direct hosts 주요 호출: equal·projectDatabase·deepEqual. */ ()=>{
 const before={...process.env};try{
  process.env.DATABASE_PROVIDER='prisma-postgres';process.env.PROJECT_DATABASE='postgres';delete process.env.PROJECT_RUNTIME_ROLE;
  process.env.DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io:5432/?sslmode=require';
  assert.equal(new URL(projectDatabase('runtime').connectionString).pathname,'/postgres');assert.deepEqual(projectDatabase('runtime').ssl,{rejectUnauthorized:true});
  process.env.MIGRATION_DATABASE_URL='postgres://provider-user:provider-password@db.prisma.io:5432/postgres?sslmode=require';assert(projectDatabase('migration'));
  process.env.DATABASE_URL=process.env.MIGRATION_DATABASE_URL;assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/pooled/);
  process.env.MIGRATION_DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io/postgres';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('migration'),/direct/);
  process.env.DATABASE_URL='postgres://provider-user:provider-password@evil.example/postgres';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'));
  process.env.DATABASE_PROVIDER='postgresql';process.env.DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io/postgres';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/DATABASE_PROVIDER/);
 }finally{process.env=before;}
});
test('Prisma managed runtime client rejects DDL, multi-statements, direct account writes and migration archives',/** test 콜백: 테스트: Prisma managed runtime client rejects DDL, multi-statements, direct account writes and migration archives 주요 호출: doesNotThrow·throws. */ ()=>{
 assert.doesNotThrow(/** doesNotThrow 콜백: doesNotThrow에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql('INSERT INTO scans(id) VALUES($1) ON CONFLICT(id) DO UPDATE SET result=$2'));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql('DO $$ BEGIN NULL; END $$'));
 for(const sql of ['SELECT id FROM users WHERE email=$1','SELECT public.register_viewer($1,$2,$3)',"WITH changed AS (INSERT INTO events(category) VALUES('scan_success') RETURNING id) SELECT id FROM changed",'UPDATE scans SET result=$1 WHERE id=$2','DELETE FROM sessions WHERE token_hash=$1',"SELECT 'DROP' AS label"])assert.doesNotThrow(/** doesNotThrow 콜백: doesNotThrow에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql(sql));
 for(const sql of ['DROP TABLE users','SELECT 1; DROP TABLE users','CREATE TABLE bad(id int)','TRUNCATE scans','GRANT ALL ON users TO PUBLIC','SELECT * FROM schema_migrations','SELECT * FROM public.scan_duplicate_archive','UPDATE users SET role=$1','INSERT INTO public.users(id) VALUES($1)','DELETE FROM "users"','SELECT set_config($1,$2,true)','SELECT 1 -- hidden'])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql(sql));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql('SELECT payload FROM webguard_archive.diagnostic_records'));
 assert.doesNotThrow(/** doesNotThrow 콜백: doesNotThrow에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql. */ ()=>assertManagedRuntimeSql('SELECT public.archive_diagnostics_30d() AS result'));
});
test('Prisma readiness reports provider-managed permissions without asserting separate SQL role isolation',/** test 콜백: 테스트: Prisma readiness reports provider-managed permissions without asserting separate SQL role isolation 주요 호출: deploymentReadiness·deepEqual·assert. */ async()=>{
 const before={...process.env};try{
  process.env.DATABASE_PROVIDER='prisma-postgres';process.env.PROJECT_DATABASE='postgres';process.env.DATABASE_URL='postgres://provider-user:provider-password@pooled.db.prisma.io/postgres';
  const queries:string[]=[];const ready=await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 주요 호출: push. */ async sql=>{queries.push(sql);return {rows:[{schema_ready:true,writes_ready:true,...moduleSchema}]};});
  assert.deepEqual(ready,{ready:true,code:'READY',permissionModel:'provider-managed'});assert(!queries.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ sql=>sql.includes('rolsuper')));
 }finally{process.env=before;}
});
test('cloud PostgreSQL URL preserves project identity and enforces verified TLS',/** test 콜백: 테스트: cloud PostgreSQL URL preserves project identity and enforces verified TLS 주요 호출: cloudEnv·projectDatabase·deepEqual. */ ()=>{
 const before={...process.env};try{
  cloudEnv();const c=projectDatabase('runtime');assert.deepEqual(c.ssl,{rejectUnauthorized:true});assert.equal(c.enableChannelBinding,true);assert.equal(new URL(c.connectionString).search,'');
  for(const query of ['user=postgres','database=other','host=evil.example','password=evil','sslcert=secret','sslmode=no-verify','sslmode=disable','sslmode=require&sslmode=verify-full','channel_binding=disable']){
   process.env.DATABASE_URL='postgresql://webguard_hub_prod_app@db.example/neondb?'+query;assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'));
  }
  process.env.DATABASE_URL='postgresql://postgres@db.example/neondb?sslmode=require';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/dedicated/);
  process.env.DATABASE_URL='postgresql://webguard_hub_prod_app@db.example/other';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/mismatch/);
 }finally{process.env=before;}
});
test('localhost database works locally and is refused explicitly on Vercel',/** test 콜백: 테스트: localhost database works locally and is refused explicitly on Vercel 주요 호출: cloudEnv·equal·projectDatabase. */ ()=>{
 const before={...process.env};try{
  cloudEnv();delete process.env.VERCEL;process.env.DATABASE_URL='postgresql://webguard_hub_prod_app@localhost/neondb';assert.equal(projectDatabase('runtime').ssl,undefined);
  process.env.VERCEL='1';
  for(const host of ['localhost','other.localhost','127.0.0.1','127.9.8.7','[::1]','[::ffff:127.0.0.1]']){
   process.env.DATABASE_URL=`postgresql://webguard_hub_prod_app@${host}/neondb`;assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: projectDatabase. */ ()=>projectDatabase('runtime'),/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 */ e=>typeof e==='object'&&e!==null&&'code' in e&&e.code==='DATABASE_LOCALHOST_ON_VERCEL');
  }
 }finally{process.env=before;}
});
test('Vercel production keeps the official HTTPS origin and Secure session cookies',/** test 콜백: 테스트: Vercel production keeps the official HTTPS origin and Secure session cookies 주요 호출: deepEqual·accessOrigins·equal. */ ()=>{
 const before={...process.env};try{
  delete process.env.APP_ORIGIN;delete process.env.APP_ADDITIONAL_ORIGINS;process.env.VERCEL='1';process.env.VERCEL_ENV='production';
  assert.deepEqual(accessOrigins(),['https://webguard-security-hub.vercel.app']);
  assert.equal(secureOriginCookie(new Request('https://webguard-security-hub.vercel.app/api/login',{headers:{origin:'https://webguard-security-hub.vercel.app'}})),true);
  assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: secureOriginCookie. */ ()=>secureOriginCookie(new Request('https://evil.vercel.app',{headers:{origin:'https://evil.vercel.app'}})));
 }finally{process.env=before;}
});
test('readiness distinguishes missing configuration, schema, unsafe role and connectivity without exposing credentials',/** test 콜백: 테스트: readiness distinguishes missing configuration, schema, unsafe role and connectivity without exposing credentials 주요 호출: deepEqual·deploymentReadiness·cloudEnv. */ async()=>{
 const before={...process.env};try{
  delete process.env.DATABASE_URL;assert.deepEqual(await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('must not query');}),{ready:false,code:'DATABASE_NOT_CONFIGURED'});
  cloudEnv();assert.equal((await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 */ async()=>({rows:[{schema_ready:false}]}))).code,'DATABASE_SCHEMA_NOT_READY');
  assert.equal((await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 주요 호출: includes. */ async sql=>({rows:[sql.includes('to_regclass')?{schema_ready:true}:{role_safe:false}]}))).code,'DATABASE_RUNTIME_ROLE_UNSAFE');
  assert.equal((await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 */ async()=>({rows:[{schema_ready:true,role_safe:true,writes_ready:false}]}))).code,'DATABASE_PERMISSIONS_NOT_READY');
  const ready=await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 */ async()=>({rows:[{schema_ready:true,role_safe:true,writes_ready:true,...moduleSchema}]}));assert.deepEqual(ready,{ready:true,code:'READY'});
  const failed=await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('private-provider-host secret-password');});assert.equal(failed.code,'DATABASE_CONNECTION_OR_PERMISSIONS_FAILED');assert(!JSON.stringify(failed).includes('secret-password'));
 }finally{process.env=before;}
});
test('Vercel client identity uses only the official platform header and is disabled on raw servers',/** test 콜백: 테스트: Vercel client identity uses only the official platform header and is disabled on raw servers 주요 호출: equal·vercelClientAddress. */ ()=>{
 const h=new Headers({'x-real-ip':'::ffff:203.0.113.2','x-forwarded-for':'8.8.8.8','x-webguard-client-ip':'1.1.1.1'});
 assert.equal(vercelClientAddress(h,{VERCEL:'1'}),'203.0.113.2');assert.equal(vercelClientAddress(h,{}),null);
 assert.equal(vercelClientAddress(new Headers({'x-real-ip':'1.1.1.1,8.8.8.8'}),{VERCEL:'1'}),null);
});
test('Vercel protection checks persistent blocks and never runs twice on local guarded server',/** test 콜백: 테스트: Vercel protection checks persistent blocks and never runs twice on local guarded server 주요 호출: equal·vercelProtection·get. */ async()=>{
 let calls=0;const query=/** query: 검증 시나리오에서 query에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: equal. */ async(_sql:string,values:unknown[])=>{calls++;assert.equal(values[0],'203.0.113.2');return {rows:[]};};
 const req=new Request('https://webguard-security-hub.vercel.app/',{headers:{'x-real-ip':'203.0.113.2'}});
 assert.equal(await vercelProtection(req,query,{}),null);assert.equal(calls,0);
 assert.equal(await vercelProtection(req,query,{VERCEL:'1'}),null);assert.equal(calls,1);
 const blocked=await vercelProtection(req,/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 */ async()=>({rows:[{blacklisted:false,strikes:2,retry_after:123}]}),{VERCEL:'1'});assert.equal(blocked?.status,429);assert.equal(blocked?.headers.get('retry-after'),'123');
 const blacklisted=await vercelProtection(req,/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 */ async()=>({rows:[{blacklisted:true,strikes:6}]}),{VERCEL:'1'});assert.equal(blacklisted?.status,403);
});
test('Vercel protection detects probes, fails closed, and leaves readiness reachable',/** test 콜백: 테스트: Vercel protection detects probes, fails closed, and leaves readiness reachable 주요 호출: vercelProtection·equal·assert. */ async()=>{
 let calls=0;const attacked=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/.env',{headers:{'x-real-ip':'203.0.113.2'}}),/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 주요 호출: startsWith. */ async sql=>{calls++;return {rows:sql.startsWith('SELECT')?[]:[{blacklisted:false,strikes:1,retry_after:300}]};},{VERCEL:'1'});
 assert.equal(calls,2);assert.equal(attacked?.status,429);
 const failed=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/',{headers:{'x-real-ip':'203.0.113.2'}}),/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('private database secret');},{VERCEL:'1'});assert.equal(failed?.status,503);assert(!(await failed!.text()).includes('secret'));
 const missing=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/'),/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('not called');},{VERCEL:'1'});assert.equal(missing?.status,503);
 for(const path of ['/api/ready','/api/health'])assert.equal(await vercelProtection(new Request('https://webguard-security-hub.vercel.app'+path),/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 */ async()=>{throw new Error('not called');},{VERCEL:'1'}),null);
});

test('Vercel protection retries a transient block read once and still enforces the recovered block',/** test 콜백: 테스트: Vercel protection retries a transient block read once and still enforces the recovered block 주요 호출: equal·vercelProtection. */ async()=>{
 const req=new Request('https://webguard-security-hub.vercel.app/api/scans',{method:'POST',headers:{'x-real-ip':'2001:db8::2'}});
 let reads=0;const query=/** query: 검증 시나리오에서 query에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: assert·startsWith·equal. */ async(sql:string,values:unknown[])=>{assert(sql.startsWith('SELECT'));assert.equal(values[0],'2001:db8::2');if(++reads===1)throw new Error('Query read timeout');return {rows:[]};};
 assert.equal(await vercelProtection(req,query,{VERCEL:'1'}),null);assert.equal(reads,2);
 reads=0;const blocked=await vercelProtection(req,/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 주요 호출: assign. */ async()=>{if(++reads===1)throw Object.assign(new Error('private connection text'),{code:'ECONNRESET'});return {rows:[{blacklisted:true,strikes:6}]};},{VERCEL:'1'});
 assert.equal(blocked?.status,403);assert.equal(reads,2);
});

test('Vercel protection stops after a failed retry, rejects permanent errors immediately, and logs no secrets',/** test 콜백: 테스트: Vercel protection stops after a failed retry, rejects permanent errors immediately, and logs no secrets 주요 호출: vercelProtection·equal·json. */ async()=>{
 const req=new Request('https://webguard-security-hub.vercel.app/api/scans',{headers:{'x-real-ip':'203.0.113.2'}});
 let calls=0;const logs:unknown[][]=[],warn=console.warn;console.warn=/** test 콜백: 테스트: Vercel protection stops after a failed retry, rejects permanent errors immediately, and logs no secrets 주요 호출: push. */ (...args:unknown[])=>{logs.push(args);};
 try{
  const unavailable=await vercelProtection(req,/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 주요 호출: assign. */ async()=>{calls++;throw Object.assign(new Error('secret-db-password'),{code:'ECONNRESET'});},{VERCEL:'1'});
  assert.equal(calls,2);assert.equal(unavailable?.status,503);assert.equal((await unavailable!.json()).errorCode,'PROTECTION_UNAVAILABLE');
  calls=0;const denied=await vercelProtection(req,/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 주요 호출: assign. */ async()=>{calls++;throw Object.assign(new Error('secret-db-password'),{code:'42501'});},{VERCEL:'1'});
  assert.equal(calls,1);assert.equal(denied?.status,503);assert(!JSON.stringify(logs).includes('secret-db-password'));assert(!JSON.stringify(logs).includes('203.0.113.2'));
 }finally{console.warn=warn;}
});

test('Vercel protection never retries a threat write after an ambiguous connection error',/** test 콜백: 테스트: Vercel protection never retries a threat write after an ambiguous connection error 주요 호출: vercelProtection·equal. */ async()=>{
 let calls=0;const response=await vercelProtection(new Request('https://webguard-security-hub.vercel.app/.env',{headers:{'x-real-ip':'203.0.113.2'}}),/** vercelProtection 콜백: vercelProtection에서 전달한 값을 처리하는 콜백입니다 주요 호출: startsWith·assign. */ async sql=>{calls++;if(sql.startsWith('SELECT'))return {rows:[]};throw Object.assign(new Error('write connection interrupted'),{code:'ECONNRESET'});},{VERCEL:'1'});
 assert.equal(calls,2);assert.equal(response?.status,503);
});
