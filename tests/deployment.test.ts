import test from 'node:test';
import assert from 'node:assert/strict';
import {projectDatabase} from '../lib/project-database';
import {deploymentReadiness} from '../lib/deployment-readiness';
import {vercelClientAddress,vercelProtection} from '../lib/vercel-protection';
import {accessOrigins,secureOriginCookie} from '../lib/access-origins';

function cloudEnv(){process.env.PROJECT_DATABASE='neondb';process.env.PROJECT_RUNTIME_ROLE='webguard_hub_prod_app';process.env.DATABASE_URL='postgresql://webguard_hub_prod_app:dummy-password@db.example/neondb?sslmode=require&channel_binding=require';}
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
