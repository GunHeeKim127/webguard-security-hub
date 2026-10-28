import {DatabaseConfigurationError,projectDatabase} from './project-database';
import {databaseProvider} from './database-provider';
import {scannerCatalog} from './assessment/registry';
import {protectionDbError} from './protection-db-error';
type Query=(sql:string)=>Promise<{rows:Record<string,unknown>[]}>;
export async function deploymentReadiness(execute:Query){
 // This function contains only fixed SELECT probes. Recover one interrupted
 // read without ever extending retry behavior to a write or permanent failure.
 let step=0;const query:Query=async sql=>{step++;try{return await execute(sql);}catch(error){if(!protectionDbError(error).retryable)throw error;console.warn('[WebGuard readiness retry]',{step,reason:protectionDbError(error).reason});return execute(sql);}};
 try{projectDatabase('runtime');}catch(error){return {ready:false,code:error instanceof DatabaseConfigurationError?error.code:'DATABASE_IDENTITY_MISMATCH'};}
 try{
  const r=await query("SELECT to_regclass('public.users') IS NOT NULL AND to_regclass('public.sessions') IS NOT NULL AND to_regclass('public.scans') IS NOT NULL AND to_regclass('public.events') IS NOT NULL AND to_regclass('public.rate_limits') IS NOT NULL AND to_regclass('public.ip_blocks') IS NOT NULL AND to_regclass('public.account_blocks') IS NOT NULL AND to_regclass('public.ai_advice_cache') IS NOT NULL AND to_regclass('public.assessment_assets') IS NOT NULL AND to_regclass('public.assessment_runs') IS NOT NULL AND to_regclass('public.assessment_traffic') IS NOT NULL AND to_regclass('public.scans_user_hostname_unique') IS NOT NULL AND to_regprocedure('public.archive_diagnostics_30d()') IS NOT NULL AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='events' AND column_name='user_id') AND (SELECT count(*)=2 FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('ip_blocks','account_blocks') AND column_name='management_id') AS schema_ready");
  if(r.rows[0]?.schema_ready!==true)return {ready:false,code:'DATABASE_SCHEMA_NOT_READY'};
  if(databaseProvider()!=='prisma-postgres'){
   const role=await query('SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND current_user<>pg_get_userbyid((SELECT datdba FROM pg_database WHERE datname=current_database())) AS role_safe FROM pg_roles WHERE rolname=current_user');
   if(role.rows[0]?.role_safe!==true)return {ready:false,code:'DATABASE_RUNTIME_ROLE_UNSAFE'};
  }
  const writes=await query("SELECT has_table_privilege('public.sessions','INSERT') AND has_table_privilege('public.sessions','DELETE') AND has_table_privilege('public.scans','INSERT') AND has_column_privilege('public.scans','result','UPDATE') AND has_table_privilege('public.events','INSERT') AND has_table_privilege('public.rate_limits','UPDATE') AND has_table_privilege('public.ip_blocks','UPDATE') AND has_table_privilege('public.account_blocks','UPDATE') AND has_table_privilege('public.account_blocks','INSERT') AND has_table_privilege('public.ai_advice_cache','UPDATE') AND has_sequence_privilege('public.events_id_seq','USAGE') AND has_function_privilege('public.register_viewer(uuid,text,text)','EXECUTE') AS writes_ready");
  if(writes.rows[0]?.writes_ready!==true)return {ready:false,code:'DATABASE_PERMISSIONS_NOT_READY'};
  const constraints=await query("SELECT pg_get_constraintdef(oid) AS module_constraint,convalidated AS validated FROM pg_catalog.pg_constraint WHERE conrelid='public.assessment_assets'::regclass AND conname='assessment_assets_module_id_check' AND contype='c'");
  const constraint=constraints.rows[0],allowed=new Set(typeof constraint?.module_constraint==='string'?[...constraint.module_constraint.matchAll(/'((?:[^']|'')*)'/g)].map(m=>m[1].replace(/''/g,"'")):[]);
  if(constraint?.validated!==true||scannerCatalog.some(module=>!allowed.has(module.id)))return {ready:false,code:'DATABASE_MODULE_SCHEMA_NOT_READY'};
  await query('SELECT 1 FROM public.users LIMIT 1');
  await query('SELECT 1 FROM public.ip_blocks LIMIT 1');
  await query('SELECT 1 FROM public.account_blocks LIMIT 1');
  await query('SELECT 1 FROM public.assessment_assets LIMIT 1');
  await query('SELECT 1 FROM public.assessment_runs LIMIT 1');
  await query('SELECT 1 FROM public.assessment_traffic LIMIT 1');
  return {ready:true,code:'READY',...(databaseProvider()==='prisma-postgres'?{permissionModel:'provider-managed'}:{})};
 }catch(error){console.warn('[WebGuard readiness database]',{step,reason:protectionDbError(error).reason});return {ready:false,code:'DATABASE_CONNECTION_OR_PERMISSIONS_FAILED'};}
}
