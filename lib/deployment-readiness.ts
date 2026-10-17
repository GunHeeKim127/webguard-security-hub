import {DatabaseConfigurationError,projectDatabase} from './project-database';
import {databaseProvider} from './database-provider';
type Query=(sql:string)=>Promise<{rows:Record<string,unknown>[]}>;
export async function deploymentReadiness(query:Query){
 try{projectDatabase('runtime');}catch(error){return {ready:false,code:error instanceof DatabaseConfigurationError?error.code:'DATABASE_IDENTITY_MISMATCH'};}
 try{
  const r=await query("SELECT to_regclass('public.users') IS NOT NULL AND to_regclass('public.sessions') IS NOT NULL AND to_regclass('public.scans') IS NOT NULL AND to_regclass('public.events') IS NOT NULL AND to_regclass('public.rate_limits') IS NOT NULL AND to_regclass('public.ip_blocks') IS NOT NULL AND to_regclass('public.ai_advice_cache') IS NOT NULL AS schema_ready");
  if(r.rows[0]?.schema_ready!==true)return {ready:false,code:'DATABASE_SCHEMA_NOT_READY'};
  if(databaseProvider()!=='prisma-postgres'){
   const role=await query('SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND current_user<>pg_get_userbyid((SELECT datdba FROM pg_database WHERE datname=current_database())) AS role_safe FROM pg_roles WHERE rolname=current_user');
   if(role.rows[0]?.role_safe!==true)return {ready:false,code:'DATABASE_RUNTIME_ROLE_UNSAFE'};
  }
  const writes=await query("SELECT has_table_privilege('public.sessions','INSERT') AND has_table_privilege('public.sessions','DELETE') AND has_table_privilege('public.scans','INSERT') AND has_column_privilege('public.scans','result','UPDATE') AND has_table_privilege('public.events','INSERT') AND has_table_privilege('public.rate_limits','UPDATE') AND has_table_privilege('public.ip_blocks','UPDATE') AND has_table_privilege('public.ai_advice_cache','UPDATE') AND has_sequence_privilege('public.events_id_seq','USAGE') AND has_function_privilege('public.register_viewer(uuid,text,text)','EXECUTE') AS writes_ready");
  if(writes.rows[0]?.writes_ready!==true)return {ready:false,code:'DATABASE_PERMISSIONS_NOT_READY'};
  await query('SELECT 1 FROM public.users LIMIT 1');
  await query('SELECT 1 FROM public.ip_blocks LIMIT 1');
  return {ready:true,code:'READY',...(databaseProvider()==='prisma-postgres'?{permissionModel:'provider-managed'}:{})};
 }catch{return {ready:false,code:'DATABASE_CONNECTION_OR_PERMISSIONS_FAILED'};}
}
