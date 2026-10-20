// Explicit one-time copy into an EMPTY target; source remains read-only.
import {Pool} from 'pg';
import {projectDatabase} from '../lib/project-database';
import {databaseProvider} from '../lib/database-provider';
let sourceUrl:URL;try{sourceUrl=new URL(process.env.DATABASE_URL??'');}catch{throw new Error('Source database URL is missing or invalid');}
if(!['postgres:','postgresql:'].includes(sourceUrl.protocol)||!['localhost','127.0.0.1','[::1]'].includes(sourceUrl.hostname)||sourceUrl.search||decodeURIComponent(sourceUrl.pathname.slice(1))!=='webguard_hub_dev'||decodeURIComponent(sourceUrl.username)!=='webguard_hub_dev_app')throw new Error('Source must be this project local runtime database');
const targetConfig=projectDatabase('migration');
const targetUrl=new URL(targetConfig.connectionString);
if(sourceUrl.hostname===targetUrl.hostname&&(sourceUrl.port||'5432')===(targetUrl.port||'5432')&&sourceUrl.pathname===targetUrl.pathname)throw new Error('Source and target must differ');
const source=new Pool({connectionString:sourceUrl.toString(),max:1,connectionTimeoutMillis:5000,statement_timeout:30000});
const target=new Pool({...targetConfig,max:1,connectionTimeoutMillis:5000,...(databaseProvider()==='prisma-postgres'?{query_timeout:30000}:{statement_timeout:30000})});
const s=await source.connect().catch(async()=>{await source.end();await target.end();console.error('Local source database connection failed.');process.exit(1);});
const t=await target.connect().catch(async()=>{s.release();await source.end();await target.end();console.error('Production target database connection failed.');process.exit(1);});
try{
 await s.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 await t.query('BEGIN');await t.query('LOCK TABLE public.users,public.scans,public.assessment_assets,public.assessment_runs,public.assessment_traffic IN ACCESS EXCLUSIVE MODE');
 if((await t.query('SELECT (SELECT count(*) FROM public.users)+(SELECT count(*) FROM public.scans)+(SELECT count(*) FROM public.assessment_assets)+(SELECT count(*) FROM public.assessment_runs)+(SELECT count(*) FROM public.assessment_traffic) AS count')).rows[0].count!=='0')throw new Error('Target already contains data; refusing to overwrite');
 const users=(await s.query('SELECT id,email,password_hash,role FROM public.users LIMIT 10001')).rows;
 const scans=(await s.query('SELECT id,user_id,hostname,result,created_at FROM public.scans LIMIT 10001')).rows;
 const assets=(await s.query('SELECT id,user_id,module_id,target_key,label,created_at,updated_at FROM public.assessment_assets LIMIT 10001')).rows;
 const runs=(await s.query('SELECT id,user_id,asset_id,report,created_at FROM public.assessment_runs LIMIT 10001')).rows;
 const traffic=(await s.query('SELECT user_id,asset_id,window_at,requests,login_failures,probes,server_errors FROM public.assessment_traffic LIMIT 10001')).rows;
 if([users,scans,assets,runs,traffic].some(rows=>rows.length>10000))throw new Error('Use a reviewed backup/restore for larger datasets');
 for(const u of users)await t.query('INSERT INTO public.users(id,email,password_hash,role) VALUES($1,$2,$3,$4)',[u.id,u.email,u.password_hash,u.role]);
 for(const r of scans)await t.query('INSERT INTO public.scans(id,user_id,hostname,result,created_at) VALUES($1,$2,$3,$4,$5)',[r.id,r.user_id,r.hostname,r.result,r.created_at]);
 for(const a of assets)await t.query('INSERT INTO public.assessment_assets(id,user_id,module_id,target_key,label,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[a.id,a.user_id,a.module_id,a.target_key,a.label,a.created_at,a.updated_at]);
 for(const r of runs)await t.query('INSERT INTO public.assessment_runs(id,user_id,asset_id,report,created_at) VALUES($1,$2,$3,$4,$5)',[r.id,r.user_id,r.asset_id,r.report,r.created_at]);
 for(const r of traffic)await t.query('INSERT INTO public.assessment_traffic(user_id,asset_id,window_at,requests,login_failures,probes,server_errors) VALUES($1,$2,$3,$4,$5,$6,$7)',[r.user_id,r.asset_id,r.window_at,r.requests,r.login_failures,r.probes,r.server_errors]);
 await t.query("INSERT INTO public.events(category) VALUES('production_data_imported')");
 await s.query('COMMIT');await t.query('COMMIT');
 console.log(`Copied ${users.length} accounts, ${scans.length} legacy results, ${assets.length} assets and ${runs.length} assessment runs. Source unchanged. Sessions and ingestion keys were not copied.`);
}catch{
 await t.query('ROLLBACK');await s.query('ROLLBACK');console.error('Data copy failed; target transaction rolled back. No passwords or connection strings printed.');process.exitCode=1;
}finally{s.release();t.release();await source.end();await target.end();}
