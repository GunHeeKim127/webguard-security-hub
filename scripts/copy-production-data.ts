// Explicit one-time copy into an EMPTY target; source remains read-only.
import {Pool} from 'pg';
import {projectDatabase} from '../lib/project-database';
let sourceUrl:URL;try{sourceUrl=new URL(process.env.DATABASE_URL??'');}catch{throw new Error('Source database URL is missing or invalid');}
if(!['postgres:','postgresql:'].includes(sourceUrl.protocol)||!['localhost','127.0.0.1','[::1]'].includes(sourceUrl.hostname)||sourceUrl.search||decodeURIComponent(sourceUrl.pathname.slice(1))!=='webguard_hub_dev'||decodeURIComponent(sourceUrl.username)!=='webguard_hub_dev_app')throw new Error('Source must be this project local runtime database');
const targetConfig=projectDatabase('migration');
const targetUrl=new URL(targetConfig.connectionString);
if(sourceUrl.hostname===targetUrl.hostname&&(sourceUrl.port||'5432')===(targetUrl.port||'5432')&&sourceUrl.pathname===targetUrl.pathname)throw new Error('Source and target must differ');
const source=new Pool({connectionString:sourceUrl.toString(),max:1,connectionTimeoutMillis:5000,statement_timeout:30000});
const target=new Pool({...targetConfig,max:1,connectionTimeoutMillis:5000,statement_timeout:30000});
const s=await source.connect().catch(async()=>{await source.end();await target.end();console.error('Local source database connection failed.');process.exit(1);});
const t=await target.connect().catch(async()=>{s.release();await source.end();await target.end();console.error('Production target database connection failed.');process.exit(1);});
try{
 await s.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 await t.query('BEGIN');await t.query('LOCK TABLE public.users,public.scans IN ACCESS EXCLUSIVE MODE');
 if((await t.query('SELECT (SELECT count(*) FROM public.users)+(SELECT count(*) FROM public.scans) AS count')).rows[0].count!=='0')throw new Error('Target already contains accounts or scans; refusing to overwrite');
 const users=(await s.query('SELECT id,email,password_hash,role FROM public.users LIMIT 10001')).rows;
 const scans=(await s.query('SELECT id,user_id,hostname,result,created_at FROM public.scans LIMIT 10001')).rows;
 if(users.length>10000||scans.length>10000)throw new Error('Use a reviewed backup/restore for larger datasets');
 for(const u of users)await t.query('INSERT INTO public.users(id,email,password_hash,role) VALUES($1,$2,$3,$4)',[u.id,u.email,u.password_hash,u.role]);
 for(const r of scans)await t.query('INSERT INTO public.scans(id,user_id,hostname,result,created_at) VALUES($1,$2,$3,$4,$5)',[r.id,r.user_id,r.hostname,r.result,r.created_at]);
 await t.query("INSERT INTO public.events(category) VALUES('production_data_imported')");
 await s.query('COMMIT');await t.query('COMMIT');
 console.log(`Copied ${users.length} accounts and ${scans.length} latest results. Source unchanged. Existing sessions were not copied; sign in again.`);
}catch{
 await t.query('ROLLBACK');await s.query('ROLLBACK');console.error('Data copy failed; target transaction rolled back. No passwords or connection strings printed.');process.exitCode=1;
}finally{s.release();t.release();await source.end();await target.end();}
