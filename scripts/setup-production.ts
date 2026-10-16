// Run locally with the new cloud project's owner connection. Never runs during Vercel build.
import {Pool} from 'pg';
import {randomBytes} from 'node:crypto';
import {open,unlink} from 'node:fs/promises';
import path from 'node:path';
import {projectDatabase} from '../lib/project-database';
const index=process.argv.indexOf('--output');
const output=path.resolve(index<0?'.env.production.local':process.argv[index+1]??'');
const relative=path.relative(process.cwd(),output);
if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw new Error('Output must be a new file inside this project');
const config=projectDatabase('migration'),role=process.env.PROJECT_RUNTIME_ROLE!;
const pool=new Pool({...config,connectionTimeoutMillis:5000,statement_timeout:10000});
let createdFile=false,committed=false;
const c=await pool.connect().catch(async()=>{await pool.end();console.error('Production database connection failed; check the local migration settings.');process.exit(1);});
try{
 await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(784294)');
 if((await c.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[role])).rowCount)throw new Error('Role already exists; refusing to overwrite');
 const file=await open(output,'wx',0o600);createdFile=true;
 try{
  const password=randomBytes(32).toString('base64url');
  // Both interpolated identifiers and the generated secret are restricted to safe character sets.
  await c.query(`CREATE ROLE "${role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`);
  const database=process.env.PROJECT_DATABASE!;if(!/^[a-z][a-z0-9_]{0,62}$/.test(database))throw new Error('Invalid project database');
  await c.query(`GRANT CONNECT ON DATABASE "${database}" TO "${role}"`);
  const url=new URL(config.connectionString);url.username=role;url.password=password;
  if(process.env.CLOUD_RUNTIME_HOST){
   if(!/^[a-z0-9.-]+$/i.test(process.env.CLOUD_RUNTIME_HOST))throw new Error('Invalid runtime database host');
   url.hostname=process.env.CLOUD_RUNTIME_HOST;
  }
  if(config.ssl)url.searchParams.set('sslmode','verify-full');
  if('enableChannelBinding' in config)url.searchParams.set('channel_binding','require');
  await file.writeFile(`APP_ORIGIN=https://webguard-security-hub.vercel.app\nPROJECT_DATABASE=${database}\nPROJECT_RUNTIME_ROLE=${role}\nDATABASE_URL=${url.toString()}\nPUBLIC_REGISTRATION_ENABLED=false\nSCAN_TARGET_POLICY=public\nAI_ENABLED=false\nDEFAULT_LOCALE=ko\n`);
 }finally{await file.close();}
 await c.query('COMMIT');committed=true;
 console.log('Production runtime role created. Credentials written only to the ignored local output file; no secrets printed.');
}catch(error){
 await c.query('ROLLBACK');if(createdFile&&!committed)await unlink(output);
 console.error('Production setup failed; existing roles and environment files were preserved.');process.exitCode=1;
}finally{c.release();await pool.end();}
