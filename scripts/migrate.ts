import { Pool } from 'pg';
import { readdir, readFile } from 'node:fs/promises';
import {migrationChecksums} from './support/migration-checksum';
import { projectDatabase } from '../lib/project-database';
import {databaseProvider} from '../lib/database-provider';
const profile=databaseProvider()==='prisma-postgres'?'prisma-postgres/':'';
const directory='sql/migrations/'+profile;
const pool=new Pool(projectDatabase('migration'));
const c=await pool.connect();
try {
 await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(784293)');
 await c.query('CREATE TABLE IF NOT EXISTS schema_migrations(name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
 const applied=(await c.query('SELECT name FROM schema_migrations')).rows;
 if(applied.some(row=>String(row.name).startsWith('prisma-postgres/')!==!!profile))throw new Error('Migration provider differs from existing schema; refusing mixed profiles');
 for(const file of (await readdir(directory)).filter(x=>/^\d+.*\.sql$/.test(x)).sort()){
 const name=profile+file;
 const sql=await readFile(directory+file,'utf8'), checksums=migrationChecksums(sql),checksum=checksums.canonical;
 const old=await c.query('SELECT checksum FROM schema_migrations WHERE name=$1',[name]);
 if(old.rowCount){if(!checksums.accepted.has(old.rows[0].checksum))throw new Error('Applied migration changed: '+name);continue;}
 await c.query(sql);await c.query('INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)',[name,checksum]);console.log('Applied',name);
 }await c.query('COMMIT');
}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();await pool.end();}
