import { Pool } from 'pg';
import { readdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { projectDatabase } from '../lib/project-database';
const pool=new Pool(projectDatabase('migration'));
const c=await pool.connect();
try {
 await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(784293)');
 await c.query('CREATE TABLE IF NOT EXISTS schema_migrations(name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
 for(const name of (await readdir('sql/migrations')).filter(x=>/^\d+.*\.sql$/.test(x)).sort()){
 const sql=await readFile('sql/migrations/'+name,'utf8'), checksum=createHash('sha256').update(sql).digest('hex');
 const old=await c.query('SELECT checksum FROM schema_migrations WHERE name=$1',[name]);
 if(old.rowCount){if(old.rows[0].checksum!==checksum)throw new Error('Applied migration changed: '+name);continue;}
 await c.query(sql);await c.query('INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)',[name,checksum]);console.log('Applied',name);
 }await c.query('COMMIT');
}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();await pool.end();}
