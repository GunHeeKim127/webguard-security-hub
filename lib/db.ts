import 'server-only';
import { Pool, type QueryResultRow } from 'pg';
import { projectDatabase } from './project-database';
const globalDb = globalThis as unknown as { wgPool?: Pool };
let localPool:Pool|undefined;
function pool(){
 if(!localPool){localPool=globalDb.wgPool??new Pool({...projectDatabase('runtime'),max:5,connectionTimeoutMillis:3000,statement_timeout:5000});if(process.env.NODE_ENV!=='production')globalDb.wgPool=localPool;}
 return localPool;
}
// Validate on first DB operation so an unconfigured project can still build/show login.
export const db={query:<R extends QueryResultRow=any>(text:string,values?:unknown[])=>pool().query<R>(text,values)};
