import {Pool,type QueryResultRow} from 'pg';
import {attachDatabasePool} from '@vercel/functions';
import {projectDatabase} from './project-database';
const shared=globalThis as unknown as {wgPool?:Pool};
function pool(){
 if(!shared.wgPool){
  const created=new Pool({...projectDatabase('runtime'),max:process.env.VERCEL==='1'?2:5,connectionTimeoutMillis:5000,statement_timeout:5000,idleTimeoutMillis:5000,allowExitOnIdle:true});
  created.on('error',()=>console.error('PostgreSQL idle connection closed'));
  if(process.env.VERCEL==='1')attachDatabasePool(created);
  shared.wgPool=created;
 }
 return shared.wgPool;
}
export const database={query:<R extends QueryResultRow=any>(text:string,values?:unknown[])=>pool().query<R>(text,values)};
