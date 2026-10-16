import {Pool,type QueryResultRow} from 'pg';
import {attachDatabasePool} from '@vercel/functions';
import {projectDatabase} from './project-database';
import {databaseProvider} from './database-provider';
import {assertManagedRuntimeSql} from './runtime-sql';
const shared=globalThis as unknown as {wgPool?:Pool};
function pool(){
 if(!shared.wgPool){
  // Prisma's pooler rejects statement_timeout in PostgreSQL startup parameters.
  // query_timeout bounds the client's wait; it does not cancel a server-side query.
  const timeout=databaseProvider()==='prisma-postgres'?{query_timeout:5000}:{statement_timeout:5000};
  const created=new Pool({...projectDatabase('runtime'),...timeout,max:process.env.VERCEL==='1'?2:5,connectionTimeoutMillis:5000,idleTimeoutMillis:5000,allowExitOnIdle:true});
  created.on('error',()=>console.error('PostgreSQL idle connection closed'));
  if(process.env.VERCEL==='1')attachDatabasePool(created);
  shared.wgPool=created;
 }
 return shared.wgPool;
}
export const database={query:<R extends QueryResultRow=any>(text:string,values?:unknown[])=>{if(databaseProvider()==='prisma-postgres')assertManagedRuntimeSql(text);return pool().query<R>(text,values);}};
