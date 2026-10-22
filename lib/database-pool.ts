import {Pool,type QueryResultRow} from 'pg';
import {attachDatabasePool} from '@vercel/functions';
import {runtimePoolConfig} from './runtime-pool-config';
import {databaseProvider} from './database-provider';
import {assertManagedRuntimeSql} from './runtime-sql';
import {protectionQuery} from './protection-query';
const shared=globalThis as unknown as {wgPool?:Pool};
function pool(){
 if(!shared.wgPool){
  const created=new Pool(runtimePoolConfig());
  created.on('error',()=>console.error('PostgreSQL idle connection closed'));
  if(process.env.VERCEL==='1')attachDatabasePool(created);
  shared.wgPool=created;
 }
 return shared.wgPool;
}
export const database={
 query:<R extends QueryResultRow=any>(text:string,values?:unknown[])=>{if(databaseProvider()==='prisma-postgres')assertManagedRuntimeSql(text);return pool().query<R>(text,values);},
 protectionQuery:(text:string,values:unknown[])=>{const managed=databaseProvider()==='prisma-postgres';if(managed)assertManagedRuntimeSql(text);return protectionQuery(pool(),text,values,managed);}
};
