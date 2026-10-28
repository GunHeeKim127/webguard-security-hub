import {Pool,type QueryResultRow} from 'pg';
import {attachDatabasePool} from '@vercel/functions';
import {runtimePoolConfig} from './runtime-pool-config';
import {databaseProvider} from './database-provider';
import {assertManagedRuntimeSql} from './runtime-sql';
import {protectionQuery} from './protection-query';
import {freshConnector,leaseQuery} from './fresh-pool';
const shared=globalThis as unknown as {wgPool?:Pool;wgFresh?:Pick<Pool,'connect'>};
function pool(){
 if(!shared.wgPool){
  const created=new Pool(runtimePoolConfig());
  created.on('error',()=>console.error('PostgreSQL idle connection closed'));
  if(process.env.VERCEL==='1')attachDatabasePool(created);
  shared.wgPool=created;
  shared.wgFresh=freshConnector(created);
 }
 return shared.wgPool;
}
function connector(){const active=pool();return shared.wgFresh??(shared.wgFresh=freshConnector(active));}
export const database={
 query:<R extends QueryResultRow=any>(text:string,values?:unknown[])=>{if(databaseProvider()==='prisma-postgres')assertManagedRuntimeSql(text);return leaseQuery<R>(connector(),text,values);},
 protectionQuery:(text:string,values:unknown[])=>{const managed=databaseProvider()==='prisma-postgres';if(managed)assertManagedRuntimeSql(text);return protectionQuery(connector(),text,values,managed);}
};
