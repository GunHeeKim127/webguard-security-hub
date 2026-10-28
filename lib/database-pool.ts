import {Pool,Client,type PoolClient,type QueryResultRow} from 'pg';
import {attachDatabasePool} from '@vercel/functions';
import {runtimePoolConfig} from './runtime-pool-config';
import {databaseProvider} from './database-provider';
import {assertManagedRuntimeSql} from './runtime-sql';
import {protectionQuery} from './protection-query';
import {freshConnector,leaseQuery} from './fresh-pool';
import {providerPreflight} from './provider-preflight';
const shared=globalThis as unknown as {wgPool?:Pool;wgFresh?:Pick<Pool,'connect'>};
function pool(){
 if(!shared.wgPool){
  const config=runtimePoolConfig();
  const created=new Pool({...config,...(databaseProvider()==='prisma-postgres'&&process.env.VERCEL==='1'?{
   verify:(client:PoolClient,done:(error?:Error)=>void)=>{
    providerPreflight(client,()=>{
     const secondary=new Client({...config,connectionTimeoutMillis:3000,query_timeout:2000});let ended=false;
     secondary.on('error',()=>{});
     const close=async()=>{if(!ended){ended=true;await secondary.end();}};
     return {run:async()=>{try{await secondary.connect();if(!ended)await secondary.query('SELECT 1');}finally{await close();}},close};
    }).then(()=>done(),error=>done(error instanceof Error?error:new Error('Database connection preflight failed')));
   }
  }: {})});
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
