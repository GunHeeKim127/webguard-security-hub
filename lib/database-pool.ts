import 'server-only';
import {Pool,type QueryResultRow} from 'pg';
import {attachDatabasePool,waitUntil} from '@vercel/functions';
import {runtimePoolConfig} from './runtime-pool-config';
import {databaseProvider} from './database-provider';
import {assertManagedRuntimeSql} from './runtime-sql';
import {protectionQuery,PROTECTION_READ_TIMEOUT_MS} from './protection-query';
import {freshConnector,leaseQuery} from './fresh-pool';
import {prismaHttp} from './prisma-http';
import {projectDatabase} from './project-database';
import {ACTIVE_BLOCK_SQL} from './ingress-guard';
const shared=globalThis as unknown as {wgPool?:Pool;wgFresh?:Pick<Pool,'connect'>;wgHttp?:ReturnType<typeof prismaHttp>};
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
function http(){return shared.wgHttp??(shared.wgHttp=prismaHttp(projectDatabase('runtime').connectionString,task=>waitUntil(task.then(()=>{},()=>{}))));}
const useHttp=()=>databaseProvider()==='prisma-postgres'&&process.env.VERCEL==='1';
export const database={
 query:<R extends QueryResultRow=any>(text:string,values?:unknown[])=>{assertManagedRuntimeSql(text);return useHttp()?http().query<R>(text,values):leaseQuery<R>(connector(),text,values);},
 protectionQuery:(text:string,values:unknown[])=>{const managed=databaseProvider()==='prisma-postgres';assertManagedRuntimeSql(text);return useHttp()?http().query(text,values,text===ACTIVE_BLOCK_SQL?PROTECTION_READ_TIMEOUT_MS:5000):protectionQuery(connector(),text,values,managed);}
};
