import 'server-only';
import {Pool,type QueryResultRow} from 'pg';
import {attachDatabasePool,waitUntil} from '@vercel/functions';
import {runtimePoolConfig} from './runtime-pool-config';
import {databaseProvider} from './database-provider';
import {assertManagedRuntimeSql,assertRuntimeParameters,assertReadinessSql} from './runtime-sql';
import {protectionQuery,PROTECTION_READ_TIMEOUT_MS} from './protection-query';
import {freshConnector,leaseQuery} from './fresh-pool';
import {prismaHttp} from './prisma-http';
import {projectDatabase} from './project-database';
import {ACTIVE_BLOCK_SQL} from './ingress-guard';
import {managedReadiness} from './managed-readiness';
const shared=globalThis as unknown as {wgPool?:Pool;wgFresh?:Pick<Pool,'connect'>;wgHttp?:ReturnType<typeof prismaHttp>};
/** pool: 프로젝트 DB 연결 풀을 준비하거나 재사용합니다 주요 호출: runtimePoolConfig·on·attachDatabasePool. */ function pool(){
 if(!shared.wgPool){
  const created=new Pool(runtimePoolConfig());
  created.on('error',/** on 콜백: on에서 전달한 값을 처리하는 콜백입니다 주요 호출: error. */ ()=>console.error('PostgreSQL idle connection closed'));
  if(process.env.VERCEL==='1')attachDatabasePool(created);
  shared.wgPool=created;
  shared.wgFresh=freshConnector(created);
 }
 return shared.wgPool;
}
/** connector: 현재 제공자에 맞는 DB 연결 인터페이스를 선택합니다 주요 호출: pool·freshConnector. */ function connector(){const active=pool();return shared.wgFresh??(shared.wgFresh=freshConnector(active));}
/** http: 관리형 HTTP 방식의 DB 조회 인터페이스를 준비합니다 주요 호출: prismaHttp·projectDatabase. */ function http(){return shared.wgHttp??(shared.wgHttp=prismaHttp(projectDatabase('runtime').connectionString,/** prismaHttp 콜백: prismaHttp에서 전달한 값을 처리하는 콜백입니다 주요 호출: waitUntil·then. */ task=>waitUntil(task.then(/** then 콜백: 앞선 비동기 결과를 후속 처리합니다 */ ()=>{},/** then 콜백: 앞선 비동기 결과를 후속 처리합니다 */ ()=>{}))));}
const useHttp=/** useHttp: 현재 환경에서 HTTP DB 연결을 사용할지 확인합니다 주요 호출: databaseProvider. */ ()=>databaseProvider()==='prisma-postgres'&&process.env.VERCEL==='1';
export const database={
 readinessQuery:/** readinessQuery: 관리형 준비 조회는 취소 가능한 HTTPS를 사용하며 일반 PostgreSQL은 검증된 연결을 유지합니다. */ (text:string,signal?:AbortSignal)=>{assertReadinessSql(text);return useHttp()?managedReadiness(projectDatabase('runtime').connectionString,text,signal):leaseQuery(connector(),text);},
 query:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: assertManagedRuntimeSql·useHttp·query. */ <R extends QueryResultRow=any>(text:string,values?:unknown[])=>{assertManagedRuntimeSql(text);assertRuntimeParameters(text,values);return useHttp()?http().query<R>(text,values):leaseQuery<R>(connector(),text,values);},
 protectionQuery:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: databaseProvider·assertManagedRuntimeSql·useHttp. */ (text:string,values:unknown[])=>{const managed=databaseProvider()==='prisma-postgres';assertManagedRuntimeSql(text);assertRuntimeParameters(text,values);return useHttp()?http().query(text,values,text===ACTIVE_BLOCK_SQL?PROTECTION_READ_TIMEOUT_MS:5000):protectionQuery(connector(),text,values,managed);}
};
