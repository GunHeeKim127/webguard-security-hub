import {client,defaultClientConfig,type Client} from '@prisma/ppg';
import {types,type QueryResult,type QueryResultRow} from 'pg';

/** parameter: 지원 DB 매개변수를 전송 가능한 형식으로 변환합니다 주요 호출: isArray·join·map. */ function parameter(value:unknown,depth=0):unknown{
 if(depth>16)throw new Error('Database parameter nesting exceeded');
 if(Array.isArray(value))return '{'+value.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: replace·String·parameter. */ v=>v===null||v===undefined?'NULL':'"'+String(parameter(v,depth+1)).replace(/\\/g,'\\\\').replace(/"/g,'\\"')+'"').join(',')+'}';
 if(value instanceof Uint8Array)throw new Error('Binary database parameters unsupported');
 if(value&&typeof value==='object'&&!(value instanceof Date))return JSON.stringify(value);
 return value;
}
/** coalescedReadProbe: 동시 읽기 복구 확인을 합쳐 중복 작업을 줄입니다 */ export function coalescedReadProbe(driver:Pick<Client,'query'>){
 let pending:Promise<void>|undefined;
 return /** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: finally. */ ()=>pending??(pending=(/** (async()=>{const started=performance.now(),result=await driver.query('SELECT 1 AS webguard_read_probe');await result.rows.collect();console.warn('[WebGuard managed HTTPS recovery]',{outcome:'completed',elapsedMs:Math.round(performance.now()-started)});}) 콜백: (async()=>{const started=performance.now(),result=await driver.query('SELECT 1 AS webguard_read_probe');await result.rows.collect();console.warn('[WebGuard manag */ async()=>{const started=performance.now(),result=await driver.query('SELECT 1 AS webguard_read_probe');await result.rows.collect();console.warn('[WebGuard managed HTTPS recovery]',{outcome:'completed',elapsedMs:Math.round(performance.now()-started)});})().finally(/** finally 콜백: 비동기 작업 후 정리를 실행합니다 */ ()=>{pending=undefined;}));
}
/** httpQueryAdapter: HTTP 조회 인터페이스를 공통 DB 조회 계약으로 연결합니다 */ export function httpQueryAdapter(driver:Pick<Client,'query'|'exec'>,onPending:(task:Promise<unknown>)=>void=/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},recover?:(()=>Promise<void>),recoveryDelayMs=2000){
 return {/** query: 요청한 자료나 현재 상태를 조회합니다 주요 호출: now·replace·map. */ async query<R extends QueryResultRow=any>(text:string,values:unknown[]=[],timeoutMs=5000):Promise<QueryResult<R>>{
  const started=performance.now();
  const structure=text.replace(/'(?:''|[^'])*'/g,"''"),returnsRows=/^\s*(SELECT|WITH)\b/i.test(structure)||/\bRETURNING\b/i.test(structure);
  const args=values.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: parameter. */ v=>parameter(v));
  const task=(/** (async():Promise<QueryResult<R>>=>{    if(!returnsRows){const n=await driver.exec(text,...args);return {rows:[],rowCount:n,command:text.trim().split(/\s/,1)[0].toUpperCase(),oid:0,fields:[]};}    const result=await driver.query(text,...args),data=await result.rows.collect();    const rows=data.map(row=>Object.fromEntries(result.columns.map((col,i)=>[col.name,row.values[i]])) as R);    return {rows,rowCount:rows.lengt */ async():Promise<QueryResult<R>>=>{
   if(!returnsRows){const n=await driver.exec(text,...args);return {rows:[],rowCount:n,command:text.trim().split(/\s/,1)[0].toUpperCase(),oid:0,fields:[]};}
   const result=await driver.query(text,...args),data=await result.rows.collect();
   const rows=data.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: fromEntries·map. */ row=>Object.fromEntries(result.columns.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ (col,i)=>[col.name,row.values[i]])) as R);
   return {rows,rowCount:rows.length,command:'SELECT',oid:0,fields:result.columns.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ col=>({name:col.name,dataTypeID:col.oid,tableID:0,columnID:0,dataTypeSize:-1,dataTypeModifier:-1,format:'text'}))};
  })();
  // The SDK has no cancellation API. A deadline bounds the caller's wait only;
  // keep the original operation draining and never retry an ambiguous write.
  let timer:ReturnType<typeof setTimeout>|undefined,recoveryTimer:ReturnType<typeof setTimeout>|undefined;
  if(recover)recoveryTimer=setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: catch·recover·onPending. */ ()=>{const recovery=recover().catch(/** catch 콜백: 비동기 실패를 후속 처리합니다 주요 호출: warn. */ ()=>{console.warn('[WebGuard managed HTTPS recovery]',{outcome:'failed'});});try{onPending(recovery);}catch{}},recoveryDelayMs);
  try{return await Promise.race([task,new Promise<never>(/** race 콜백: race에서 전달한 값을 처리하는 콜백입니다 주요 호출: setTimeout. */ (_,reject)=>{timer=setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: then·onPending·reject. */ ()=>{const pending=task.then(/** then 콜백: 앞선 비동기 결과를 후속 처리합니다 주요 호출: warn·round·now. */ ()=>{console.warn('[WebGuard managed HTTPS settlement]',{outcome:'completed',elapsedMs:Math.round(performance.now()-started),deadlineMs:timeoutMs});},/** then 콜백: 앞선 비동기 결과를 후속 처리합니다 주요 호출: warn·round·now. */ ()=>{console.warn('[WebGuard managed HTTPS settlement]',{outcome:'failed',elapsedMs:Math.round(performance.now()-started),deadlineMs:timeoutMs});});try{onPending(pending);}catch{}reject(new Error('Query read timeout'));},timeoutMs);})]);}
  finally{clearTimeout(timer);clearTimeout(recoveryTimer);}
 }};
}
/** managedHttpConfig: 관리형 DB의 HTTP 연결 구성을 검증합니다 주요 호출: includes·defaultClientConfig·toString. */ export function managedHttpConfig(connectionString:string){
 const url=new URL(connectionString);
 if(!['postgres:','postgresql:'].includes(url.protocol)||!['pooled.db.prisma.io','db.prisma.io'].includes(url.hostname)||!url.username||!url.password)throw new Error('Invalid managed HTTP database configuration');
 // The SDK derives its HTTPS endpoint from this hostname. pooled.db is the
 // TCP pooler, not its documented HTTP endpoint. Prisma documents the same
 // credentials for both hosts; retain them and target the official HTTP host.
 // This never opens a direct TCP connection or uses a migration credential.
 url.hostname='db.prisma.io';
 return defaultClientConfig(url.toString());
}
/** prismaHttp: 관리형 DB의 HTTP 조회 실행기를 구성합니다 주요 호출: managedHttpConfig·map·client. */ export function prismaHttp(connectionString:string,onPending?:(task:Promise<unknown>)=>void){
 const config=managedHttpConfig(connectionString);
 // Match node-postgres: int8 remains a string and timestamps serialize as ISO.
 config.parsers=[16,20,21,23,700,701,25,1043,114,3802,1082,1114,1184,1700].map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ oid=>({oid,parse:/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: getTypeParser. */ (value:string|null)=>value===null?null:types.getTypeParser(oid,'text')(value)}));
 const driver=client(config);
 // Preserve the original operation while issuing at most one coalesced,
 // fixed read probe for a slow provider response. Never replay app SQL.
 return httpQueryAdapter(driver,onPending,coalescedReadProbe(driver));
}
