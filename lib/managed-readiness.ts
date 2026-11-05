import {randomUUID} from 'node:crypto';
import {types} from 'pg';
import {assertReadinessSql} from './runtime-sql';

/** readinessFailure: 제공자 원문·접속키 없이 고정 오류와 필요한 SQLSTATE만 전달합니다. */
function readinessFailure(code='08006'){return Object.assign(new Error('Readiness transport failed'),{code});}
/** managedReadinessQuery: 고정 SELECT만 취소 가능한 HTTPS 요청으로 실행합니다. 프로토콜은 고정한 @prisma/ppg 1.0.1의 HTTP 전송과 대조합니다. */
export async function managedReadinessQuery(connectionString:string,sql:string,signal?:AbortSignal,send:typeof fetch=fetch,timeoutMs=8000){
 assertReadinessSql(sql);
 const source=new URL(connectionString);
 if(!['postgres:','postgresql:'].includes(source.protocol)||source.hostname!=='pooled.db.prisma.io'||!source.username||!source.password)throw readinessFailure();
 const endpoint=new URL('https://db.prisma.io/v0/statement');endpoint.searchParams.set('db',source.pathname.slice(1));
 const boundary='WebGuard'+randomUUID(),descriptor='urn:prisma:query:descriptor';
 const body=`--${boundary}\r\nContent-Disposition: form-data; name="${descriptor}"\r\nContent-Type: application/json; profile="${descriptor}"\r\n\r\n${JSON.stringify({query:sql})}\r\n--${boundary}--\r\n`;
 const controller=new AbortController(),abort=/** abort: 상위 준비 검사 종료 시 헤더·본문 대기도 중단합니다. */ ()=>controller.abort();
 signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 const timer=setTimeout(abort,timeoutMs);let reader:ReadableStreamDefaultReader<Uint8Array>|undefined,responseReceived=false;
 try{
  const response=await send(endpoint,{method:'POST',headers:{Authorization:'Basic '+Buffer.from(source.username+':'+source.password).toString('base64'),'Content-Type':`multipart/form-data; profile="urn:prisma:query"; boundary=${boundary}`},body,signal:controller.signal,redirect:'error',cache:'no-store'});
  responseReceived=true;
  if(!response.ok){await response.body?.cancel();throw readinessFailure([401,403].includes(response.status)?'42501':response.status>=500||response.status===429?'08006':'WG_PROTOCOL');}
  if(!response.body||!response.headers.get('content-type')?.includes('application/x-ndjson'))throw readinessFailure('WG_PROTOCOL');
  reader=response.body.getReader();const decoder=new TextDecoder('utf-8',{fatal:true});let buffer='',bytes=0,complete=false;
  let columns:Array<{name:string;typeOid:number}>=[];const rows:Record<string,unknown>[]=[];
  const frame=/** frame: 준비 조회 응답의 열·행·완료 경계를 검증하고 제한된 자료만 디코딩합니다. */ (line:string)=>{
   if(!line.trim())return;if(complete)throw readinessFailure('WG_PROTOCOL');
   const value=JSON.parse(line);
   if(value.error){throw readinessFailure(typeof value.error.code==='string'&&/^[0-9A-Z]{5}$/.test(value.error.code)?value.error.code:'WG_PROTOCOL');}
   if(Array.isArray(value.columns)){
    if(columns.length||rows.length||value.columns.length>64||value.columns.some(/** some: 열 이름·타입이 잘못된 응답은 거절합니다. */ (col:{name?:unknown;typeOid?:unknown})=>typeof col.name!=='string'||!Number.isInteger(col.typeOid)))throw readinessFailure('WG_PROTOCOL');
    columns=value.columns;if(new Set(columns.map(/** map: 중복 열 이름을 대조합니다. */ col=>col.name)).size!==columns.length)throw readinessFailure('WG_PROTOCOL');
   }else if(Array.isArray(value.values)){
    if(!columns.length||value.values.length!==columns.length||rows.length>=64)throw readinessFailure('WG_PROTOCOL');
    rows.push(Object.fromEntries(columns.map(/** map: PostgreSQL 타입 해석을 기존 pg 드라이버와 맞춥니다. */ (col,index)=>{const raw=value.values[index];if(raw!==null&&typeof raw!=='string')throw readinessFailure('WG_PROTOCOL');return [col.name,raw===null?null:types.getTypeParser(col.typeOid,'text')(raw)];})));
   }else if(value.complete===true)complete=true;
   else throw readinessFailure('WG_PROTOCOL');
  };
  while(!complete){const part=await reader.read();if(part.done){buffer+=decoder.decode();if(buffer.trim())frame(buffer);break;}
   bytes+=part.value.byteLength;if(bytes>262144)throw readinessFailure('WG_PROTOCOL');buffer+=decoder.decode(part.value,{stream:true});
   let end;while((end=buffer.indexOf('\n'))>=0){frame(buffer.slice(0,end));buffer=buffer.slice(end+1);}
  }
  if(!complete||!columns.length)throw readinessFailure('WG_PROTOCOL');
  return {rows,rowCount:rows.length};
 }catch(error){
  if(controller.signal.aborted)throw new Error('Query read timeout');
  if(error&&typeof error==='object'&&'code' in error&&typeof error.code==='string'&&/^(?:[0-9A-Z]{5}|WG_PROTOCOL)$/.test(error.code))throw readinessFailure(error.code);
  throw readinessFailure(responseReceived?'WG_PROTOCOL':'08006');
 }finally{
  clearTimeout(timer);signal?.removeEventListener('abort',abort);controller.abort();
  if(reader){await reader.cancel().catch(/** catch: 취소 후 닫힌 응답의 정리 오류는 원래 실패를 가리지 않습니다. */ ()=>{});reader.releaseLock();}
 }
}

/** managedReadiness: 느린 준비 조회에만 고정 SELECT 1 연결 확인을 한 번 보내고 두 요청을 모두 정리합니다. 원래 문장 재전송이나 백그라운드 작업은 만들지 않습니다. */
export async function managedReadiness(connectionString:string,sql:string,signal?:AbortSignal,send:typeof fetch=fetch,probeDelayMs=2000,timeoutMs=8000){
 const controller=new AbortController(),abort=/** abort: 전체 준비 검사 취소를 원래 요청과 고정 연결 확인에 함께 전달합니다. */ ()=>controller.abort();
 signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 let pending:Promise<unknown>|undefined;
 const timer=setTimeout(/** probe: 느린 읽기마다 고정된 연결 확인만 한 번 실행합니다. */ ()=>{
  pending=managedReadinessQuery(connectionString,'SELECT 1 AS webguard_read_probe',controller.signal,send,timeoutMs).catch(/** catch: 연결 확인 실패로 원래 조회의 권한·결과를 바꾸지 않습니다. */ ()=>null);
 },probeDelayMs);
 try{return await managedReadinessQuery(connectionString,sql,controller.signal,send,timeoutMs);}
 finally{clearTimeout(timer);controller.abort();signal?.removeEventListener('abort',abort);await pending;}
}
