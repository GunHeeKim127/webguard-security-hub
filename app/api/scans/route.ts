import {approvedHosts,targetPolicy} from '../../../lib/scan-policy';
import {saveScan} from '../../../lib/scan-store';
import {db} from '../../../lib/db';
import {scan,scanFailureReason} from '../../../lib/scanner';
import {scanFailureCode} from '../../../lib/scan-failure';
import type {ScanEvent,Stage} from '../../../lib/scan-run';
import {errorCode} from '../../../lib/errors-i18n';
import {body,sameOrigin,requireUser,limit,event,failure,HttpError} from '../../../lib/security';
import {authSourceBucket} from '../../../lib/auth-rate-identity';
export const runtime='nodejs';
export const maxDuration=30;
/** POST: 권한 있는 웹 점검 요청을 스트림 작업으로 실행합니다。 */ export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser();await limit('scan:'+user.id,5,60);
 await limit(authSourceBucket('assessment',req),60,60);await limit('assessment:global',300,60);
 const data=await body(req);if(typeof data.url!=='string'||!data.url.trim()||data.url.length>300||data.authorized!==true)throw new HttpError(400,'Owned target and authorization confirmation required');
 const url=data.url,hosts=targetPolicy()==='approved'?approvedHosts():undefined;
 /** run: 현재 작업의 비동기 실행과 완료 처리를 담당합니다 주요 호출: any·timeout·scan. */ async function run(progress:(stage:Stage,state:'running'|'success')=>void,signal:AbortSignal){
  if(hosts&&!hosts.length)throw new HttpError(409,'No approved targets configured');
  const targetSignal=AbortSignal.any([signal,AbortSignal.timeout(20000)]);
  let result;try{result=await scan(url,hosts,progress,targetSignal);}catch(error){console.warn('[WebGuard target rejected]',{reason:scanFailureReason(error,targetSignal)});if(!signal.aborted)await event('scan_rejected',user.id);throw new HttpError(400,scanFailureCode(error,targetSignal));}
  targetSignal.throwIfAborted();
  progress('store','running');const id=await saveScan(/** saveScan 콜백: saveScan에서 전달한 값을 처리하는 콜백입니다 주요 호출: query. */ (sql,values)=>db.query(sql,values),user.id,new URL(url).hostname,result);
  progress('store','success');return {id,result};
 }
 if(!req.headers.get('accept')?.includes('application/x-ndjson'))return Response.json(await run(/** run 콜백: run에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},req.signal));
 const abort=new AbortController();const cancel=/** cancel: 작업의 완료·실패·취소에 맞춰 관련 상태와 자원을 정리합니다 주요 호출: abort. */ ()=>abort.abort();req.signal.addEventListener('abort',cancel,{once:true});if(req.signal.aborted)cancel();
 const encoder=new TextEncoder();let closed=false;
 const stream=new ReadableStream<Uint8Array>({
  /** start: 스트림 또는 작업의 초기 실행을 시작합니다 주요 호출: run·emit·toISOString. */ async start(controller){
   const emit=/** emit: 전달된 자료를 결과·상태·출력에 반영합니다 주요 호출: enqueue·encode·stringify. */ (value:ScanEvent)=>{if(!closed&&!abort.signal.aborted)controller.enqueue(encoder.encode(JSON.stringify(value)+'\n'));};
   try{const result=await run(/** run 콜백: run에서 전달한 값을 처리하는 콜백입니다 주요 호출: emit·toISOString. */ (stage,state)=>emit({type:'progress',stage,state,at:new Date().toISOString()}),abort.signal);emit({type:'result',...result,at:new Date().toISOString()});}
   catch(error){emit({type:'error',errorCode:errorCode(error instanceof HttpError?error.message:'',error instanceof HttpError?error.status:503),at:new Date().toISOString()});}
   finally{req.signal.removeEventListener('abort',cancel);if(!closed){closed=true;controller.close();}}
  },/** cancel: 작업의 완료·실패·취소에 맞춰 관련 상태와 자원을 정리합니다 주요 호출: cancel·removeEventListener. */ cancel(){closed=true;cancel();req.signal.removeEventListener('abort',cancel);}
 });
 return new Response(stream,{headers:{'Content-Type':'application/x-ndjson; charset=utf-8','Cache-Control':'no-store, no-transform','X-Accel-Buffering':'no'}});
 }catch(error){return failure(error,req);}}
