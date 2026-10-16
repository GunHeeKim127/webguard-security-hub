import {approvedHosts,targetPolicy} from '../../../lib/scan-policy';
import {saveScan} from '../../../lib/scan-store';
import {db} from '../../../lib/db';
import {scan} from '../../../lib/scanner';
import type {ScanEvent,Stage} from '../../../lib/scan-run';
import {errorCode} from '../../../lib/errors-i18n';
import {body,sameOrigin,requireUser,limit,event,failure,HttpError} from '../../../lib/security';
export const runtime='nodejs';
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser(['admin','analyst']);await limit('scan:'+user.id,5,60);
 const data=await body(req);if(typeof data.url!=='string'||!data.url.trim()||data.url.length>300||data.authorized!==true)throw new HttpError(400,'Owned target and authorization confirmation required');
 const url=data.url,hosts=targetPolicy()==='approved'?approvedHosts():undefined;
 async function run(progress:(stage:Stage,state:'running'|'success')=>void,signal:AbortSignal){
  if(hosts&&!hosts.length)throw new HttpError(409,'No approved targets configured');
  let result;try{result=await scan(url,hosts,progress,signal);}catch{if(!signal.aborted)await event('scan_rejected');throw new HttpError(400,'Target rejected or unreachable. Check allowlist, public DNS and TLS.');}
  if(signal.aborted)throw new Error('Scan cancelled');
  progress('store','running');const id=await saveScan((sql,values)=>db.query(sql,values),user.id,new URL(url).hostname,result);
  progress('store','success');return {id,result};
 }
 if(!req.headers.get('accept')?.includes('application/x-ndjson'))return Response.json(await run(()=>{},req.signal));
 const abort=new AbortController();const cancel=()=>abort.abort();req.signal.addEventListener('abort',cancel,{once:true});if(req.signal.aborted)cancel();
 const encoder=new TextEncoder();let closed=false;
 const stream=new ReadableStream<Uint8Array>({
  async start(controller){
   const emit=(value:ScanEvent)=>{if(!closed&&!abort.signal.aborted)controller.enqueue(encoder.encode(JSON.stringify(value)+'\n'));};
   try{const result=await run((stage,state)=>emit({type:'progress',stage,state,at:new Date().toISOString()}),abort.signal);emit({type:'result',...result,at:new Date().toISOString()});}
   catch(error){emit({type:'error',errorCode:errorCode(error instanceof HttpError?error.message:'',error instanceof HttpError?error.status:503),at:new Date().toISOString()});}
   finally{req.signal.removeEventListener('abort',cancel);if(!closed){closed=true;controller.close();}}
  },cancel(){closed=true;cancel();req.signal.removeEventListener('abort',cancel);}
 });
 return new Response(stream,{headers:{'Content-Type':'application/x-ndjson; charset=utf-8','Cache-Control':'no-store, no-transform','X-Accel-Buffering':'no'}});
 }catch(error){return failure(error,req);}}
