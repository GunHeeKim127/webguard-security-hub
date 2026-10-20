import {randomBytes} from 'node:crypto';
import {db} from '../../../lib/db';
import {body,sameOrigin,requireUser,limit,event,failure,HttpError} from '../../../lib/security';
import {requestLocale} from '../../../lib/request-locale';
import {tokenHash} from '../../../lib/password';
import {assessmentInput} from '../../../lib/assessment/input';
import {runAssessment,scannerCatalog} from '../../../lib/assessment/registry';
import {saveAssessment,trafficSignals} from '../../../lib/assessment/store';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const maxDuration=40;
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(v);
export async function GET(req:Request){try{
 const user=await requireUser(),id=new URL(req.url).searchParams.get('assetId');if(id&&!uuid(id))throw new HttpError(400,'Invalid scan ID');
 if(id&&!(await db.query('SELECT id FROM public.assessment_assets WHERE id=$1 AND user_id=$2',[id,user.id])).rowCount)throw new HttpError(404,'Scan not found');
 const [assets,runs,traffic,hub]=await Promise.all([
  db.query('SELECT id,module_id,target_key,label,created_at,updated_at FROM public.assessment_assets WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50',[user.id]),
  id?db.query('SELECT id,asset_id,report,created_at FROM public.assessment_runs WHERE asset_id=$1 AND user_id=$2 ORDER BY created_at DESC,id DESC LIMIT 10',[id,user.id]):Promise.resolve({rows:[]}),
  id?db.query("SELECT coalesce(sum(requests),0)::text requests,coalesce(sum(login_failures),0)::text login_failures,coalesce(sum(probes),0)::text probes,coalesce(sum(server_errors),0)::text server_errors FROM public.assessment_traffic WHERE user_id=$1 AND asset_id=$2 AND window_at>=date_trunc('minute',now())-interval '4 minutes'",[user.id,id]):Promise.resolve({rows:[{requests:0,login_failures:0,probes:0,server_errors:0}]}),
  db.query("SELECT category,count(*)::int count FROM public.events WHERE user_id=$1 AND created_at>now()-interval '5 minutes' GROUP BY category",[user.id]),
 ]);
 const counts=traffic.rows[0];return Response.json({user,modules:scannerCatalog,assets:assets.rows,runs:runs.rows,traffic:counts,signals:trafficSignals(counts),hubEvents:hub.rows},{headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser(['admin','analyst']);await limit('assessment:'+user.id,5,60);
 const data=await body(req,3*1024*1024);
 if(data.action==='rotateTelemetryToken'){
  if(!uuid(data.assetId)||Object.keys(data).some(k=>!['action','assetId'].includes(k)))throw new HttpError(400,'Invalid scan ID');
  const token=randomBytes(32).toString('hex');
  const asset=await db.query("UPDATE public.assessment_assets SET ingest_token_hash=$1 WHERE id=$2 AND user_id=$3 AND module_id='web.compare' RETURNING id",[tokenHash(token),data.assetId,user.id]);
  if(!asset.rowCount)throw new HttpError(404,'Scan not found');await event('telemetry_key_rotated',user.id);
  return Response.json({token,assetId:data.assetId},{headers:{'Cache-Control':'no-store'}});
 }
 let input;try{input=assessmentInput(data);}catch{throw new HttpError(400,'Invalid assessment input');}
 const locale=requestLocale(req.headers).locale==='ko'?'ko':'en';
 const signal=AbortSignal.any([req.signal,AbortSignal.timeout(20000)]);
 let report;try{report=await runAssessment(input,{signal,locale});}catch{await event('assessment_rejected',user.id);throw new HttpError(400,'Target rejected or unreachable. Check allowlist, public DNS and TLS.');}
 signal.throwIfAborted();
 const key=input.moduleId==='web.compare'?new URL(input.url!).hostname:input.label.toLowerCase();
 const saved=await saveAssessment((sql,values)=>db.query(sql,values),user.id,key,input.label,report);
 return Response.json({...saved,report},{headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
