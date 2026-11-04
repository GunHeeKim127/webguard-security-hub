import {randomUUID} from 'node:crypto';
import {db} from '../../../lib/db';
import {body,sameOrigin,requireUser,limit,failure,HttpError} from '../../../lib/security';
import {remediationInput,remediationBaseline} from '../../../lib/assessment/remediation';
export const runtime='nodejs';
export const dynamic='force-dynamic';
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
/** GET: 현재 회원의 활성 자산에 속한 조치와 최근 변경 이력만 조회합니다. */
export async function GET(req:Request){try{
 const user=await requireUser(),params=new URL(req.url).searchParams,assetId=params.get('assetId');
 if(!assetId||!uuid.test(assetId)||params.getAll('assetId').length!==1||[...params.keys()].some(/** some: 알 수 없는 조회 조건을 거절합니다. */ k=>k!=='assetId'))throw new HttpError(400,'Invalid scan ID');
 await limit('remediation-read:'+user.id,120,60);
 const asset=await db.query("SELECT id FROM public.assessment_assets WHERE id=$1 AND user_id=$2 AND updated_at>=now()-interval '30 days'",[assetId,user.id]);if(!asset.rowCount)throw new HttpError(404,'Scan not found');
 const [rows,history]=await Promise.all([
  db.query("SELECT id,asset_id,run_id,finding_id,state,owner_label,note,version,baseline,created_at,updated_at FROM public.assessment_remediations WHERE user_id=$1 AND asset_id=$2 AND updated_at>=now()-interval '30 days' ORDER BY updated_at DESC LIMIT 500",[user.id,assetId]),
  db.query("SELECT id,remediation_id,snapshot,created_at FROM public.assessment_remediation_events WHERE user_id=$1 AND asset_id=$2 AND created_at>=now()-interval '30 days' ORDER BY created_at DESC,id DESC LIMIT 20",[user.id,assetId])
 ]);
 return Response.json({items:rows.rows,history:history.rows},{headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
/** POST: 계정별 실제 검사 항목을 검증하고 버전 충돌 없이 조치·감사 이력을 한 번에 저장합니다. */
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser();await limit('remediation-write:'+user.id,30,60);
 let input;try{input=remediationInput(await body(req,8192));}catch{throw new HttpError(400,'Invalid assessment input');}
 const result=await db.query("SELECT r.report FROM public.assessment_runs r JOIN public.assessment_assets a ON a.id=r.asset_id AND a.user_id=r.user_id WHERE r.id=$1 AND r.asset_id=$2 AND r.user_id=$3 AND r.created_at>=now()-interval '30 days' AND a.updated_at>=now()-interval '30 days'",[input.runId,input.assetId,user.id]);
 if(!result.rowCount)throw new HttpError(404,'Scan not found');
 let baseline;try{baseline=remediationBaseline(result.rows[0].report,input.findingId);}catch{throw new HttpError(400,'Invalid assessment input');}
 const changed=await db.query(`WITH saved AS (
 INSERT INTO public.assessment_remediations(id,user_id,asset_id,run_id,finding_id,state,owner_label,note,version,baseline)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,1,$9::jsonb WHERE $10::integer=0
 ON CONFLICT(user_id,asset_id,finding_id) DO NOTHING RETURNING id,version
 ), edited AS (
 UPDATE public.assessment_remediations SET state=$6,owner_label=$7,note=$8,version=version+1,updated_at=clock_timestamp()
 WHERE user_id=$2 AND asset_id=$3 AND finding_id=$5 AND version=$10::integer AND $10::integer>0 RETURNING id,version
 ), changes AS (SELECT id,version FROM saved UNION ALL SELECT id,version FROM edited), audited AS (
 INSERT INTO public.assessment_remediation_events(id,user_id,asset_id,remediation_id,snapshot)
 SELECT $11,$2,$3,changes.id,jsonb_build_object('findingId',$5::text,'state',$6::text,'ownerLabel',$7::text,'note',$8::text,'version',changes.version) FROM changes RETURNING id
 ) SELECT changes.id,changes.version FROM changes CROSS JOIN audited`,[randomUUID(),user.id,input.assetId,input.runId,input.findingId,input.state,input.ownerLabel,input.note,JSON.stringify(baseline),input.version,randomUUID()]);
 if(!changed.rowCount)return Response.json({errorCode:'REMEDIATION_CONFLICT'},{status:409,headers:{'Cache-Control':'no-store'}});
 return Response.json(changed.rows[0],{headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
