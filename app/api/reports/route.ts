import {db} from '../../../lib/db';
import {requireUser,limit,HttpError,failure} from '../../../lib/security';
import {requestLocale} from '../../../lib/request-locale';
import {reportBundleText,reportBundleHtml} from '../../../lib/assessment/report-bundle';
export const runtime='nodejs';
export const dynamic='force-dynamic';
/** GET: 현재 계정의 자산·결과·조치만 보고서로 내려주고 원본이나 다른 계정은 포함하지 않습니다. */
export async function GET(req:Request){try{
 const user=await requireUser(),params=new URL(req.url).searchParams,assetId=params.get('assetId'),format=params.get('format')??'txt';
 if(!assetId||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(assetId)||!['txt','html'].includes(format)||[...params.keys()].some(/** some: 추가·중복 조회 필드를 거절합니다. */ key=>!['assetId','format'].includes(key)||params.getAll(key).length!==1))throw new HttpError(400,'Invalid scan ID');
 await limit('report-export:'+user.id,20,60);
 const asset=await db.query("SELECT id FROM public.assessment_assets WHERE user_id=$1 AND id=$2 AND updated_at>=now()-interval '30 days'",[user.id,assetId]);if(!asset.rowCount)throw new HttpError(404,'Scan not found');
 const [runs,actions]=await Promise.all([
  db.query("SELECT id,report,created_at FROM public.assessment_runs WHERE user_id=$1 AND asset_id=$2 AND created_at>=now()-interval '30 days' ORDER BY created_at DESC,id DESC LIMIT 10",[user.id,assetId]),
  db.query("SELECT id,asset_id,run_id,finding_id,state,owner_label,note,version,baseline,created_at,updated_at FROM public.assessment_remediations WHERE user_id=$1 AND asset_id=$2 AND updated_at>=now()-interval '30 days' ORDER BY updated_at DESC LIMIT 500",[user.id,assetId])
 ]);
 if(!runs.rowCount)throw new HttpError(404,'Scan not found');const locale=requestLocale(req.headers).locale==='ko'?'ko':'en',html=format==='html';
 const reportRuns=runs.rows.map(/** map: DB 시각을 JSON 응답과 동일한 ISO 문자열로 정규화합니다. */ row=>({...row,created_at:new Date(row.created_at).toISOString()}));
 return new Response(html?reportBundleHtml(reportRuns,actions.rows,locale):reportBundleText(reportRuns,actions.rows,locale),{headers:{'Content-Type':html?'text/html;charset=utf-8':'text/plain;charset=utf-8','Content-Disposition':`attachment; filename="velthara-report.${format}"`,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; sandbox"}});
 }catch(error){return failure(error,req);}}
