import {db} from '../../../lib/db';
import {requireUser,limit,HttpError,failure} from '../../../lib/security';
import {requestLocale} from '../../../lib/request-locale';
import {reportBundleText,reportBundleHtml} from '../../../lib/assessment/report-bundle';
import {loadReportSnapshot} from '../../../lib/assessment/report-store';
export const runtime='nodejs';
export const dynamic='force-dynamic';
/** GET: 현재 계정의 자산·결과·조치만 보고서로 내려주고 원본이나 다른 계정은 포함하지 않습니다. */
export async function GET(req:Request){try{
 const user=await requireUser(),params=new URL(req.url).searchParams,assetId=params.get('assetId'),format=params.get('format')??'txt';
 if(!assetId||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(assetId)||!['txt','html'].includes(format)||[...params.keys()].some(/** some: 추가·중복 조회 필드를 거절합니다. */ key=>!['assetId','format'].includes(key)||params.getAll(key).length!==1))throw new HttpError(400,'Invalid scan ID');
 await limit('report-export:'+user.id,20,60);
 const snapshot=await loadReportSnapshot(/** loadReportSnapshot: 현재 사용자로 바인딩한 고정 읽기 문장만 실행합니다. */ (sql,values)=>db.query(sql,values),user.id,assetId);
 if(!snapshot)throw new HttpError(404,'Scan not found');const locale=requestLocale(req.headers).locale==='ko'?'ko':'en',html=format==='html';
 return new Response(html?reportBundleHtml(snapshot.runs,snapshot.actions,locale):reportBundleText(snapshot.runs,snapshot.actions,locale),{headers:{'Content-Type':html?'text/html;charset=utf-8':'text/plain;charset=utf-8','Content-Disposition':`attachment; filename="velthara-report.${format}"`,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; sandbox"}});
 }catch(error){return failure(error,req);}}
