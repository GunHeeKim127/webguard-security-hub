import {db} from '../../../lib/db';
import {deploymentReadiness} from '../../../lib/deployment-readiness';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const maxDuration=30;
/** GET: 서비스 실행 준비 상태를 응답합니다。 */ export async function GET(){
 const started=performance.now();
 const result=await deploymentReadiness(/** deploymentReadiness 콜백: deploymentReadiness에서 전달한 값을 처리하는 콜백입니다 주요 호출: query. */ sql=>db.query(sql));
 if(!result.ready)console.warn('[WebGuard readiness]',{code:result.code,durationMs:Math.round(performance.now()-started)});
 // Detailed schema/permission diagnostics belong in operator tooling, not public responses.
 return Response.json({status:result.ready?'ready':'not_ready',code:result.ready?'READY':'NOT_READY'},{status:result.ready?200:503,headers:{'Cache-Control':'no-store'}});
}
