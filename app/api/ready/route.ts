import {db} from '../../../lib/db';
import {deploymentReadiness} from '../../../lib/deployment-readiness';
import {coalescedReadiness} from '../../../lib/readiness-coordinator';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const maxDuration=30;
const probe=coalescedReadiness(/** probe: 동시 호출만 합치고 매 새 준비 검사는 실제 DB 권한을 대조합니다. */ ()=>deploymentReadiness(/** deploymentReadiness: 고정 읽기 전용 준비 검사에만 별도 연결 수명을 적용합니다. */ sql=>db.readinessQuery(sql)));
/** GET: 서비스 실행 준비 상태를 응답합니다。 */ export async function GET(){
 const started=performance.now();
 const result=await probe();
 if(!result.ready)console.warn('[WebGuard readiness]',{code:result.code,durationMs:Math.round(performance.now()-started)});
 // Detailed schema/permission diagnostics belong in operator tooling, not public responses.
 return Response.json({status:result.ready?'ready':'not_ready',code:result.ready?'READY':'NOT_READY'},{status:result.ready?200:503,headers:{'Cache-Control':'no-store'}});
}
