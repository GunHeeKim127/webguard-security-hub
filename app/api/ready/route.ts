import {db} from '../../../lib/db';
import {deploymentReadiness} from '../../../lib/deployment-readiness';
import {coalescedReadiness} from '../../../lib/readiness-coordinator';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const maxDuration=30;
const probe=coalescedReadiness(/** probe: 동시 조회를 합치되 완료 결과는 저장하지 않고 관리형 준비 검사를 20초 안에 중단합니다. */ async()=>{
 const controller=new AbortController(),timer=setTimeout(/** deadline: 준비 조회 전체의 실제 HTTPS 작업을 종료합니다. */ ()=>controller.abort(),20000);
 try{return await deploymentReadiness(/** deploymentReadiness: 고정 읽기 SELECT에만 동일한 전체 수명을 적용합니다. */ sql=>db.readinessQuery(sql,controller.signal));}
 finally{clearTimeout(timer);}
});
/** GET: 서비스 실행 준비 상태를 응답합니다。 */ export async function GET(){
 const started=performance.now();
 const result=await probe();
 if(!result.ready)console.warn('[WebGuard readiness]',{code:result.code,durationMs:Math.round(performance.now()-started)});
 // Detailed schema/permission diagnostics belong in operator tooling, not public responses.
 return Response.json({status:result.ready?'ready':'not_ready',code:result.ready?'READY':'NOT_READY'},{status:result.ready?200:503,headers:{'Cache-Control':'no-store'}});
}
