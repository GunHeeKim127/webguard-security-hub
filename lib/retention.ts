import {createHash,timingSafeEqual} from 'node:crypto';
/** maintenanceAuthorized: 유지보수 요청의 실행 권한을 확인합니다 주요 호출: timingSafeEqual·digest. */ export function maintenanceAuthorized(header:string|null,secret:string|undefined){
 if(!secret||secret.length<32||!header||header.length>512)return false;
 const digest=/** digest: 검증용 입력의 해시를 계산합니다 주요 호출: digest·update·createHash. */ (value:string)=>createHash('sha256').update(value).digest();
 return timingSafeEqual(digest(header),digest('Bearer '+secret));
}
type Query=(sql:string)=>Promise<{rows:Record<string,unknown>[]}>;
/** archiveDiagnostics: 보관 정책에 따라 진단 이력을 이관합니다 주요 호출: query. */ export async function archiveDiagnostics(query:Query){
 const result=await query('SELECT public.archive_diagnostics_30d() AS result');
 return result.rows[0].result;
}
