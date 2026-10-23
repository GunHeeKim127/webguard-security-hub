import {createHash,timingSafeEqual} from 'node:crypto';
export function maintenanceAuthorized(header:string|null,secret:string|undefined){
 if(!secret||secret.length<32||!header||header.length>512)return false;
 const digest=(value:string)=>createHash('sha256').update(value).digest();
 return timingSafeEqual(digest(header),digest('Bearer '+secret));
}
type Query=(sql:string)=>Promise<{rows:Record<string,unknown>[]}>;
export async function archiveDiagnostics(query:Query){
 const result=await query('SELECT public.archive_diagnostics_30d() AS result');
 return result.rows[0].result;
}
