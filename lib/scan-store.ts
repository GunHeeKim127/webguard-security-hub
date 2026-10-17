import {randomUUID} from 'node:crypto';
import type {CheckResult} from './inspection';
type Query=(sql:string,values:unknown[])=>Promise<{rows:{id:string}[]}>;
// The DB uniqueness constraint also handles simultaneous requests and keeps the record ID stable.
// Save the result and completion audit event together so an error cannot leave a partial write.
export async function saveScan(query:Query,userId:string,hostname:string,result:CheckResult){
 const saved=await query(`WITH saved AS (
  INSERT INTO public.scans(id,user_id,hostname,result) VALUES($1,$2,$3,$4)
  ON CONFLICT (user_id,hostname) DO UPDATE
   SET result=EXCLUDED.result,created_at=clock_timestamp()
  RETURNING id
 ), logged AS (
  INSERT INTO public.events(category,user_id) SELECT 'scan_completed',$2 FROM saved RETURNING id
 ) SELECT saved.id FROM saved CROSS JOIN logged`,[randomUUID(),userId,hostname,JSON.stringify(result)]);
 return saved.rows[0].id;
}
