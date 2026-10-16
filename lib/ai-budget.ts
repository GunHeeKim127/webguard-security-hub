import {HttpError} from './request';
type Query=(sql:string,values:unknown[])=>Promise<{rows:{window?:string}[]}>;
// Reserve before sending an external request, so simultaneous calls cannot exceed the budget.
// A failed request refunds only its original window; it cannot alter a later reset window.
export async function withAiBudget<T>(query:Query,bucket:string,work:()=>Promise<T>):Promise<T>{
 const reserved=await query(`INSERT INTO rate_limits(bucket,hits,reset_at) VALUES($1,1,now()+interval '1 hour')
 ON CONFLICT(bucket) DO UPDATE SET
  hits=CASE WHEN rate_limits.reset_at<=now() THEN 1 ELSE rate_limits.hits+1 END,
  reset_at=CASE WHEN rate_limits.reset_at<=now() THEN now()+interval '1 hour' ELSE rate_limits.reset_at END
 WHERE rate_limits.reset_at<=now() OR rate_limits.hits<3
 RETURNING reset_at::text AS window`,[bucket]);
 if(!reserved.rows.length)throw new HttpError(429,'AI_LOCAL_RATE_LIMITED');
 try{return await work();}catch(error){
  try{await query('UPDATE rate_limits SET hits=greatest(hits-1,0) WHERE bucket=$1 AND reset_at=$2::timestamptz',[bucket,reserved.rows[0].window]);}
  catch{console.warn('[WebGuard AI]',{code:'AI_BUDGET_REFUND_FAILED'});}
  throw error;
 }
}
