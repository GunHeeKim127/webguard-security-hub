import {createHash} from 'node:crypto';
import {normalizeIp,type GuardQuery} from './ingress-guard';
export async function releaseIpBlock(query:GuardQuery,raw:string,actorId:string,reference:string|null=null){
 const address=normalizeIp(raw);if(!address||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(actorId))throw new Error('INPUT_INVALID');
 const audit='ip_unblocked_target:'+createHash('sha256').update(address).digest('hex');
 const result=await query(`WITH released_block AS (
 UPDATE public.ip_blocks SET strikes=0,blacklisted=false,blocked_until=NULL,last_reason='manual_reset',last_seen=now()
 WHERE address=$1::inet AND ($4::uuid IS NULL OR management_id=$4) AND (strikes>0 OR blacklisted OR blocked_until IS NOT NULL) RETURNING address
 ), logged AS (
 INSERT INTO public.events(category,user_id)
 SELECT categories.category,$2::uuid FROM released_block CROSS JOIN (VALUES ('ip_unblocked'),($3::text)) AS categories(category) RETURNING id
 ) SELECT count(*)::int AS audit_count FROM logged`,[address,actorId,audit,reference]);
 return Number(result.rows[0]?.audit_count)===2;
}
