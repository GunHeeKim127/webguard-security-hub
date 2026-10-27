import {createHash} from 'node:crypto';
import type {GuardQuery} from './ingress-guard';
const uuid=(v:string)=>/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(v);
export async function releaseAccountBlock(query:GuardQuery,userId:string,actorId:string|null,reference:string|null=null){
 if(!uuid(userId)||(actorId!==null&&!uuid(actorId)))throw new Error('INPUT_INVALID');
 const audit='account_unblocked_target:'+createHash('sha256').update(userId.toLowerCase()).digest('hex');
 const result=await query(`WITH reset AS (
 UPDATE public.account_blocks SET strikes=0,blacklisted=false,last_reason='manual_reset',last_seen=now()
 WHERE user_id=$1::uuid AND ($5::uuid IS NULL OR management_id=$5) AND (strikes>0 OR blacklisted) RETURNING user_id
 ), revoked AS (
 DELETE FROM public.sessions WHERE user_id IN(SELECT user_id FROM reset) RETURNING user_id
 ), logged AS (
 INSERT INTO public.events(category,user_id) SELECT categories.category,$2::uuid FROM reset CROSS JOIN (VALUES ($3::text),($4::text)) AS categories(category) RETURNING id
 ) SELECT count(*)::int AS audit_count FROM logged`,[userId,actorId,actorId===null?'account_unblocked_local':'account_unblocked',audit,reference]);
 return Number(result.rows[0]?.audit_count)===2;
}
