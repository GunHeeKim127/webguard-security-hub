import ipaddr from 'ipaddr.js';
import {createHash,timingSafeEqual} from 'node:crypto';
import {tokenHash} from './password';
export function threatSessionHash(cookie:string|null|undefined){
 const values=(cookie??'').split(';').map(p=>p.trim()).filter(p=>p.startsWith('wg_session='));
 if(values.length!==1)return null;const token=values[0].slice('wg_session='.length);return /^[a-f0-9]{64}$/.test(token)?tokenHash(token):null;
}
export type ThreatReason='probe'|'injection'|'traversal';
export type IpBlock={address:string,strikes:number,blacklisted:boolean,blocked_until:string|null,retry_after:number,last_reason:string};
export type GuardQuery=(sql:string,values:unknown[])=>Promise<{rows:any[]}>;
export function normalizeIp(raw:string|undefined){try{if(!raw||raw.includes('%'))return null;return ipaddr.process(raw).toString();}catch{return null;}}
export function clientAddress(peer:string|undefined,headers:Pick<Headers,'get'>,env:Readonly<Record<string,string|undefined>>=process.env){
 const address=normalizeIp(peer);if(!address)return null;
 const configured=(env.TRUSTED_PROXY_IPS??'').split(',').map(v=>v.trim()).filter(Boolean),proxies=configured.map(v=>normalizeIp(v));
 if(proxies.some(ip=>!ip))return null;
 if(!proxies.includes(address))return address; // Ignore all forwarded-IP headers from ordinary clients.
 const secret=env.WEBGUARD_PROXY_SECRET,token=headers.get('x-webguard-proxy-token');
 if(!secret||secret.length<32||secret.length>256||!token||token.length>256||!timingSafeEqual(createHash('sha256').update(secret).digest(),createHash('sha256').update(token).digest()))return null;
 return normalizeIp(headers.get('x-webguard-client-ip')??undefined);
}
export function detectThreat(rawTarget:string):ThreatReason|null{
 let text=rawTarget.slice(0,8192);for(let i=0;i<2;i++){try{const decoded=decodeURIComponent(text);if(decoded===text)break;text=decoded;}catch{break;}}
 const path=text.split('?')[0];
 if(/^\/(?:\.env(?:[./]|$)|\.git(?:\/|$)|wp-admin(?:\/|$)|wp-login\.php(?:\?|$)|phpmyadmin(?:\/|$))/i.test(path))return 'probe';
 if(/(?:^|\/)\.\.(?:\/|\\)|%00|\u0000/i.test(text))return 'traversal';
 // Only unmistakable URL-level payloads. Never inspect or retain passwords, cookies or arbitrary body text.
 if(/<script(?:\s|>)|\bunion\s+(?:all\s+)?select\b|(?:__proto__|constructor\[prototype\])(?:\[|=)/i.test(text))return 'injection';
 return null;
}
export const ACTIVE_BLOCK_SQL="SELECT host(address) AS address,strikes,blacklisted,blocked_until,last_reason,ceil(greatest(0,extract(epoch FROM blocked_until-now())))::int AS retry_after FROM public.ip_blocks WHERE address=$1::inet AND (blacklisted OR blocked_until>now())";
export async function activeBlock(query:GuardQuery,address:string):Promise<IpBlock|null>{
 const row=(await query(ACTIVE_BLOCK_SQL,[address])).rows[0];return row??null;
}
export async function recordThreat(query:GuardQuery,address:string,reason:ThreatReason,sessionHash:string|null=null):Promise<IpBlock>{
 const result=await query(`WITH changed AS (
  INSERT INTO public.ip_blocks(address,strikes,blacklisted,blocked_until,last_reason)
  VALUES($1::inet,1,false,now()+interval '5 minutes',$2)
  ON CONFLICT(address) DO UPDATE SET strikes=ip_blocks.strikes+1,
   blacklisted=ip_blocks.strikes>=5,
   blocked_until=CASE WHEN ip_blocks.strikes>=5 THEN NULL ELSE now()+interval '5 minutes' END,
   last_reason=EXCLUDED.last_reason,last_seen=now()
  WHERE NOT ip_blocks.blacklisted AND (ip_blocks.blocked_until IS NULL OR ip_blocks.blocked_until<=now())
  RETURNING host(address) AS address,strikes,blacklisted,blocked_until,last_reason
 ), authenticated AS (
 SELECT user_id FROM public.sessions WHERE token_hash=$3 AND expires_at>now()
 ), account_changed AS (
 INSERT INTO public.account_blocks(user_id,strikes,blacklisted,last_reason)
 SELECT authenticated.user_id,1,false,$2 FROM authenticated CROSS JOIN changed
 ON CONFLICT(user_id) DO UPDATE SET strikes=least(6,account_blocks.strikes+1),blacklisted=account_blocks.strikes>=5,last_reason=EXCLUDED.last_reason,last_seen=now()
 WHERE NOT account_blocks.blacklisted RETURNING user_id,blacklisted
 ), revoked AS (
 DELETE FROM public.sessions WHERE user_id IN(SELECT user_id FROM account_changed WHERE blacklisted) RETURNING user_id
 ), account_logged AS (
 INSERT INTO public.events(category,user_id) SELECT CASE WHEN blacklisted THEN 'account_blacklisted' ELSE 'account_threat_recorded' END,user_id FROM account_changed RETURNING id
 ), logged AS (
  INSERT INTO public.events(category) SELECT CASE WHEN blacklisted THEN 'ip_blacklisted' ELSE 'threat_blocked' END FROM changed RETURNING id
 ) SELECT changed.*,300 AS retry_after FROM changed CROSS JOIN logged`,[address,reason,sessionHash]);
 return result.rows[0]??await activeBlock(query,address)??Promise.reject(new Error('Block state unavailable'));
}
