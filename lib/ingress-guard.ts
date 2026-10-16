import ipaddr from 'ipaddr.js';
import {createHash,timingSafeEqual} from 'node:crypto';
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
export async function activeBlock(query:GuardQuery,address:string):Promise<IpBlock|null>{
 const row=(await query("SELECT host(address) AS address,strikes,blacklisted,blocked_until,last_reason,ceil(greatest(0,extract(epoch FROM blocked_until-now())))::int AS retry_after FROM public.ip_blocks WHERE address=$1::inet AND (blacklisted OR blocked_until>now())",[address])).rows[0];return row??null;
}
export async function recordThreat(query:GuardQuery,address:string,reason:ThreatReason):Promise<IpBlock>{
 const result=await query(`WITH changed AS (
  INSERT INTO public.ip_blocks(address,strikes,blacklisted,blocked_until,last_reason)
  VALUES($1::inet,1,false,now()+interval '5 minutes',$2)
  ON CONFLICT(address) DO UPDATE SET strikes=ip_blocks.strikes+1,
   blacklisted=ip_blocks.strikes>=5,
   blocked_until=CASE WHEN ip_blocks.strikes>=5 THEN NULL ELSE now()+interval '5 minutes' END,
   last_reason=EXCLUDED.last_reason,last_seen=now()
  WHERE NOT ip_blocks.blacklisted AND (ip_blocks.blocked_until IS NULL OR ip_blocks.blocked_until<=now())
  RETURNING host(address) AS address,strikes,blacklisted,blocked_until,last_reason
 ), logged AS (
  INSERT INTO public.events(category) SELECT CASE WHEN blacklisted THEN 'ip_blacklisted' ELSE 'threat_blocked' END FROM changed RETURNING id
 ) SELECT changed.*,300 AS retry_after FROM changed CROSS JOIN logged`,[address,reason]);
 return result.rows[0]??await activeBlock(query,address)??Promise.reject(new Error('Block state unavailable'));
}
