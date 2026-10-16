import {activeBlock,recordThreat,detectThreat,normalizeIp,type GuardQuery} from './ingress-guard';
import {requestLocale} from './request-locale';
import {defenseText} from './defense-copy';
import {ipAddress} from '@vercel/functions';

export function vercelClientAddress(headers:Pick<Headers,'get'>,env:Readonly<Record<string,string|undefined>>=process.env){
 // Use the platform's official client IP header, only inside a Vercel deployment.
 return env.VERCEL==='1'?normalizeIp(ipAddress(new Headers({'x-real-ip':headers.get('x-real-ip')??''}))):null;
}
export async function vercelProtection(req:Request,query:GuardQuery,env:Readonly<Record<string,string|undefined>>=process.env):Promise<Response|null>{
 if(env.VERCEL!=='1')return null;
 const url=new URL(req.url);
 if(['/api/health','/api/ready'].includes(url.pathname))return null;
 const {locale}=requestLocale(req.headers);
 try{
  const address=vercelClientAddress(req.headers,env);if(!address)throw new Error('Client IP missing');
  let block=await activeBlock(query,address);
  if(!block){const reason=detectThreat(url.pathname+url.search);if(reason)block=await recordThreat(query,address,reason);}
  if(!block)return null;
  const errorCode=block.blacklisted?'IP_BLACKLISTED':'THREAT_BLOCKED';
  return Response.json({error:defenseText(locale,block.blacklisted?'permanent':'temporary'),errorCode,locale,retryAfter:block.blacklisted?null:Math.max(1,block.retry_after),strikes:block.strikes},{status:block.blacklisted?403:429,headers:{'Cache-Control':'no-store','Content-Language':locale,...(!block.blacklisted?{'Retry-After':String(Math.max(1,block.retry_after))}:{})}});
 }catch{
  return Response.json({error:defenseText(locale,'unavailable'),errorCode:'PROTECTION_UNAVAILABLE',locale},{status:503,headers:{'Cache-Control':'no-store','Content-Language':locale}});
 }
}
