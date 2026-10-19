import {activeBlock,recordThreat,detectThreat,normalizeIp,type GuardQuery} from './ingress-guard';
import {requestLocale} from './request-locale';
import {defenseText} from './defense-copy';
import {ipAddress} from '@vercel/functions';
import {protectionDbError} from './protection-db-error';

export function vercelClientAddress(headers:Pick<Headers,'get'>,env:Readonly<Record<string,string|undefined>>=process.env){
 // Use the platform's official client IP header, only inside a Vercel deployment.
 return env.VERCEL==='1'?normalizeIp(ipAddress(new Headers({'x-real-ip':headers.get('x-real-ip')??''}))):null;
}
export async function vercelProtection(req:Request,query:GuardQuery,env:Readonly<Record<string,string|undefined>>=process.env):Promise<Response|null>{
 if(env.VERCEL!=='1')return null;
 const url=new URL(req.url);
 if(['/api/health','/api/ready'].includes(url.pathname))return null;
 const {locale}=requestLocale(req.headers);
 let stage='client_identity';
 try{
  const address=vercelClientAddress(req.headers,env);if(!address)throw new Error('Client IP missing');
  stage='block_lookup';
  // This operation is read-only. A disconnected/timed-out client is discarded by pg.Pool.
  // Retry once with another checkout; never repeat writes or skip the protection check.
  let block;
  try{block=await activeBlock(query,address);}catch(error){
   const issue=protectionDbError(error);if(!issue.retryable)throw error;
   console.warn('[WebGuard protection]',{stage,reason:issue.reason,retry:1});
   block=await activeBlock(query,address);
  }
  if(!block){const reason=detectThreat(url.pathname+url.search);if(reason){stage='threat_record';block=await recordThreat(query,address,reason);}}
  if(!block)return null;
  const errorCode=block.blacklisted?'IP_BLACKLISTED':'THREAT_BLOCKED';
  return Response.json({error:defenseText(locale,block.blacklisted?'permanent':'temporary'),errorCode,locale,retryAfter:block.blacklisted?null:Math.max(1,block.retry_after),strikes:block.strikes},{status:block.blacklisted?403:429,headers:{'Cache-Control':'no-store','Content-Language':locale,...(!block.blacklisted?{'Retry-After':String(Math.max(1,block.retry_after))}:{})}});
 }catch(error){
  console.warn('[WebGuard protection]',{stage,reason:stage==='client_identity'?'CLIENT_IP_MISSING':protectionDbError(error).reason});
  return Response.json({error:defenseText(locale,'unavailable'),errorCode:'PROTECTION_UNAVAILABLE',locale},{status:503,headers:{'Cache-Control':'no-store','Content-Language':locale}});
 }
}
