import dns from 'node:dns/promises';
import https from 'node:https';
import ipaddr from 'ipaddr.js';
import type {Stage} from './scan-run';
import type {TLSSocket} from 'node:tls';
import {assessWeb,corsProbeOrigin} from './web-assessment';
import type {CheckResult} from './inspection';
import {scanTarget} from './scan-policy';
import {observeTechnology} from './web-technology';
export function publicAddress(address:string){try{return ipaddr.parse(address).range()==='unicast';}catch{return false;}}
export const target=scanTarget;
// Keep cold/slow public targets bounded while allowing more than a five-second response.
export const HEAD_RESPONSE_DEADLINE_MS=15000;
export function scanFailureReason(error:unknown,signal?:AbortSignal){
 if(signal?.aborted)return 'CANCELLED';
 const message=error instanceof Error?error.message:'',code=error&&typeof error==='object'&&'code' in error?error.code:undefined;
 if(message==='Scan deadline exceeded')return 'HEAD_RESPONSE_DEADLINE';
 if(message==='DNS timeout')return 'DNS_TIMEOUT';
 if(message==='Non-public DNS rejected')return 'TARGET_ADDRESS_REJECTED';
 if(message==='Scan cancelled')return 'CANCELLED';
 if(message==='TLS verification failed'||typeof code==='string'&&(/^(?:ERR_TLS_|ERR_SSL_|CERT_)/.test(code)||['DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(code)))return 'TLS_REJECTED';
 if(code==='HPE_HEADER_OVERFLOW')return 'RESPONSE_HEADERS_TOO_LARGE';
 if(['ECONNRESET','ECONNREFUSED','ETIMEDOUT','ENOTFOUND','EAI_AGAIN','EHOSTUNREACH','ENETUNREACH'].includes(code as string))return 'TARGET_CONNECTION_FAILED';
 return 'TARGET_REJECTED';
}
export function findings(headers:Record<string,string|string[]|undefined>){
 return ['content-security-policy','strict-transport-security','x-content-type-options','referrer-policy'].map(header=>({header,present:!!headers[header],severity:headers[header]?'info':'medium'}));
}
export async function scan(raw:string,allowed?:string[],progress:(stage:Stage,state:'running'|'success')=>void=()=>{},signal?:AbortSignal,profile?:'desktop'|'mobile') {
 const checkAbort=()=>{if(signal?.aborted)throw new Error('Scan cancelled');};
 checkAbort();progress('target','running');
 const u=target(raw,allowed);progress('target','success');progress('network','running');
 let dnsTimer:ReturnType<typeof setTimeout>|undefined,abortDns:(()=>void)|undefined;
 const addresses=await Promise.race([dns.lookup(u.hostname,{all:true}),new Promise<never>((_,reject)=>{
  dnsTimer=setTimeout(()=>reject(new Error('DNS timeout')),3000);dnsTimer.unref();
  abortDns=()=>reject(new Error('Scan cancelled'));signal?.addEventListener('abort',abortDns,{once:true});if(signal?.aborted)abortDns();
 })]).finally(()=>{clearTimeout(dnsTimer);if(abortDns)signal?.removeEventListener('abort',abortDns);});
 checkAbort();
 if(!addresses.length || addresses.some(a=>!publicAddress(a.address)))throw new Error('Non-public DNS rejected');
 const pinned=addresses[0];
 return new Promise<CheckResult>((resolve,reject)=>{
 const userAgent=profile==='mobile'?'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 WebGuard/0.3':profile==='desktop'?'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 WebGuard/0.3':'WebGuard/0.2 authorized-passive-check';
 const req=https.request(u,{method:'HEAD',agent:false,rejectUnauthorized:true,minVersion:'TLSv1.2',maxHeaderSize:16384,family:pinned.family,lookup:((_hostname:unknown,_options:unknown,callback:Function)=>callback(null,pinned.address,pinned.family)) as never,headers:{'User-Agent':userAgent,Origin:corsProbeOrigin}},res=>{
  try{checkAbort();progress('network','success');progress('headers','running');
   const socket=res.socket as TLSSocket,certificate=socket?.getPeerCertificate?.();
   const tls=socket?.getProtocol?{authorized:socket.authorized===true,protocol:socket.getProtocol(),validTo:certificate?.valid_to??null}:undefined;
   if(tls&&!tls.authorized)throw new Error('TLS verification failed');
   const checks=findings(res.headers),assessment=assessWeb(res.headers,tls),status=res.statusCode??0;
   // Unsupported HEAD and error/redirect pages do not establish the target application's policy.
   if(status<200||status>=300)for(const item of assessment)if(item.group!=='tls'){item.status='not_assessed';item.severity='info';item.issues=['response_scope'];}
   progress('headers','success');resolve({status,checks,assessment,assessmentVersion:2,technology:observeTechnology(res.headers,status)});
  }catch(error){reject(error);}finally{res.destroy();}
 });
 const abort=()=>req.destroy(new Error('Scan cancelled'));signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 const timer=setTimeout(()=>req.destroy(new Error('Scan deadline exceeded')),HEAD_RESPONSE_DEADLINE_MS);
 req.on('close',()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);});req.on('error',reject);req.end();
 });
}
