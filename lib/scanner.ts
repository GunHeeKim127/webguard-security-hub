import dns from 'node:dns/promises';
import https from 'node:https';
import ipaddr from 'ipaddr.js';
import type {Stage} from './scan-run';
import type {TLSSocket} from 'node:tls';
import {assessWeb,corsProbeOrigin} from './web-assessment';
import type {CheckResult} from './inspection';
import {scanTarget} from './scan-policy';
import {observeTechnology} from './web-technology';
/** publicAddress: 공개 접근이 가능한 주소인지 검토합니다 주요 호출: range·parse. */ export function publicAddress(address:string){try{return ipaddr.parse(address).range()==='unicast';}catch{return false;}}
export const target=scanTarget;
// Keep cold/slow public targets bounded while allowing more than a five-second response.
export const HEAD_RESPONSE_DEADLINE_MS=15000;
/** scanFailureReason: 검사 실패를 공개 가능한 원인 분류로 바꿉니다 주요 호출: includes. */ export function scanFailureReason(error:unknown,signal?:AbortSignal){
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
/** findings: 해당 자료의 관찰·검토 결과를 계산합니다 주요 호출: map. */ export function findings(headers:Record<string,string|string[]|undefined>){
 return ['content-security-policy','strict-transport-security','x-content-type-options','referrer-policy'].map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ header=>({header,present:!!headers[header],severity:headers[header]?'info':'medium'}));
}
/** scan: 해당 자료의 관찰·검토 결과를 계산합니다 주요 호출: checkAbort·progress·target. */ export async function scan(raw:string,allowed?:string[],progress:(stage:Stage,state:'running'|'success')=>void=/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},signal?:AbortSignal,profile?:'desktop'|'mobile') {
 const checkAbort=/** checkAbort: 값의 형식이나 처리 조건을 확인합니다 */ ()=>{if(signal?.aborted)throw new Error('Scan cancelled');};
 checkAbort();progress('target','running');
 const u=target(raw,allowed);progress('target','success');progress('network','running');
 let dnsTimer:ReturnType<typeof setTimeout>|undefined,abortDns:(()=>void)|undefined;
 const addresses=await Promise.race([dns.lookup(u.hostname,{all:true}),new Promise<never>(/** race 콜백: race에서 전달한 값을 처리하는 콜백입니다 주요 호출: setTimeout·unref·addEventListener. */ (_,reject)=>{
  dnsTimer=setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: reject. */ ()=>reject(new Error('DNS timeout')),3000);dnsTimer.unref();
  abortDns=/** race 콜백: race에서 전달한 값을 처리하는 콜백입니다 주요 호출: reject. */ ()=>reject(new Error('Scan cancelled'));signal?.addEventListener('abort',abortDns,{once:true});if(signal?.aborted)abortDns();
 })]).finally(/** finally 콜백: 비동기 작업 후 정리를 실행합니다 주요 호출: clearTimeout·removeEventListener. */ ()=>{clearTimeout(dnsTimer);if(abortDns)signal?.removeEventListener('abort',abortDns);});
 checkAbort();
 if(!addresses.length || addresses.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: publicAddress. */ a=>!publicAddress(a.address)))throw new Error('Non-public DNS rejected');
 const pinned=addresses[0];
 return new Promise<CheckResult>(/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: request·addEventListener·abort. */ (resolve,reject)=>{
 const userAgent=profile==='mobile'?'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 WebGuard/0.3':profile==='desktop'?'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 WebGuard/0.3':'WebGuard/0.2 authorized-passive-check';
 const req=https.request(u,{method:'HEAD',agent:false,rejectUnauthorized:true,minVersion:'TLSv1.2',maxHeaderSize:16384,family:pinned.family,lookup:(/** request 콜백: request에서 전달한 값을 처리하는 콜백입니다 주요 호출: callback. */ (_hostname:unknown,_options:unknown,callback:Function)=>callback(null,pinned.address,pinned.family)) as never,headers:{'User-Agent':userAgent,Origin:corsProbeOrigin}},/** request 콜백: request에서 전달한 값을 처리하는 콜백입니다 주요 호출: checkAbort·progress·getPeerCertificate. */ res=>{
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
 const abort=/** abort: 작업의 완료·실패·취소에 맞춰 관련 상태와 자원을 정리합니다 주요 호출: destroy. */ ()=>req.destroy(new Error('Scan cancelled'));signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 const timer=setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: destroy. */ ()=>req.destroy(new Error('Scan deadline exceeded')),HEAD_RESPONSE_DEADLINE_MS);
 req.on('close',/** on 콜백: on에서 전달한 값을 처리하는 콜백입니다 주요 호출: clearTimeout·removeEventListener. */ ()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);});req.on('error',reject);req.end();
 });
}
