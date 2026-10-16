import dns from 'node:dns/promises';
import https from 'node:https';
import ipaddr from 'ipaddr.js';
import type {Stage} from './scan-run';
export function publicAddress(address:string){try{return ipaddr.parse(address).range()==='unicast';}catch{return false;}}
export function target(raw:string,allowed:string[]) {
 const u=new URL(raw);
 if(u.protocol!=='https:' || u.username || u.password || (u.port && u.port!=='443') || u.pathname!=='/' || u.search || u.hash) throw new Error('Only HTTPS origin on port 443 is allowed');
 if(ipaddr.isValid(u.hostname.replace(/^\[|\]$/g,'')) || !allowed.includes(u.hostname) || !/^[a-z0-9.-]+$/.test(u.hostname))throw new Error('Hostname is not allowed');
 return u;
}
export function findings(headers:Record<string,string|string[]|undefined>){
 return ['content-security-policy','strict-transport-security','x-content-type-options','referrer-policy'].map(header=>({header,present:!!headers[header],severity:headers[header]?'info':'medium'}));
}
export async function scan(raw:string,allowed:string[],progress:(stage:Stage,state:'running'|'success')=>void=()=>{},signal?:AbortSignal) {
 const checkAbort=()=>{if(signal?.aborted)throw new Error('Scan cancelled');};
 checkAbort();progress('target','running');
 const u=target(raw,allowed);progress('target','success');progress('network','running');
 const addresses=await Promise.race([dns.lookup(u.hostname,{all:true}),new Promise<never>((_,reject)=>{const timer=setTimeout(()=>reject(new Error('DNS timeout')),3000);timer.unref();})]);
 checkAbort();
 if(!addresses.length || addresses.some(a=>!publicAddress(a.address)))throw new Error('Non-public DNS rejected');
 const pinned=addresses[0];
 return new Promise<{status:number,checks:ReturnType<typeof findings>}>((resolve,reject)=>{
 const req=https.request(u,{method:'HEAD',agent:false,family:pinned.family,lookup:((_hostname:unknown,_options:unknown,callback:Function)=>callback(null,pinned.address,pinned.family)) as never,headers:{'User-Agent':'WebGuard/0.1 authorized-header-check'}},res=>{
  res.destroy();
  try{checkAbort();progress('network','success');progress('headers','running');const checks=findings(res.headers);progress('headers','success');resolve({status:res.statusCode??0,checks});}catch(error){reject(error);}
 });
 const abort=()=>req.destroy(new Error('Scan cancelled'));signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 const timer=setTimeout(()=>req.destroy(new Error('Scan deadline exceeded')),5000);
 req.on('close',()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);});req.on('error',reject);req.end();
 });
}
