import dns from 'node:dns/promises';
import https from 'node:https';
import ipaddr from 'ipaddr.js';
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
export async function scan(raw:string,allowed:string[]) {
 const u=target(raw,allowed);
 const addresses=await Promise.race([dns.lookup(u.hostname,{all:true}),new Promise<never>((_,reject)=>{const timer=setTimeout(()=>reject(new Error('DNS timeout')),3000);timer.unref();})]);
 if(!addresses.length || addresses.some(a=>!publicAddress(a.address)))throw new Error('Non-public DNS rejected');
 const pinned=addresses[0];
 return new Promise<{status:number,checks:ReturnType<typeof findings>}>((resolve,reject)=>{
 const req=https.request(u,{method:'HEAD',agent:false,family:pinned.family,lookup:((_hostname:unknown,_options:unknown,callback:Function)=>callback(null,pinned.address,pinned.family)) as never,headers:{'User-Agent':'WebGuard/0.1 authorized-header-check'}},res=>{
  res.destroy();resolve({status:res.statusCode??0,checks:findings(res.headers)});
 });
 const timer=setTimeout(()=>req.destroy(new Error('Scan deadline exceeded')),5000);
 req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end();
 });
}
