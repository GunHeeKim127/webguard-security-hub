// PROTECTION_UNAVAILABLE is returned by the ingress guard before the API runs.
// Only that explicit response can safely replay a write. Network errors and
// other server failures may follow a committed write and must never be retried.
export async function protectedRequest(url:string,init:RequestInit={},transport:typeof fetch=fetch):Promise<Response>{
 const first=await transport(url,init);
 if(first.status!==503)return first;
 try{if((await first.clone().json()).errorCode!=='PROTECTION_UNAVAILABLE')return first;}catch{return first;}
 const signal=init.signal;
 signal?.throwIfAborted();
 await new Promise<void>((resolve,reject)=>{
  const finish=()=>{signal?.removeEventListener('abort',abort);resolve();};
  const timer=setTimeout(finish,300);
  const abort=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);reject(signal?.reason??new DOMException('Aborted','AbortError'));};
  signal?.addEventListener('abort',abort,{once:true});
 });
 signal?.throwIfAborted();
 return transport(url,init);
}
