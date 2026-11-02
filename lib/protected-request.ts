// PROTECTION_UNAVAILABLE is returned by the ingress guard before the API runs.
// Only that explicit response can safely replay a write. Network errors and
// other server failures may follow a committed write and must never be retried.
/** protectedRequest: 허용된 보호 복구 조건에서 요청을 실행하며 취소를 전달합니다 주요 호출: transport·json·clone. */ export async function protectedRequest(url:string,init:RequestInit={},transport:typeof fetch=fetch):Promise<Response>{
 const first=await transport(url,init);
 if(first.status!==503)return first;
 try{if((await first.clone().json()).errorCode!=='PROTECTION_UNAVAILABLE')return first;}catch{return first;}
 const signal=init.signal;
 signal?.throwIfAborted();
 await new Promise<void>(/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: setTimeout·addEventListener. */ (resolve,reject)=>{
  const finish=/** finish: 작업의 완료·실패·취소에 맞춰 관련 상태와 자원을 정리합니다 주요 호출: removeEventListener·resolve. */ ()=>{signal?.removeEventListener('abort',abort);resolve();};
  const timer=setTimeout(finish,300);
  const abort=/** abort: 작업의 완료·실패·취소에 맞춰 관련 상태와 자원을 정리합니다 주요 호출: clearTimeout·removeEventListener·reject. */ ()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);reject(signal?.reason??new DOMException('Aborted','AbortError'));};
  signal?.addEventListener('abort',abort,{once:true});
 });
 signal?.throwIfAborted();
 return transport(url,init);
}
