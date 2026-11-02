import {accessOrigins} from './access-origins';
export class HttpError extends Error { /** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ constructor(public status:number,message:string){super(message);} }
/** sameOrigin: 변경 요청의 출처가 허용된 서비스 출처인지 검증합니다 주요 호출: get·includes·accessOrigins. */ export function sameOrigin(req:Request) {
 const origin=req.headers.get('origin');
 if(!origin||!accessOrigins().includes(origin)||new URL(origin).host!==(req.headers.get('host')??new URL(req.url).host))throw new HttpError(403,'Origin rejected');
}
/** body: 허용 크기의 요청 본문을 읽고 객체 입력을 확인합니다 주요 호출: toLowerCase·trim·split. */ export async function body(req:Request,maxBytes=4096,timeoutMs=10000) {
 if(req.headers.get('content-type')?.split(';',1)[0].trim().toLowerCase()!=='application/json') throw new HttpError(415,'JSON required');
 const reader=req.body?.getReader(); if(!reader) throw new HttpError(400,'Body required');
 const parts:Uint8Array[]=[]; let size=0,timer:ReturnType<typeof setTimeout>|undefined;
 const deadline=new Promise<never>(/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: setTimeout. */ (_,reject)=>{timer=setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: reject·catch·cancel. */ ()=>{reject(new HttpError(408,'Request body timeout'));void reader.cancel().catch(/** catch 콜백: 비동기 실패를 후속 처리합니다 */ ()=>{});},timeoutMs);});
 try{await Promise.race([deadline,(/** (async()=>{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new HttpError(413,'Body too large');}parts.push(value);}}) 콜백: (async()=>{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new HttpError(413,'Body too large');}parts.push(value);}})에서 전달한 값을 처리하는 콜백 */ async()=>{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new HttpError(413,'Body too large');}parts.push(value);}})()]);}finally{clearTimeout(timer);reader.releaseLock();}
 try{const parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)));if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error();return parsed;}catch{throw new HttpError(400,'Invalid JSON object');}
}
/** roleAllowed: 해당 작업에 허용된 역할인지 확인합니다 주요 호출: includes. */ export function roleAllowed(role:string,roles:readonly string[]){return roles.includes(role);}
