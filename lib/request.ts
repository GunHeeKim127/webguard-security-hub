import {accessOrigins} from './access-origins';
export class HttpError extends Error { constructor(public status:number,message:string){super(message);} }
export function sameOrigin(req:Request) {
 const origin=req.headers.get('origin');
 if(!origin||!accessOrigins().includes(origin)||new URL(origin).host!==(req.headers.get('host')??new URL(req.url).host))throw new HttpError(403,'Origin rejected');
}
export async function body(req:Request,maxBytes=4096,timeoutMs=10000) {
 if(req.headers.get('content-type')?.split(';',1)[0].trim().toLowerCase()!=='application/json') throw new HttpError(415,'JSON required');
 const reader=req.body?.getReader(); if(!reader) throw new HttpError(400,'Body required');
 const parts:Uint8Array[]=[]; let size=0,timer:ReturnType<typeof setTimeout>|undefined;
 const deadline=new Promise<never>((_,reject)=>{timer=setTimeout(()=>{reject(new HttpError(408,'Request body timeout'));void reader.cancel().catch(()=>{});},timeoutMs);});
 try{await Promise.race([deadline,(async()=>{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new HttpError(413,'Body too large');}parts.push(value);}})()]);}finally{clearTimeout(timer);reader.releaseLock();}
 try{const parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)));if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error();return parsed;}catch{throw new HttpError(400,'Invalid JSON object');}
}
export function roleAllowed(role:string,roles:readonly string[]){return roles.includes(role);}
