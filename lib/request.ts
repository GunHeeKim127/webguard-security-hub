import {accessOrigins} from './access-origins';
export class HttpError extends Error { constructor(public status:number,message:string){super(message);} }
export function sameOrigin(req:Request) {
 const origin=req.headers.get('origin');
 if(!origin||!accessOrigins().includes(origin)||new URL(origin).host!==(req.headers.get('host')??new URL(req.url).host))throw new HttpError(403,'Origin rejected');
}
export async function body(req:Request,maxBytes=4096) {
 if(req.headers.get('content-type')?.split(';',1)[0].trim().toLowerCase()!=='application/json') throw new HttpError(415,'JSON required');
 const reader=req.body?.getReader(); if(!reader) throw new HttpError(400,'Body required');
 const parts:Uint8Array[]=[]; let size=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new HttpError(413,'Body too large');}parts.push(value);}}finally{reader.releaseLock();}
 try{const parsed=JSON.parse(Buffer.concat(parts).toString());if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error();return parsed;}catch{throw new HttpError(400,'Invalid JSON object');}
}
export function roleAllowed(role:string,roles:readonly string[]){return roles.includes(role);}
