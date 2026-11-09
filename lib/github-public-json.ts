/** Read bounded JSON from the fixed official API. No credentials, redirects or caller-provided origins. */
export async function githubPublicJson(url:string,maxBytes:number,signal:AbortSignal,request:typeof fetch=fetch):Promise<unknown>{
 const target=new URL(url);if(target.origin!=='https://api.github.com'||target.username||target.password)throw new Error('GITHUB_UNAVAILABLE');signal.throwIfAborted();
 const response=await request(target.href,{signal,redirect:'error',cache:'no-store',headers:{Accept:'application/vnd.github+json','User-Agent':'VELTHARA-static-review','X-GitHub-Api-Version':'2022-11-28'}});
 if(!response.ok){await response.body?.cancel();throw new Error(response.status===403||response.status===429?'GITHUB_RATE_LIMIT':response.status===404?'GITHUB_NOT_FOUND':'GITHUB_UNAVAILABLE');}
 const reader=response.body?.getReader();if(!reader)throw new Error('GITHUB_UNAVAILABLE');let size=0;const chunks:Uint8Array[]=[];
 try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes)throw new Error('GITHUB_RESPONSE_TOO_LARGE');chunks.push(value);}}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
}
