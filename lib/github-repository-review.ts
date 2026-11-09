import {createHash} from 'node:crypto';
import {inspectRepositoryFiles,reviewablePath,type RepositoryFile} from './repository-review';

export function githubRepository(value:unknown){
 if(typeof value!=='string'||value.length>200)throw new Error('REPOSITORY_URL');
 let url:URL;try{url=new URL(value);}catch{throw new Error('REPOSITORY_URL');}
 if(url.protocol!=='https:'||url.hostname!=='github.com'||url.port||url.username||url.password||url.search||url.hash||!/^\/[A-Za-z\d](?:[A-Za-z\d-]{0,38})\/[A-Za-z\d_.-]{1,100}\/?$/.test(url.pathname))throw new Error('REPOSITORY_URL');
 const [owner,repo]=url.pathname.slice(1).replace(/\/$/,'').split('/');
 if(repo==='.'||repo==='..'||repo.endsWith('.git'))throw new Error('REPOSITORY_URL');
 return {owner,repo};
}
/** GitHub API only; no clone, archive extraction, redirects, tokens or repository-provided URLs. */
export async function inspectGithubRepository(value:unknown,locale:'ko'|'en',signal:AbortSignal,request:typeof fetch=fetch){
 const {owner,repo}=githubRepository(value),base=`https://api.github.com/repos/${owner}/${repo}`;
 async function json(url:string,maxBytes:number):Promise<any>{
  signal.throwIfAborted();
  const response=await request(url,{signal,redirect:'error',cache:'no-store',headers:{Accept:'application/vnd.github+json','User-Agent':'VELTHARA-static-review','X-GitHub-Api-Version':'2022-11-28'}});
  if(!response.ok){await response.body?.cancel();throw new Error(response.status===403||response.status===429?'GITHUB_RATE_LIMIT':response.status===404?'GITHUB_NOT_FOUND':'GITHUB_UNAVAILABLE');}
  const reader=response.body?.getReader();if(!reader)throw new Error('GITHUB_UNAVAILABLE');
  let size=0;const chunks:Uint8Array[]=[];
  try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes)throw new Error('GITHUB_RESPONSE_TOO_LARGE');chunks.push(value);}}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
 }
 const metadata=await json(base,32768);
 if(metadata.private!==false||typeof metadata.default_branch!=='string'||metadata.default_branch.length>200)throw new Error('GITHUB_UNAVAILABLE');
 const commit=await json(`${base}/commits/${encodeURIComponent(metadata.default_branch)}`,262144);
 const sha=commit.sha,treeSha=commit.commit?.tree?.sha;
 if(!/^[a-f\d]{40}$/.test(sha)||!/^[a-f\d]{40}$/.test(treeSha))throw new Error('GITHUB_UNAVAILABLE');
 const tree=await json(`${base}/git/trees/${treeSha}?recursive=1`,1048576);
 if(!Array.isArray(tree.tree)||tree.tree.length>5000)throw new Error('GITHUB_RESPONSE_TOO_LARGE');
 const candidates=tree.tree.filter((entry:any)=>entry.type==='blob'&&typeof entry.path==='string'&&reviewablePath(entry.path));
 // Prioritize build/install entry points; the cap is explicitly partial coverage.
 candidates.sort((a:any,b:any)=>priority(a.path)-priority(b.path)||a.path.localeCompare(b.path));
 const files:RepositoryFile[]=[],skipped:{path:string;reason:string}[]=[];let total=0;
 for(const entry of candidates){
  signal.throwIfAborted();
  if(files.length>=12){skipped.push({path:entry.path,reason:'file-count-limit'});continue;}
  if(entry.mode!=='100644'&&entry.mode!=='100755'||!Number.isSafeInteger(entry.size)||entry.size<0||entry.size>32768||total+entry.size>262144||!/^[a-f\d]{40}$/.test(entry.sha)){skipped.push({path:entry.path,reason:'unsupported-or-size-limit'});continue;}
  const blob=await json(`${base}/git/blobs/${entry.sha}`,65536);
  if(blob.encoding!=='base64'||typeof blob.content!=='string'||blob.size!==entry.size)throw new Error('GITHUB_UNAVAILABLE');
  const encoded=blob.content.replace(/\n/g,''),bytes=Buffer.from(encoded,'base64');
  if(bytes.length!==entry.size||bytes.toString('base64')!==encoded||createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')!==entry.sha)throw new Error('GITHUB_UNAVAILABLE');
  let text:string;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);if(text.includes('\0'))throw new Error();}catch{skipped.push({path:entry.path,reason:'not-utf8-text'});continue;}
  files.push({path:entry.path,text});total+=bytes.length;
 }
 const report=files.length?inspectRepositoryFiles(files,locale):null;
 return {repository:`https://github.com/${owner}/${repo}`,commit:sha,report,coverage:{treeTruncated:tree.truncated===true,listedEntries:tree.tree.length,candidateFiles:candidates.length,checkedFiles:files.map(f=>f.path),skipped,excludedEntries:tree.tree.length-candidates.length,partial:true}};
}
function priority(path:string){
 if(/^(?:docs|tests)\//i.test(path))return 5;
 if(/(?:package\.json|\.(?:csproj|props|targets)|\.github\/workflows\/|(?:^|\/)(?:install|setup)\.)/i.test(path))return 0;
 if(/^readme(?:\.|$)/i.test(path))return 1;
 if(/\.(?:py|go|ps1|sh|bat|cmd)$/i.test(path))return 2;
 return /\.md$/i.test(path)?4:3;
}
