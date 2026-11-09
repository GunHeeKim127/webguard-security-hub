import type {RepositoryFile} from './repository-review';
import {githubPublicJson} from './github-public-json';
export type Advisory={id:string;cve:string|null;summary:string;severity:string;url:string;ranges:{affected:string;patched:string|null}[]};
export type AdvisoryReview={status:'not_requested'|'completed'|'partial';eligiblePackages:number;unresolvedPackages:string[];unparsedFiles:string[];omittedPackages:number;checks:{name:string;version:string;status:'matched'|'no_matches'|'unavailable'|'not_checked';errorCode?:string;truncated?:boolean;advisories:Advisory[]}[];observedAt:string};
const packageName=(name:string)=>/^(?:@[a-z\d][a-z\d._-]*\/)?[a-z\d][a-z\d._-]*$/.test(name)&&name.length<=150;
const exact=(value:unknown):value is string=>typeof value==='string'&&/^\d{1,5}\.\d{1,5}\.\d{1,5}$/.test(value);
/** Extract declared versions only; never install packages or resolve ranges by guessing. */
export function repositoryPackages(files:RepositoryFile[]){
 const known=new Map<string,{name:string;version:string}>(),unknown=new Set<string>(),unparsedFiles:string[]=[];
 const add=(name:string,version:unknown)=>{if(!packageName(name))return;if(exact(version))known.set(name+'@'+version,{name,version});else unknown.add(name);};
 for(const file of files){
  if(!/(?:^|\/)(?:package|package-lock)\.json$/i.test(file.path))continue;
  let value;try{value=JSON.parse(file.text);}catch{unparsedFiles.push(file.path);continue;}
  if(!value||typeof value!=='object'||Array.isArray(value)){unparsedFiles.push(file.path);continue;}
  if(/package-lock\.json$/i.test(file.path)&&(![2,3].includes(value.lockfileVersion)||!value.packages||typeof value.packages!=='object'||Array.isArray(value.packages))){unparsedFiles.push(file.path);continue;}
  for(const group of ['dependencies','devDependencies','optionalDependencies'])if(value[group]&&typeof value[group]==='object'&&!Array.isArray(value[group]))for(const [name,entry]of Object.entries(value[group]))add(name,typeof entry==='string'?entry:(entry as {version?:unknown})?.version);
  if(value.packages&&typeof value.packages==='object'&&!Array.isArray(value.packages))for(const [path,entry]of Object.entries(value.packages)){
   if(!path.includes('node_modules/')||!entry||typeof entry!=='object')continue;add(path.split('node_modules/').at(-1)!, (entry as {version?:unknown}).version);
  }
 }
 for(const value of known.values())unknown.delete(value.name);
 const priority=(name:string)=>['next','react','react-dom','react-server-dom-webpack','react-server-dom-parcel','react-server-dom-turbopack'].indexOf(name);
 const packages=[...known.values()].sort((a,b)=>(priority(a.name)<0?99:priority(a.name))-(priority(b.name)<0?99:priority(b.name))||a.name.localeCompare(b.name)||a.version.localeCompare(b.version));
 return {packages,unresolvedPackages:[...unknown].sort(),unparsedFiles};
}
/** GitHub-reviewed advisories for up to five exact npm versions. Failure never becomes a clean result. */
export async function inspectGithubAdvisories(files:RepositoryFile[],enabled:boolean,signal:AbortSignal,request:typeof fetch=fetch):Promise<AdvisoryReview>{
 const inventory=repositoryPackages(files),checks:AdvisoryReview['checks']=[],selected=inventory.packages.slice(0,5);
 if(!enabled)return {status:'not_requested',eligiblePackages:inventory.packages.length,unresolvedPackages:inventory.unresolvedPackages,unparsedFiles:inventory.unparsedFiles,omittedPackages:inventory.packages.length,checks,observedAt:new Date().toISOString()};
 let stopped=false;
 for(const entry of selected){
  if(stopped||signal.aborted){checks.push({...entry,status:'not_checked',advisories:[]});continue;}
  try{
   const query=new URLSearchParams({ecosystem:'npm',affects:entry.name+'@'+entry.version,type:'reviewed',is_withdrawn:'false',per_page:'20'});
   const rows=await githubPublicJson('https://api.github.com/advisories?'+query,524288,signal,request);
   if(!Array.isArray(rows)||rows.length>20)throw new Error('GITHUB_UNAVAILABLE');
   const advisories:Advisory[]=rows.map(row=>{
    if(!row||typeof row!=='object'||!/^GHSA-(?:[a-z\d]{4}-){2}[a-z\d]{4}$/i.test(row.ghsa_id)||row.type!=='reviewed'||row.withdrawn_at!==null||!Array.isArray(row.vulnerabilities))throw new Error('GITHUB_UNAVAILABLE');
    const matches=row.vulnerabilities.filter((v:unknown)=>!!v&&typeof v==='object'&&(v as {package?:{ecosystem?:unknown;name?:unknown}}).package?.ecosystem==='npm'&&(v as {package:{name?:unknown}}).package.name===entry.name);
    if(!matches.length)throw new Error('GITHUB_UNAVAILABLE');
    return {id:row.ghsa_id,cve:typeof row.cve_id==='string'&&/^CVE-\d{4}-\d{4,}$/.test(row.cve_id)?row.cve_id:null,summary:typeof row.summary==='string'?row.summary.slice(0,1000):'',severity:['low','medium','high','critical'].includes(row.severity)?row.severity:'unknown',url:'https://github.com/advisories/'+row.ghsa_id,ranges:matches.slice(0,20).map((v:{vulnerable_version_range?:unknown;first_patched_version?:unknown})=>({affected:typeof v.vulnerable_version_range==='string'?v.vulnerable_version_range.slice(0,200):'unknown',patched:typeof v.first_patched_version==='string'?v.first_patched_version.slice(0,100):null}))};
   });
   checks.push({...entry,status:advisories.length?'matched':'no_matches',truncated:rows.length===20,advisories});
  }catch(e){const code=e instanceof Error&&e.message==='GITHUB_RATE_LIMIT'?'GITHUB_RATE_LIMIT':'GITHUB_UNAVAILABLE';checks.push({...entry,status:'unavailable',errorCode:code,advisories:[]});if(code==='GITHUB_RATE_LIMIT'||signal.aborted)stopped=true;}
 }
 const omittedPackages=Math.max(0,inventory.packages.length-selected.length);
 return {status:omittedPackages||inventory.unresolvedPackages.length||inventory.unparsedFiles.length||checks.some(c=>c.status==='unavailable'||c.status==='not_checked'||c.truncated)?'partial':'completed',eligiblePackages:inventory.packages.length,unresolvedPackages:inventory.unresolvedPackages,unparsedFiles:inventory.unparsedFiles,omittedPackages,checks,observedAt:new Date().toISOString()};
}
