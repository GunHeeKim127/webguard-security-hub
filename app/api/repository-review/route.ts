import {body,sameOrigin,requireUser,limit,failure,HttpError} from '../../../lib/security';
import {authSourceBucket} from '../../../lib/auth-rate-identity';
import {requestLocale} from '../../../lib/request-locale';
import {inspectRepositoryFiles} from '../../../lib/repository-review';
import {inspectGithubRepository} from '../../../lib/github-repository-review';
import {inspectGithubAdvisories} from '../../../lib/github-advisories';
import type {RepositoryFile} from '../../../lib/repository-review';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const maxDuration=40;
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser();await limit('repository-review:'+user.id,3,60);await limit(authSourceBucket('assessment',req),60,60);await limit('repository-review:global',30,60);
 const data=await body(req,1000000);if(data.authorized!==true||Object.keys(data).some(k=>!['authorized','files','url','advisories'].includes(k))||('files'in data)===('url'in data)||data.advisories!==undefined&&typeof data.advisories!=='boolean')throw new HttpError(400,'Invalid assessment input');
 const locale=requestLocale(req.headers).locale==='ko'?'ko':'en';
 try{
  const signal=AbortSignal.any([req.signal,AbortSignal.timeout(25000)]);
  let result;
  if('url'in data)result=await inspectGithubRepository(data.url,locale,signal,fetch,data.advisories===true);
  else {const report=inspectRepositoryFiles(data.files,locale);result={report,advisories:await inspectGithubAdvisories(data.files as RepositoryFile[],data.advisories===true,signal)};}
  return Response.json(result,{headers:{'Cache-Control':'no-store, private'}});
 }catch(e){
  const code=e instanceof Error?e.message:'';
  // Fixed codes only: never return source, upstream response bodies, tokens or stack traces.
  if(['REPOSITORY_URL','INPUT_INVALID'].includes(code))return Response.json({errorCode:code},{status:400,headers:{'Cache-Control':'no-store'}});
  return Response.json({errorCode:['GITHUB_RATE_LIMIT','GITHUB_NOT_FOUND','GITHUB_RESPONSE_TOO_LARGE'].includes(code)?code:'GITHUB_UNAVAILABLE'},{status:code==='GITHUB_RATE_LIMIT'?429:502,headers:{'Cache-Control':'no-store'}});
 }
}catch(e){return failure(e,req);}}
