import {body,sameOrigin,requireUser,limit,failure,HttpError} from '../../../lib/security';
import {authSourceBucket} from '../../../lib/auth-rate-identity';
import {requestLocale} from '../../../lib/request-locale';
import {inspectJavaRuntime} from '../../../lib/java-runtime-review';
export const runtime='nodejs';
export const dynamic='force-dynamic';
/** Review supplied JVM observations without contacting or executing the target. */
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser();await limit('java-review:'+user.id,10,60);await limit(authSourceBucket('assessment',req),60,60);await limit('java-review:global',100,60);
 const data=await body(req,4096);if(data.authorized!==true||Object.keys(data).some(k=>!['authorized','runtime'].includes(k)))throw new HttpError(400,'Invalid assessment input');
 let report;try{report=inspectJavaRuntime(data.runtime,requestLocale(req.headers).locale==='ko'?'ko':'en');}catch{throw new HttpError(400,'Invalid assessment input');}
 return Response.json({report},{headers:{'Cache-Control':'no-store, private'}});
}catch(e){return failure(e,req);}}
