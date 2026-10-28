import {body,sameOrigin,requireUser,limit,failure,HttpError} from '../../../lib/security';
import {requestLocale} from '../../../lib/request-locale';
import {authSourceBucket} from '../../../lib/auth-rate-identity';
import {inspectSource} from '../../../lib/source-inspection';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser();await limit('source-inspection:'+user.id,5,60);await limit(authSourceBucket('assessment',req),60,60);await limit('source-inspection:global',300,60);
 const data=await body(req,400000);
 if(Object.keys(data).some(k=>!['text','authorized'].includes(k))||data.authorized!==true||typeof data.text!=='string')throw new HttpError(400,'Invalid assessment input');
 let report;try{report=inspectSource(data.text,requestLocale(req.headers).locale==='ko'?'ko':'en');}catch{throw new HttpError(400,'Invalid assessment input');}
 return Response.json({report},{headers:{'Cache-Control':'no-store, private'}});
}catch(e){return failure(e,req);}}
