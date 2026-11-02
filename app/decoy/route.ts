import {requestLocale} from '../../lib/request-locale';
import {messages} from '../../lib/messages';
import { event,limit,failure } from '../../lib/security';
/** GET: 해당 경로의 조회 요청을 처리하고 응답을 반환합니다 주요 호출: limit·event·requestLocale. */ export async function GET(req:Request){try{await limit('decoy:global',60,60);await event('decoy_visit');return new Response(messages[requestLocale(req.headers).locale].notFound,{status:404,headers:{'Cache-Control':'no-store','Content-Type':'text/plain; charset=utf-8','Content-Language':requestLocale(req.headers).locale}});}catch(e){return failure(e,req);}}
