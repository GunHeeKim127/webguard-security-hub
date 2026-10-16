import {isLocale,locales} from '../../../lib/locale';
import {requestLocale} from '../../../lib/request-locale';
import {sameOrigin,body,HttpError,failure} from '../../../lib/security';
import {secureOriginCookie} from '../../../lib/access-origins';
export async function GET(req:Request){const selection=requestLocale(req.headers);return Response.json({...selection,supportedLocales:locales},{headers:{'Cache-Control':'no-store','Content-Language':selection.locale,'Vary':'Cookie, Accept-Language'}});}
export async function POST(req:Request){try{
 sameOrigin(req);const data=await body(req);if(!isLocale(data.locale))throw new HttpError(400,'Invalid locale');
 return Response.json({locale:data.locale},{headers:{'Cache-Control':'no-store','Content-Language':data.locale,'Set-Cookie':`wg_locale=${data.locale}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000${secureOriginCookie(req)?'; Secure':''}`}});
}catch(e){return failure(e,req);}}
