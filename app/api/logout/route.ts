import { cookies } from 'next/headers';
import { db } from '../../../lib/db';
import { tokenHash } from '../../../lib/password';
import { sameOrigin,failure } from '../../../lib/security';
import {secureOriginCookie} from '../../../lib/access-origins';
/** POST: 현재 세션을 폐기하고 로그아웃 응답을 만듭니다。 */ export async function POST(req:Request){try{sameOrigin(req);const t=(await cookies()).get('wg_session')?.value;if(t)await db.query('DELETE FROM sessions WHERE token_hash=$1',[tokenHash(t)]);return Response.json({ok:true},{headers:{'Cache-Control':'no-store','Set-Cookie':`wg_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureOriginCookie(req)?'; Secure':''}`}});}catch(e){return failure(e,req);}}
