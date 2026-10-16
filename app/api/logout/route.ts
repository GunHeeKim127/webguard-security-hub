import { cookies } from 'next/headers';
import { db } from '../../../lib/db';
import { tokenHash } from '../../../lib/password';
import { sameOrigin,failure } from '../../../lib/security';
export async function POST(req:Request){try{sameOrigin(req);const t=(await cookies()).get('wg_session')?.value;if(t)await db.query('DELETE FROM sessions WHERE token_hash=$1',[tokenHash(t)]);return Response.json({ok:true},{headers:{'Set-Cookie':'wg_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'}});}catch(e){return failure(e);}}
