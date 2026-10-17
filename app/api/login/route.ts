import { randomBytes } from 'node:crypto';
import { db } from '../../../lib/db';
import { hashPassword,verifyPassword,tokenHash } from '../../../lib/password';
import { body,sameOrigin,limit,event,failure,HttpError } from '../../../lib/security';
import {secureOriginCookie} from '../../../lib/access-origins';
const dummy=hashPassword(randomBytes(32).toString('hex'));
export async function POST(req:Request){try{
 sameOrigin(req);await limit('login:global',30,60);
 const data=await body(req);if(typeof data.email!=='string'||typeof data.password!=='string'||data.email.length>254)throw new HttpError(400,'Invalid credentials');
 const email=data.email.trim().toLowerCase();await limit('login:'+tokenHash(email),5,300);
 const r=await db.query('SELECT id,password_hash FROM users WHERE email=$1',[email]);
 if(!verifyPassword(data.password,r.rows[0]?.password_hash??dummy)||!r.rowCount){await event('login_failed',r.rows[0]?.id??null);throw new HttpError(401,'Invalid credentials');}
 const token=randomBytes(32).toString('hex');
 await db.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '8 hours')",[tokenHash(token),r.rows[0].id]);
 await event('login_success',r.rows[0].id);
 return Response.json({ok:true},{headers:{'Cache-Control':'no-store','Set-Cookie':`wg_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secureOriginCookie(req)?'; Secure':''}`}});
 }catch(e){return failure(e,req);}}
