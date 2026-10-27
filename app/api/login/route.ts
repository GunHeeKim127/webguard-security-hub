import { randomBytes } from 'node:crypto';
import { db } from '../../../lib/db';
import { hashPassword,verifyPassword,tokenHash } from '../../../lib/password';
import { body,sameOrigin,limit,event,failure,HttpError } from '../../../lib/security';
import {secureOriginCookie} from '../../../lib/access-origins';
import {authSourceBucket} from '../../../lib/auth-rate-identity';
const dummy=hashPassword(randomBytes(32).toString('hex'));
export async function POST(req:Request){try{
 sameOrigin(req);await limit(authSourceBucket('login',req),30,60);await limit('login:global',300,60);
 const data=await body(req);if(typeof data.email!=='string'||typeof data.password!=='string'||data.email.length>254)throw new HttpError(400,'Invalid credentials');
 const email=data.email.trim().toLowerCase();await limit('login:'+tokenHash(email),5,300);
 const r=await db.query('SELECT u.id,u.password_hash,EXISTS(SELECT 1 FROM public.account_blocks b WHERE b.user_id=u.id AND b.blacklisted) AS blocked FROM users u WHERE u.email=$1',[email]);
 if(!verifyPassword(data.password,r.rows[0]?.password_hash??dummy)||!r.rowCount||r.rows[0]?.blocked){await event('login_failed',r.rows[0]?.id??null);throw new HttpError(401,'Invalid credentials');}
 const token=randomBytes(32).toString('hex');
 const inserted=await db.query("INSERT INTO sessions(token_hash,user_id,expires_at) SELECT $1,$2,now()+interval '8 hours' WHERE NOT EXISTS(SELECT 1 FROM public.account_blocks b WHERE b.user_id=$2 AND b.blacklisted) RETURNING user_id",[tokenHash(token),r.rows[0].id]);
 if(!inserted.rowCount)throw new HttpError(401,'Invalid credentials');
 await event('login_success',r.rows[0].id);
 return Response.json({ok:true},{headers:{'Cache-Control':'no-store','Set-Cookie':`wg_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secureOriginCookie(req)?'; Secure':''}`}});
 }catch(e){return failure(e,req);}}
