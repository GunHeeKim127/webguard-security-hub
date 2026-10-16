import 'server-only';
import { cookies } from 'next/headers';
import { db } from './db';
import {errorCode,errorText} from './errors-i18n';
import {requestLocale} from './request-locale';
import { tokenHash } from './password';
import { HttpError,roleAllowed } from './request';
export { HttpError,sameOrigin,body } from './request';
export async function currentUser(){
 const token=(await cookies()).get('wg_session')?.value;
 if(!token || token.length!==64) return null;
 const r=await db.query('SELECT u.id,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',[tokenHash(token)]);
 return r.rows[0] as {id:string,email:string,role:string}|undefined;
}
export async function requireUser(roles=['admin','analyst','viewer']) {
 const user=await currentUser();if(!user)throw new HttpError(401,'Login required');
 if(!roleAllowed(user.role,roles))throw new HttpError(403,'Insufficient permission');return user;
}
export async function limit(bucket:string,max:number,seconds:number){
 const r=await db.query(`INSERT INTO rate_limits(bucket,hits,reset_at) VALUES($1,1,now()+$2*interval '1 second') ON CONFLICT(bucket) DO UPDATE SET hits=CASE WHEN rate_limits.reset_at<=now() THEN 1 ELSE rate_limits.hits+1 END,reset_at=CASE WHEN rate_limits.reset_at<=now() THEN now()+$2*interval '1 second' ELSE rate_limits.reset_at END RETURNING hits`,[bucket,seconds]);
 if(r.rows[0].hits>max)throw new HttpError(429,'Rate limit exceeded');
}
export async function event(category:string){await db.query('INSERT INTO events(category) VALUES($1)',[category]);}
export function failure(e:unknown,req:Request){const status=e instanceof HttpError?e.status:503;const code=errorCode(e instanceof HttpError?e.message:'',status);const {locale}=requestLocale(req.headers);return Response.json({error:errorText(locale,code),errorCode:code,locale},{status,headers:{'Cache-Control':'no-store','Content-Language':locale,'Vary':'Cookie, Accept-Language'}});}
