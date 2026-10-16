import { randomUUID } from 'node:crypto';
import { db } from '../../../lib/db';
import { scan } from '../../../lib/scanner';
import { body,sameOrigin,requireUser,limit,event,failure,HttpError } from '../../../lib/security';
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser(['admin','analyst']);await limit('scan:'+user.id,5,60);
 const data=await body(req);if(typeof data.url!=='string'||data.url.length>300||data.authorized!==true)throw new HttpError(400,'Owned target and authorization confirmation required');
 let result;try{result=await scan(data.url,(process.env.ALLOWED_SCAN_HOSTS??'').split(',').map(s=>s.trim()).filter(Boolean));}catch{await event('scan_rejected');throw new HttpError(400,'Target rejected or unreachable. Check allowlist, public DNS and TLS.');}
 const id=randomUUID();await db.query('INSERT INTO scans(id,user_id,hostname,result) VALUES($1,$2,$3,$4)',[id,user.id,new URL(data.url).hostname,JSON.stringify(result)]);await event('scan_completed');return Response.json({id,result});
 }catch(e){return failure(e);}}
