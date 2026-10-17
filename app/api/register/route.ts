import {randomUUID} from 'node:crypto';
import {db} from '../../../lib/db';
import {hashPassword,tokenHash} from '../../../lib/password';
import {registrationInput} from '../../../lib/registration';
import {body,sameOrigin,limit,event,failure,HttpError} from '../../../lib/security';
export async function POST(req:Request){try{
 sameOrigin(req);if(process.env.PUBLIC_REGISTRATION_ENABLED==='false')throw new HttpError(403,'Insufficient permission');await limit('register:global',10,600);
 const input=registrationInput(await body(req));if(!input)throw new HttpError(400,'Invalid registration');
 await limit('register:'+tokenHash(input.email),3,3600);
 // Only a constrained DB function can create viewer accounts. Never accept a role from the client.
 await db.query('SELECT public.register_viewer($1::uuid,$2::text,$3::text)',[randomUUID(),input.email,hashPassword(input.password)]);
 // A duplicate request still belongs only to the matching account's audit history.
 const account=await db.query('SELECT id FROM users WHERE email=$1',[input.email]);
 await event('registration_requested',account.rows[0]?.id??null);
 // Same response for a duplicate email; never alter its password or role.
 return Response.json({ok:true},{status:202,headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
