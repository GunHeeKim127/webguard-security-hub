import {randomUUID} from 'node:crypto';
import {db} from '../../../lib/db';
import {hashPassword,tokenHash} from '../../../lib/password';
import {registrationInput} from '../../../lib/registration';
import {body,sameOrigin,limit,event,failure,HttpError} from '../../../lib/security';
export async function POST(req:Request){try{
 sameOrigin(req);await limit('register:global',10,600);
 const input=registrationInput(await body(req));if(!input)throw new HttpError(400,'Invalid registration');
 await limit('register:'+tokenHash(input.email),3,3600);
 // Only a constrained DB function can create viewer accounts. Never accept a role from the client.
 await db.query('SELECT public.register_viewer($1::uuid,$2::text,$3::text)',[randomUUID(),input.email,hashPassword(input.password)]);
 await event('registration_requested');
 // Same response for a duplicate email; never alter its password or role.
 return Response.json({ok:true},{status:202,headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
