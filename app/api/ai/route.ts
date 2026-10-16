import OpenAI from 'openai';
import { db } from '../../../lib/db';
import { body,sameOrigin,requireUser,limit,event,failure,HttpError } from '../../../lib/security';
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser(['admin','analyst']);await limit('ai:'+user.id,3,3600);
 if(process.env.AI_ENABLED!=='true'||!process.env.OPENAI_API_KEY||!process.env.OPENAI_MODEL)throw new HttpError(503,'AI disabled: configure server environment');
 const data=await body(req);if(typeof data.scanId!=='string'||!/^[a-f0-9-]{36}$/.test(data.scanId))throw new HttpError(400,'Invalid scan ID');
 const r=await db.query('SELECT result FROM scans WHERE id=$1',[data.scanId]);if(!r.rowCount)throw new HttpError(404,'Scan not found');
 // Only locally generated booleans/header names go to OpenAI. No target HTML, credentials, hostname or logs.
 const client=new OpenAI({apiKey:process.env.OPENAI_API_KEY,timeout:20000,maxRetries:0});
 const result=await client.responses.create({model:process.env.OPENAI_MODEL,store:false,max_output_tokens:800,instructions:'Explain these security header presence checks in Korean. Presence alone does not establish security. Give defensive remediation only. You cannot execute changes or guarantee safety.',input:JSON.stringify(r.rows[0].result.checks)});
 await event('ai_advice');return Response.json({advice:result.output_text},{headers:{'Cache-Control':'no-store'}});
 }catch(e){return failure(e);}}
