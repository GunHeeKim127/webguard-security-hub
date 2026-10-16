import { db } from '../../../lib/db';
import { requireUser,failure } from '../../../lib/security';
export const dynamic='force-dynamic';
export async function GET(){try{const user=await requireUser();const scans=await db.query('SELECT id,hostname,result,created_at FROM scans ORDER BY created_at DESC LIMIT 30');const events=await db.query("SELECT category,count(*)::int AS count FROM events WHERE created_at>now()-interval '24 hours' GROUP BY category");return Response.json({user,scans:scans.rows,events:events.rows,aiEnabled:process.env.AI_ENABLED==='true'&&!!process.env.OPENAI_API_KEY},{headers:{'Cache-Control':'no-store'}});}catch(e){return failure(e);}}
