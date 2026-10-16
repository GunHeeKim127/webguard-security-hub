import {providerConfigs} from '../../../lib/ai-providers';
import {db} from '../../../lib/db';
import {requireUser,failure} from '../../../lib/security';
import {approvedHosts} from '../../../lib/scan-policy';
export const dynamic='force-dynamic';
export async function GET(req:Request){try{
 const user=await requireUser();
 const [scans,events,recent,total]=await Promise.all([
  db.query('SELECT id,hostname,result,created_at FROM scans ORDER BY created_at DESC LIMIT 30'),
  db.query("SELECT category,count(*)::int AS count FROM events WHERE created_at>now()-interval '24 hours' GROUP BY category"),
  db.query("SELECT category,created_at FROM events WHERE created_at>now()-interval '24 hours' ORDER BY id DESC LIMIT 12"),
  db.query('SELECT count(*)::int AS count FROM scans')
 ]);
 const hosts=approvedHosts();
 return Response.json({user,scans:scans.rows,events:events.rows,recentEvents:recent.rows,aiEnabled:process.env.AI_ENABLED==='true'&&providerConfigs().length>0,aiProviders:providerConfigs().map(({provider,model})=>({provider,model})),overview:{approvedCount:hosts.length,approvedHosts:user.role==='viewer'?[]:hosts,savedCount:total.rows[0].count,updatedAt:new Date().toISOString()}},{headers:{'Cache-Control':'no-store'}});
}catch(e){return failure(e,req);}}
