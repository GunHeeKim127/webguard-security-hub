import {providerConfigs} from '../../../lib/ai-providers';
import {db} from '../../../lib/db';
import {requireUser,failure} from '../../../lib/security';
import {approvedHosts,targetPolicy} from '../../../lib/scan-policy';
export const dynamic='force-dynamic';
export async function GET(req:Request){try{
 const user=await requireUser();
 const [scans,events,recent,total,blocks]=await Promise.all([
  db.query('SELECT id,hostname,result,created_at FROM scans WHERE user_id=$1 ORDER BY created_at DESC LIMIT 30',[user.id]),
  db.query("SELECT category,count(*)::int AS count FROM events WHERE user_id=$1 AND created_at>now()-interval '24 hours' GROUP BY category",[user.id]),
  db.query("SELECT category,created_at FROM events WHERE user_id=$1 AND created_at>now()-interval '24 hours' ORDER BY id DESC LIMIT 12",[user.id]),
  db.query('SELECT count(*)::int AS count FROM scans WHERE user_id=$1',[user.id]),
  user.role==='admin'?db.query('SELECT host(address) AS address,strikes,blacklisted,blocked_until,last_reason,last_seen FROM public.ip_blocks WHERE strikes>0 ORDER BY last_seen DESC LIMIT 50'):Promise.resolve({rows:[]})
 ]);
 const hosts=approvedHosts();
 return Response.json({user,scans:scans.rows,events:events.rows,recentEvents:recent.rows,...(user.role==='admin'?{ipBlocks:blocks.rows}:{}),aiEnabled:process.env.AI_ENABLED==='true'&&providerConfigs().length>0,aiProviders:providerConfigs().map(({provider,model})=>({provider,model})),overview:{targetPolicy:targetPolicy(),approvedCount:hosts.length,approvedHosts:user.role==='viewer'?[]:hosts,savedCount:total.rows[0].count,updatedAt:new Date().toISOString()}},{headers:{'Cache-Control':'no-store'}});
}catch(e){return failure(e,req);}}
