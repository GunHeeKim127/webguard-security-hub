import {publicUser,publicIpBlock,publicAccountBlock,publicEvents,publicEventCategory} from '../../../lib/public-identity';
import {providerConfigs} from '../../../lib/ai-providers';
import {db} from '../../../lib/db';
import {requireUser,failure} from '../../../lib/security';
import {approvedHosts,targetPolicy} from '../../../lib/scan-policy';
export const dynamic='force-dynamic';
export async function GET(req:Request){try{
 const user=await requireUser();
 const [scans,events,recent,total,blocks,accounts]=await Promise.all([
  db.query("SELECT id,hostname,result,created_at FROM scans WHERE user_id=$1 AND created_at>=now()-interval '30 days' ORDER BY created_at DESC LIMIT 30",[user.id]),
  db.query("SELECT category,count(*)::int AS count FROM events WHERE user_id=$1 AND created_at>now()-interval '24 hours' GROUP BY category",[user.id]),
  db.query("SELECT category,created_at FROM events WHERE user_id=$1 AND created_at>now()-interval '24 hours' ORDER BY id DESC LIMIT 12",[user.id]),
  db.query('SELECT count(*)::int AS count FROM scans WHERE user_id=$1 AND created_at>=now()-interval \'30 days\'',[user.id]),
  user.role==='admin'?db.query('SELECT management_id,host(address) AS address,strikes,blacklisted,blocked_until,last_reason,last_seen FROM public.ip_blocks WHERE strikes>0 ORDER BY last_seen DESC LIMIT 50'):Promise.resolve({rows:[]}),
  user.role==='admin'?db.query('SELECT b.management_id,u.email,b.strikes,b.blacklisted,b.last_reason,b.last_seen FROM public.account_blocks b JOIN public.users u ON u.id=b.user_id WHERE b.strikes>0 ORDER BY b.last_seen DESC LIMIT 50'):Promise.resolve({rows:[]})
 ]);
 const hosts=approvedHosts();
 return Response.json({user:publicUser(user),scans:scans.rows,events:publicEvents(events.rows),recentEvents:recent.rows.map(row=>({category:publicEventCategory(row.category),created_at:row.created_at})),...(user.role==='admin'?{ipBlocks:blocks.rows.map(publicIpBlock),accountBlocks:accounts.rows.map(publicAccountBlock)}:{}),aiEnabled:process.env.AI_ENABLED==='true'&&providerConfigs().length>0,aiProviders:providerConfigs().map(({provider,model})=>({provider,model})),overview:{targetPolicy:targetPolicy(),approvedCount:hosts.length,approvedHosts:hosts,savedCount:total.rows[0].count,updatedAt:new Date().toISOString()}},{headers:{'Cache-Control':'no-store'}});
}catch(e){return failure(e,req);}}
