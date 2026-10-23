import {db} from '../../../lib/db';
import {body,limit,failure,HttpError} from '../../../lib/security';
import {tokenHash} from '../../../lib/password';
export const runtime='nodejs';
export const maxDuration=15;
// Server-to-server only. Tokens must never be embedded in a browser script.
export async function POST(req:Request){try{
 const bearer=req.headers.get('authorization');if(!bearer||!/^Bearer [0-9a-f]{64}$/.test(bearer))throw new HttpError(401,'Login required');
 const data=await body(req);
 const keys=['assetId','requests','loginFailures','probes','serverErrors'];
 if(Object.keys(data).some(k=>!keys.includes(k))||typeof data.assetId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(data.assetId))throw new HttpError(400,'Invalid scan ID');
 for(const k of keys.slice(1))if(!Number.isInteger(data[k])||data[k]<0||data[k]>1000)throw new HttpError(400,'Invalid scan ID');
 if(data.requests<1||[data.loginFailures,data.probes,data.serverErrors].some(n=>n>data.requests))throw new HttpError(400,'Invalid scan ID');
 const owner=await db.query("SELECT id,user_id FROM public.assessment_assets WHERE id=$1 AND ingest_token_hash=$2 AND module_id='web.compare' AND updated_at>=now()-interval '30 days'",[data.assetId,tokenHash(bearer.slice(7))]);
 if(!owner.rowCount)throw new HttpError(401,'Login required');
 await limit('telemetry:'+data.assetId,60,60);
 await db.query(`INSERT INTO public.assessment_traffic(user_id,asset_id,window_at,requests,login_failures,probes,server_errors)
 VALUES($1,$2,date_trunc('minute',now()),$3,$4,$5,$6)
 ON CONFLICT(user_id,asset_id,window_at) DO UPDATE SET requests=assessment_traffic.requests+EXCLUDED.requests,
 login_failures=assessment_traffic.login_failures+EXCLUDED.login_failures,probes=assessment_traffic.probes+EXCLUDED.probes,server_errors=assessment_traffic.server_errors+EXCLUDED.server_errors`,[owner.rows[0].user_id,data.assetId,data.requests,data.loginFailures,data.probes,data.serverErrors]);
 return Response.json({ok:true},{status:202,headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
