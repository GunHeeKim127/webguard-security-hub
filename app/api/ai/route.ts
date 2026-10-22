import {withAiBudget} from '../../../lib/ai-budget';
import {aiProviderError} from '../../../lib/ai-provider-error';
import {providerConfigs,generateAdvice} from '../../../lib/ai-providers';
import {adviceChain} from '../../../lib/ai-chain';
import {adviceKey,cachedAdvice} from '../../../lib/advice-cache';
import {localAdvice} from '../../../lib/local-advice';
import {tokenHash} from '../../../lib/password';
import {requestLocale} from '../../../lib/request-locale';
import {db} from '../../../lib/db';
import {body,sameOrigin,requireUser,limit,event,failure,HttpError} from '../../../lib/security';
export const runtime='nodejs';
export const maxDuration=60;
export async function POST(req:Request){try{
 sameOrigin(req);const user=await requireUser();await limit('ai-attempt:'+user.id,10,60);
 const data=await body(req);if(typeof data.scanId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(data.scanId))throw new HttpError(400,'Invalid scan ID');
 const r=await db.query('SELECT result FROM scans WHERE id=$1 AND user_id=$2',[data.scanId,user.id]);if(!r.rowCount)throw new HttpError(404,'Scan not found');
 const configs=providerConfigs();if(process.env.AI_ENABLED!=='true'||!configs.length)throw new HttpError(503,'AI disabled: configure server environment');
 const checks=r.rows[0].result.checks,locale=requestLocale(req.headers).locale,query=(sql:string,values:unknown[])=>db.query(sql,values);
 const codes=['AI_QUOTA_EXCEEDED','AI_RATE_LIMITED','AI_AUTH_FAILED','AI_MODEL_UNAVAILABLE','AI_CONNECTION_FAILED','AI_REQUEST_REJECTED','AI_PROVIDER_FAILED'];
 const result=await adviceChain(configs,config=>cachedAdvice(query,adviceKey(config.provider+':'+config.model,locale,checks,user.id),async()=>{
  const cooldown='ai-cooldown:'+config.provider+':'+tokenHash(config.apiKey);
  const blocked=(await query('SELECT hits FROM rate_limits WHERE bucket=$1 AND reset_at>now()',[cooldown])).rows[0];
  if(blocked)throw new HttpError(503,codes[blocked.hits-1]??'AI_PROVIDER_FAILED');
  return withAiBudget(query,'ai:'+user.id,async()=>{
   let advice;
   try{advice=await generateAdvice(config,locale,checks);if(!advice.advice.trim())throw new HttpError(503,'AI_PROVIDER_FAILED');}
   catch(error){const code=error instanceof HttpError?error.message:aiProviderError(error);if(!code)throw error;
    console.warn('[WebGuard AI]',{provider:config.provider,code});
    const seconds=code==='AI_QUOTA_EXCEEDED'?1800:code==='AI_RATE_LIMITED'?60:code==='AI_AUTH_FAILED'||code==='AI_MODEL_UNAVAILABLE'?600:30;
    await query("INSERT INTO rate_limits(bucket,hits,reset_at) VALUES($1,$2,now()+$3*interval '1 second') ON CONFLICT(bucket) DO UPDATE SET hits=EXCLUDED.hits,reset_at=EXCLUDED.reset_at",[cooldown,codes.indexOf(code)+1,seconds]);
    throw new HttpError(503,code);
   }
   await event('ai_advice',user.id);return advice;
  });
 }));
 return Response.json(result.source==='local'?{...result,advice:localAdvice(locale,checks)}:result,{headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
