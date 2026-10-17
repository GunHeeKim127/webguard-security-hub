import {createHash,randomUUID} from 'node:crypto';
import {adviceHeaders} from './local-advice';
import type {CheckResult} from './inspection';
export type AdviceQuery=(sql:string,values:unknown[])=>Promise<{rows:any[]}>;
export type GeneratedAdvice={advice:string,inputTokens:number,outputTokens:number};
export function adviceKey(model:string,locale:string,checks:CheckResult['checks'],accountId?:string){return createHash('sha256').update(JSON.stringify({version:2,accountId:accountId??null,model,locale,output:400,checks:adviceHeaders.map(header=>!!checks.find(check=>check.header===header)?.present)})).digest('hex');}
export async function cachedAdvice(query:AdviceQuery,key:string,generate:()=>Promise<GeneratedAdvice>):Promise<GeneratedAdvice&{source:'ai'|'cache'}|{source:'busy'}>{
 const read=async()=>{const row=(await query('SELECT advice,input_tokens,output_tokens FROM ai_advice_cache WHERE cache_key=$1 AND expires_at>now() AND advice IS NOT NULL',[key])).rows[0];return row?{source:'cache' as const,advice:row.advice,inputTokens:row.input_tokens,outputTokens:row.output_tokens}:null;};
 const existing=await read();if(existing)return existing;
 const lease=randomUUID();const claim=await query(`INSERT INTO ai_advice_cache(cache_key,lease,expires_at) VALUES($1,$2,now()+interval '45 seconds')
 ON CONFLICT(cache_key) DO UPDATE SET lease=EXCLUDED.lease,advice=NULL,input_tokens=0,output_tokens=0,expires_at=EXCLUDED.expires_at
 WHERE ai_advice_cache.expires_at<=now() RETURNING lease`,[key,lease]);
 if(!claim.rows.length)return await read()??{source:'busy'};
 try{const result=await generate();if(!result.advice.trim())throw new Error('Empty advice');
  await query("UPDATE ai_advice_cache SET advice=$3,input_tokens=$4,output_tokens=$5,expires_at=now()+interval '24 hours' WHERE cache_key=$1 AND lease=$2",[key,lease,result.advice,result.inputTokens,result.outputTokens]);return {...result,source:'ai'};
 }catch(error){try{await query('UPDATE ai_advice_cache SET expires_at=now() WHERE cache_key=$1 AND lease=$2',[key,lease]);}catch{}throw error;}
}
