import OpenAI from 'openai';
import {adviceHeaders} from './local-advice';
import {languageNames,type Locale} from './locale';
import type {CheckResult} from './inspection';
export type Provider='groq'|'gemini'|'openai';
export type ProviderConfig={provider:Provider,model:string,apiKey:string,baseURL:string};
export function providerConfigs(env:Readonly<Record<string,string|undefined>>=process.env):ProviderConfig[]{
 const mode=env.AI_PROVIDER??'auto';
 const configs:ProviderConfig[]=[];
 if((mode==='auto'||mode==='groq')&&env.GROQ_API_KEY?.trim())configs.push({provider:'groq',model:env.OPENAI_MODEL?.trim()||'openai/gpt-oss-120b',apiKey:env.GROQ_API_KEY.trim(),baseURL:'https://api.groq.com/openai/v1'});
 if((mode==='auto'||mode==='gemini')&&env.GEMINI_API_KEY?.trim())configs.push({provider:'gemini',model:env.GEMINI_MODEL?.trim()||'gemini-3.5-flash-lite',apiKey:env.GEMINI_API_KEY.trim(),baseURL:'https://generativelanguage.googleapis.com/v1beta/openai/'});
 // Paid OpenAI is available only by explicit selection. It never enters the automatic chain.
 if(mode==='openai'&&env.OPENAI_API_KEY?.trim()&&env.OPENAI_MODEL?.trim())configs.push({provider:'openai',model:env.OPENAI_MODEL.trim(),apiKey:env.OPENAI_API_KEY.trim(),baseURL:env.OPENAI_BASE_URL?.trim()||'https://api.openai.com/v1'});
 return configs;
}
export async function generateAdvice(config:ProviderConfig,locale:Locale,checks:CheckResult['checks']){
 const client=new OpenAI({apiKey:config.apiKey,baseURL:config.baseURL,timeout:20000,maxRetries:0});
 const instructions=`Give brief defensive security-header advice in ${languageNames[locale]}. At most 4 short bullets, under 100 words. Presence is not proof of safety. You cannot execute changes.`;
 const input=JSON.stringify(Object.fromEntries(adviceHeaders.map(header=>[header,!!checks.find(check=>check.header===header)?.present])));
 if(config.provider==='openai'){
  const result=await client.responses.create({model:config.model,reasoning:{effort:'low'},store:false,max_output_tokens:400,instructions,input});
  return {advice:result.output_text??'',inputTokens:result.usage?.input_tokens??0,outputTokens:result.usage?.output_tokens??0};
 }
 const result=await client.chat.completions.create({model:config.model,messages:[{role:'system',content:instructions},{role:'user',content:input}],reasoning_effort:'low',max_tokens:400});
 return {advice:result.choices[0]?.message.content??'',inputTokens:result.usage?.prompt_tokens??0,outputTokens:result.usage?.completion_tokens??0};
}
