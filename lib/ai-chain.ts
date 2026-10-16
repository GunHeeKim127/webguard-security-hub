import {HttpError} from './request';
import type {ProviderConfig} from './ai-providers';
import type {GeneratedAdvice} from './advice-cache';
export type ProviderReply=(GeneratedAdvice&{source:'ai'|'cache'})|{source:'busy'};
export async function adviceChain(configs:ProviderConfig[],attempt:(config:ProviderConfig)=>Promise<ProviderReply>){
 let reasonCode='AI_PROVIDER_FAILED';
 for(const config of configs){
  try{const result=await attempt(config);if(result.source==='busy')return {source:'local' as const,reasonCode:'AI_IN_PROGRESS'};
   return {...result,provider:config.provider,model:config.model};
  }catch(error){if(!(error instanceof HttpError))throw error;reasonCode=error.message;
   // An account-level budget is shared across providers and cannot be bypassed by rotation.
   if(error.message==='AI_LOCAL_RATE_LIMITED')break;
  }
 }
 return {source:'local' as const,reasonCode};
}
