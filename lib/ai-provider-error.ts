import OpenAI from 'openai';
import type {AiErrorCode} from './ai-error-copy';
export function aiProviderError(error:unknown):AiErrorCode|null{
 if(!(error instanceof OpenAI.APIError))return null;
 if(error instanceof OpenAI.APIConnectionError)return 'AI_CONNECTION_FAILED';
 if(error.status===401||error.status===403)return 'AI_AUTH_FAILED';
 if(error.code==='model_not_found'||error.status===404)return 'AI_MODEL_UNAVAILABLE';
 if(['insufficient_quota','credit_balance_exhausted','billing_hard_limit_reached','organization_spend_limit_exceeded','project_spend_limit_exceeded','organization_usage_limit_exceeded'].includes(error.code??'')||error.type==='insufficient_quota')return 'AI_QUOTA_EXCEEDED';
 if(error.status===429)return 'AI_RATE_LIMITED';
 if(error.status===400||error.status===422)return 'AI_REQUEST_REJECTED';
 return 'AI_PROVIDER_FAILED';
}
