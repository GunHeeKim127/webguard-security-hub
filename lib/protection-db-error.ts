// Return only fixed labels: database errors may contain connection secrets.
export function protectionDbError(error:unknown){
 const code=typeof error==='object'&&error&&'code' in error?String(error.code):'';
 const message=error instanceof Error?error.message:'';
 if(message==='Query read timeout')return {reason:'DB_QUERY_TIMEOUT',retryable:true};
 if(['ETIMEDOUT','EAI_AGAIN','ECONNRESET','ECONNREFUSED','EPIPE','57P01','57P02','57P03'].includes(code)||/^08[0-9A-Z]{3}$/.test(code))return {reason:'DB_CONNECTION_INTERRUPTED',retryable:true};
 if(['Connection terminated unexpectedly','Connection terminated','Connection terminated due to connection timeout','timeout exceeded when trying to connect'].includes(message))return {reason:'DB_CONNECTION_INTERRUPTED',retryable:true};
 if(code==='42501')return {reason:'DB_PERMISSION_DENIED',retryable:false};
 return {reason:'DB_CHECK_FAILED',retryable:false};
}
