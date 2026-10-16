import {normalizeIp} from './ingress-guard';
export class DatabaseConfigurationError extends Error {
 constructor(public code:'DATABASE_NOT_CONFIGURED'|'DATABASE_URL_INVALID'|'DATABASE_LOCALHOST_ON_VERCEL'|'DATABASE_TLS_REQUIRED'|'DATABASE_IDENTITY_MISMATCH',message:string){super(message);}
}
export function projectDatabase(kind:'runtime'|'migration', allowUnconfigured=false) {
 const raw=kind==='migration'?process.env.MIGRATION_DATABASE_URL:process.env.DATABASE_URL;
 const expected=process.env.PROJECT_DATABASE;
 if(!raw || !expected){
  if(allowUnconfigured && !raw)return {connectionString:'postgresql://unconfigured@127.0.0.1:1/unconfigured'};
  throw new DatabaseConfigurationError('DATABASE_NOT_CONFIGURED','Set PROJECT_DATABASE and '+(kind==='migration'?'MIGRATION_DATABASE_URL':'DATABASE_URL'));
 }
 let u:URL;try{u=new URL(raw);}catch{throw new DatabaseConfigurationError('DATABASE_URL_INVALID','Invalid PostgreSQL URL');}
 if(!['postgres:','postgresql:'].includes(u.protocol)||decodeURIComponent(u.pathname.slice(1))!==expected)throw new Error('Project database mismatch; refusing connection');
 // Provider TLS parameters are parsed explicitly. Never let pg URL options override identity or TLS.
 for(const key of u.searchParams.keys())if(!['sslmode','channel_binding'].includes(key)||u.searchParams.getAll(key).length!==1)throw new Error('Connection URL query parameters are not allowed');
 const sslmode=u.searchParams.get('sslmode'),binding=u.searchParams.get('channel_binding');
 if(sslmode&&!['require','verify-full'].includes(sslmode))throw new DatabaseConfigurationError('DATABASE_TLS_REQUIRED','Use sslmode=require or verify-full');
 if(binding&&binding!=='require')throw new Error('Unsupported channel_binding');
 const host=u.hostname.replace(/^\[|\]$/g,'').toLowerCase();
 const ip=normalizeIp(host);
 const local=host==='localhost'||host.endsWith('.localhost')||ip==='::1'||ip==='::'||ip==='0.0.0.0'||ip?.startsWith('127.')===true;
 if(process.env.VERCEL==='1'&&local)throw new DatabaseConfigurationError('DATABASE_LOCALHOST_ON_VERCEL','Vercel requires an externally reachable PostgreSQL host');
 const role=process.env.PROJECT_RUNTIME_ROLE;
 if(!role || !/^[a-z][a-z0-9_]{0,62}$/.test(role))throw new Error('Set PROJECT_RUNTIME_ROLE');
 if(kind==='runtime' && decodeURIComponent(u.username)!==role)throw new Error('Runtime must use its dedicated project role');
 if(kind==='migration' && decodeURIComponent(u.username)===role)throw new Error('Use a separate migration account');
 u.search='';
 return {connectionString:u.toString(),...(!local||sslmode?{ssl:{rejectUnauthorized:true}}:{}),...(binding?{enableChannelBinding:true}:{})};
}
