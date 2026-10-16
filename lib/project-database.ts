export function projectDatabase(kind:'runtime'|'migration', allowUnconfigured=false) {
 const raw=kind==='migration'?process.env.MIGRATION_DATABASE_URL:process.env.DATABASE_URL;
 const expected=process.env.PROJECT_DATABASE;
 if(!raw || !expected){
  if(allowUnconfigured && !raw)return {connectionString:'postgresql://unconfigured@127.0.0.1:1/unconfigured'};
  throw new Error('Set PROJECT_DATABASE and '+(kind==='migration'?'MIGRATION_DATABASE_URL':'DATABASE_URL'));
 }
 const u=new URL(raw);
 if(!['postgres:','postgresql:'].includes(u.protocol)||decodeURIComponent(u.pathname.slice(1))!==expected)throw new Error('Project database mismatch; refusing connection');
 // pg accepts query parameters overriding database/user; prohibit those bypasses.
 if(u.search)throw new Error('Connection URL query parameters are not allowed');
 const role=process.env.PROJECT_RUNTIME_ROLE;
 if(!role || !/^[a-z][a-z0-9_]{0,62}$/.test(role))throw new Error('Set PROJECT_RUNTIME_ROLE');
 if(kind==='runtime' && decodeURIComponent(u.username)!==role)throw new Error('Runtime must use its dedicated project role');
 if(kind==='migration' && decodeURIComponent(u.username)===role)throw new Error('Use a separate migration account');
 return {connectionString:raw};
}
