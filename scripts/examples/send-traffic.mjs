// Run on your own server only. Never import this into client-side code.
const origin=process.env.WEBGUARD_ORIGIN??'https://webguard-security-hub.vercel.app';
const assetId=process.env.WEBGUARD_ASSET_ID,token=process.env.WEBGUARD_INGEST_TOKEN;
const u=new URL(origin);if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error('Set a HTTPS WebGuard origin');
if(!assetId||!token||!/^[0-9a-f]{64}$/.test(token))throw Error('Set the asset ID and server-only ingestion token');
const result=await fetch(new URL('/api/telemetry',u),{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({assetId,requests:1,loginFailures:0,probes:0,serverErrors:0}),signal:AbortSignal.timeout(20000)});
console.log('Aggregate ingestion status:',result.status);
if(result.status!==202)process.exitCode=1;
