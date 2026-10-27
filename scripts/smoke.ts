import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
const port=33000+Math.floor(Math.random()*10000),base=`http://127.0.0.1:${port}`;
const child=spawn(process.execPath,['node_modules/next/dist/bin/next','start','--hostname','127.0.0.1','--port',String(port)],{env:{...process.env,DATABASE_PROVIDER:'postgresql',VERCEL:'',PROJECT_DATABASE:'unconfigured',PROJECT_RUNTIME_ROLE:'unconfigured',APP_ORIGIN:base,APP_ADDITIONAL_ORIGINS:'',AI_ENABLED:'false',DATABASE_URL:'postgresql://unconfigured@127.0.0.1:1/unconfigured'},stdio:['ignore','pipe','pipe'],windowsHide:true});
let output='';child.stdout.on('data',d=>output+=d);child.stderr.on('data',d=>output+=d);
try{
 let ready=false;for(let i=0;i<60;i++){if(child.exitCode!==null)throw new Error(output);try{if((await fetch(base+'/api/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,500));}assert(ready,'Server startup timeout: '+output);
 const page=await fetch(base);assert.equal(page.status,200);const html=await page.text();assert(html.includes('WebGuard')&&html.includes('<html lang='));assert.equal(page.headers.get('x-frame-options'),'DENY');assert.equal(page.headers.get('x-content-type-options'),'nosniff');assert(page.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"));console.log('PASS rendered app shell and security headers independent of selected language');
 const policy=page.headers.get('content-security-policy')??'',nonce=/script-src[^;]*'nonce-([^']+)'/.exec(policy)?.[1];assert(nonce,'Missing response script nonce');
 assert(!/script-src[^;]*'unsafe-inline'/.test(policy));
 const scriptTags=[...html.matchAll(/<script\b[^>]*>/g)].map(m=>m[0]);assert(scriptTags.length>0);for(const tag of scriptTags)assert(tag.includes(`nonce="${nonce}"`),'Script tag must share response nonce');
 const another=await fetch(base);assert.notEqual(another.headers.get('content-security-policy'),policy,'Every document must receive a fresh nonce');
 console.log('PASS unique document nonce matches every rendered script; inline script fallback absent');
 const dashboard=await fetch(base+'/api/dashboard');assert.equal(dashboard.status,401);assert.equal(dashboard.headers.get('cache-control'),'no-store');console.log('PASS unauthenticated dashboard denied');
 for(const path of ['/api/login','/api/logout','/api/scans','/api/ai']){const csrf=await fetch(base+path,{method:'POST',headers:{origin:'https://evil.example','Content-Type':'application/json'},body:'{}'});assert.equal(csrf.status,403,path);}
 console.log('PASS cross-origin mutations denied');
 for(const path of ['/api/scans','/api/ai']){const r=await fetch(base+path,{method:'POST',headers:{origin:base,'Content-Type':'application/json'},body:'{}'});assert.equal(r.status,401,path);}
 console.log('PASS unauthenticated scan and AI denied');
}finally{child.kill();}
