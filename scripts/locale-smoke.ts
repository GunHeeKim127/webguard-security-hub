import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
import {locales} from '../lib/locale';
import {registrationCopy} from '../lib/registration-copy';
import {messages} from '../lib/messages';
import {errorText} from '../lib/errors-i18n';
const port=34000+Math.floor(Math.random()*8000),base=`http://127.0.0.1:${port}`,token='test-gateway-secret-'+'x'.repeat(40);
const child=spawn(process.execPath,['node_modules/next/dist/bin/next','start','--hostname','127.0.0.1','--port',String(port)],{env:{...process.env,DATABASE_PROVIDER:'postgresql',VERCEL:'',PROJECT_DATABASE:'unconfigured',PROJECT_RUNTIME_ROLE:'unconfigured',DATABASE_URL:'postgresql://unconfigured@127.0.0.1:1/unconfigured',APP_ORIGIN:base,APP_ADDITIONAL_ORIGINS:'',AI_ENABLED:'false',DEFAULT_LOCALE:'en',GEOIP_PROXY_SECRET:token,GEOIP_COUNTRY_HEADER:'cf-ipcountry'},stdio:'ignore',windowsHide:true});
try{
 let ready=false;for(let i=0;i<60;i++){if(child.exitCode!==null)throw new Error('Server startup failed');try{if((await fetch(base+'/api/health',{signal:AbortSignal.timeout(1000)})).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,500));}assert(ready,'Server startup timeout');
 for(const locale of locales){
  const headers={'Accept-Language':`${locale}-ZZ`};
  const page=await fetch(base,{headers});const html=await page.text();assert.equal(page.status,200);assert(html.includes(`lang="${locale}"`),locale);assert(html.includes(messages[locale].title),locale);
  const signup=await fetch(base+'/signup',{headers});const signupHtml=await signup.text();assert.equal(signup.status,200);assert(signupHtml.includes(registrationCopy[locale].title),locale+' signup');
  const denied=await fetch(base+'/api/dashboard',{headers});assert.equal(denied.status,401);assert.equal(denied.headers.get('content-language'),locale);const error=await denied.json();assert.equal(error.errorCode,'LOGIN_REQUIRED');assert.equal(error.error,errorText(locale,'LOGIN_REQUIRED'));
  const csrf=await fetch(base+'/api/scans',{method:'POST',headers:{...headers,origin:'https://untrusted.example','Content-Type':'application/json'},body:'{}'});assert.equal(csrf.status,403);assert.equal((await csrf.json()).error,errorText(locale,'ORIGIN_REJECTED'));
 }
 console.log('PASS six SSR languages, translated API errors, language headers and CSRF errors');
 const changed=await fetch(base+'/api/locale',{method:'POST',headers:{origin:base,'Content-Type':'application/json'},body:'{"locale":"ja"}'});assert.equal(changed.status,200);const cookie=changed.headers.get('set-cookie')!;assert(cookie.includes('HttpOnly'));assert(cookie.includes('SameSite=Lax'));
 const manual=await fetch(base+'/api/locale',{headers:{cookie:cookie.split(';')[0],'Accept-Language':'ko-KR','cf-ipcountry':'FR','x-webguard-geo-token':token}});assert.deepEqual(await manual.json(),{locale:'ja',source:'manual',supportedLocales:locales});
 const invalid=await fetch(base+'/api/locale',{method:'POST',headers:{origin:base,'Content-Type':'application/json','Accept-Language':'fr'},body:'{"locale":"<script>"}'});assert.equal(invalid.status,400);assert.equal((await invalid.json()).errorCode,'INVALID_LOCALE');
 console.log('PASS persisted explicit preference and invalid locale rejection');
 const spoofed=await fetch(base+'/api/locale',{headers:{'Accept-Language':'de','cf-ipcountry':'KR'}});assert.equal((await spoofed.json()).locale,'en');
 const trusted=await fetch(base+'/api/locale',{headers:{'Accept-Language':'de','cf-ipcountry':'KR','x-webguard-geo-token':token}});assert.equal((await trusted.json()).source,'country');
 const browser=await fetch(base+'/api/locale',{headers:{'Accept-Language':'es','cf-ipcountry':'KR','x-webguard-geo-token':token}});assert.equal((await browser.json()).locale,'es');
 console.log('PASS forged country ignored; authenticated IP-country hint used only as fallback');
}finally{child.kill();}
