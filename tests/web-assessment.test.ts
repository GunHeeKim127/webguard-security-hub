import test from 'node:test';
import assert from 'node:assert/strict';
import {assessWeb,corsProbeOrigin} from '../lib/web-assessment';
import {assessmentText} from '../lib/assessment-copy';
import {locales} from '../lib/locale';
import {scan} from '../lib/scanner';
import dns from 'node:dns/promises';
import https from 'node:https';
import {EventEmitter} from 'node:events';
const now=Date.parse('2026-10-16T00:00:00Z');
const by=(headers:Record<string,string|string[]>,id:string)=>assessWeb(headers).find(f=>f.id===id)!;
test('present but insecure header values produce review findings',()=>{
 const headers={'content-security-policy':"default-src * 'unsafe-inline'; script-src https: 'unsafe-eval'",'strict-transport-security':'max-age=0','x-content-type-options':'sniff','referrer-policy':'unsafe-url'};
 for(const id of ['csp','hsts','nosniff','referrer'])assert.equal(by(headers,id).status,'warning');
 assert(by(headers,'csp').issues.includes('csp_broad'));
 assert(by(headers,'hsts').issues.includes('hsts_short'));
});
test('baseline header policies pass only their limited static checks',()=>{
 const headers={'content-security-policy':"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",'strict-transport-security':'max-age=31536000; includeSubDomains','x-content-type-options':'NoSniff','referrer-policy':'invalid, strict-origin-when-cross-origin'};
 for(const id of ['csp','hsts','nosniff','referrer'])assert.equal(by(headers,id).status,'pass');
 assert.equal(by({'content-security-policy-report-only':headers['content-security-policy']},'csp').status,'warning');
});
test('HSTS malformed, duplicate and negative max-age cannot pass',()=>{
 for(const v of ['max-age=-1','max-age=31536000; max-age=31536000','max-age=31536000x','max-age="31536000','nonsense'])assert.equal(by({'strict-transport-security':v},'hsts').status,'warning',v);
 assert.equal(by({'strict-transport-security':'max-age="31536000"'},'hsts').status,'pass');
});
test('certificate assessment covers expiry boundaries without claiming protocol enumeration',()=>{
 const tls=(validTo:string|null,protocol='TLSv1.3')=>assessWeb({},{authorized:true,protocol,validTo},now).find(f=>f.id==='tls')!;
 assert.equal(tls('2027-01-01').status,'pass');assert(tls('2026-10-16').issues.includes('tls_expired'));
 assert(tls('2026-11-01').issues.includes('tls_expiring'));assert(tls(null).issues.includes('tls_expiry_unknown'));
 assert(tls('2027-01-01','TLSv1.1').issues.includes('tls_protocol'));
 assert.equal(assessWeb({}).find(f=>f.id==='tls')!.status,'not_assessed');
});
test('cookie observations redact names, values, domains and paths from all findings',()=>{
 const result=assessWeb({'set-cookie':['secret-session=top-secret-value; Domain=private.example; Path=/private-path','__Host-other=another-secret; Secure; HttpOnly; SameSite=Lax; Path=/']});
 const encoded=JSON.stringify(result);for(const secret of ['secret-session','top-secret-value','private.example','private-path','another-secret','__Host-other'])assert(!encoded.includes(secret));
 assert.equal(result.find(f=>f.id==='cookie-1')!.status,'warning');assert.equal(result.find(f=>f.id==='cookie-2')!.status,'pass');
 assert.equal(by({},'cookies').status,'not_assessed');
});
test('cookie prefix, None, partition and duplicate attribute requirements are checked',()=>{
 for(const v of ['__Host-session=v; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com','__Secure-session=v; HttpOnly; SameSite=Lax','session=v; HttpOnly; SameSite=None','session=v; HttpOnly; SameSite=Lax; Partitioned','session=v; Secure; Secure; HttpOnly; SameSite=Lax'])assert.equal(by({'set-cookie':v},'cookie-1').status,'warning',v);
 assert.equal(assessWeb({'set-cookie':Array.from({length:100},()=>`a=value; Secure; HttpOnly; SameSite=Lax`)}).filter(f=>f.group==='cookies').length,33);
});
test('CORS separates public wildcard, invalid combinations and credentialed probe allowance',()=>{
 assert.equal(by({'access-control-allow-origin':'*'},'cors').status,'info');
 assert(by({'access-control-allow-origin':'*','access-control-allow-credentials':'true'},'cors').issues.includes('cors_invalid'));
 const probe=by({'access-control-allow-origin':corsProbeOrigin,'access-control-allow-credentials':'true'},'cors');assert(probe.issues.includes('cors_credentials'));assert(probe.issues.includes('cors_vary'));
 assert(!by({'access-control-allow-origin':corsProbeOrigin,vary:'Accept-Encoding, Origin'},'cors').issues.includes('cors_vary'));
 assert.equal(by({},'cors').status,'not_assessed');
 assert(by({'access-control-allow-origin':'null'},'cors').issues.includes('cors_null'));
 for(const v of ['https://a.example https://b.example','https://a.example/path'])assert(by({'access-control-allow-origin':v},'cors').issues.includes('cors_invalid'));
});
test('server version values are not persisted or labelled proven vulnerabilities',()=>{
 const item=by({'server':'private-product/1.2.3'},'exposure');assert.equal(item.status,'info');assert(!JSON.stringify(item).includes('private-product'));
});
test('every emitted finding and issue has text in all six locales',()=>{
 const headers={'content-security-policy':"default-src *",'strict-transport-security':'max-age=0','x-content-type-options':'x','referrer-policy':'unsafe-url','set-cookie':['__Host-secret=value; SameSite=None; Partitioned; Secure; Secure; Domain=x','foo=bar'],'access-control-allow-origin':corsProbeOrigin,'access-control-allow-credentials':'true',server:'x'};
 const findings=assessWeb(headers,{authorized:false,protocol:'TLSv1.1',validTo:null});
 for(const locale of locales)for(const item of findings){for(const key of [item.group,item.status,`${item.group}_fix`,...item.issues.map(i=>i==='exposure'?'exposure_note':i)])assert.notEqual(assessmentText(locale,key),key,`${locale}:${key}`);}
});
test('transport uses one bounded pinned HEAD with certificate verification and redacted observations',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);
 const transport=t.mock.method(https,'request',(_url:URL,options:any,callback:Function)=>{
  assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,'TLSv1.2');assert.equal(options.maxHeaderSize,16384);assert.equal(options.headers.Origin,corsProbeOrigin);assert.equal(options.headers.Cookie,undefined);assert.equal(options.headers.Authorization,undefined);
  const req=new EventEmitter() as any;req.end=()=>{callback({statusCode:200,headers:{'set-cookie':['secret=hidden; Secure; HttpOnly; SameSite=Lax']},socket:{authorized:true,getProtocol:()=> 'TLSv1.3',getPeerCertificate:()=>({valid_to:'Jan 1 00:00:00 2030 GMT'})},destroy(){}});req.emit('close');};req.destroy=(e:Error)=>{req.emit('error',e);req.emit('close');};return req;
 });
 const result=await scan('https://owned.example',['owned.example']);assert.equal(result.assessmentVersion,2);assert.equal(result.assessment?.find(f=>f.id==='tls')?.status,'pass');assert(!JSON.stringify(result).includes('hidden'));assert.equal(transport.mock.callCount(),1);
});
test('TLS connection failure rejects scan without insecure retry',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);
 const transport=t.mock.method(https,'request',()=>{const req=new EventEmitter() as any;req.end=()=>{queueMicrotask(()=>{req.emit('error',new Error('CERT_HAS_EXPIRED'));req.emit('close');});};return req;});
 await assert.rejects(scan('https://owned.example',['owned.example']),/CERT_HAS_EXPIRED/);assert.equal(transport.mock.callCount(),1);
});
