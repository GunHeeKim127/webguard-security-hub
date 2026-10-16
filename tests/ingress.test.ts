import test from 'node:test';
import assert from 'node:assert/strict';
import {clientAddress,normalizeIp,detectThreat} from '../lib/ingress-guard';
import {scanTarget,targetPolicy} from '../lib/scan-policy';
import {defenseText} from '../lib/defense-copy';
import {locales} from '../lib/locale';
import {scan} from '../lib/scanner';
import dns from 'node:dns/promises';
import https from 'node:https';
test('public scan accepts unregistered public hostnames without accepting unsafe URL shapes',()=>{
 assert.equal(scanTarget('https://not-preregistered.example').hostname,'not-preregistered.example');
 for(const value of ['https://127.0.0.1','https://2130706433','https://[::1]','https://localhost','http://public.example','https://public.example:8443','https://public.example/path','https://public.example?x=1','https://public.example#x','https://user:password@public.example','https://evil..example'])assert.throws(()=>scanTarget(value));
 assert.throws(()=>scanTarget('https://other.example',['owned.example']));assert.throws(()=>scanTarget('https://other.example',[]));
});
test('scan policy defaults to public, supports strict approval and rejects invalid configuration',()=>{const before=process.env.SCAN_TARGET_POLICY;try{delete process.env.SCAN_TARGET_POLICY;assert.equal(targetPolicy(),'public');process.env.SCAN_TARGET_POLICY='approved';assert.equal(targetPolicy(),'approved');process.env.SCAN_TARGET_POLICY='appproved';assert.throws(()=>targetPolicy(),/Invalid/);}finally{if(before===undefined)delete process.env.SCAN_TARGET_POLICY;else process.env.SCAN_TARGET_POLICY=before;}});
test('actual peer IP ignores forged forwarding headers and canonicalizes mapped IPv4',()=>{
 const headers=new Headers({'x-forwarded-for':'8.8.8.8','x-real-ip':'8.8.4.4','x-webguard-client-ip':'1.1.1.1','x-webguard-proxy-token':'forged'});
 assert.equal(clientAddress('::ffff:127.0.0.1',headers,{}),'127.0.0.1');assert.equal(clientAddress(undefined,headers,{}),null);
 assert.equal(normalizeIp('8.8.8.8:1234'),null);assert.equal(normalizeIp('8.8.8.8,1.1.1.1'),null);assert.equal(normalizeIp('not-an-ip'),null);
});
test('gateway identity requires both exact trusted peer and secret; XFF is never authoritative',()=>{
 const secret='s'.repeat(40),env={TRUSTED_PROXY_IPS:'127.0.0.1',WEBGUARD_PROXY_SECRET:secret};
 assert.equal(clientAddress('127.0.0.1',new Headers({'x-forwarded-for':'8.8.8.8'}),env),null);
 assert.equal(clientAddress('127.0.0.1',new Headers({'x-webguard-client-ip':'8.8.8.8','x-webguard-proxy-token':secret}),env),'8.8.8.8');
 assert.equal(clientAddress('127.0.0.2',new Headers({'x-webguard-client-ip':'8.8.8.8','x-webguard-proxy-token':secret}),env),'127.0.0.2');
 assert.equal(clientAddress('127.0.0.1',new Headers({'x-webguard-client-ip':'8.8.8.8,1.1.1.1','x-webguard-proxy-token':secret}),env),null);
});
test('bounded threat rules detect probes and encoded URL payloads, not ordinary application routes',()=>{
 for(const url of ['/.env','/.env.local','/.git/config','/wp-admin','/wp-login.php'])assert.equal(detectThreat(url),'probe',url);
 assert.equal(detectThreat('/?x=%253Cscript%253E'),'injection');assert.equal(detectThreat('/?x=UNION%20ALL%20SELECT'),'injection');assert.equal(detectThreat('/%252e%252e%252fetc/passwd'),'traversal');
 for(const url of ['/','/api/login','/api/scans','/_next/static/chunk.js','/?_rsc=abc123','/.well-known/appspecific/com.chrome.devtools.json','/signup','/api/locale'])assert.equal(detectThreat(url),null,url);
});
test('public target mode still rejects private DNS before opening a connection',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4},{address:'192.168.1.1',family:4}]);
 const transport=t.mock.method(https,'request',()=>{throw new Error('Must not connect');});
 await assert.rejects(scan('https://not-preregistered.example'),/Non-public DNS/);assert.equal(transport.mock.callCount(),0);
});
test('defense notices exist in every UI language',()=>{for(const locale of locales)for(const key of ['title','temporary','permanent','unavailable','policy','strikes','blocked','blacklist','released','probe','traversal','injection','manual_reset'])assert.notEqual(defenseText(locale,key),key);});
