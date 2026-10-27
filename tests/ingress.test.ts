import test from 'node:test';
import assert from 'node:assert/strict';
import {clientAddress,normalizeIp,detectThreat,threatSessionHash} from '../lib/ingress-guard';
import {tokenHash} from '../lib/password';
import {releaseAccountBlock} from '../lib/account-block-management';
import {publicUser,publicIpBlock,publicAccountBlock,maskEmail,publicEvents,publicEventCategory} from '../lib/public-identity';

test('server identity serializers whitelist fields and never ship raw identifiers behind masks',()=>{
 const user={id:'PRIVATE_USER_ID',email:'private-customer@secret.example',role:'viewer',password_hash:'PRIVATE_HASH'};
 const profile=publicUser(user);assert.deepEqual(Object.keys(profile).sort(),['email','role']);assert.equal(profile.email,'p***@***.example');
 const ip={management_id:'opaque-reference',address:'198.51.100.22',strikes:6,blacklisted:true,blocked_until:null,last_reason:'probe',last_seen:'2026-10-27T00:00:00Z'};
 const account={management_id:'opaque-account-reference',email:user.email,strikes:6,blacklisted:true,last_reason:'probe',last_seen:ip.last_seen,user_id:user.id};
 const serialized=JSON.stringify({profile,ip:publicIpBlock(ip),account:publicAccountBlock(account)});
 for(const secret of [user.id,user.email,user.password_hash,ip.address])assert(!serialized.includes(secret));
 assert.equal(publicIpBlock(ip).blockId,'opaque-reference');assert.equal(publicIpBlock({...ip,address:'2001:db8::1'}).address,'****:****:****:****');assert.equal(maskEmail('invalid-secret'),'***');
 assert.equal(publicEventCategory('PRIVATE_EVENT_USER_VALUE'),'other');
 assert.deepEqual(publicEvents([{category:'ip_unblocked_target:'+'a'.repeat(64),count:1},{category:'ip_unblocked_target:'+'b'.repeat(64),count:2}]),[{category:'ip_unblocked_audit',count:3}]);
});
import {scanTarget,targetPolicy} from '../lib/scan-policy';
import {defenseText} from '../lib/defense-copy';
import {locales} from '../lib/locale';
import {scan} from '../lib/scanner';
import dns from 'node:dns/promises';
import https from 'node:https';
import {releaseIpBlock} from '../lib/ip-block-management';

test('IP management canonicalizes the target and never stores raw addresses in audit categories',async()=>{
 let captured:unknown[]=[];
 const query=async(sql:string,values:unknown[])=>{assert(sql.includes('WITH reset'));assert(sql.includes('INSERT INTO public.events(category,user_id)'));captured=values;return {rows:[{audit_count:2}]};};
 assert(await releaseIpBlock(query,'::ffff:192.0.2.4','11111111-1111-4111-8111-111111111111'));
 assert.equal(captured[0],'192.0.2.4');assert(/^ip_unblocked_target:[a-f0-9]{64}$/.test(String(captured[2])));
 await assert.rejects(releaseIpBlock(query,'not-an-ip','11111111-1111-4111-8111-111111111111'));
 await assert.rejects(releaseIpBlock(query,'192.0.2.4','forged'));
 assert.equal(await releaseIpBlock(async()=>({rows:[{audit_count:0}]}),'192.0.2.4','11111111-1111-4111-8111-111111111111'),false);
});

test('account attribution requires one exact session cookie and release audits a fixed target',async()=>{
 const token='a'.repeat(64);assert.equal(threatSessionHash('other=x; wg_session='+token),tokenHash(token));
 for(const cookie of [undefined,'','wg_session=root@example.test','wg_session='+token+'; wg_session='+token,'wg_session='+token+'x'])assert.equal(threatSessionHash(cookie),null);
 let values:unknown[]=[];assert(await releaseAccountBlock(async(sql,args)=>{assert(sql.includes('DELETE FROM public.sessions'));assert(sql.includes('INSERT INTO public.events(category,user_id)'));values=args;return {rows:[{audit_count:2}]};},'11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222'));
 assert(/^account_unblocked_target:[a-f0-9]{64}$/.test(String(values[3])));
 await assert.rejects(releaseAccountBlock(async()=>({rows:[]}),'bad','22222222-2222-4222-8222-222222222222'));
});
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
test('defense notices exist in every UI language',()=>{for(const locale of locales)for(const key of ['title','temporary','permanent','unavailable','policy','strikes','blocked','blacklist','released','probe','traversal','injection','manual_reset','release','release_audit','masked_notice','account_empty','account_reset','account_blacklist','account_warning','account_title','account_policy','account_release','release_done','release_failed','releasing'])assert.notEqual(defenseText(locale,key),key);});
