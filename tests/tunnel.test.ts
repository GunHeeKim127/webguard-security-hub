import test from 'node:test';
import assert from 'node:assert/strict';
import {tunnelHeaders,tunnelHttpsRedirect} from '../lib/tunnel-gateway';
import {clientAddress} from '../lib/ingress-guard';
test('tunnel gateway replaces spoofed proxy headers and authenticates to the guard',/** test 콜백: 테스트: tunnel gateway replaces spoofed proxy headers and authenticates to the guard 주요 호출: repeat·tunnelHeaders·equal. */ ()=>{
 const secret='a'.repeat(64),host='test.trycloudflare.com';
 const headers=tunnelHeaders({host,'cf-connecting-ip':'203.0.113.2','x-webguard-client-ip':'8.8.8.8','x-webguard-proxy-token':'spoof','x-webguard-geo-token':'spoof',forwarded:'spoof',connection:'keep-alive, x-remove','x-remove':'spoof','x-forwarded-for':'8.8.8.8','x-forwarded-proto':'http'},host,secret);
 assert.equal(headers['x-webguard-client-ip'],'203.0.113.2');assert.equal(headers['x-webguard-proxy-token'],secret);assert.equal(headers['x-forwarded-proto'],'https');
 for(const key of ['x-remove','x-forwarded-for','forwarded','x-webguard-geo-token','connection'])assert.equal(headers[key],undefined);
 const get=/** get: 검증 시나리오에서 get에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: String. */ (key:string)=>String(headers[key]??'');
 assert.equal(clientAddress('127.0.0.1',{get},{TRUSTED_PROXY_IPS:'127.0.0.1',WEBGUARD_PROXY_SECRET:secret}),'203.0.113.2');
});
test('tunnel gateway rejects mismatched hosts and missing or ambiguous client IP',/** test 콜백: 테스트: tunnel gateway rejects mismatched hosts and missing or ambiguous client IP 주요 호출: throws. */ ()=>{
 const host='test.trycloudflare.com';
 for(const input of [{host:'evil.example','cf-connecting-ip':'8.8.8.8'},{host},{host,'cf-connecting-ip':'8.8.8.8,1.1.1.1'},{host,'cf-connecting-ip':['8.8.8.8','1.1.1.1']}])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: tunnelHeaders·repeat. */ ()=>tunnelHeaders(input,host,'a'.repeat(64)));
});
test('HTTP tunnel entry redirects to HTTPS before login and preserves the same destination host',/** test 콜백: 테스트: HTTP tunnel entry redirects to HTTPS before login and preserves the same destination host 주요 호출: equal·tunnelHttpsRedirect·throws. */ ()=>{
 const host='test.trycloudflare.com';
 assert.equal(tunnelHttpsRedirect({host,'x-forwarded-proto':'http'},host,'/?locale=ko'),`https://${host}/?locale=ko`);
 assert.equal(tunnelHttpsRedirect({host,'x-forwarded-proto':'https'},host,'/'),null);
 assert.equal(new URL(tunnelHttpsRedirect({host,'x-forwarded-proto':'http'},host,'//evil.example/')!).host,host);
 for(const proto of [undefined,'http,https','ftp'])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: tunnelHttpsRedirect. */ ()=>tunnelHttpsRedirect({host,'x-forwarded-proto':proto},host,'/'));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: tunnelHttpsRedirect. */ ()=>tunnelHttpsRedirect({host:'evil.example','x-forwarded-proto':'http'},host,'/'));
});
