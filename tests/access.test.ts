import test from 'node:test';
import assert from 'node:assert/strict';
import {accessOrigins,secureOriginCookie} from '../lib/access-origins';
import {sameOrigin} from '../lib/request';
import {pcEntryRedirects} from '../lib/pc-entry';

test('Vercel PC entry redirects only login pages and leaves local operation unchanged',()=>{
 const origin='https://example-tunnel.trycloudflare.com';
 assert.deepEqual(pcEntryRedirects({PC_APP_ORIGIN:origin}),[]);
 assert.deepEqual(pcEntryRedirects({VERCEL:'1'}),[]);
 assert.deepEqual(pcEntryRedirects({VERCEL:'1',PC_APP_ORIGIN:origin}),[
  {source:'/',destination:origin+'/',permanent:false},
  {source:'/signup',destination:origin+'/signup',permanent:false},
 ]);
});
test('Vercel PC entry refuses insecure, ambiguous and arbitrary redirect targets',()=>{
 for(const origin of ['http://example-tunnel.trycloudflare.com','https://evil.example','https://trycloudflare.com','https://example.trycloudflare.com.evil.example','https://user:secret@example.trycloudflare.com','https://example.trycloudflare.com/path','https://example.trycloudflare.com?next=evil','https://example.trycloudflare.com#fragment','https://example.trycloudflare.com:3000'])assert.throws(()=>pcEntryRedirects({VERCEL:'1',PC_APP_ORIGIN:origin}));
});
test('device access allows only explicit canonical application origins',()=>{
 assert.deepEqual(accessOrigins({APP_ORIGIN:'http://localhost:3000',APP_ADDITIONAL_ORIGINS:'https://hub.example/,http://localhost:3000'}),['http://localhost:3000','https://hub.example']);
 for(const value of ['https://*.example','https://user:password@hub.example','https://hub.example/path','https://hub.example?x=1','https://hub.example#x','file:///tmp'])assert.throws(()=>accessOrigins({APP_ORIGIN:value}));
});
test('multiple device addresses keep exact Origin and destination Host checks',()=>{
 const before={...process.env};try{
  process.env.APP_ORIGIN='http://localhost:3000';process.env.APP_ADDITIONAL_ORIGINS='https://hub.example';
  sameOrigin(new Request('https://hub.example/api/login',{headers:{origin:'https://hub.example',host:'hub.example'}}));
  for(const [origin,host] of [['https://evil.example','hub.example'],['https://hub.example','evil.example'],['null','hub.example'],['','hub.example'],['http://localhost:3000','hub.example']])assert.throws(()=>sameOrigin(new Request('https://hub.example/api/login',{headers:{origin,host}})));
 }finally{process.env=before;}
});
test('cookie security follows the trusted device entry address, independent of primary origin',()=>{
 const before={...process.env};try{
  process.env.APP_ORIGIN='http://localhost:3000';process.env.APP_ADDITIONAL_ORIGINS='https://hub.example';
  assert.equal(secureOriginCookie(new Request('https://hub.example',{headers:{origin:'https://hub.example'}})),true);
  assert.equal(secureOriginCookie(new Request('http://localhost:3000',{headers:{origin:'http://localhost:3000'}})),false);
  assert.throws(()=>secureOriginCookie(new Request('https://evil.example',{headers:{origin:'https://evil.example'}})));
 }finally{process.env=before;}
});
