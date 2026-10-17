import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectionSummary} from '../lib/inspection';
import {approvedHosts} from '../lib/scan-policy';
import {operationsMessages} from '../lib/operations-messages';
import {locales} from '../lib/locale';
import {errorCode,errorText} from '../lib/errors-i18n';
test('pending/failed checks never display a stale successful result',()=>{const result={status:200,checks:[{header:'content-security-policy',present:false}]};for(const state of ['idle','running','error'] as const)assert.deepEqual(inspectionSummary({state,target:'https://example.com',result}),{complete:false,httpStatus:null,missing:null});assert.deepEqual(inspectionSummary({state:'success',target:'https://example.com',result}),{complete:true,httpStatus:200,missing:1});});
test('approved site list excludes malformed entries, IPs, wildcards and duplicate casing',()=>{assert.deepEqual(approvedHosts('owned.example,OWNED.EXAMPLE,*,http://example.com,127.0.0.1,localhost,evil..com,-bad.example'),['owned.example']);assert.deepEqual(approvedHosts(''),[]);});
test('operations UI and unconfigured-target error are translated in every supported language',()=>{for(const locale of locales){assert.deepEqual(Object.keys(operationsMessages[locale]),Object.keys(operationsMessages.en));assert(Object.values(operationsMessages[locale]).every(value=>value.trim().length>0));assert.equal(errorText(locale,'NO_APPROVED_TARGETS'),operationsMessages[locale].notConfigured);}assert.equal(errorCode('No approved targets configured',409),'NO_APPROVED_TARGETS');});

import {appendLog,readScanStream,scanReport,type ScanEvent} from '../lib/scan-run';
test('stream parser handles arbitrary byte boundaries and requires terminal outcome',async()=>{
 const events:ScanEvent[]=[{type:'progress',stage:'target',state:'running',at:'2026-10-16T00:00:00Z'},{type:'error',errorCode:'TARGET_REJECTED',at:'2026-10-16T00:00:01Z'}];
 const bytes=new TextEncoder().encode(events.map(e=>JSON.stringify(e)).join('\n')+'\n');
 const received:ScanEvent[]=[];await readScanStream(new ReadableStream({start(c){for(const byte of bytes)c.enqueue(new Uint8Array([byte]));c.close();}}),e=>received.push(e));assert.deepEqual(received,events);
 await assert.rejects(readScanStream(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode(JSON.stringify(events[0])+'\n'));c.close();}}),()=>{}),/Incomplete/);
});
test('failed stage logs and downloaded report cannot reuse an old successful result',()=>{
 const logs=appendLog([{stage:'network',state:'running',at:'now'}],{type:'error',errorCode:'TARGET_REJECTED',at:'later'});
 assert.equal(logs.at(-1)?.stage,'network');assert.equal(logs.at(-1)?.state,'error');
 const report=JSON.parse(scanReport('https://owned.example',logs,{state:'error',result:{status:200,checks:[]}}));assert.equal(report.result,null);assert.equal(report.logs.length,2);assert.equal(report.target,'https://owned.example');
});
test('stream parser rejects invalid stage and oversized pending line',async()=>{
 for(const value of [JSON.stringify({type:'progress',stage:'fake',state:'running',at:'now'})+'\n','x'.repeat(65537)])await assert.rejects(readScanStream(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode(value));c.close();}}),()=>{}));
});

import {registrationInput} from '../lib/registration';
import {registrationCopy} from '../lib/registration-copy';
import {scanUI} from '../lib/scan-ui';
test('registration validates passwords and rejects client privilege escalation',()=>{
 assert.deepEqual(registrationInput({email:' Viewer@Example.test ',password:'long-enough-password'}),{email:'viewer@example.test',password:'long-enough-password'});
 for(const input of [{email:'bad',password:'long-enough-password'},{email:'v@example.test',password:'short'},{email:'v@example.test',password:'x'.repeat(129)},{email:'v@example.test',password:'long-enough-password',role:'admin'}])assert.equal(registrationInput(input),null);
});
test('registration and scan controls are translated in all supported languages',()=>{
 for(const locale of locales){assert.deepEqual(Object.keys(registrationCopy[locale]),Object.keys(registrationCopy.en));assert.deepEqual(Object.keys(scanUI[locale]),Object.keys(scanUI.en));assert.equal(errorText(locale,'INVALID_REGISTRATION'),registrationCopy[locale].validation);assert(Object.values(registrationCopy[locale]).every(Boolean));}
});

import {localAdvice,adviceCopy,adviceHeaders} from '../lib/local-advice';
import {adviceKey} from '../lib/advice-cache';
test('offline advice is translated and checks all missing headers without an API',()=>{
 for(const locale of locales){const guide=localAdvice(locale,[]);assert(guide.includes(adviceCopy[locale].help));assert(adviceCopy[locale].lines.every(line=>guide.includes(line)));const present=localAdvice(locale,adviceHeaders.map(header=>({header,present:true})));assert(!present.includes(adviceCopy[locale].lines[0]));}
});
test('cache identity follows actual sent findings, language and model rather than header order',()=>{
 assert.notEqual(adviceKey('model','ko',[],'account-a'),adviceKey('model','ko',[],'account-b'));
 assert.equal(adviceKey('model','ko',[],'account-a'),adviceKey('model','ko',[],'account-a'));
 const checks=[{header:'content-security-policy',present:true},{header:'referrer-policy',present:false}];
 assert.equal(adviceKey('model','ko',checks),adviceKey('model','ko',[...checks].reverse()));
 assert.notEqual(adviceKey('model','ko',checks),adviceKey('model','en',checks));assert.notEqual(adviceKey('model','ko',checks),adviceKey('other','ko',checks));assert.notEqual(adviceKey('model','ko',checks),adviceKey('model','ko',[]));
});

import {providerConfigs} from '../lib/ai-providers';
import {adviceChain} from '../lib/ai-chain';
import {HttpError} from '../lib/request';
test('automatic providers use only configured free-provider keys and never paid OpenAI',()=>{
 const env={AI_PROVIDER:'auto',GROQ_API_KEY:'groq-test',GEMINI_API_KEY:'gemini-test',OPENAI_API_KEY:'paid-test',OPENAI_MODEL:'openai/gpt-oss-120b'};
 const configs=providerConfigs(env);assert.deepEqual(configs.map(c=>c.provider),['groq','gemini']);assert.equal(configs[0].apiKey,'groq-test');assert.equal(configs[1].model,'gemini-3.5-flash-lite');assert.deepEqual(providerConfigs({...env,AI_PROVIDER:'invalid'}),[]);
});
test('provider quota falls back to Gemini and account budget cannot be bypassed',async()=>{
 const configs=providerConfigs({AI_PROVIDER:'auto',GROQ_API_KEY:'one',GEMINI_API_KEY:'two'}),calls:string[]=[];
 const result=await adviceChain(configs,async config=>{calls.push(config.provider);if(config.provider==='groq')throw new HttpError(503,'AI_QUOTA_EXCEEDED');return {source:'ai',advice:'Safe advice',inputTokens:10,outputTokens:20};});assert.deepEqual(calls,['groq','gemini']);assert.equal('provider' in result&&result.provider,'gemini');
 let attempts=0;const limited=await adviceChain(configs,async()=>{attempts++;throw new HttpError(429,'AI_LOCAL_RATE_LIMITED');});assert.equal(limited.source,'local');assert.equal(attempts,1);
 const exhausted=await adviceChain(configs,async()=>{throw new HttpError(503,'AI_RATE_LIMITED');});assert.equal(exhausted.source,'local');
});
