import test from 'node:test';
import assert from 'node:assert/strict';
import {locales,preferredLanguage,localeCookie,resolveLocale} from '../lib/locale';
import {trustedCountry} from '../lib/geo-country';
import {messages,en,eventLabel} from '../lib/messages';
import {errorMessages,errorCode,errorText} from '../lib/errors-i18n';
test('offline assessment errors refer to supplied input rather than HTTPS or DNS',()=>{
 assert.equal(errorCode('Invalid assessment input',400),'ASSESSMENT_INPUT_INVALID');
 for(const locale of locales){const message=errorText(locale,'ASSESSMENT_INPUT_INVALID');assert(message.length>20);assert(!/HTTPS|DNS/.test(message));assert.notEqual(message,errorText(locale,'SERVICE_UNAVAILABLE'));}
});
test('all six languages have complete UI and error dictionaries',()=>{for(const locale of locales){assert.deepEqual(Object.keys(messages[locale]).sort(),Object.keys(en).sort());assert(Object.values(messages[locale]).every(v=>v.trim().length));assert.deepEqual(Object.keys(errorMessages[locale]).sort(),Object.keys(errorMessages.en).sort());assert(Object.values(errorMessages[locale]).every(v=>v.trim().length));}});
test('manual language outranks browser and country; browser outranks country',()=>{assert.deepEqual(resolveLocale({cookie:'wg_locale=ja',acceptLanguage:'ko-KR',trustedCountry:'US'}),{locale:'ja',source:'manual'});assert.deepEqual(resolveLocale({acceptLanguage:'fr-CA,fr;q=0.9,en;q=0.8',trustedCountry:'KR'}),{locale:'fr',source:'browser'});});
test('language negotiation handles weights, regional tags, exclusions and malformed q',()=>{assert.equal(preferredLanguage('en;q=0.2,ja-JP;q=0.9,ko;q=0'),'ja');assert.equal(preferredLanguage('en;q=0,es;q=0.8'),'es');assert.equal(preferredLanguage('fr;q=bad,ko-KR;q=0.5'),'ko');assert.equal(preferredLanguage('de-DE,zh-Hans;q=0.8'),'zh');assert.equal(preferredLanguage('en;q=2,fr;q=0.123'),'fr');assert.equal(preferredLanguage('de-DE'),undefined);});
test('invalid or malicious cookies are ignored',()=>{for(const cookie of ['wg_locale=%E0%A4%A','wg_locale=__proto__','wg_locale=<script>','wg_locale=ko-KR'])assert.equal(localeCookie(cookie),undefined);assert.equal(localeCookie('other=value; wg_locale=es; x=y'),'es');});
test('country fallback only uses supported hints; unknown countries safely fall back',()=>{assert.deepEqual(resolveLocale({acceptLanguage:'de-DE',trustedCountry:'JP'}),{locale:'ja',source:'country'});assert.equal(resolveLocale({trustedCountry:'__proto__'}).locale,'en');assert.equal(resolveLocale({trustedCountry:'XX',defaultLocale:'ko'}).locale,'ko');assert.equal(resolveLocale({trustedCountry:'DE',defaultLocale:'invalid'}).locale,'en');});
test('forged IP/country headers without authenticated gateway are ignored',()=>{const headers=new Headers({'cf-ipcountry':'KR','x-forwarded-for':'8.8.8.8'});assert.equal(trustedCountry(headers,''),undefined);assert.equal(trustedCountry(headers,'x'.repeat(32)),undefined);headers.set('x-webguard-geo-token','bad');assert.equal(trustedCountry(headers,'x'.repeat(32)),undefined);headers.set('x-webguard-geo-token','x'.repeat(32));assert.equal(trustedCountry(headers,'x'.repeat(32)),'KR');headers.set('cf-ipcountry','XX');assert.equal(trustedCountry(headers,'x'.repeat(32)),undefined);});
test('errors use stable codes with localized text and never expose internal details',()=>{assert.equal(errorCode('Invalid credentials',401),'INVALID_CREDENTIALS');assert.equal(errorCode('secret DB connection details',503),'SERVICE_UNAVAILABLE');assert.equal(errorText('ko','INVALID_CREDENTIALS'),'이메일 또는 비밀번호가 올바르지 않습니다.');assert.equal(errorText('fr','unknown'),errorMessages.fr.SERVICE_UNAVAILABLE);assert.equal(errorText('ja','__proto__'),errorMessages.ja.SERVICE_UNAVAILABLE);assert.equal(eventLabel('ko','login_failed'),'로그인 실패');assert.equal(eventLabel('ko','unexpected raw message'),'기타 이벤트');});

import OpenAI from 'openai';
import {aiProviderError} from '../lib/ai-provider-error';
import {aiErrorCopy} from '../lib/ai-error-copy';
test('AI failures distinguish authentication, model, quota, rate and connection without leaking provider text',()=>{
 const samples:[number,string,string][]=[[401,'invalid_api_key','AI_AUTH_FAILED'],[403,'permission_denied','AI_AUTH_FAILED'],[404,'model_not_found','AI_MODEL_UNAVAILABLE'],[429,'insufficient_quota','AI_QUOTA_EXCEEDED'],[429,'project_spend_limit_exceeded','AI_QUOTA_EXCEEDED'],[429,'rate_limit_exceeded','AI_RATE_LIMITED'],[400,'unsupported_parameter','AI_REQUEST_REJECTED'],[500,'internal_error','AI_PROVIDER_FAILED']];
 for(const [status,code,expected] of samples){const failure=OpenAI.APIError.generate(status,{error:{code,message:'private-key-and-server-detail'}},undefined,new Headers());const mapped=aiProviderError(failure);assert.equal(mapped,expected);assert.equal(errorCode(mapped!,503),expected);for(const locale of locales)assert(!errorText(locale,mapped!).includes('private-key'));}
 assert.equal(aiProviderError(new OpenAI.APIConnectionTimeoutError()),'AI_CONNECTION_FAILED');assert.equal(aiProviderError(new Error('database-secret')),null);
 for(const locale of locales){assert.deepEqual(Object.keys(aiErrorCopy[locale]),Object.keys(aiErrorCopy.en));assert(Object.values(aiErrorCopy[locale]).every(Boolean));}
});
