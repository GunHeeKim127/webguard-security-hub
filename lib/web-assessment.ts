export type FindingStatus='pass'|'warning'|'info'|'not_assessed';
export type WebFinding={id:string,group:'headers'|'tls'|'cookies'|'cors'|'exposure',status:FindingStatus,severity:'info'|'low'|'medium',evidence:string[],issues:string[]};
export type TlsObservation={authorized:boolean,protocol:string|null,validTo:string|null};
export const corsProbeOrigin='https://webguard-probe.invalid';
type Headers=Record<string,string|string[]|undefined>;
const value=/** value: 지원 응답 필드의 값을 읽어 비교 형태로 정리합니다 주요 호출: isArray·join. */ (headers:Headers,name:string)=>{const v=headers[name];return Array.isArray(v)?v.join(','):v??'';};
const finding=/** finding: 웹 관찰 항목의 상태·근거·개선 안내를 조립합니다 */ (id:string,group:WebFinding['group'],evidence:string[],issues:string[],status:FindingStatus=issues.length?'warning':'pass'):WebFinding=>({id,group,status,severity:status==='warning'?'medium':'info',evidence,issues});

// Deliberately a conservative static baseline, not a browser CSP parser or exploit verdict.
/** assessWeb: 허가된 웹 대상의 제한된 공개 응답을 검사합니다 주요 호출: value·map·split. */ export function assessWeb(headers:Headers,tls?:TlsObservation,now=Date.now()):WebFinding[]{
 const result:WebFinding[]=[];
 const csp=value(headers,'content-security-policy');
 const policies=csp.split(',').map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: split·trim·has. */ policy=>{const directives=new Map<string,string[]>();for(const part of policy.split(';')){const [name,...tokens]=part.trim().split(/\s+/);if(name&&!directives.has(name.toLowerCase()))directives.set(name.toLowerCase(),tokens);}return directives;});
 const cspIssues:string[]=[];
 if(!csp)cspIssues.push('missing');
 else {
  // Each delivered policy is reviewed; multiple policies can intersect more restrictively.
  for(const directives of policies){
   if(!directives.has('default-src')&&!directives.has('script-src'))cspIssues.push('csp_baseline');
   const script=[...(directives.get('script-src-elem')??directives.get('script-src')??directives.get('default-src')??[]),...(directives.get('script-src')??[])];
   if(script.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes·toLowerCase. */ token=>['*','http:','https:','data:',"'unsafe-inline'","'unsafe-eval'"].includes(token.toLowerCase())))cspIssues.push('csp_broad');
   const broad=/** broad: 넓은 허용 선언이 포함됐는지 검토합니다 주요 호출: some. */ (tokens:string[]|undefined)=>tokens?.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes·toLowerCase. */ token=>['*','http:','https:','data:'].includes(token.toLowerCase()));
   if((!directives.has('object-src')&&!directives.has('default-src'))||broad(directives.get('object-src')??directives.get('default-src')))cspIssues.push('csp_objects');
   if(!directives.has('base-uri')||broad(directives.get('base-uri')))cspIssues.push('csp_base');
   if(!directives.has('frame-ancestors')||broad(directives.get('frame-ancestors')))cspIssues.push('csp_frame');
  }
 }
 result.push(finding('csp','headers',[`enforced=${!!csp}`,`reportOnly=${!!value(headers,'content-security-policy-report-only')}`,`policies=${csp?policies.length:0}`],[...new Set(cspIssues)]));
 const hsts=value(headers,'strict-transport-security'),hstsIssues:string[]=[];
 const ages=[...hsts.matchAll(/(?:^|;)\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*(?=;|$)/gi)],age=ages.length===1?(ages[0][1]??ages[0][2]):null;
 const ageDirectives=hsts.split(';').filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ part=>/^\s*max-age\b/i.test(part)).length;
 if(!hsts)hstsIssues.push('missing');else if(age===null||ageDirectives!==1)hstsIssues.push('hsts_invalid');else if(BigInt(age)<15552000n)hstsIssues.push('hsts_short');
 result.push(finding('hsts','headers',[`max-age=${age??'unknown'}`,`includeSubDomains=${/(?:^|;)\s*includeSubDomains\s*(?:;|$)/i.test(hsts)}`],hstsIssues));
 const nosniff=value(headers,'x-content-type-options');
 result.push(finding('nosniff','headers',[`nosniff=${nosniff.trim().toLowerCase()==='nosniff'}`],!nosniff?['missing']:nosniff.trim().toLowerCase()!=='nosniff'?['nosniff_invalid']:[]));
 const referrer=value(headers,'referrer-policy'),known=['no-referrer','no-referrer-when-downgrade','origin','origin-when-cross-origin','same-origin','strict-origin','strict-origin-when-cross-origin','unsafe-url'];
 const effective=referrer.split(',').map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: trim. */ v=>v.trim()).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes. */ v=>known.includes(v)).at(-1);
 result.push(finding('referrer','headers',[`effective=${effective??'unknown'}`],!referrer?['missing']:!effective?['referrer_invalid']:['unsafe-url','no-referrer-when-downgrade'].includes(effective)?['referrer_broad']:[]));

 if(!tls)result.push(finding('tls','tls',[],['tls_unavailable'],'not_assessed'));
 else {
  const expires=tls.validTo?Date.parse(tls.validTo):NaN,remaining=Number.isFinite(expires)?Math.floor((expires-now)/86400000):null;
  const issues:string[]=[];
  if(!tls.authorized)issues.push('tls_untrusted');
  if(!['TLSv1.2','TLSv1.3'].includes(tls.protocol??''))issues.push('tls_protocol');
  if(remaining===null)issues.push('tls_expiry_unknown');else if(expires<=now)issues.push('tls_expired');else if(remaining<=30)issues.push('tls_expiring');
  result.push(finding('tls','tls',[`trusted=${tls.authorized}`,`protocol=${tls.protocol??'unknown'}`,`expires=${Number.isFinite(expires)?new Date(expires).toISOString():'unknown'}`,`days=${remaining??'unknown'}`],issues));
 }

 const cookies=headers['set-cookie'],list=Array.isArray(cookies)?cookies:cookies?[cookies]:[];
 if(!list.length)result.push(finding('cookies','cookies',['observed=0'],['cookies_unobserved'],'not_assessed'));
 list.slice(0,32).forEach(/** forEach 콜백: 각 항목의 처리를 순서대로 실행합니다 주요 호출: split·shift·slice. */ (cookie,index)=>{
  // Never copy a cookie name, value, domain or path to storage, UI, logs or AI.
  const parts=cookie.split(';'),first=parts.shift()??'',name=first.slice(0,first.indexOf('='));
  const attrs=new Map<string,string>();const duplicates=new Set<string>();
  for(const part of parts){const i=part.indexOf('='),key=(i<0?part:part.slice(0,i)).trim().toLowerCase();if(attrs.has(key))duplicates.add(key);attrs.set(key,i<0?'':part.slice(i+1).trim());}
  const secure=attrs.has('secure'),httpOnly=attrs.has('httponly'),sameSite=(attrs.get('samesite')??'').toLowerCase(),issues:string[]=[];
  if(!secure)issues.push('cookie_secure');
  if(!httpOnly)issues.push('cookie_httponly');
  if(!['lax','strict','none'].includes(sameSite))issues.push('cookie_samesite');
  if(sameSite==='none'&&!secure)issues.push('cookie_none');
  if((name.startsWith('__Secure-')&&!secure)||(name.startsWith('__Host-')&&(!secure||attrs.has('domain')||attrs.get('path')!=='/'))||(attrs.has('partitioned')&&!secure))issues.push('cookie_prefix');
  if(duplicates.size)issues.push('cookie_duplicate');
  result.push(finding(`cookie-${index+1}`,'cookies',[`cookie=#${index+1}`,`Secure=${secure}`,`HttpOnly=${httpOnly}`,`SameSite=${['lax','strict','none'].includes(sameSite)?sameSite:'unspecified'}`,`Domain=${attrs.has('domain')}`],issues));
 });
 if(list.length>32)result.push(finding('cookie-limit','cookies',['limit=32'],['cookie_limit'],'not_assessed'));
 const origin=value(headers,'access-control-allow-origin'),credentials=value(headers,'access-control-allow-credentials'),vary=value(headers,'vary').toLowerCase().split(',').map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: trim. */ v=>v.trim()),corsIssues:string[]=[];
 if(origin===corsProbeOrigin)corsIssues.push(credentials==='true'?'cors_credentials':'cors_probe');
 if(origin===corsProbeOrigin&&!vary.includes('origin')&&!vary.includes('*'))corsIssues.push('cors_vary');
 if(origin==='*'&&credentials==='true')corsIssues.push('cors_invalid');
 if(origin==='null')corsIssues.push('cors_null');
 if(origin&&origin!=='*'&&origin!=='null'&&origin!==corsProbeOrigin){try{const parsed=new URL(origin);if(parsed.origin!==origin||!['https:','http:'].includes(parsed.protocol))corsIssues.push('cors_invalid');}catch{corsIssues.push('cors_invalid');}}
 result.push(finding('cors','cors',[`allowOrigin=${!origin?'absent':origin===corsProbeOrigin?'probe':origin==='*'?'wildcard':'configured'}`,`credentials=${credentials==='true'}`,`varyOrigin=${vary.includes('origin')||vary.includes('*')}`],corsIssues,origin==='*'&&!corsIssues.length?'info':!origin?'not_assessed':corsIssues.length?'warning':'info'));
 const disclosed=['server','x-powered-by','x-aspnet-version'].filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: value. */ name=>!!value(headers,name));
 result.push(finding('exposure','exposure',disclosed.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ name=>`${name}=present`),disclosed.length?['exposure']:[],disclosed.length?'info':'pass'));
 return result;
}
