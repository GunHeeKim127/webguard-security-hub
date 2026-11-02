import {checkpoint,pick,report,textInput,type AssessmentInput,type AssessmentContext,type Finding,type SecurityScanner} from './types';

export type NetworkPolicy={type:'network-security-config';schemaVersion:1;format:'cisco-ios'|'bind9';configuration:string};
/** networkPolicy: 네트워크 설정 입력 형식과 필수 필드를 확인합니다 주요 호출: textInput·parse·some. */ export function networkPolicy(input:AssessmentInput):NetworkPolicy|null{
 const text=textInput(input);let value:unknown;try{value=JSON.parse(text);}catch{return null;}
 if(!value||typeof value!=='object'||(value as Record<string,unknown>).type!=='network-security-config')return null;
 const v=value as Record<string,unknown>;
 if(Object.keys(v).some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ k=>!['type','schemaVersion','format','configuration'].includes(k))||v.schemaVersion!==1||!['cisco-ios','bind9'].includes(String(v.format))||typeof v.configuration!=='string'||!v.configuration.trim()||v.configuration.includes('\0'))throw new Error('NETWORK_CONFIG_INVALID');
 return v as NetworkPolicy;
}
const references={dns:'https://bind9.readthedocs.io/en/latest/reference.html',rip:'https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_rip/configuration/xe-2/irr-xe-2-book.pdf',eigrp:'https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/command/ire-cr-book/ire-i1.html',isis:'https://www.cisco.com/c/en/us/support/docs/ip/integrated-intermediate-system-to-intermediate-system-is-is/13792-isis-authent.html'};
// Tokenize comments and quoted strings before checking BIND statements. Quoted
// names/secrets are opaque; no supplied token is copied into a finding.
/** bindTokens: BIND 주석·문자열·지시어를 구분해 토큰으로 읽습니다 주요 호출: slice·indexOf·push. */ function bindTokens(text:string){
 const tokens:string[]=[];let i=0;
 while(i<text.length){const c=text[i];if(/\s/.test(c)){i++;continue;}
  if(c==='#'||text.slice(i,i+2)==='//'){while(i<text.length&&text[i]!=='\n')i++;continue;}
  if(text.slice(i,i+2)==='/*'){const end=text.indexOf('*/',i+2);if(end<0)throw new Error('NETWORK_CONFIG_INVALID');i=end+2;continue;}
  if(c==='"'){i++;let closed=false;while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"'){closed=true;break;}}if(!closed)throw new Error('NETWORK_CONFIG_INVALID');tokens.push('quoted');continue;}
  if('{};!'.includes(c)){tokens.push(c);i++;continue;}
  let end=i;while(end<text.length&&!/[\s{};!"#]/.test(text[end])&&!['//','/*'].includes(text.slice(end,end+2)))end++;if(end===i)throw new Error('NETWORK_CONFIG_INVALID');tokens.push(text.slice(i,end).toLowerCase());i=end;
 }
 let depth=0;for(const token of tokens){if(token==='{')depth++;if(token==='}')depth--;if(depth<0||depth>32)throw new Error('NETWORK_CONFIG_INVALID');}if(depth)throw new Error('NETWORK_CONFIG_INVALID');return tokens;
}
/** dnsFindings: 지원되는 DNS 설정 선언에서 관찰·보완·미확인 항목을 만듭니다 주요 호출: bindTokens·some·includes. */ function dnsFindings(config:string,ctx:AssessmentContext):Finding[]{
 const tokens=bindTokens(config),findings:Finding[]=[];
 if(!tokens.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ t=>['options','zone','view','include'].includes(t)))throw new Error('NETWORK_CONFIG_INVALID');
 const scoped=tokens.includes('include')||tokens.includes('view')||tokens.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ t=>t==='options').length!==1;
 const start=tokens.indexOf('options');let options:string[]=[];
 if(!scoped&&tokens[start+1]==='{'){let depth=1;for(let i=start+2;i<tokens.length&&depth;i++){if(tokens[i]==='{')depth++;if(tokens[i]==='}')depth--;if(depth)options.push(tokens[i]);}}
 const values=/** values: 지원 설정 범위에서 지정 지시어의 선언들을 모읍니다 주요 호출: push. */ (name:string)=>{const result:string[][]=[];let depth=0;for(let i=0;i<options.length;i++){if(depth===0&&options[i]===name){if(result.length===2)return [[],[],[]];const v:string[]=[];let nested=0;for(let j=i+1;j<options.length;j++){const t=options[j];if(t===';'&&nested===0)break;if(t==='{')nested++;if(t==='}')nested--;v.push(t);}result.push(v);}if(options[i]==='{')depth++;if(options[i]==='}')depth--;}return result;};
 const one=/** one: 충돌하지 않는 단일 지시어 값을 반환하고 모호함은 미확인으로 둡니다 주요 호출: values·join. */ (key:string)=>{const v=values(key);return v.length===1?v[0].join(' '):'unknown';};
 const recursion=one('recursion'),recursive=['yes','true','1'].includes(recursion),authoritativeOnly=['no','false','0'].includes(recursion);
 const add=/** add: 고정된 관찰과 개선 안내를 현재 진단 결과에 추가합니다 주요 호출: push·pick. */ (id:string,ko:string,en:string,observed:string,warning:boolean,action:string,actionEn:string)=>findings.push({id:'net:dns:'+id,title:pick(ctx,ko,en),status:observed==='unknown'?'not_assessed':warning?'warning':'info',severity:warning?'medium':'info',evidence:[`observed=${observed}`,'effectivePolicyVerified=false'],remediation:pick(ctx,action,actionEn),reference:references.dns});
 const acl=one('allow-recursion');
 add('recursion','DNS 재귀 질의 허용 범위','DNS recursion access',scoped?'unknown':authoritativeOnly?'recursion-disabled':recursive&&acl==='{ any ; }'?'explicit-any':recursive&&acl!=='unknown'?'acl-declared':'unknown',recursive&&acl==='{ any ; }','재귀 허용과 any ACL이 함께 선언되면 외부 접근 가능 시 DNS 증폭 공격에 악용될 수 있습니다. 허가된 내부 클라이언트 ACL로 제한하고 allow-query-cache·방화벽·실제 외부 질의도 확인하세요. ACL 선언만으로 허용 범위가 안전하다고 인증하지 않습니다.','Recursion plus an any ACL may enable amplification if reachable. Restrict approved clients; verify cache ACLs, firewalls and external queries. An ACL declaration is not proof of safe access.');
 const transfer=one('allow-transfer');
 add('transfer','DNS 영역 전송 제한','DNS zone transfer access',scoped||transfer==='unknown'?'unknown':transfer==='{ any ; }'?'explicit-any':'restriction-declared',transfer==='{ any ; }','any 영역 전송 선언은 허가되지 않은 대상에 영역 정보를 노출할 수 있습니다. 보조 DNS와 TSIG 등 필요한 대상만 허용하고 각 zone의 재정의와 실제 AXFR 거절을 확인하세요. 이 검사는 zone별 실효 권한을 계산하지 않습니다.','An any transfer declaration may expose zone information. Limit authorized secondaries/TSIG, review zone overrides and test denied AXFR. Effective per-zone access is not computed.');
 const validation=one('dnssec-validation');
 add('dnssec','DNS 응답 DNSSEC 검증','DNSSEC validation',scoped?'unknown':authoritativeOnly?'authoritative-role-review':['no','false','0'].includes(validation)?'explicit-disabled':['auto','yes','true','1'].includes(validation)?'validation-declared':'unknown',!authoritativeOnly&&['no','false','0'].includes(validation),'재귀 DNS에서 검증을 끄면 서명된 응답의 위변조를 거르는 보호가 줄어듭니다. 역할에 맞춰 검증·신뢰 앵커·시각 동기화를 확인하고 정상/깨진 서명 도메인으로 대조하세요. 권한 전용 서버의 영역 서명과 재귀 검증은 다른 항목입니다.','Disabling resolver validation removes protection for signed responses. Review role, trust anchors and clock; compare valid/bogus signed answers. Authoritative zone signing is a separate concern.');
 add('scope','DNS 설정 범위·추가 자료','DNS scope and additional evidence','unknown',false,'include/view·ACL 정의·zone별 재정의·동적 업데이트·RRL·캐시 접근·실제 응답과 버전은 추가 확인해야 합니다. 누락은 비활성 또는 안전을 뜻하지 않습니다. include 경로를 자동으로 읽지 않습니다.','Includes, views, ACL definitions, zone overrides, dynamic updates, RRL, cache access, live responses and versions need separate verification. Missing values do not imply disabled or safe. Include paths are never opened.');
 return findings;
}
/** iosFindings: 지원되는 라우팅 설정 선언에서 관찰·보완·미확인 항목을 만듭니다 주요 호출: map·split·filter. */ function iosFindings(config:string,ctx:AssessmentContext):Finding[]{
 let context='';const rows=config.split(/\r?\n/).map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: trim·replace·join. */ raw=>{const line=raw.replace(/\s+!.*$/,'').trim();if(/^router\s+/i.test(line))context=line.toLowerCase().split(/\s+/).slice(0,2).join(' ');else if(line==='!'||/^(?:interface|line|ip access-list|key chain|end|exit)\b/i.test(line))context='';return {line,context};});
 const lines=rows.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ r=>r.line).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: startsWith. */ l=>l&&!l.startsWith('!'));
 if(!lines.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ l=>/^(?:router (?:rip|eigrp|isis)\b|interface\s+\S+)/i.test(l)))throw new Error('NETWORK_CONFIG_INVALID');
 const findings:Finding[]=[];
 for(const protocol of ['rip','eigrp','isis'] as const){
  const present=lines.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ l=>new RegExp('^router '+protocol+'(?:\\s|$)','i').test(l));
  // Scope attribution is intentionally conservative. Named EIGRP address-family,
  // interface/level coverage, key validity and defaults are not inferred.
  const relevant=protocol==='rip'?lines.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ l=>/^(?:no )?ip rip authentication\b/i.test(l)):protocol==='eigrp'?lines.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ l=>/^(?:no )?ip authentication (?:mode|key-chain) eigrp\b/i.test(l)):rows.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ r=>/^(?:no )?isis authentication (?:mode|key-chain)\b/i.test(r.line)||r.context==='router isis'&&/^(?:(?:no )?authentication (?:mode|key-chain)\b|(?:area|domain)-password\s)/i.test(r.line)).map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ r=>r.line);
  const weak=relevant.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ l=>/^no /i.test(l)||/\bmode text(?:\s|$)/i.test(l)||/^(?:area|domain)-password\s/i.test(l)).length;
  const digest=relevant.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ l=>!/^no /i.test(l)&&(protocol==='eigrp'?/\bmode eigrp \d+ md5(?:\s|$)/i.test(l):/\bmode (?:md5|hmac-sha-256)(?:\s|$)/i.test(l))).length;
  const name=protocol==='isis'?'IS-IS':protocol.toUpperCase();
  findings.push({id:'net:'+protocol+':authentication',title:pick(ctx,name+' 라우팅 메시지 인증',name+' routing message authentication'),status:!present?'not_assessed':weak?'warning':digest?'info':'not_assessed',severity:present&&weak?'medium':'info',evidence:[`processDeclared=${present}`,`weakOrDisabledDeclarations=${weak}`,`digestModeDeclarations=${digest}`,'effectivePolicyVerified=false'],remediation:pick(ctx,`${name}의 인증 해제·평문 선언은 같은 라우팅 구간의 비인가 업데이트 주입 위험을 검토할 단서입니다. 장비가 지원하는 메시지 인증을 양쪽 이웃에 맞추고 키 연결·유효기간·인터페이스별 적용을 확인하세요. MD5 선언은 최신 강도 보증이 아닙니다. 자료에 인증이 없으면 설정·실효 출력을 추가해야 하며 실제 무인증을 확정하지 않습니다.`,`${name} disabled/plaintext declarations warrant review of unauthorized routing update injection. Match supported message authentication on neighbors and verify key binding, lifetime and interface coverage. MD5 is not a modern-strength guarantee. Missing declarations require additional configuration/effective output, not a no-authentication verdict.`),reference:references[protocol]});
  findings.push({id:'net:'+protocol+':boundary',title:pick(ctx,name+' 이웃·경로 전파 경계',name+' neighbor and route boundaries'),status:'not_assessed',severity:'info',evidence:[`processDeclared=${present}`,'neighborCoverageVerified=false'],remediation:pick(ctx,`${name}이 필요한 구간인지 확인하고 비이웃 구간의 업데이트·접근을 제한하세요. passive-interface는 프로토콜마다 송수신 효과가 다르며 RIP에서는 수신 차단을 보장하지 않습니다. ACL·경로 필터·재분배 정책과 실제 이웃/경로 출력을 함께 검토해야 합니다.`,`Confirm intended ${name} segments and restrict non-neighbor access/updates. Passive-interface behavior varies; RIP passive mode does not guarantee receive blocking. Review ACLs, route filters, redistribution and actual neighbors/routes.`),reference:references[protocol]});
 }
 const rip1=rows.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ r=>r.context==='router rip'&&/^version 1$/i.test(r.line)||/^ip rip (?:send|receive) version [12](?: [12])?$/i.test(r.line)&&/\b1\b/.test(r.line));
 findings.push({id:'net:rip:version',title:pick(ctx,'RIP 버전 1 선언','RIP version 1 declaration'),status:rip1?'warning':'not_assessed',severity:rip1?'medium':'info',evidence:[`versionOneDeclaration=${rip1}`,'effectiveVersionVerified=false'],remediation:pick(ctx,'RIPv1은 메시지 인증을 제공하지 않습니다. 사용 중인 인터페이스·수신 버전을 확인하고 호환성을 검토해 인증이 가능한 RIPv2 또는 지원 프로토콜로 전환하세요. version 2 한 줄만으로 모든 인터페이스가 안전하다고 판단하지 않습니다.','RIPv1 has no message authentication. Review effective send/receive versions and migrate compatibly to authenticated RIPv2 or a supported protocol. One version 2 line does not prove interface coverage.'),reference:references.rip});
 return findings;
}
/** scanNetworkPolicy: 선택한 네트워크 자료 종류에 맞춰 정적 검토 보고서를 만듭니다 주요 호출: checkpoint·networkPolicy·dnsFindings. */ export async function scanNetworkPolicy(module:SecurityScanner,input:AssessmentInput,ctx:AssessmentContext){
 checkpoint(ctx);const policy=networkPolicy(input);if(!policy)throw new Error('NETWORK_CONFIG_INVALID');
 const findings=policy.format==='bind9'?dnsFindings(policy.configuration,ctx):iosFindings(policy.configuration,ctx);
 return {...report(module,findings,[pick(ctx,'제공된 BIND 9 또는 Cisco IOS 계열 설정의 제한된 정적 선언 검토','Limited static declaration review of supplied BIND 9 or Cisco IOS-style configuration')],[pick(ctx,'장비 접속·공격 실행·실효 정책 계산 없음. 설정 조각·미지원 문법·누락은 안전/취약 확정이 아닙니다. 원문·키·주소·이름은 결과에 저장하지 않습니다.','No device access, attack execution or effective-policy computation. Fragments, unsupported syntax and omissions do not prove safety or vulnerability. Raw content, keys, addresses and names are excluded from findings.')]),targetKind:'network-security-config:'+policy.format,ruleVersion:'2026-10-30.1'};
}
