/** Bounded, non-executing source heuristics. Findings are review signals, not malware verdicts. */
export type RepositoryFile = {path:string;text:string};
export type RepositoryFinding = {path:string;line:number;rule:string;severity:'high'|'medium';title:string;remediation:string};
export type RepositoryReview = {version:1;ruleVersion:string;files:number;bytes:number;findings:RepositoryFinding[];truncated:boolean;observedAt:string};
export const repositoryLimits={files:30,fileBytes:65536,totalBytes:524288,findings:150} as const;
export function reviewablePath(path:string){
 return path.length<=240&&!/[\x00-\x1f\x7f\\]/.test(path)&&!path.startsWith('/')&&!path.split('/').some(p=>!p||p==='.'||p==='..')&&
 !/(^|\/)(?:\.env(?:\..*)?|node_modules|\.git|vendor|\.next|dist|build)(\/|$)/i.test(path)&&
 /(?:\.(?:[cm]?[jt]sx?|py|go|ps1|sh|bat|cmd|csproj|vbproj|props|targets|ya?ml|json|md|toml)|(?:^|\/)(?:Dockerfile|Makefile))$/i.test(path);
}
type Rule={id:string;pattern:RegExp;title:[string,string];fix:[string,string];severity:'high'|'medium'};
const rules:Rule[]=[
 {id:'download-execute',pattern:/(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|\biwr\b|\birm\b).*(?:\|\s*(?:sh|bash|iex|Invoke-Expression)|Invoke-Expression|\bIEX\b|Start-Process|\beval\s*\()/i,title:['다운로드와 실행을 연결한 명령','Download-and-execute command'],fix:['내용·공식 출처·해시를 검토하고 다운로드 즉시 실행하는 흐름을 제거하세요.','Review content, official provenance and hashes; remove immediate execution of downloads.'],severity:'high'},
 {id:'encoded-shell',pattern:/(?:powershell|pwsh)(?:\.exe)?\b.*(?:-(?:enc(?:odedcommand)?|e)\s|ExecutionPolicy\s+Bypass|WindowStyle\s+Hidden)/i,title:['인코딩·숨김·정책 우회 PowerShell','Encoded, hidden or policy-bypassing PowerShell'],fix:['정상 관리 작업일 수도 있습니다. 명령을 실행하지 말고 디코딩된 내용과 필요성을 확인하세요.','May be legitimate administration. Review decoded content and necessity without executing it.'],severity:'high'},
 {id:'defense-change',pattern:/(?:Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|AmsiScanBuffer|EtwEventWrite|VerifiedAndReputablePolicyState|vssadmin\s+delete\s+shadows)/i,title:['보안·복구 기능 변경 단서','Security or recovery modification signal'],fix:['보호 기능·백업을 끄거나 예외를 추가하는 설치 지침을 따르지 말고 담당자에게 확인하세요.','Do not follow instructions disabling protection, backups or adding exclusions; obtain a review.'],severity:'high'},
 {id:'build-exec',pattern:/<(?:PreBuildEvent|PostBuildEvent|Exec)\b|BeforeTargets\s*=|AfterTargets\s*=/i,title:['빌드 중 자동 명령 실행','Build-time command execution'],fix:['빌드 전에 프로젝트·props·targets의 명령과 가져오는 파일을 검토하세요. 존재 자체로 악성은 아닙니다.','Review commands and imported project/props/targets files before building. Presence alone is not malicious.'],severity:'medium'},
 {id:'concealed-line',pattern:/[ \t]{180,}\S|[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/,title:['공백·방향 제어 문자로 숨긴 내용','Whitespace or directional concealment'],fix:['공백 표시를 켜고 전체 줄을 확인하세요. 압축 코드·서식 때문에 오탐할 수 있습니다.','Display whitespace and inspect the full line. Minification or formatting can cause false positives.'],severity:'medium'},
 {id:'persistence',pattern:/schtasks(?:\.exe)?\b.*\/create|CurrentVersion\\Run\b|sc(?:\.exe)?\s+create\b/i,title:['자동 시작 등록 단서','Persistence registration signal'],fix:['등록 대상·서명·설치 목적을 확인하세요. 자동 시작이 곧 감염의 증거는 아닙니다.','Review target, signature and installation purpose. Autostart is not proof of infection.'],severity:'medium'},
 {id:'campaign-ioc',pattern:/(?:^|[^\w.-])(?:muckanthropic\.com|muckduck\.duckdns\.org|muckcoding\.com|muckdeveloper\.com|130\.12\.182\.(?:172|209))(?![\w.-])/i,title:['공개 공격 지표 문자열 일치','Published campaign indicator string match'],fix:['Dr.Web 2026-11-05 지표와 일치합니다. 문서·시험 데이터도 일치할 수 있으므로 실행 이력과 함께 확인하세요. 해당 주소에 접속하지 마세요.','Matches Dr.Web 2026-11-05 indicators. Documentation/tests may match too; correlate execution history. Do not visit the address.'],severity:'high'},
];
export function inspectRepositoryFiles(input:unknown,locale:'ko'|'en'='ko'):RepositoryReview{
 if(!Array.isArray(input)||!input.length||input.length>repositoryLimits.files)throw new Error('INPUT_INVALID');
 const seen=new Set<string>();let bytes=0,truncated=false;const findings:RepositoryFinding[]=[];
 const add=(file:RepositoryFile,line:number,rule:string,title:[string,string],fix:[string,string],severity:'high'|'medium')=>{
  if(findings.length>=repositoryLimits.findings){truncated=true;return;}
  findings.push({path:file.path,line,rule,severity,title:title[locale==='ko'?0:1],remediation:fix[locale==='ko'?0:1]});
 };
 for(const value of input){
  if(!value||typeof value!=='object'||typeof value.path!=='string'||typeof value.text!=='string'||!reviewablePath(value.path)||seen.has(value.path)||value.text.includes('\0'))throw new Error('INPUT_INVALID');
  const file=value as RepositoryFile;seen.add(file.path);const size=new TextEncoder().encode(file.text).length;bytes+=size;
  if(size>repositoryLimits.fileBytes||bytes>repositoryLimits.totalBytes)throw new Error('INPUT_INVALID');
  const lines=file.text.split(/\r?\n/);
  lines.forEach((line,i)=>{for(const rule of rules)if(rule.pattern.test(line))add(file,i+1,rule.id,rule.title,rule.fix,rule.severity);});
  if(/(?:^|\/)package\.json$/i.test(file.path)){
   try {const scripts=JSON.parse(file.text).scripts;for(const key of ['preinstall','install','postinstall','prepare'])if(typeof scripts?.[key]==='string'&&scripts[key].trim()){
    add(file,Math.max(1,lines.findIndex(l=>l.includes('"'+key+'"'))+1),'install-hook',['의존 패키지 설치 시 자동 실행: '+key,'Install-time execution: '+key],['npm 설치도 명령을 실행할 수 있습니다. 스크립트와 의존성을 검토하고 시험 환경에서 scripts 비활성화를 고려하세요.','Installing packages may execute commands. Review scripts/dependencies; consider disabling scripts in a test environment.'],'medium');
   }}catch{add(file,1,'invalid-manifest',['package.json 해석 불가','Cannot parse package.json'],['유효한 원본 manifest를 다시 제공하세요. 설치 훅은 미검사입니다.','Provide a valid manifest. Install hooks remain unassessed.'],'medium');}
  }
  // Browsers expose base names for directly selected files, so YAML heuristics also cover ci.yml.
  if(/\.ya?ml$/i.test(file.path)){
   if(/\bpull_request_target\b/.test(file.text))add(file,1,'privileged-pr',['권한 있는 PR 이벤트 검토','Privileged PR trigger review'],['외부 PR 코드를 checkout·실행하는지, secrets·토큰 쓰기 권한이 노출되는지 확인하세요.','Review untrusted PR checkout/execution and access to secrets or write-capable tokens.'],'medium');
   lines.forEach((line,i)=>{const match=line.match(/\buses:\s*["']?([\w.-]+\/[\w./-]+)@([^\s"'#]+)/);if(match&&!/^[a-f\d]{40}$/i.test(match[2]))add(file,i+1,'unpinned-action',['Action이 전체 커밋 SHA에 고정되지 않음','Action not pinned to full commit SHA'],['검토한 전체 40자리 커밋 SHA에 고정하고 업데이트를 검토하세요. SHA 고정도 안전성 보증은 아닙니다.','Pin a reviewed full 40-character commit SHA and review updates. Pinning does not guarantee safety.'],'medium');});
  }
 }
 return {version:1,ruleVersion:'2026-11-09.1',files:input.length,bytes,findings,truncated,observedAt:new Date().toISOString()};
}
