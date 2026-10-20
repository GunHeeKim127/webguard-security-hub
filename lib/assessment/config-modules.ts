import {checkpoint,pick,report,textInput,type SecurityScanner,type Finding,type AssessmentContext} from './types';
const sshRef='https://man.openbsd.org/sshd_config';
export const linuxSsh:SecurityScanner={id:'linux.ssh',version:'1.0.0',targetKind:'linux-sshd-config',maxBytes:65536,validate(input){textInput(input);},async scan(input,ctx){
 checkpoint(ctx);const lines=textInput(input).split(/\r?\n/);if(lines.length>5000)throw new Error('INPUT_INVALID');
 const values=new Map<string,{value:string,line:number}>();let conditional=false;
 for(let n=0;n<lines.length;n++){checkpoint(ctx);const line=lines[n].replace(/#.*/,'').trim();if(!line)continue;const [key,...rest]=line.split(/\s+/);if(['include','match'].includes(key.toLowerCase())||/["'\\]/.test(line))conditional=true;if(!values.has(key.toLowerCase()))values.set(key.toLowerCase(),{value:rest.join(' ').toLowerCase(),line:n+1});}
 if(!['permitrootlogin','passwordauthentication','permitemptypasswords','pubkeyauthentication','maxauthtries','include','match'].some(k=>values.has(k)))throw new Error('INPUT_INVALID');
 const rules:[string,string,string,(s:string)=>boolean,string,string][]=[
 ['permitrootlogin','root 비밀번호 로그인 제한','Root password login restriction',v=>['no','prohibit-password','without-password','forced-commands-only'].includes(v),'PermitRootLogin과 실제 적용값을 확인하고 운영 정책에 따라 root 직접 접속을 제한하세요.','Review effective PermitRootLogin and restrict direct root access according to policy.'],
 ['passwordauthentication','SSH 비밀번호 인증','SSH password authentication',v=>v==='no','키 인증과 복구 접속을 먼저 검증한 뒤 비밀번호 인증을 제한하세요.','Verify key authentication and recovery access before restricting password authentication.'],
 ['permitemptypasswords','빈 비밀번호 허용','Empty password authentication',v=>v==='no','PermitEmptyPasswords를 no로 설정하고 실제 인증 정책을 확인하세요.','Set PermitEmptyPasswords no and verify effective authentication policy.'],
 ['pubkeyauthentication','공개키 인증','Public key authentication',v=>v==='yes','승인된 키와 파일 권한을 확인하고 공개키 인증을 검토하세요.','Review approved keys, file permissions and public key authentication.'],
 ['maxauthtries','인증 시도 제한','Authentication attempt limit',v=>/^\d+$/.test(v)&&Number(v)>=1&&Number(v)<=4,'MaxAuthTries 4 이하는 이 모듈의 검토 기준입니다. 운영 접근과 영향도를 확인하세요.','MaxAuthTries at most 4 is this module’s review baseline. Check operational impact.'],
 ];
 const findings:Finding[]=rules.map(([key,ko,en,test,koFix,enFix])=>{const value=values.get(key),known=!!value&&!conditional;return {id:key,title:pick(ctx,ko,en),status:!known?'not_assessed':test(value.value)?'pass':'warning',severity:known&&!test(value.value)?'medium':'info',evidence:[`explicit=${!!value}`,`line=${value?.line??0}`,`conditionalOrInclude=${conditional}`],remediation:pick(ctx,koFix,enFix),reference:sshRef};});
 return report(this,findings,[pick(ctx,'제공된 sshd_config의 명시적 전역 설정만 검사','Only explicit global directives in the supplied sshd_config')],[pick(ctx,'Include/Match가 있으면 유효 설정을 확정하지 않습니다. 기본값·실제 장비·키·서버 버전·접근 가능성은 미검사입니다.','Include/Match prevents effective-policy conclusions. Defaults, live hosts, keys, server versions and reachability are not assessed.')]);
}};
export const windowsPolicy:SecurityScanner={id:'windows.policy',version:'1.0.0',targetKind:'windows-policy-export',maxBytes:65536,validate(input){textInput(input);},async scan(input,ctx){
 checkpoint(ctx);let data:any;try{data=JSON.parse(textInput(input));}catch{throw new Error('INPUT_INVALID');}
 if(!data||Array.isArray(data)||data.schemaVersion!==1)throw new Error('INPUT_INVALID');
 const rules:[string,string,string,unknown,boolean,string,string][]=[
 ['firewall.domain','도메인 방화벽','Domain firewall',data.firewall?.domain,true,'도메인 프로필 방화벽과 허용 규칙을 검토하세요.','Review the domain firewall profile and allowed rules.'],
 ['firewall.private','개인 방화벽','Private firewall',data.firewall?.private,true,'개인 프로필 방화벽과 허용 규칙을 검토하세요.','Review the private firewall profile and allowed rules.'],
 ['firewall.public','공용 방화벽','Public firewall',data.firewall?.public,true,'공용 프로필 방화벽을 활성화하고 노출 서비스를 확인하세요.','Enable the public firewall profile and review exposed services.'],
 ['defender.antivirus','백신 활성 상태','Antivirus enabled',data.defender?.antivirus,true,'다른 백신을 사용하는 경우도 포함하여 보호 상태를 운영자가 확인하세요.','Review antivirus protection, including any third-party provider.'],
 ['defender.realtime','실시간 보호','Real-time protection',data.defender?.realtime,true,'보호 공급자와 실시간 보호 정책을 확인하세요.','Review the protection provider and real-time policy.'],
 ['rdp.nla','원격 데스크톱 NLA','Remote Desktop NLA',data.rdp?.enabled===false?true:data.rdp?.nla,true,'RDP 사용 여부와 NLA·방화벽·승인된 접근 경로를 함께 검토하세요.','Review RDP use, NLA, firewall and approved access paths together.'],
 ];
 const findings:Finding[]=rules.map(([id,ko,en,value,wanted,fix,fixEn])=>({id,title:pick(ctx,ko,en),status:typeof value!=='boolean'?'not_assessed':value===wanted?'pass':'warning',severity:typeof value==='boolean'&&value!==wanted?'medium':'info',evidence:[`reported=${typeof value==='boolean'?value:'unknown'}`],remediation:pick(ctx,fix,fixEn),reference:'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/'}));
 if(data.rdp?.enabled===false){const item=findings.find(f=>f.id==='rdp.nla')!;item.status='info';item.severity='info';item.evidence=['rdpReportedDisabled=true'];}
 return report(this,findings,[pick(ctx,'버전 1 JSON 내보내기의 선택된 상태값 검사','Selected state values in a version 1 JSON export')],[pick(ctx,'제공자가 작성한 스냅샷이며 현재 장비 상태·GPO 우선순위·예외 규칙·타사 백신은 검증하지 않습니다.','This is a supplied snapshot. Live state, GPO precedence, exceptions and third-party antivirus are unverified.')]);
}};
