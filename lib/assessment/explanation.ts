import type {AssessmentStatus,Finding,ModuleId} from './types';

type Explanation={title:string;meaning:string;why:string;action:string};
type Copy=[string,string,string,string];
// Presentation only: never infer a verdict from prose, titles or evidence.
const ko:Record<string,Copy>={
 permitrootlogin:['관리자 계정의 비밀번호 직접 접속','서버의 최고 관리자(root) 계정에 비밀번호로 바로 접속할 수 있는지 봅니다.','이 계정의 비밀번호가 유출되면 서버 전체에 큰 영향을 줄 수 있습니다.','서버 담당자에게 root 비밀번호 직접 접속 제한을 요청하세요. 먼저 일반 관리자 계정과 복구 접속이 되는지 확인해야 합니다.'],
 passwordauthentication:['비밀번호만 사용하는 서버 접속','SSH 접속에서 비밀번호 인증이 허용되는지 봅니다.','비밀번호 추측이나 유출에 의한 접속 위험을 줄일 필요가 있습니다.','서버 담당자와 키 인증 도입을 검토하세요. 키와 복구 접속을 먼저 확인하고 비밀번호 인증 제한 여부를 결정하세요.'],
 permitemptypasswords:['비밀번호 없는 계정의 접속','빈 비밀번호를 사용하는 계정의 SSH 접속을 허용하는지 봅니다.','비밀번호 없는 계정이 접속할 수 있으면 다른 인증 조건에 따라 무단 접근 위험이 생길 수 있습니다.','담당자에게 PermitEmptyPasswords를 no로 설정하고 실제 인증 정책도 확인해 달라고 요청하세요.'],
 pubkeyauthentication:['접속용 보안 키 사용','승인된 보안 키를 사용한 SSH 인증이 켜져 있는지 봅니다.','키 인증을 이용하면 비밀번호에만 의존하는 접속을 줄일 수 있습니다.','승인된 키와 키 파일 권한을 점검한 뒤 공개키 인증을 사용할 수 있는지 확인하세요.'],
 maxauthtries:['로그인 실패 허용 횟수','한 번의 SSH 연결에서 인증을 몇 번까지 시도할 수 있는지 봅니다.','너무 많은 재시도를 허용하면 비밀번호 추측을 제한하기 어려워집니다. 이 검사는 4회 이하를 기준으로 삼습니다.','담당자에게 MaxAuthTries 값을 확인해 달라고 요청하세요. 운영 접속에 미치는 영향을 검토한 뒤 4회 이하 적용을 검토하세요.'],
 'firewall.domain':['회사 네트워크의 방화벽','회사 도메인 네트워크용 방화벽이 켜졌다고 보고됐는지 봅니다.','방화벽이 꺼져 있으면 원하지 않는 연결을 제한하는 보호가 줄어들 수 있습니다.','Windows 보안의 방화벽 설정에서 도메인 네트워크 보호와 필요한 예외 규칙을 확인하세요.'],
 'firewall.private':['개인 네트워크의 방화벽','집이나 신뢰하는 네트워크용 방화벽 상태를 봅니다.','신뢰하는 네트워크에서도 다른 기기의 불필요한 접근을 제한할 필요가 있습니다.','Windows 보안에서 개인 네트워크 방화벽을 확인하고 업무에 필요한 연결만 예외로 검토하세요.'],
 'firewall.public':['공용 네트워크의 방화벽','카페·공공 Wi-Fi 등에 적용되는 방화벽 상태를 봅니다.','같은 네트워크의 모르는 기기에서 들어오는 접근에 대비해야 합니다.','Windows 보안에서 공용 네트워크 방화벽이 켜졌는지, 외부에 열어 둔 서비스가 필요한지 확인하세요.'],
 'defender.antivirus':['백신 보호 상태','제공된 자료에서 백신이 활성 상태로 보고됐는지 봅니다.','백신 보호가 없거나 중단돼 있으면 악성 파일을 탐지할 기회가 줄어들 수 있습니다.','Windows 보안에서 실제 보호 공급자와 상태를 확인하세요. 다른 회사 백신을 쓴다면 해당 제품에서도 확인하세요.'],
 'defender.realtime':['파일을 사용할 때의 실시간 보호','파일을 열거나 사용할 때 백신이 검사하도록 설정됐는지 봅니다.','실시간 보호가 꺼져 있으면 위험한 파일을 사용할 때 바로 탐지하지 못할 수 있습니다.','사용 중인 백신의 실시간 보호 상태와 조직의 관리 정책을 확인하세요.'],
 'rdp.nla':['원격 화면 접속 전 사용자 확인','원격 데스크톱 연결 전에 사용자 인증을 요구하는지 봅니다.','원격 연결에 필요한 인증과 접속 경로를 함께 제한할 필요가 있습니다.','원격 데스크톱을 쓰는지 먼저 확인하세요. 사용한다면 NLA 인증, 방화벽, 승인된 접속 경로를 담당자와 함께 확인하세요.'],
 aslr:['프로그램 메모리 위치 보호 설정','프로그램이 메모리 위치를 무작위로 배치하는 보호 기능을 요청하는지 봅니다.','이 보호가 없으면 일부 메모리 취약점 공격을 어렵게 만드는 장치 하나가 부족할 수 있습니다.','프로그램 제작자에게 ASLR 또는 PIE 빌드 옵션을 확인해 달라고 요청하세요. 파일의 표시만으로 실제 보호 작동이 증명되지는 않습니다.'],
 nx:['데이터 영역의 코드 실행 제한','프로그램이 데이터 저장 영역에서 코드 실행을 막는 보호 기능을 요청하는지 봅니다.','이 보호가 없으면 일부 메모리 공격을 막는 장치 하나가 부족할 수 있습니다.','프로그램 제작자에게 DEP/NX 빌드 옵션과 실제 운영체제 적용 상태를 확인해 달라고 요청하세요.'],
 stack:['스택 메모리의 실행 허용','프로그램이 스택이라는 메모리 영역에서 코드 실행을 요청하는지 봅니다.','불필요한 실행 권한은 일부 메모리 공격에 이용될 여지를 늘릴 수 있습니다.','제작자에게 실행 가능한 스택이 꼭 필요한지 확인하세요. 필요한 기능과 운영체제의 실제 정책을 함께 검토하세요.'],
 wx:['같은 메모리 영역의 수정·실행 허용','같은 영역에 데이터를 쓰면서 코드를 실행하도록 선언했는지 봅니다.','필요 이상의 권한은 변조된 코드를 실행하는 공격에 이용될 수 있습니다.','제작자에게 해당 권한이 필요한지 확인하세요. JIT·패커 같은 기능에 필요한 경우도 있어 임의로 바꾸면 안 됩니다.'],
 debuggable:['앱의 개발자 디버깅 허용','앱에 개발자용 디버깅을 허용하는 설정이 있는지 봅니다.','배포용 앱에서 불필요한 디버깅은 내부 동작을 들여다볼 여지를 늘릴 수 있습니다.','앱 제작자에게 배포용 빌드에서 디버깅을 허용해야 하는지 확인해 달라고 요청하세요.'],
 allowBackup:['앱 데이터의 백업 허용','앱 데이터의 백업을 허용하는 설정을 봅니다.','백업 대상과 보호 방식에 따라 중요한 앱 데이터가 추가로 복사될 수 있습니다.','앱 담당자와 백업에 포함되는 데이터, 운영체제 버전별 보호, 필요한 예외를 함께 확인하세요.'],
 cleartext:['암호화하지 않은 앱 통신 허용','앱이 암호화되지 않은 통신을 허용하도록 설정됐는지 봅니다.','실제로 암호화되지 않은 통신을 쓰면 네트워크에서 내용이 노출·변조될 수 있습니다.','제작자에게 HTTPS 사용과 통신 예외를 확인해 달라고 요청하세요. 허용 설정만으로 실제 통신이 노출됐다고 단정하지 않습니다.'],
 arbitraryLoads:['앱의 폭넓은 HTTP 통신 허용','iOS 앱이 암호화 통신 제한을 넓게 완화했는지 봅니다.','실제 HTTP 통신을 사용하면 전송 내용을 보호하지 못할 수 있습니다.','앱 제작자와 HTTPS 사용 및 꼭 필요한 예외만 남길 수 있는지 확인하세요.'],
 networkBoundary:['가상 PC와 실제 네트워크의 연결','가상 PC가 실제 네트워크에 직접 연결되는 브리지 설정 등을 봅니다.','분리하려던 실습 환경이 실제 네트워크와 연결될 수 있습니다.','격리하려는 목적을 담당자에게 알려 주세요. 실제 어댑터·라우팅·방화벽도 함께 확인해야 하며 NAT나 Host-only만으로 안전이 보장되지는 않습니다.'],
 externalBoundary:['실습망의 외부 연결','GNS3 프로젝트에 Cloud·NAT 같은 외부 연결 노드가 있는지 봅니다.','실습 중인 트래픽이 호스트나 외부 네트워크로 연결될 수 있습니다.','이 연결이 의도된 것인지 확인하고 실제 어댑터·라우팅·방화벽도 함께 점검하세요.'],
 consoleBinding:['장비 관리 콘솔의 접속 범위','장비 관리 콘솔이 이 컴퓨터 안에서만 접속되도록 선언됐는지 봅니다.','다른 기기에서도 관리 콘솔에 접근할 수 있다면 관리 기능이 노출될 수 있습니다.','GNS3 담당자에게 콘솔 접속 주소와 접근 제한을 확인해 달라고 요청하세요. 프로젝트에 주소가 없으면 서버 설정에서 확인해야 합니다.'],
};
const shared:Copy=['가상 PC와 호스트 사이의 공유','가상 PC와 이 컴퓨터 사이에 복사·붙여넣기·파일 공유가 허용되는지 봅니다.','공유가 필요 이상으로 열려 있으면 격리하려던 환경 사이로 데이터가 이동할 수 있습니다.','업무에 필요한 공유만 남길 수 있는지 담당자와 검토하세요. 실제 VM 설정과 게스트에서 적용되는지도 따로 확인하세요.'];
for(const key of ['copy','paste','dragDrop','sharedFolders'])ko[key]=[({copy:'가상 PC에서 복사하기',paste:'가상 PC에 붙여넣기',dragDrop:'가상 PC와 파일 끌어놓기',sharedFolders:'가상 PC의 공유 폴더'} as Record<string,string>)[key],...shared.slice(1)] as Copy;
ko.remoteConsole=['가상 PC의 원격 화면 접속','VNC 방식의 원격 화면 접속이 켜져 있는지 봅니다.','필요하지 않은 원격 화면 접속은 추가 접근 경로가 될 수 있습니다.','VNC 접속이 업무상 필요한지 확인하고 접속 범위와 인증을 담당자와 함께 검토하세요.'];
ko['writable-executable']=ko.wx;
ko.signature=['파일의 제작자 서명 확인','파일 서명이 운영체제에서 유효한지 확인하는 항목입니다.','서명 확인은 제작자와 파일 변경 여부를 판단하는 데 도움이 되지만 악성코드가 없다는 보증은 아닙니다.','해당 파일의 운영체제에서 서명 검사를 실행해 유효기간과 신뢰 연결을 확인하세요. 브라우저 파일 구조 검사만으로는 이 판단을 대신할 수 없습니다.'];
ko.authenticode=ko.signature;ko['signature-trust']=ko.signature;
ko['signature-structure']=['파일 안의 서명 데이터','파일에 서명용 데이터 구조가 있는지 관찰합니다.','서명 데이터가 있다는 사실만으로 제작자의 신원이나 서명이 유효하다고 판단할 수 없습니다.','해당 운영체제의 서명 도구로 실제 유효성을 추가 확인하세요.'];
ko.gatekeeper=['macOS의 앱 실행 허용 확인','macOS가 앱 실행을 허용하는지 확인하는 항목입니다.','브라우저에서는 실제 Mac의 실행 정책을 확인할 수 없습니다. 실행 허용도 악성코드 부재를 보장하지 않습니다.','승인된 Mac에서 Gatekeeper 정책 검사 결과를 확인하세요.'];
ko.hardenedRuntime=['macOS 앱의 추가 실행 보호','앱에 추가 실행 보호 설정이 적용됐는지 확인합니다.','실제 운영체제의 보호 상태는 파일 일부 관찰만으로 확정할 수 없습니다.','Mac의 분석 도구에서 Hardened Runtime 설정과 실제 적용을 확인하세요.'];
ko.debugEntitlement=['앱 내부에 대한 디버깅 접근','macOS 앱이 디버깅 접근을 허용하는지 확인합니다.','배포 앱에 불필요한 개발 권한이 남았는지 검토할 필요가 있습니다.','제작자와 Mac 분석 담당자에게 배포용 앱의 디버깅 허용 권한을 확인해 달라고 요청하세요.'];
ko.permissions=['앱이 요청하는 기기 권한','앱이 기기 기능이나 데이터에 어떤 접근을 요청하는지 확인하는 항목입니다.','권한 수만으로 위험 여부를 판단할 수 없으며 앱 기능에 필요한 권한인지 확인해야 합니다.','앱 담당자에게 권한 목록과 기능상 필요성을 검토해 달라고 요청하세요. 현재 검사에서 목록을 확인하지 못했다면 Android 분석 도구로 추가 확인하세요.'];
ko['content-security-policy']=['웹페이지가 불러올 콘텐츠 제한','브라우저에 어떤 출처의 코드를 허용할지 알려 주는 정책을 봅니다.','불필요한 출처가 허용되면 일부 코드 삽입 공격을 제한하는 보호가 부족할 수 있습니다.','웹 담당자에게 CSP 정책과 필요한 외부 콘텐츠를 함께 검토해 달라고 요청하세요. 실제 페이지 동작도 확인해야 합니다.'];
ko['strict-transport-security']=['암호화된 웹 연결 유지','브라우저가 HTTPS 연결을 계속 사용하도록 안내하는지 봅니다.','보호 정책이 부족하면 암호화되지 않은 연결로 되돌아가는 상황을 충분히 제한하지 못할 수 있습니다.','웹 담당자에게 HSTS 설정을 확인해 달라고 요청하세요. 하위 도메인 영향과 HTTPS 준비 상태를 먼저 확인해야 합니다.'];
ko['x-content-type-options']=['웹 파일 형식의 잘못된 해석 방지','브라우저가 서버가 지정한 파일 형식을 따르도록 하는지 봅니다.','브라우저가 파일 형식을 임의로 해석하는 일부 상황을 제한할 필요가 있습니다.','웹 담당자에게 X-Content-Type-Options와 실제 콘텐츠 형식 설정을 확인해 달라고 요청하세요.'];
ko['referrer-policy']=['다른 사이트로 전달되는 주소 정보','링크를 따라갈 때 원래 페이지 주소가 얼마나 전달되는지 봅니다.','페이지 주소에 중요한 값이 포함돼 있다면 다른 사이트로 노출될 수 있습니다.','웹 담당자와 Referrer-Policy를 검토하고 민감한 값을 주소에 넣지 않는지도 확인하세요.'];
ko.csp=ko['content-security-policy'];ko.hsts=ko['strict-transport-security'];ko.nosniff=ko['x-content-type-options'];ko.referrer=ko['referrer-policy'];

export const statusCopy:Record<AssessmentStatus,{ko:string;en:string}>={warning:{ko:'보완·검토 필요',en:'Review or improve'},not_assessed:{ko:'아직 확인하지 못함',en:'Not yet verified'},pass:{ko:'이 항목의 기준 충족',en:'Meets this check'},info:{ko:'참고할 정보',en:'Observation'}};
export function orderedFindings(findings:readonly Finding[]){const order={warning:0,not_assessed:1,info:2,pass:3},priority={high:0,medium:1,low:2,info:3};return findings.map((finding,index)=>({finding,index})).sort((a,b)=>order[a.finding.status]-order[b.finding.status]||(a.finding.status==='warning'?priority[a.finding.severity]-priority[b.finding.severity]:0)||a.index-b.index).map(v=>v.finding);}
export function explainFinding(f:Finding,moduleId:ModuleId,locale:'ko'|'en'):Explanation{
 const key=f.id.replace(/^(?:arch-\d+|local|desktop|mobile):/,'');
 const profile=f.id.startsWith('desktop:')?'PC · ':f.id.startsWith('mobile:')?(locale==='ko'?'모바일 · ':'Mobile · '):'';
 const architecture=/^arch-(\d+):/.exec(f.id);
 const prefix=profile+(architecture?(locale==='ko'?`실행 형식 ${architecture[1]} · `:`Architecture ${architecture[1]} · `):'');
 if(locale==='ko'&&ko[key]){const [title,meaning,why,action]=ko[key];return {title:prefix+title,meaning,why,action};}
 const signature=/signature|authenticode|gatekeeper|hardenedRuntime|debugEntitlement/.test(key);
 const advisory=key.startsWith('technology:')&&/(?:CVE-|GHSA-)/.test(key);
 return {
  title:f.title,
  meaning:locale==='ko'?(advisory?'응답에서 관찰한 제품·버전 흔적을 등록된 보안 권고와 비교한 항목입니다.':signature?'파일의 서명이나 운영체제 보호 설정을 확인하는 항목입니다.':moduleId.startsWith('application.')?'제공한 파일에서 확인할 수 있는 구조나 설정 정보입니다.':'아래 검사 결과와 제공된 자료를 바탕으로 이 항목을 확인합니다.'):'This item describes what was observed in the supplied input. Review the result and next step below.',
  why:locale==='ko'?(advisory?'버전 흔적이 영향 범위와 맞아도 실제 취약점이나 침해가 확정된 것은 아닙니다. 설치된 버전과 구성을 따로 확인해야 합니다.':signature?'서명 데이터가 있거나 운영체제가 허용했다는 사실만으로 악성코드가 없다고 보장할 수 없습니다.':f.status==='warning'?'제공된 자료에서 이 항목의 검토 기준에 맞지 않는 신호가 관찰됐습니다. 실제 사용 환경에 미치는 영향을 확인해야 합니다.':'이 항목의 관찰만으로 전체 파일·기기·사이트가 안전하다고 판단할 수 없습니다.'):'A finding is limited to this check; it does not establish compromise or the overall safety of the asset.',
  action:locale==='ko'&&advisory?'운영 담당자에게 실제 설치 버전과 공식 보안 업데이트 적용 여부를 확인해 달라고 요청하세요.':f.remediation,
 };
}
