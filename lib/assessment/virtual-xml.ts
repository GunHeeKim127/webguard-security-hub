import {DOMParser,type Element} from '@xmldom/xmldom';
import {pick,report,textInput,type AssessmentInput,type AssessmentContext,type Finding,type SecurityScanner} from './types';

/** children: 같은 네임스페이스의 직계 자식 요소만 선택합니다 주요 호출: filter·from. */ function children(parent:Element,name:string){return Array.from(parent.childNodes).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ (n):n is Element=>n.nodeType===1&&n.localName===name&&n.namespaceURI===parent.namespaceURI);}
/** virtualXml: 입력 XML의 지원 형식·구조를 검증하고 안전하게 읽은 문서를 반환합니다 주요 호출: textInput·startsWith·trimStart. */ export function virtualXml(input:AssessmentInput){
 const text=textInput(input);if(!text.trimStart().startsWith('<'))return null;
 // No DTDs, entity definitions, stylesheet processing or remote resolution.
 if(/<!\s*(?:DOCTYPE|ENTITY)|<\?(?!xml\s)/i.test(text)||(text.match(/</g)?.length??0)>4096)throw new Error('VIRTUAL_XML_INVALID');
 let root:Element;try{root=new DOMParser({/** onError: 파서 오류를 중단 처리합니다 */ onError(){throw new Error('VIRTUAL_XML_INVALID');}}).parseFromString(text,'application/xml').documentElement!;}catch{throw new Error('VIRTUAL_XML_INVALID');}
 if(!root)throw new Error('VIRTUAL_XML_INVALID');
 const todo:[Element,number][]=[[root,0]];while(todo.length){const [node,depth]=todo.pop()!;if(depth>48)throw new Error('VIRTUAL_XML_INVALID');for(const child of Array.from(node.childNodes))if(child.nodeType===1)todo.push([child as Element,depth+1]);}
 const ns=root.namespaceURI??'';
 if(root.localName==='Envelope'&&['http://schemas.dmtf.org/ovf/envelope/1','http://schemas.dmtf.org/ovf/envelope/2'].includes(ns)&&root.getElementsByTagNameNS(ns,'VirtualSystem').length)return {format:'ovf' as const,root};
 if(root.localName==='domain'&&!ns&&['kvm','qemu','xen','lxc','bhyve','vmware','hyperv'].includes(root.getAttribute('type')??'')&&children(root,'devices').length===1)return {format:'libvirt' as const,root};
 if(root.localName==='VirtualBox'&&ns==='http://www.virtualbox.org/'&&children(root,'Machine').length===1)return {format:'vbox' as const,root};
 throw new Error('VIRTUAL_XML_UNSUPPORTED');
}
/** scanVirtualXml: 지원 가상화 XML의 명시적 설정을 진단 결과로 변환합니다 주요 호출: virtualXml·push·pick. */ export function scanVirtualXml(module:SecurityScanner,input:AssessmentInput,ctx:AssessmentContext){
 const parsed=virtualXml(input);if(!parsed)throw new Error('VIRTUAL_XML_INVALID');const {format,root}=parsed,findings:Finding[]=[];
 const add=/** add: 고정된 관찰과 개선 안내를 현재 진단 결과에 추가합니다 주요 호출: push·pick. */ (id:string,ko:string,en:string,value:number|null,why:string,whyEn:string)=>findings.push({id:'virtual:'+id,title:pick(ctx,ko,en),status:value===null?'not_assessed':value>0?'warning':'info',severity:value!==null&&value>0?'medium':'info',evidence:[`declarations=${value??'unknown'}`,'effectiveStateVerified=false'],remediation:pick(ctx,why,whyEn)});
 if(format==='ovf'){
  findings.push({id:'virtual:inventory',title:pick(ctx,'OVF 가상 시스템 설명','OVF virtual-system descriptor'),status:'info',severity:'info',evidence:[`systems=${root.getElementsByTagNameNS(root.namespaceURI!,'VirtualSystem').length}`],remediation:pick(ctx,'설명 파일의 구조만 확인했습니다. 실제 하이퍼바이저로 가져온 뒤 설정과 격리 상태를 별도로 확인하세요. 참조 디스크나 외부 주소를 열지 않습니다.','Only descriptor structure was observed. Verify imported hypervisor configuration and isolation separately. Referenced disks and URLs are never opened.')});
  add('isolation','OVF의 실제 공유·격리 상태','OVF effective sharing and isolation',null,'OVF만으로 실제 복사·공유·원격 콘솔 상태를 확정할 수 없습니다. 가져온 VM의 설정 자료가 추가로 필요합니다.','OVF alone does not establish effective sharing or remote-console state. Supply the imported VM configuration.');
 }else if(format==='libvirt'){
  const devices=children(root,'devices')[0],interfaces=children(devices,'interface'),shares=children(devices,'filesystem'),graphics=children(devices,'graphics').filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes·getAttribute. */ e=>['vnc','spice'].includes(e.getAttribute('type')??''));
  add('sharing','게스트와 연결된 파일 시스템 선언','Guest filesystem sharing',shares.length,'공유 파일 시스템이 의도된 것인지 확인하고 쓰기 권한·게스트 신뢰 수준을 검토하세요. 경로 자체를 위험으로 판정하지 않습니다.','Review intended sharing, write permissions and guest trust. A path by itself is not a vulnerability.');
  const bridged=interfaces.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes·getAttribute. */ e=>['bridge','direct'].includes(e.getAttribute('type')??'')).length;
  add('bridging','브리지·직접 NIC 연결 선언','Bridge/direct NIC declarations',interfaces.length?bridged:null,'실제 LAN과의 연결 목적 및 호스트/게스트 방화벽을 확인하세요. network/NAT 선언만으로 격리를 보장하지 않습니다.','Review intended LAN connectivity and host/guest firewalls. A network/NAT declaration does not prove isolation.');
  let unknown=false,exposed=0;for(const g of graphics){const listens=children(g,'listen'),attr=g.getAttribute('listen');if(listens.length>1){unknown=true;continue;}const l=listens[0],type=l?.getAttribute('type'),address=l?.getAttribute('address');if(type==='none'||type==='socket')continue;if(type&&type!=='address'){unknown=true;continue;}if(attr&&address&&attr!==address){unknown=true;continue;}const v=address||attr;if(!v){unknown=true;continue;}if(!['127.0.0.1','::1'].includes(v))exposed++;}
  add('console','그래픽 콘솔 바인딩 선언','Graphics console binding',unknown||!graphics.length?null:exposed,'다른 기기의 콘솔 접근이 필요한지 확인하고 바인딩·인증·TLS·방화벽을 함께 검토하세요. 선언은 실제 도달성 검사가 아닙니다.','Review intended remote access together with binding, authentication, TLS and firewall policy. Declarations do not prove reachability.');
 }else{
  const machine=children(root,'Machine')[0],hardware=children(machine,'Hardware');if(hardware.length!==1)throw new Error('VIRTUAL_XML_UNSUPPORTED');const h=hardware[0];
  for(const [tag,id,ko,en] of [['Clipboard','clipboard','클립보드 공유 선언','Clipboard sharing'],['DragAndDrop','dragDrop','드래그앤드롭 공유 선언','Drag-and-drop sharing']] as const){const list=children(h,tag),mode=list[0]?.getAttribute('mode');add(id,ko,en,list.length===1&&['Disabled','HostToGuest','GuestToHost','Bidirectional'].includes(mode??'')?(mode==='Disabled'?0:1):null,'업무상 필요한 공유 방향인지 확인하세요. 명시된 설정만 검토하며 게스트 도구의 실제 적용은 별도입니다.','Review the required sharing direction. Only explicit declarations are assessed; guest-tool behavior is separate.');}
  const folders=children(h,'SharedFolders');add('sharing','공유 폴더 선언','Shared-folder declarations',folders.length===1?children(folders[0],'SharedFolder').length:null,'공유 목적·쓰기 권한을 확인하세요. 경로·폴더 이름은 결과에 보관하지 않으며 기본값은 추정하지 않습니다.','Review purpose and write access. Paths/names are excluded and defaults are not inferred.');
  const remote=children(h,'RemoteDisplay'),enabled=remote[0]?.getAttribute('enabled');add('console','원격 디스플레이 허용 선언','Remote-display declaration',remote.length===1&&['true','false'].includes(enabled??'')?(enabled==='true'?1:0):null,'필요한 원격 관리인지 확인하고 인증·암호화·접근 제한을 별도로 검토하세요.','Review intended remote administration, authentication, encryption and access control separately.');
 }
 findings.push({id:'virtual:limits',title:pick(ctx,'실효 설정·게스트 검증','Effective configuration and guest verification'),status:'not_assessed',severity:'info',evidence:['liveGuestVerified=false'],remediation:pick(ctx,'실제 VM 실행·게스트 OS·디스크 내부·취약점·네트워크 차단은 별도 환경에서 확인해야 합니다.','Live VM behavior, guest OS, disk contents, vulnerabilities and network blocking require separate verification.')});
 return {...report(module,findings,[pick(ctx,'선택한 XML 설정의 지원 구조·명시적 공유/콘솔 선언만 검토','Supported XML structure and explicit sharing/console declarations only')],[pick(ctx,'VM 실행·설정 변경·디스크/외부 참조 읽기 없음. 하이퍼바이저별 모든 설정을 지원하지 않으며 안전 인증이 아닙니다.','No VM execution, settings changes, disks or external reference reads. Not all hypervisor settings are supported; this is not a safety certification.')]),targetKind:'virtual-config:'+format,ruleVersion:'2026-11-02.1'};
}
