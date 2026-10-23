import {checkpoint,pick,report,textInput,type AssessmentContext,type AssessmentInput,type Finding,type SecurityScanner} from './types';

export function parseVmx(input:AssessmentInput){
 const values=new Map<string,string>();
 for(const line of textInput(input).split(/\r?\n/)){
  if(!line.trim()||line.trim().startsWith('#'))continue;
  const match=/^\s*([\w.:-]+)\s*=\s*"([^"\r\n]*)"\s*$/.exec(line);
  if(!match)throw new Error('VMX_INVALID');
  const key=match[1].toLowerCase();if(values.has(key))throw new Error('VMX_DUPLICATE');values.set(key,match[2]);
 }
 if(!values.has('config.version')||!values.has('virtualhw.version'))throw new Error('VMX_INVALID');
 return values;
}
export const vmwareConfig:SecurityScanner={id:'virtualization.vmx',version:'1.0.0',targetKind:'vmware-vmx-config',maxBytes:65536,
 validate(input){parseVmx(input);},async scan(input,ctx){checkpoint(ctx);const config=parseVmx(input),findings:Finding[]=[];
 const flag=(id:string,key:string,ko:string,en:string,safe:boolean)=>{
  const raw=config.get(key)?.toLowerCase(),known=raw==='true'||raw==='false',ok=known&&(raw==='true')===safe;
  findings.push({id,title:pick(ctx,ko,en),status:known?(ok?'pass':'warning'):'not_assessed',severity:known&&!ok?'medium':'info',evidence:[`explicit=${known}`,`safeDeclaration=${known?ok:'unknown'}`],remediation:pick(ctx,'업무상 필요한 공유인지 확인하고 VM 설정과 게스트에서 실제 적용을 별도로 검토하세요. 누락된 값의 기본 동작은 추정하지 않습니다.','Review the sharing requirement and effective VM/guest settings. Missing values do not establish a default.')});
 };
 flag('copy','isolation.tools.copy.disable','게스트 복사 격리 선언','Guest copy isolation declaration',true);
 flag('paste','isolation.tools.paste.disable','게스트 붙여넣기 격리 선언','Guest paste isolation declaration',true);
 flag('dragDrop','isolation.tools.dnd.disable','드래그 앤 드롭 격리 선언','Drag-and-drop isolation declaration',true);
 flag('sharedFolders','isolation.tools.hgfs.disable','공유 폴더 격리 선언','Shared-folder isolation declaration',true);
 flag('remoteConsole','remotedisplay.vnc.enabled','원격 VNC 비활성 선언','Remote VNC disabled declaration',false);
 const modes=[...config].filter(([key])=>/^ethernet\d+\.connectiontype$/.test(key)).filter(([key])=>config.get(key.replace('connectiontype','present'))?.toLowerCase()!=='false').map(([,value])=>value.toLowerCase());
 const bridged=modes.filter(v=>v==='bridged').length,unknown=modes.filter(v=>!['bridged','nat','hostonly','custom'].includes(v)).length;
 findings.push({id:'networkBoundary',title:pick(ctx,'가상 NIC의 네트워크 경계','Virtual NIC network boundary'),status:bridged?'warning':modes.length&&!unknown?'info':'not_assessed',severity:bridged?'medium':'info',evidence:[`declaredAdapters=${modes.length}`,`bridged=${bridged}`,`unknown=${unknown}`],remediation:pick(ctx,'브리지는 실제 LAN에 연결될 수 있으므로 격리 목적과 방화벽을 확인하세요. NAT·Host-only·Custom도 외부 차단이나 안전을 증명하지 않습니다.','Bridging may join the physical LAN; review isolation and firewall policy. NAT, host-only and custom do not prove isolation or safety.')});
 return report(this,findings,[pick(ctx,'사용자가 제공한 VMX의 명시적 설정만 점검','Only explicit declarations in the supplied VMX are assessed')],[pick(ctx,'VM 실행·변경·게스트 접속 없음. 기본값·실효 정책·VMware 취약점·게스트 OS·암호화·네트워크 도달성은 미검사. 경로·UUID·이름·비밀 값은 결과에 넣지 않습니다.','No VM execution/change or guest access. Defaults, effective policy, VMware vulnerabilities, guest OS, encryption and reachability are unassessed. No paths, UUIDs, names or secrets in reports.')]);
 }};

type LabNode={node_id:string,node_type:string,console_host?:string};
export function parseGns3(input:AssessmentInput){
 const value=JSON.parse(textInput(input));
 if(!value||typeof value!=='object'||value.type!=='topology'||typeof value.version!=='string'||!value.topology||!Array.isArray(value.topology.nodes)||!Array.isArray(value.topology.links))throw new Error('GNS3_INVALID');
 const {nodes,links}=value.topology;if(nodes.length>200||links.length>400)throw new Error('GNS3_LIMIT');
 const ids=new Set<string>();
 for(const node of nodes){if(!node||typeof node.node_id!=='string'||!node.node_id||node.node_id.length>128||ids.has(node.node_id)||typeof node.node_type!=='string'||!node.node_type||node.node_type.length>80||node.console_host!==undefined&&typeof node.console_host!=='string')throw new Error('GNS3_NODE_INVALID');ids.add(node.node_id);}
 for(const link of links)if(!link||!Array.isArray(link.nodes)||link.nodes.length!==2||link.nodes.some((end:any)=>!end||!ids.has(end.node_id)))throw new Error('GNS3_LINK_INVALID');
 return {nodes:nodes as LabNode[],links:links as {nodes:{node_id:string}[]}[]};
}
export const gns3Topology:SecurityScanner={id:'network.gns3',version:'1.0.0',targetKind:'gns3-topology-config',maxBytes:65536,
 validate(input){parseGns3(input);},async scan(input,ctx){checkpoint(ctx);const {nodes,links}=parseGns3(input);
 const external=nodes.filter(n=>['cloud','nat'].includes(n.node_type.toLowerCase())).length;
 const knownHosts=nodes.filter(n=>n.console_host!==undefined),exposed=knownHosts.filter(n=>!['127.0.0.1','::1','localhost'].includes(n.console_host!.toLowerCase())).length;
 const connected=new Set(links.flatMap(l=>l.nodes.map(n=>n.node_id))),isolated=nodes.filter(n=>!connected.has(n.node_id)).length;
 const findings:Finding[]=[
  {id:'externalBoundary',title:pick(ctx,'외부 연결 노드 선언','External connection node declarations'),status:external?'warning':'info',severity:external?'medium':'info',evidence:[`nodes=${nodes.length}`,`links=${links.length}`,`cloudOrNat=${external}`],remediation:pick(ctx,'Cloud/NAT 연결은 실습망을 외부 또는 호스트에 연결할 수 있습니다. 실제 어댑터·라우팅·방화벽을 별도로 확인하세요. 노드가 없다고 격리가 증명되지는 않습니다.','Cloud/NAT may join a lab to external or host networks. Separately verify adapters, routing and firewalls. Absence does not prove isolation.')},
  {id:'consoleBinding',title:pick(ctx,'콘솔 주소의 루프백 제한 선언','Console loopback binding declarations'),status:exposed?'warning':knownHosts.length===nodes.length&&nodes.length?'pass':'not_assessed',severity:exposed?'high':'info',evidence:[`explicitHosts=${knownHosts.length}`,`nonLoopback=${exposed}`],remediation:pick(ctx,'콘솔 호스트가 있으면 루프백 제한을 검토하세요. 프로젝트에 없으면 GNS3 서버 설정에서 직접 확인해야 합니다. Telnet 콘솔 형식은 장비의 Telnet 서비스 취약점을 의미하지 않습니다.','Review explicit console hosts and loopback restrictions. Missing project values require server-side verification. A Telnet console type does not establish a device Telnet vulnerability.')},
  {id:'topologyInventory',title:pick(ctx,'연결 구성 관찰','Topology connectivity inventory'),status:'info',severity:'info',evidence:[`nodes=${nodes.length}`,`links=${links.length}`,`unlinkedNodes=${isolated}`],remediation:pick(ctx,'연결 유무는 구성 정보입니다. 별도 격리 실습에서 의도한 통신과 차단을 확인하세요.','Connectivity is configuration information. Validate intended traffic and isolation in a separate lab.')},
  {id:'devicePolicy',title:pick(ctx,'장비 실효 정책·실제 통신','Effective device policy and live traffic'),status:'not_assessed',severity:'info',evidence:['liveProbe=false','deviceConfigurationRead=false'],remediation:pick(ctx,'프로젝트 파일만으로 장비 ACL·OS·암호·실제 포트·라우팅이나 취약점을 확정할 수 없습니다.','A project file does not establish device ACLs, OS, passwords, real ports, routing or vulnerabilities.')}
 ];
 return report(this,findings,[pick(ctx,'GNS3 2.x 프로젝트 JSON의 구조와 명시적 연결 선언','GNS3 2.x project JSON structure and explicit connectivity declarations')],[pick(ctx,'서버/장비 접속·스캔·설정 변경·프로젝트 실행 없음. 이름·주소·경로·명령·비밀 값은 결과에 저장하지 않습니다.','No server/device connection, scan, setting change or project execution. Names, addresses, paths, commands and secrets are excluded from reports.')]);
 }};
