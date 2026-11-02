/** infrastructureFileIssue: 미지원 인프라 파일 형식에 맞는 대체 자료 안내를 반환합니다 주요 호출: pop·split·toLowerCase. */ export function infrastructureFileIssue(name:string,kind:'virtualization.vmx'|'network.gns3',locale:'ko'|'en'){
 const ext=name.toLowerCase().split('.').pop()??'',ko=locale==='ko';
 if(kind==='virtualization.vmx'&&['ova','vmdk','vdi','vhd','vhdx','qcow','qcow2','iso','vhdset'].includes(ext))return ko?'확인 불가 형식입니다. VM 디스크·OVA 묶음은 직접 검사하지 않습니다. 가상화 도구에서 VMX·OVF·libvirt XML 또는 VirtualBox .vbox 설정을 내보내 선택하세요.':'Unsupported format. Disks and OVA bundles are not directly inspected. Export VMX, OVF, libvirt XML or VirtualBox .vbox configuration using your hypervisor.';
 if(kind==='network.gns3'&&['gns3project','pkt','pka','pcap','pcapng'].includes(ext))return ko?'확인 불가 형식입니다. 프로젝트 묶음·Packet Tracer·패킷 캡처는 직접 검사하지 않습니다. GNS3 .gns3 프로젝트 또는 지원 장비/DNS의 텍스트 설정을 내보내 자료 종류에 맞춰 선택하세요.':'Unsupported format. Project bundles, Packet Tracer and packet captures are not directly inspected. Export a GNS3 .gns3 project or supported device/DNS text configuration and choose its evidence type.';
 return null;
}
