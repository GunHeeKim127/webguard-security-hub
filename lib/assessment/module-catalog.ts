import type {ModuleId} from './types';

export type Category='web'|'mobile'|'endpoint'|'cloud'|'virtualization'|'network'|'iot'|'container'|'repository';
export const assessmentCategories:{id:Category,title:string,subtitle:string,module?:ModuleId,href?:string,scope:[string,string]}[]=[
 {id:'web',title:'Web',subtitle:'HTTP / TLS / 인증',module:'web.compare',href:'/?view=web',scope:['공개 헤더·TLS·응답 비교','Public headers, TLS and response comparison']},
 {id:'mobile',title:'Mobile',subtitle:'APK / IPA / PWA',module:'application.package',href:'/workbench/mobile',scope:['패키지 정적 점검 · PWA 준비 중','Package baseline · PWA planned']},
 {id:'endpoint',title:'Endpoint',subtitle:'Windows / Linux / macOS / JVM',module:'application.pe',href:'/workbench/endpoint',scope:['실행 파일·시스템·Java 런타임 점검','Executable, system and Java runtime review']},
 {id:'cloud',title:'Cloud',subtitle:'AWS / Azure / GCP',scope:['클라우드 설정·권한 점검 예정','Cloud configuration and access · planned']},
 {id:'virtualization',title:'Virtualization',subtitle:'VMX / OVF / XML / VBOX',module:'virtualization.vmx',href:'/workbench/virtualization',scope:['지원 VM 설정·제한 범위 확인','Supported VM configuration review']},
 {id:'network',title:'Network',subtitle:'GNS3 / DNS / Routing',module:'network.gns3',href:'/workbench/network',scope:['GNS3·DNS·라우팅 설정 점검','GNS3 / DNS / routing configuration review']},
 {id:'iot',title:'IoT',subtitle:'Firmware / Device Config',scope:['펌웨어·장비 설정 분석 예정','Firmware and device configuration · planned']},
 {id:'container',title:'Container',subtitle:'Docker / Kubernetes',scope:['컨테이너·클러스터 점검 예정','Container and cluster assessment · planned']},
 {id:'repository',title:'GitHub',subtitle:'Source / Dependencies / Advisories',href:'/workbench/repository',scope:['소스·공급망·공개 취약점 권고 검토','Source, supply chain and public advisory review']},
];
