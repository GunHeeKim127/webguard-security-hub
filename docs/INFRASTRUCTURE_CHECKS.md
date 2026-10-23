# VM·네트워크 설정 점검 — 2026-10-23

## 제품 기능

- Virtualization → `/workbench/virtualization`: VMware Workstation VMX 설정 64 KiB 이하.
- Network → `/workbench/network`: GNS3 2.x `.gns3` 프로젝트 JSON 64 KiB 이하, 최대 200노드·400링크.
- 일반 가입 회원도 본인 자산을 점검·저장·재검증한다. 기존 계정 격리와 30일 보관 정책을 그대로 사용한다.
- 파일 선택만으로 읽지 않는다. 해당 파일 읽기를 명시적으로 허용한 뒤 미리 보고, 별도 소유/진단 동의 후 전송한다. 직접 붙여넣기도 가능하다. 설정 원문은 현재 서버 요청의 메모리에서만 분석하고 저장하지 않는다.
- 결과에는 고정된 명시 여부·개수·관찰값만 남긴다. VM/노드 이름·UUID·주소·경로·비밀번호·명령 원문은 결과에서 제외한다. 시험 파일은 제품에 포함하지 않는다.

## 판정 범위

VMX는 복사·붙여넣기·드래그앤드롭·HGFS 격리 및 원격 VNC의 명시적 Boolean 값, 가상 NIC 연결 모드를 점검한다. 브리지는 검토 경고이며 NAT·Host-only를 안전/완전 격리로 판정하지 않는다. 값이 누락되면 기본값을 추정하지 않고 미검사다. 중복 키·잘못된 문법·VMX 식별 필드 누락은 거절한다. 통과는 해당 선언만의 통과다.

GNS3는 구조·노드 ID/링크 참조·Cloud/NAT 외부 연결 선언·명시된 콘솔 루프백 바인딩과 연결 수를 점검한다. 프로젝트에 콘솔 주소가 없으면 미검사다. GNS3의 Telnet 콘솔 형식은 장비의 실제 Telnet 서비스 취약점을 뜻하지 않는다. 장비 OS/ACL/암호/포트·실제 트래픽은 프로젝트 파일만으로 판정하지 않는다.

제품 서버가 고객 PC의 VMware/GNS3에 연결하거나 VM·프로젝트·장비를 실행/변경하지 않는다. 고객이 실제 실행 검증을 수행한 것처럼 결과를 표시하지 않는다. Cloud/AWS·Docker/Container·IoT는 준비 중으로 유지한다.

## 이 PC에서 확인한 실환경

- VMware Workstation vmrun: 등록 VM 13개, 확인 당시 실행 중 0개. Debian·Kali·Ubuntu의 기존 실제 VMX 3개를 원본 변경 없이 검사했다. 각 파일은 공유/복사 격리 Boolean이 명시되지 않아 5개 미검사·NIC 구성 참고로 나왔다. 게스트 부팅/로그인·실효 정책은 확인하지 않았다.
- GNS3 2.2.61 설치 확인. 기존 프로젝트와 별개로 127.0.0.1:3081의 HTTP Basic 인증된 검증 서버를 준비했다. 외부 Cloud/NAT/브리지 없이 VPCS 2대·링크 1개에 문서용 사설 실습 주소를 설정하고 ping 3회 응답을 확인했다. 자체 프로젝트의 노드를 중지·닫고 자체 서버도 중지했다. 기존 프로젝트와 호스트 방화벽은 바꾸지 않았다.
- 이 실습에서 생성한 실제 `.gns3` 파일과 기존 GNS3 프로젝트 2개를 새 엔진으로 분석했다. 프로젝트에 없는 콘솔 설정과 장비 정책은 미검사로 남았다. 실제 ping 검증은 이 PC의 별도 실습 증거이며 제품의 정적 판정과 구분한다.
- 실환경 자료·인증 값·패킷/콘솔 증거는 Git 제외 work/ 또는 별도 로컬 검증 경로에만 남긴다. 운영 DB에 시험 자료를 넣지 않는다.

## 검증·배포

105개 단위/회귀 검사·타입 검사·production 빌드가 통과했다. 경고/미검사 구분·중복 VMX 키·잘못된 링크·비밀 값 비노출·크기/취소 경계를 포함한다. 빌드는 최초 샌드박스의 출력 폴더 권한 오류 후 같은 명령을 권한 있는 실행으로 재검증했다.

최종 API/DB 통합도 통과했다. 일반 회원의 두 작전실·진단·경고→통과 재검증·이력·타 계정(관리자 포함) 404·원문 비노출과 기존 30일 보관/복구를 대조했다. 실제 로컬 브라우저에서는 파일 선택 직후 텍스트가 비어 있고 미동의 시 읽기 비활성인 것을 확인한 다음, 별도 동의를 거쳐 VMX 경고 2개·미검사 4개와 GNS3 경고 1개·미검사 2개를 저장했다. 증거는 Git 제외 work/vmware-module-verified.jpg, work/gns3-module-verified.jpg다. 운영 DB에 시험 파일·계정을 넣지 않았다.

일반 PostgreSQL migration 010, Prisma migration 006이 모듈 ID만 추가한다. 기존 데이터와 30일 보관 스키마는 변경하지 않는다.

기준 자료: [GNS3 공식 API 예제](https://github.com/GNS3/gns3-server/blob/master/docs/curl.rst), [GNS3 서버 설정](https://docs.gns3.com/docs/using-gns3/administration/gns3-server-configuration-file), [VMware/Broadcom 복사·붙여넣기 설정 설명](https://knowledge.broadcom.com/external/article/319537/enable-content-copypaste-between-vmrc-cl.html). 제품·버전마다 기본값과 실제 적용이 다르므로 명시된 파일 값을 실효 정책으로 과장하지 않는다.
