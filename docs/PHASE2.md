# VELTHARA 2단계 구현 범위

2026-10-27 후속: 파일 무결성 근거/서버 원본 검증·클라이언트 비신뢰 요청 경계·웹 기술 및 일부 CVE 대조를 [검토 보고서 13~15절](PROJECT_REVIEW_2026-10-27.md)에 추가했다. 회귀 127개·타입·빌드 통과. [웹 규칙 범위](WEB_TECHNOLOGY_ADVISORIES.md)는 전체 언어/전체 CVE 감사와 구분하며 2단계 진행 중이다.

2026-10-27 실환경 후속은 [검토 보고서 12절](PROJECT_REVIEW_2026-10-27.md)과 [검증 근거](validation/2026-10-27-local-environment/README.md)에 기록했다. 실제 VMX/GNS3/Windows PE의 현재 엔진 처리를 확인했으며 Linux 실효 설정·Windows 정책/서명 도구 환경 차이·장비 통신은 미완료다. 1단계 완료·2단계 진행 중을 유지한다.

2026-10-20 파일 검사 확장: 아래 초기 2 MiB 서버 검사 외에, 사용자 읽기 허용을 받는 Windows/macOS 및 모바일 패키지 브라우저 부분 점검과 선택형 로컬 실행 파일 검사 결과 가져오기를 추가했습니다. 최신 크기·형식별 범위와 절차는 [파일 검사 문서](FILE_INSPECTION.md)를 우선 참고하세요. 모바일 AAB/APKS/XAPK는 구조 관찰이며 IPA/APK의 지원하는 명시적 설정만 제한적으로 해독합니다.

기준은 `prompt.md` 13절의 2주 차와 2026-10-19 추가한 모듈형 설계입니다. 기존 WebGuard와 배포 주소·DB·계정을 유지하고 `/workbench`에 VELTHARA 모듈 진단 콘솔을 추가합니다. 저장소를 대규모 monorepo로 옮기지 않고 `lib/assessment/`의 공통 인터페이스·명시적 레지스트리·독립 검사 모듈로 경계를 만듭니다.

## 이번 범위와 다음 단계

| 기준 | 이번 구현 | 명시적 한계 |
|---|---|---|
| PC·모바일 웹 비교 | `web.compare`로 User-Agent별 공개 루트 HEAD 각 1회, 기존 DNS 고정·TLS·SSRF 방어 재사용 | 실제 모바일 브라우저·PWA·세션·GET·리디렉션은 미검사. 응답 차이는 취약점 확정 아님 |
| 개선 안내와 재검증 | 공통 Finding, 근거·심각도·개선 안내·규칙 버전, 같은 자산의 새 실행, 최근 10개 선택 비교·JSON 다운로드 | 파일은 다시 제공해야 함. 이전 미검사→현재 미검사를 개선으로 계산하지 않음. 정식 보고서·추세 UI는 다음 단계 |
| Windows/Linux 설정 | Windows 상태 JSON과 Linux sshd_config의 명시적 설정 | 실제 OS·서버 접근이나 에이전트가 아님. Include/Match/복잡한 인용 구문은 유효 설정을 확정하지 않음 |
| 애플리케이션 정적 분석 | PE/Mach-O 헤더·모바일 ZIP 구조, APK의 제한된 AXML Boolean·IPA plist ATS 선언 | 파일 실행·멀웨어·전체 CVE·MSI/ELF·서명 신뢰·설치 검증은 미지원. AAB/APKS/XAPK는 목록/구조만 |
| 가상화·네트워크 설정 | VMX 명시적 격리/VNC/NIC, GNS3 2.x 구조·외부 연결·콘솔 바인딩 | 실제 VM 실행·장비 정책·통신·다른 GNS3 메이저 버전은 미검사/거절 |
| 트래픽 이벤트 수집 | 명시적 연동 서버의 집계값 수집, 자산별 키 교체·해시 보관, 최근 5분 통계 | 연동 없는 외부 사이트를 자동 감시하지 않음. 원본 IP·URL·쿠키·본문은 수집 불가 |
| 이상 접근 규칙 | 집계 로그인 실패/탐색/5xx/요청량 임계 신호, 계정별 허브 이벤트 표시 | 공격자·봇·AI를 확정하지 않고 외부 자산을 자동 차단하지 않음 |

추가 설계의 클라우드·Cisco 장비 직접 접속·전체 네트워크 진단·컨테이너·IoT·자동 대응은 제외합니다. VMX/GNS3 정적 입력 검사는 제한된 추가 범위로 제공하며 전체 가상화/장비 진단과 구분합니다. 사용자에게 준비 중으로 표시하며 동작하지 않는 모듈을 선택하게 하지 않습니다. 기존 1단계 기록은 기존 화면에서 유지합니다. 신규 모듈 실행은 공통 자산/실행 기록에서 관리하며 과거 데이터를 임의로 다른 계정에 배정하지 않습니다.

## 모듈과 원문 처리

- SecurityScanner는 ID·버전·대상 종류·크기 제한·검증·scan을 가지며 AbortSignal과 언어를 받습니다. 사용자 입력 경로로 모듈을 import하거나 AI 생성 코드를 실행하지 않습니다.
- 구성 파일 64 KiB, 기존 서버 전송 EXE/DLL/APK 2 MiB. 브라우저 요약 경로는 최대 8 GiB 입력·총 8 MiB 읽기이며 해당 원본은 업로드하지 않습니다. JSON 요청은 해당 API만 3 MiB까지 스트리밍 제한합니다. 다른 API는 기존 4 KiB 제한을 유지합니다.
- 원문은 요청 메모리에서만 읽습니다. 설정·바이너리·파일명·비밀번호·키를 DB·로그·AI·다운로드에 복사하지 않습니다. 파일 지문, 고정 상태 분류와 근거만 저장합니다. 자산 이름은 사용자가 입력하므로 비밀값을 이름으로 사용하지 마세요.
- PE는 ASLR/DEP 선언 플래그와 W+X 섹션을 관찰합니다. 플래그가 런타임 보호를 증명하지 않습니다. 인증서 테이블 유무와 Authenticode 유효성은 구분합니다.
- 기존 APK 예비 모드는 중앙/로컬 ZIP 헤더·수량·경계·이름 일관성만 검사합니다. 새 모바일 부분 읽기는 제한된 APK Manifest/IPA plist 항목만 예산 내 해독합니다. ZIP64·분할·암호화·손상 컨테이너는 거절합니다. APK 서명 신뢰는 검증하지 않으며 AXML의 전체 의미·리소스 기본값·AAB protobuf·중첩 앱은 해독하지 않습니다.
- 새 콘솔의 UI/개선 안내는 한국어·영어를 지원합니다. 기존 웹 화면의 6개 언어는 유지합니다. 저장 결과는 실행 당시 언어이며 언어 전환만으로 다시 분석하거나 LLM을 호출하지 않습니다.

## 사용 방법

1. 기존 계정으로 로그인하고 검사 선택 버튼에서 전용 작전실로 이동합니다. 일반 회원(viewer 포함)도 자기 자산의 진단·저장·재검증이 가능합니다. 관리자 운영 정보는 분리합니다.
2. 모듈·자산 이름·HTTPS 주소 또는 허가된 파일/설정 내용을 제공하고 권한 선언에 체크합니다.
3. 진단 후 근거·개선 안내·미검사 범위를 확인합니다. 같은 자산 이름과 모듈로 수정된 파일을 제공해 재검증하면 두 결과를 비교할 수 있습니다. 웹 자산은 이름 대신 정규화한 hostname이 같은 자산 기준입니다.

Windows 상태 내보내기는 점검할 PC의 프로젝트 폴더에서 다음 읽기 전용 예제를 사용할 수 있습니다. 출력이 이미 있으면 덮어쓰지 않으므로 다른 파일명을 지정하세요. 권한/기능 부재로 조회할 수 없는 값은 null이며 안전으로 해석하지 않습니다.

```powershell
powershell -File scripts/examples/export-windows-policy.ps1 -OutputPath work/windows-policy-export.json
```

방화벽 ActiveStore, Defender 상태와 RDP 관련 읽기 조회만 수행하며 설정을 바꾸지 않습니다. 타사 백신과 GPO 우선순위 전체를 점검하지 않습니다. 생성한 JSON을 Windows 정책 모듈에 제공하세요. Linux는 허가된 sshd_config 텍스트를 제공하며 웹 서버가 SSH로 접속하지 않습니다.

## 트래픽 연동

웹 모듈로 만든 자신의 자산을 선택하고 수집 키 발급·교체를 누릅니다. 256-bit 키는 화면에 한 번 표시하며 DB에는 SHA-256만 저장합니다. 키 교체는 기존 키를 즉시 무효화합니다. 브라우저·NEXT_PUBLIC 변수·Git에 키를 넣지 마세요. 연동할 서버의 비밀 환경에만 다음을 둡니다.

```text
WEBGUARD_ORIGIN=https://webguard-security-hub.vercel.app
WEBGUARD_ASSET_ID=자산_ID
WEBGUARD_INGEST_TOKEN=발급한_서버전용_키
```

`scripts/examples/send-traffic.mjs`는 환경변수를 읽어 서버 간 집계 1건을 보내는 예제입니다. 실제 서비스의 서버에서 집계 후 다음 POST를 사용합니다. 자동 수집 에이전트를 설치하는 도구가 아닙니다. 전송 성공 여부가 불확실할 때 무조건 재시도하면 중복 집계될 수 있습니다.

```text
POST /api/telemetry
Authorization: Bearer <server-only-token>
Content-Type: application/json

{"assetId":"자산_UUID","requests":10,"loginFailures":2,"probes":1,"serverErrors":0}
```

원본 IP/경로를 받는 필드 자체가 없습니다. 각 수량은 0~1000, requests는 1 이상이며 다른 수량은 requests를 초과할 수 없습니다. 자산별 분당 60회로 제한하며 서버 시각의 분 단위로 합산합니다. 최근 5분 기준 로그인 실패 5회, 탐색 3회, 5xx 5회, 요청 1000회부터 검토 신호를 표시합니다. 정상 사용·잘못된 설정도 신호가 될 수 있고 송신 서버가 제공한 자기 보고 집계이며 인증된 사실이나 공격자 신원으로 보증하지 않습니다. 집계 자동 삭제 스케줄러·분산 WAF는 미구현입니다.

## DB와 보안

일반 PG는 `007_modular_assessments.sql`, Prisma는 `prisma-postgres/003_modular_assessments.sql`을 추가합니다. 기존 적용 migration은 수정하지 않습니다. 로컬은 db:migrate 뒤 db:grant, Prisma는 db:migrate:production만 사용합니다.

assessment_assets·assessment_runs·assessment_traffic에 계정/자산 결합 FK를 적용합니다. API는 세션 user_id를 조건으로 읽고 쓰며 admin도 다른 회원의 결과·키를 자동 조회하지 않습니다. 일반 PG runtime은 실행 기록 UPDATE와 자산 소유자 변경을 할 수 없습니다. Prisma의 넓은 제공자 키 제약은 기존 정책과 동일하며 RLS를 제공한다고 주장하지 않습니다. 기록은 DB에서 보존하고 화면에는 자산 50개/선택 자산 실행 10개를 보여줍니다. 작업 예약·격리 실행기·장비 설정 변경·AI 원문 분석은 추가하지 않았습니다.

기존 DB 복사 도구는 2단계 자산·실행·집계도 빈 대상에 복사하지만 로그인 세션과 수집 키는 복사하지 않습니다. 기존 계정/결과가 있는 DB는 덮어쓰지 않습니다.

## 기준 문서

- [OpenSSH sshd_config](https://man.openbsd.org/sshd_config)
- [Microsoft PE 형식](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft 방화벽 조회](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile)
- [Android APK Analyzer](https://developer.android.com/studio/debug/apk-analyzer)

제조사·OS·장비별 완전한 지원과 전체 취약점 탐지를 보장하지 않습니다. 추가 모듈은 기준 버전·입력 경계·정상/위험 샘플·실환경 검증을 갖춘 후 레지스트리에 명시적으로 등록합니다.


## 2026-10-27 재검토 및 완료 판단

9종 레지스트리(웹 비교·Linux·Windows 정책·PE·기존 APK 예비·Mach-O·모바일 패키지·VMX·GNS3)를 기준으로 합니다. 최근 30일 고객 표시와 별도 아카이브 정책을 유지합니다. GNS3는 2.x 입력 버전을 제한하며 readiness는 등록 모듈과 DB 제약의 호환성을 확인합니다. 운영 가용성·관리형 DB 비밀 복구의 잔여 위험은 별도입니다.

[취약/보완 더미 파일](../tests/fixtures/phase2/README.md), [전후 결과·화면 및 미검증 대상](PROJECT_REVIEW_2026-10-27.md), [관리형 DB 복구 경계](DB_SECRET_RECOVERY.md)를 참고합니다. 합성 검증 성공을 실제 Mac/모바일/다른 컴퓨터/장비 검증 완료로 대체하지 않으므로 **2단계는 진행 중**입니다.
