# VELTHARA / WebGuard Security Hub — 기능·변경 이력·보안 코드 리뷰

작성일: **2026-10-27, 한국 시간** · 검토 소스: **`7565d4f`** · Git 기록 범위: **2026-10-16~2026-10-23, 31개 커밋**

이 보고서는 프로젝트에서 확인한 기능, 요구 변경, 발생 이슈, 보안 문제의 수정 근거와 현재 남은 항목을 한곳에 정리한다. 날짜는 Git 커밋 시각 또는 기존 검증 문서의 기록이며 실제 장애 최초 발생·운영 배포 시각과 동일하다고 가정하지 않는다.

## 1. 현재 결론과 읽는 방법

- **1단계는 공개 웹 기본 진단 MVP 범위에서 완료했고 2단계는 진행 중이다.**
- 현재 등록된 공통 진단 엔진은 **9개**다. 기존 웹 기본 진단은 별도 API로 유지한다.
- 10월 22일 이후 일반 회원도 자신의 진단·저장·재검증·수집 키 관리를 이용한다. DB의 viewer 역할 이름은 남지만 예전의 조회 전용 정책과 다르다.
- 10월 23일 VMware VMX와 GNS3 구성 검사가 추가됐다. Cloud·IoT·Container는 준비 중이며 네트워크 장비 전체 진단이나 하이퍼바이저 취약점 스캔을 제공하는 것은 아니다.
- 오늘 **105개 자동 테스트, production 빌드와 타입 검사, 전체 임시 DB 통합, 보안·6개 언어 HTTP 검증**을 다시 통과했다.
- 정식 사이트 `/signup`에서는 오늘도 **`PROTECTION_UNAVAILABLE`** 오류를 관찰했다. 임시 환경의 검사 성공과 운영 가용성 문제를 구분한다.

보고서의 상태는 **현재 코드 확인 / 이번 실행으로 확인 / 과거 기록 / 미해결 / 미검증**으로 구분한다. 새로 촬영한 사진은 8절에 있으며 운영 사진과 임시 데이터 사진을 명시했다. 실제 운영 계정·DB에 테스트 결과를 추가하지 않았다.

관련 증거: [전체 커밋·소스 목록](REVIEW_HISTORY_2026-10-27.md), [오프라인 리뷰 재현 결과](assets/review-2026-10-27/review-probes.json), [사진·검증 근거 목록](assets/review-2026-10-27/evidence-manifest.json).

## 2. 실제 화면 구조와 전체 진단 엔진

로그인 → `/workbench` 검사 선택 버튼 → **별도 진단 작전실** → 결과·개선안·재검증 순서다. 기존 남색·민트 테마, 로그인 폼과 오른쪽 보안 그림을 유지한다. 긴 안내와 개선안은 토글로 펼친다.

| 검사 ID / 화면 | 추가 근거 | 실제 기능 | 반드시 구분할 한계 |
|---|---|---|---|
| 기존 웹 `/api/scans`, `/?view=web` | 10/16 `fc7cc08`, `0057f11` | 공개 루트 HEAD 1회·TLS·CSP/HSTS/nosniff/Referrer·관찰 쿠키/CORS/정보 노출, 실제 단계 스트림 | GET·로그인 후·모든 경로·전체 TLS 열거·모든 취약점 검사가 아님 |
| `web.compare`, `/workbench/web` | 10/20 `420499a` | PC·모바일 User-Agent별 고정 DNS HEAD 비교 | 실제 모바일 브라우저·PWA·세션·리디렉션은 미검사 |
| `linux.ssh`, Endpoint | 10/20 `420499a` | 명시적 SSH 설정 5개와 근거 줄 번호·개선안 | Include/Match/일부 복잡 구문·기본값·실제 유효 정책·OS 전체·ELF 미검사 |
| `windows.policy`, Endpoint | 10/20 `420499a` | 정책 JSON의 방화벽 3종·Defender·RDP NLA 관찰 | 자기 보고 스냅샷; GPO·예외·타사 백신·실제 OS 종합 진단 아님 |
| `application.pe`, Endpoint | 10/20 `420499a`, `1e1142a` | EXE/DLL PE32/PE32+ ASLR·NX·W+X·서명 구조, 로컬 도구 결과 | 보호 선언은 실제 실행 보호의 증명이 아님. MSI·악성코드·전체 CVE 미지원 |
| `application.apk`, Mobile의 기존 모드 | 10/20 `420499a` | 최대 2 MiB 원본 서버 전송의 APK 구조 예비 검사 | 새 원본 미전송 모드와 다름. 권한·서명·코드 분석 아님 |
| `application.macho`, Endpoint | 10/20 `1e1142a` | Mach-O/Universal·PIE·실행 스택·W+X·서명 명령, 선택형 로컬 도구 | 실제 Mac 서명/공증 신뢰·앱 전체·DMG/PKG·실행 미검증 |
| `application.package`, Mobile | 10/20 `1e1142a`, `86557eb` | APK/AAB/IPA/APKS/XAPK 분류, 제한된 AXML·XML/binary plist의 명시 설정 | AAB protobuf·중첩 APK·실제 권한 승인·서명 신뢰·악성코드 미검사 |
| `virtualization.vmx`, `/workbench/virtualization` | 10/23 `7565d4f` | VMX 복사/붙여넣기/DnD/HGFS·VNC 명시 선언, NIC 연결 모드 | VM 실행·게스트 접속·실효 정책·암호화·VMware CVE·도달성 미검사 |
| `network.gns3`, `/workbench/network` | 10/23 `7565d4f` | GNS3 구조·노드/링크 참조·Cloud/NAT·콘솔 루프백 선언 | 장비 ACL·암호·OS·포트·라우팅·실제 통신은 미검사. GNS3 콘솔 Telnet과 장비 Telnet 서비스를 혼동하지 않음 |

등록 근거: [registry.ts](../lib/assessment/registry.ts), [types.ts](../lib/assessment/types.ts), [설정 검사](../lib/assessment/config-modules.ts), [실행/모바일 요약 검사](../lib/assessment/local-modules.ts), [VMX/GNS3 검사](../lib/assessment/infrastructure-modules.ts).

## 3. 진단 외에 추가된 기능 전수 목록

아래는 고객 기능·자체 방어·운영 도구를 합친 목록이다. 일반 회원에게 노출되는 화면과 로컬 관리 기능을 구분한다.

| 영역 | 등록된 기능·현재 처리 | 주요 코드·문서 |
|---|---|---|
| 가입 | 이메일 정규화, 비밀번호 14~128자, DB 함수의 viewer 강제, 중복 가입 시 기존 해시/역할 유지 | `app/api/register`, `lib/registration.ts`, SQL 가입 함수 |
| 인증 | scrypt+salt, 해시 세션, 8시간 만료, HttpOnly/SameSite·HTTPS Secure 쿠키 | `lib/password.ts`, `app/api/login`, `lib/security.ts` |
| 다른 기기 | 같은 계정의 독립 세션, 로그아웃·만료, 브라우저 세션 변경 시 화면 정리 | 인증 API·`app/home-client.tsx`·Workbench |
| 고객 권한 | 일반 회원의 본인 진단/저장/재검증/AI 요청·집계 키; 관리자 운영 정보는 admin 전용 | `lib/assessment-permission.ts`, [고객 정책](CUSTOMER_ACCESS_2026-10-22.md) |
| 계정 격리 | 목록·개수·이벤트·자산·AI ID/캐시를 계정별 제한. admin도 타 고객 결과 404 | 대시보드·assessments·AI·telemetry API |
| 웹 결과 | 계정+호스트별 안정 ID로 최신 성공 갱신, 실패 시 기존 결과 보존 | `lib/scan-store.ts` |
| 모듈 이력 | 계정+모듈+대상 자산 ID 유지, 매 실행 추가, 버전이 호환될 때만 전후 비교 | `lib/assessment/store.ts`, `compare.ts` |
| 고객 조회 기한 | 최근 30일 결과·자산·AI·수집 키/집계 접근. 목록 개수 제한 유지 | [보관 정책](DATA_RETENTION.md), 각 조회 API |
| 비공개 보관 | 30일 초과 진단을 별도 schema에 트랜잭션 이관, 재실행·잠금·실패 롤백 | migration 009/Prisma 005, `lib/retention.ts` |
| 예약 보관 | Cron 00:00 UTC/한국 09:00 설정, CRON_SECRET만 허용, 횟수·시간 상한 | `vercel.json`, `/api/maintenance/archive` |
| 결과 화면 | 위험도·근거·경고/미검사 개수·접이식 개선안·원문 비포함 JSON | Workbench·assessment panel |
| 작전실 로그 | 실제 서버 단계 스트림·점멸·취소·주소 변경 초기화·로그 JSON | `lib/scan-run.ts`, `app/operations-panel.tsx` |
| 파일 동의 | 선택과 읽기 분리, 현재 파일 일회성 동의, 취소/변경 시 초기화, 저장 동의 별도 | `file-inspection.tsx`, `infrastructure-input.tsx` |
| 대용량 | 최대 8 GiB 입력의 범위 읽기·총 읽기 8 MiB·Worker 시간 제한 | `public/tools/*-inspector.mjs` |
| 구조 제한 | ZIP 수량·경계·중복/위험 경로·압축 비율·출력량, Mach-O 슬라이스 경계 등 | 파일 파서·`tests/file-inspection.test.ts` |
| 로컬 검사 도구 | Node CLI, 명시적 consent, SHA-256·선택 native 서명 조회·기존 출력 덮어쓰기 거절 | `public/tools/executable-inspector.mjs` |
| 요약 신뢰 | 추가 필드·경로·원문 주입 거절, 자기 보고를 서버 독립 안전 판정으로 처리하지 않음 | `executable-snapshot.ts`, `local-modules.ts` |
| 기본 개선안 | 외부 API 없이 제공·추가 호출 없이 토글 | `lib/local-advice.ts` |
| 선택형 AI | Groq→Gemini→기본 안내, OpenAI는 명시 선택, 서버 전용 키 | `lib/ai-providers.ts`, `ai-chain.ts` |
| AI 비용 | 400 출력 토큰·20초·SDK 자동 재시도 0, 24시간 캐시·중복 lease·동시 예산·실패 환불·제공자 대기 | `ai-budget.ts`, `advice-cache.ts`, AI API |
| 다국어 | 기존 웹/가입/오류 6개 언어, 신규 작전실 한국어·영어, 명시 선택 우선·신뢰 국가 힌트 | locale/messages·request-locale·geo-country |
| 외부 집계 | 자산별 256-bit 키 발급/회전·해시 보관, 서버 간 집계 수신, 최근 5분 임계 신호 | `/api/telemetry`, `trafficSignals` |
| 자체 IP 방어 | 실제 접속 IP·위험 URL 패턴, 5분 차단 5회 뒤 6번째 블랙리스트, 차단 중 strike 비증가 | `lib/ingress-guard.ts`, Vercel Proxy |
| 프록시 신뢰 | 일반 위조 forwarded header 무시, 로컬 프록시 secret·Vercel 플랫폼 IP 경계 | ingress/tunnel/vercel-protection |
| 최소 디코이 | 정해진 경로의 제한된 이벤트·404. 완전한 격리형 허니팟 아님 | catch-all probe·decoy route |
| 요청 방어 | Origin+Host, JSON MIME·실제 바이트 제한, SQL 파라미터, 고정 모듈 레지스트리 | `lib/request.ts`, security·assessment input |
| 보안 헤더 | CSP·프레임 거절·nosniff·Referrer·권한 정책, 서버 식별 축소 | `next.config.ts` |
| 운영 연결 | 로컬/Prisma 제공자 프로필·검증 TLS·프로젝트 ID·readiness·제공자별 풀 | project-database/database-pool/readiness |
| SQL 관리 | 일반 PG 001~010, Prisma 001~006, 체크섬·트랜잭션·반복 검증·개발 역할 분리 | `sql/`, migrate·grant 스크립트 |
| 운영 복구 | 로컬 관리용 비밀번호 재설정·세션 폐기·감사·부분 실패 롤백, IP 해제 | `scripts/reset-password.ts`, `unblock-ip.ts` |
| 데이터 이전 | 빈 대상만 허용, 기존 사용자/결과 보존, 세션·수집 키 복사 제외 | copy-production-data 스크립트 |
| 환경정보 보호 | 환경 파일 전체 Git 제외, 추적 중이던 템플릿 제거 | 10/23 `5d53617`, `.gitignore` |

Cloud·IoT·Container, 작업 예약 진단, 정식 PDF 보고서, 메일 인증/MFA/공개 비밀번호 찾기, 외부 WAF/봇 확정 판별·IP 역추적·자동 대응·고객 장비 자동 접속은 현재 완료 기능으로 세지 않는다. 로컬 관리용 비밀번호 복구와 고객용 비밀번호 찾기는 별개다.

## 4. 언제·왜·어떻게 바뀌었는가

| 날짜·커밋 | 요구·문제 | 변경 방식 |
|---|---|---|
| 10/16 `fc7cc08`, `0057f11` | URL 진단과 진행 상태·AI 한도·자체 방어 필요 | 작전실·기본 검사·개선안·API 전환·한도·IP 보호를 MVP에 묶음 |
| 10/16 `b75dc48`~`c1d4a8c` | 다른 기기 접속·HTTP/HTTPS·PC 임시 공유와 Vercel 혼동 | HTTP→HTTPS 및 정확한 Origin/Host, 임시 PC 공유와 Vercel 직접 운영 구성 분리 |
| 10/16 `d78f1be`, `26055be` | Vercel의 localhost DB·Prisma 역할/GRANT 실패 | 외부 Prisma DB 프로필·TLS·별도 SQL 경로·제공자 권한 제한 공개 |
| 10/16 `8390374` | 로그인 헤더/가입 노출·빈 오른쪽 영역 | 기존 로그인 전용 폼과 보안 SVG 구성 |
| 10/17 `5c5455f` | 헤더 존재만으로 통과·취소/입력/풀 호환성 문제 | 정책값·인증서·쿠키/CORS 분석, 취소·입력·역할 검증·회귀 검사 보완 |
| 10/17 `d389dd8` | 가입·로그인 서비스 필요 | 운영 공개 가입, 당시 viewer 조회 정책 |
| 10/17 `c4d07dc`, `5690023` | 다른 계정 주소/진단 공유·AI ID 접근 위험 | 소유자 조건·계정별 유일키·이벤트/AI 캐시 격리·실환경 교차 검사 |
| 10/17 `5816713` | 비밀번호 조회/복구 혼동 | 비밀번호 원문 조회 대신 관리용 숨김 입력 재설정·세션 폐기·롤백 |
| 10/19 `f7af285`, `fa259fa` | 다른 기기에서 접속 보호 503 | 일시적 차단 조회 읽기만 1회 재시도·실패 연결 폐기, 보호 우회 금지 |
| 10/20 `420499a`~`c1c1cb8` | 2단계 시스템/앱·비교·집계 확장 | 공통 모듈·불변 이력·자산·재검증·서버 집계·운영 검증 |
| 10/20 `1e1142a`, `86557eb` | 무거운 EXE/Mac/모바일 파일·동의 요구 | 브라우저 부분 읽기·요약·확장 형식·binary plist·로컬 도구 |
| 10/21 `08a6307`, `fb7a54c` | 통합 플랫폼 선택 화면 요구 | 최초 밝은 카드·홈 펼침 폼 구현·검증. 이후 사용자 의도와 달라 대체 |
| 10/21 `7236fc4` | 버튼→별도 검사 페이지, 기존 웹/테마/로그인 유지 요청 | 현재 전용 작전실 라우팅과 남색·민트 테마·기존 로그인 복원 |
| 10/22 `83096b2` | 단계·다른 컴퓨터 Linux/네트워크 검증 정리 | prompt와 실환경 검증 계획 갱신 |
| 10/22 `36af967` | 설정 바꿔도 동의 유지·파일 없음·오류 안내/경고 부재 | 동의 초기화·비동기 세대/취소·입력 잠금·파일 오류·경고 요약·보호 전용 복구 |
| 10/22 `1f977d5` | 보호 DB 조회가 기존 5초를 넘겨 실패 | 정확한 관리형 차단 SELECT만 10초·단계별 비밀 없는 로그·실제 지연 DB 검증 |
| 10/22 `5832563` | 일반 고객이 진단을 못 하는 정책 불일치 | viewer 역할을 승격하지 않고 본인 진단 권한을 허용; 관리자 운영 권한 분리 유지 |
| 10/23 `128772e` | 고객 결과의 조회 기한·오래된 기록 보존 | API 30일 필터·비공개 archive·인증된 정기 작업·원자적 이관 |
| 10/23 `5d53617` | 환경 설정 파일을 원격에 포함하지 않는 요구 | 템플릿 추적 제거·환경 파일 이름 전반 ignore. 실제 키 유출 확인과는 다름 |
| 10/23 `7565d4f` | VM·네트워크 설정 검사 요구 | VMX/GNS3 전용 화면·파서·근거·제한·고객 격리·검증 |

빠짐없는 31개 커밋 원문과 한국 시간은 [전체 변경 이력](REVIEW_HISTORY_2026-10-27.md)에 별도 수록했다. 한 커밋에 여러 사전 작업이 묶인 경우 더 세밀한 발생 시점을 추측하지 않았다.

## 5. 취약점·보안 위험과 실제 수정 근거

발생했던 기능 오류를 모두 취약점으로 부르지 않는다. 아래는 코드에서 확인한 위험과 방어이며 실제 침해·키 탈취가 발생했다는 뜻은 아니다.

### 5.1 계정 간 결과 노출·AI 결과 ID 접근 — 수정 확인

**영향:** 로그인한 사용자가 다른 계정의 도메인·진단·활동을 보거나 타 계정 진단 ID로 AI 처리를 요청할 수 있었던 소유권 검사 부족. 심각도는 높음으로 평가한다.

`c4d07dc`의 실제 diff에서 다음 변경을 확인했다.

```sql
-- 이전: 전체 목록 / ID만으로 결과 선택
SELECT ... FROM scans ORDER BY created_at DESC LIMIT 30;
SELECT result FROM scans WHERE id=$1;

-- 수정: 세션 사용자 소유권 조건
SELECT ... FROM scans WHERE user_id=$1 ORDER BY created_at DESC LIMIT 30;
SELECT result FROM scans WHERE id=$1 AND user_id=$2;
```

호스트 유일성도 `hostname`에서 `(user_id,hostname)`으로 바꾸고 upsert가 소유자를 덮어쓰지 않도록 했다. AI 캐시 키·이벤트에도 계정을 포함했다. 현재 코드는 여기에 30일 필터까지 적용한다. **이번 통합 검증에서 관리자 포함 타 계정 404·같은 호스트 독립 결과·계정별 이벤트/캐시를 확인했다.**

근거: [dashboard API](../app/api/dashboard/route.ts), [AI API](../app/api/ai/route.ts), [scan-store](../lib/scan-store.ts), [006 migration](../sql/migrations/006_account_isolation.sql).

### 5.2 SSRF·프록시 IP 위조 — 방어 구현·현재 회귀 통과

HTTPS/443 루트·일반 도메인만 허용하고 DNS의 모든 응답을 검사한다. 하나라도 비공개/특수 주소면 연결 전 거절한다. 검증 IP를 HTTPS lookup에 고정하고 TLS 인증서를 검증하며 리디렉션을 따라가지 않는다. 일반 클라이언트의 위조 전달 헤더는 무시한다.

이번 테스트는 URL 우회·혼합 DNS·메타데이터 주소·DNS 고정·TLS 실패·취소와 위조 헤더를 포함한다. 이는 방어 검증이며 **실제 SSRF 침해가 과거 발생했다는 증거는 없다.**

근거: [scan-policy](../lib/scan-policy.ts), [scanner](../lib/scanner.ts), [ingress-guard](../lib/ingress-guard.ts), [관련 테스트](../tests/security.test.ts).

### 5.3 파일 읽기 동의·입력 변경 경합 — 수정 확인

설정을 바꾸거나 파일을 바꾼 후 이전 동의가 유지되면 다른 내용에 대한 승인을 재사용할 위험이 있다. `36af967`에서 설정 변경 시 동의 해제·비동기 읽기 세대 비교·전송 중 잠금·Enter와 버튼의 제출 조건 통일을 적용했다. 파일 미선택/빈 파일/손상 파일을 구분하고 자동 샘플을 실제 파일처럼 읽지 않는다.

근거: [Workbench](../app/workbench/workbench-client.tsx), [파일 읽기](../app/workbench/file-inspection.tsx), [인프라 설정 읽기](../app/workbench/infrastructure-input.tsx). 이번 브라우저는 파일 미선택 오류와 저장 비활성, Linux 재검증 후 경고→개선 비교를 확인했다.

### 5.4 대용량·악성 구조·요약 위조 — 입력 경계 확인

파일 크기·총 읽기·목록 수·슬라이스·압축 출력·시간 제한을 적용한다. ZIP 위험 경로·중복·손상, Mach-O 겹친 범위 등을 거절하고 파일을 실행하지 않는다. 서버 요약 검증은 허용 필드·형식·범위를 제한하며 임의 경로·원문 속성을 거절한다. 사용자 제공 서명 결과나 헤더 선언은 서버 독립 안전 판정으로 승격하지 않는다.

근거: [실행 파일 파서](../public/tools/executable-inspector.mjs), [모바일 파서](../public/tools/package-inspector.mjs), [서버 요약 검증](../lib/assessment/executable-snapshot.ts), [파일 회귀 테스트](../tests/file-inspection.test.ts). 모든 파일의 안전을 보장하는 샌드박스/백신 엔진은 아니다.

### 5.5 AI 비용·실패 한도·중복 생성 — 보완 확인

기존 기록에는 키/모델 접근·잔액/요청 한도 오류와 실패 시도 누적이 있었다. 현재는 시도 제한과 성공 예산을 분리해 요청 전에 원자 예약하고 실패한 원래 시간창에만 환불한다. 계정·언어·모델·규칙 입력 기반 캐시, lease, 제공자별 대기, SDK 자동 재시도 제거를 적용한다. raw HTTP 응답 대신 정해진 헤더 존재 Boolean만 AI 입력으로 만든다.

이번 외부 AI 생성은 실행하지 않았다. 로컬 모형 통합에서 비용 예약·환불·동시 제한·캐시·제공자 실패 처리를 확인했다. 실제 제공자의 잔액/모델 지원을 보증하지 않는다.

근거: [ai-budget](../lib/ai-budget.ts), [advice-cache](../lib/advice-cache.ts), [ai-providers](../lib/ai-providers.ts), [누적 기록](../VALIDATION.md).

### 5.6 오래된 진단의 고객 노출·보관 실패 — 정책·원자성 보완

`128772e`에서 고객 API에 30일 필터를 적용하고 소유자가 같은 오래된 ID도 직접 조회되지 않게 했다. 보관 INSERT와 활성 행 이관을 같은 트랜잭션에서 처리하며 고정 함수·잠금·중복 방지·관리 인증을 둔다. 보관 실패 시 원본 유지·재실행·계정 격리를 이번 통합에서 통과했다. 기존 데이터 유실 사고가 확인됐다는 의미는 아니다.

근거: [보관 SQL](../sql/migrations/009_diagnostic_retention.sql), [Cron API](../app/api/maintenance/archive/route.ts), [retention](../lib/retention.ts), [보관 정책](DATA_RETENTION.md).

## 6. 일반 이슈와 해결 과정

| 이슈 | 원인·성격 | 조치·현재 판단 |
|---|---|---|
| Vercel 로그인 실패 | localhost DB·APP_ORIGIN 불일치, 배포 구성 오류 | 외부 DB·정식 Origin·TLS·직접/풀 프로필. 오늘 운영 전체 로그인을 재검증한 것은 아님 |
| DB role/GRANT 거절 | 관리형 제공자 기능 제한 | Prisma 전용 migration·권한 모델 공개. 실제 DB ACL 분리 한계는 남음 |
| 풀 시작 옵션·정상 DML 거절 | statement_timeout 호환성 및 보조 SQL 검사 과잉 | 제공자별 풀, 정상 UPDATE/upsert 허용·DDL 거절 회귀 |
| 다른 기기의 접속 보호 503 | 차단 조회 지연·연결 장애. 기기 계정 고정 문제와 별개 | 읽기만 재시도·정확한 SELECT만 10초. **오늘 운영 signup에서 같은 종류 오류 관찰; 근본 해결 완료로 쓰지 않음** |
| 일반 회원 진단 버튼 비활성 | 관리자만 실행하게 만든 과거 정책과 고객 서비스 목적 불일치 | 10/22 본인 진단 허용. 관리자 정보·타 계정 접근은 계속 제한 |
| 밝은 홈·펼침 폼이 의도와 다름 | UI 요구 해석 오류 | 10/21 버튼→전용 페이지·기존 웹·어두운 테마·로그인 복원 |
| 주소/계정 변경 후 오래된 응답 | 비동기 화면 상태 경합 | 요청 세대 비교·취소·상태 초기화·계정 변경 방송 |
| DNS 취소 지연 | 대기 작업 종료 처리 부족 | AbortSignal·DNS 타이머/리스너 정리·연결 전 중단 |
| 파일 없음·빈 파일·혼동되는 오류 | 검증/피드백 부족 | 명시적 오류·동의 초기화·검사별 오류 코드·경고/미검사 요약 |
| 한글 경로 initdb·빌드 권한 | Windows 검증 환경 제약 | 임시 PG를 ASCII/OS temp 경로로 분리·허용된 실행으로 동일 검사 재수행 |
| `.env`의 #·URL 비밀번호 혼동 | 환경 문법과 DB 계정 비밀번호 변경의 차이 | URL 비밀번호 부분의 percent encoding과 DB 역할 비밀번호를 구분해 안내. 웹 로그인 비밀번호에 URL 인코딩을 적용하지 않음 |
| 환경 템플릿 추적 | 환경 파일 원격 제외 요구 | 10/23 추적 제거·이름 패턴 ignore. 과거 키 유출 여부나 Git 전체 비밀 이력 감사는 미확인 |

## 7. 현재 코드 리뷰: 미해결·추가 검토 항목

P1은 우선 대응할 운영/보안 위험, P2는 후속 보완 항목이다. 아래 항목을 모두 실제 악용 취약점으로 확정하지 않는다. 이번 요청에서는 제품 코드를 수정하거나 운영 설정을 바꾸지 않았다.

| ID·우선순위 | 근거·관찰 | 영향·판단 | 후속 조치 |
|---|---|---|---|
| R01 · P1 운영 가용성 | 오늘 정식 `/signup` 화면에 PROTECTION_UNAVAILABLE 표시. [사진 11](assets/review-2026-10-27/11-production-protection-error.jpg) | 일반 사용자의 접속/가입도 차단될 수 있음. 특정 제공자 원인·상시 재현률은 미확인 | 같은 시각의 Proxy 로그·풀 대기/조회 시간·DB 제공자 상태 대조. 보호 우회로 해결하지 않음 |
| R02 · P1 보안 경계 | [runtime-sql.ts L1~6](../lib/runtime-sql.ts), 관리형 제공자 역할 제약 | 정규식 SQL 검사는 탈취된 광범위 DB 키의 권한을 줄이지 못함. 실제 키 탈취는 확인되지 않음 | 최소 권한을 제공하는 DB 모델·네트워크/비밀 관리·복구 전략 검토 |
| R03 · P2 CSP 완화 | [next.config.ts L13](../next.config.ts)에 script/style unsafe-inline | XSS 발생 시 추가 방어력이 약함. 이 리뷰에서 실행 가능한 XSS를 확인한 것은 아님 | nonce/hash 기반 정책과 MUI/Next 호환성 별도 검증 |
| R04 · P2 공유 한도 | [login route L8](../app/api/login/route.ts)의 전체 30회/분, 가입 전체 10회/10분 | 한 사용자의 요청이 다른 정상 사용자의 예산을 소진할 가능성. 운영 부하 실험은 하지 않음 | 신뢰 IP·계정·서비스 전체 한도의 계층화와 악용/정상 부하 검증 |
| R05 · P2 버전 검증 | [infrastructure-modules.ts L34](../lib/assessment/infrastructure-modules.ts)는 version 문자열 여부만 검사. `999.0`도 오프라인 실행에서 허용됨 | GNS3 2.x라는 표시와 입력 허용 범위가 불일치. 호환성/오판 위험이며 코드 실행 취약점은 입증되지 않음 | 지원 버전 경계 검사·미지원 버전 거절/미검사 정책·회귀 사례 추가 |
| R06 · P2 문서 불일치 | prompt.md·PHASE2.md에 viewer 조회 전용·Network/Virtualization 준비 중 설명이 남음 | 10/22~23 이후 코드와 상충. 현재 권한·지원 범위 판단을 잘못할 수 있음 | 최신 정책·지원표로 정리하고 과거 이력은 날짜별 보존. 이 보고서는 현재 코드를 기준으로 함 |
| R07 · P2 배포 준비 검사 | [deployment-readiness.ts](../lib/deployment-readiness.ts)는 표/보관 함수는 확인하지만 새 모듈 허용 제약까지 확인하지 않음 | 이전 schema와 새 앱 조합에서 READY여도 새 ID 저장이 실패할 가능성. 실제 운영 실패 재현은 하지 않음 | 적용 migration 버전·모듈 허용 schema 호환 검사 추가 검토 |

R05 재현은 [review-probes.json](assets/review-2026-10-27/review-probes.json)에 남겼다. 가짜 버전의 빈 토폴로지를 메모리에서 분석했으며 운영 서버·장비에 보내지 않았다.

추가 한계: 메일 인증·MFA·고객 복구 UI, 장기 archive 자동 삭제 기한·복구 UI, 실물 Mac/iOS·모든 Linux 유효 정책, 장비/클라우드 종합 진단, 새로운 의존성 CVE 감사·침투/부하 시험은 이번 검증으로 완료되지 않는다.

## 8. 실제 촬영 스크린샷

촬영일은 모두 **2026-10-27**이다. 원본 JPG를 프로젝트에 포함했으며 이미지 편집·결과 합성·과거 화면의 현재 화면 위장은 하지 않았다. 사진 01·11만 정식 운영 사이트이며 나머지는 `7565d4f`의 별도 빌드와 임시 PostgreSQL·일반 회원 `review-demo@example.test`를 사용했다. 이 이메일은 데모용이며 비밀번호·쿠키·운영 개인정보는 사진에 넣지 않았다.

### 01. 정식 사이트 로그인 — 운영 화면

기존 남색 테마·폼·언어 선택·오른쪽 보안 그림을 확인했다. 로그인 성공·DB 전체 정상의 증거로 대신하지 않는다.

![정식 사이트 로그인](assets/review-2026-10-27/01-production-login.jpg)

### 02. 검사 선택 버튼 — 임시 환경

Web/Mobile/Endpoint/Virtualization/Network는 검사 화면으로 이동하며 Cloud/IoT/Container는 준비 중이다.

![진단 작전실 선택 버튼](assets/review-2026-10-27/02-local-rooms.jpg)

### 03. 파일 미선택·읽기 동의 보호 — 임시 환경

파일 없는 점검에 명시적 오류가 표시되고 요약 저장은 비활성이다. 이번 사진은 실제 모바일 앱 파일 분석의 증거가 아니다.

![파일 미선택 오류와 동의](assets/review-2026-10-27/03-local-file-consent-error.jpg)

### 04. 실행 파일·시스템 진단 작전실 — 임시 환경

PE·Mac 실행 파일과 Linux/Windows 설정 검사 선택을 제공한다. 원본 미전송과 동의 안내를 확인했다.

![실행 파일 시스템 진단 화면](assets/review-2026-10-27/04-local-endpoint.jpg)

### 05~06. Linux 경고 5개 → 개선 관찰 5개 — 합성 설정

일반 회원의 실제 UI 제출·임시 DB 저장·재검증을 촬영했다. 실제 Linux 서버의 설정을 변경한 결과가 아니다.

![Linux 경고 결과](assets/review-2026-10-27/05-local-linux-warning.jpg)

![Linux 개선 비교](assets/review-2026-10-27/06-local-linux-retest.jpg)

### 07. VMware VMX — 합성 설정

복사 격리 미선언 보호와 VNC 활성 선언에 경고 2개, 나머지 확인 불가 4개를 표시했다. VM 실행이나 실제 게스트 정책 검증은 하지 않았다.

![VMX 경고와 미검사](assets/review-2026-10-27/07-local-vmware.jpg)

### 08. GNS3 네트워크 구성 — 합성 설정

Cloud 연결과 비루프백 콘솔 선언에 경고 2개, 실제 장비 정책은 미검사 1개다. 실제 포트 스캔·노드 실행·ping 검증을 수행한 사진이 아니다.

![GNS3 구성 경고](assets/review-2026-10-27/08-local-gns3.jpg)

### 09. 내 진단 결과·최근 30일 안내 — 임시 환경

선택 자산과 JSON 다운로드·현재 경고를 표시한다. 30일 경과 동작 자체는 사진이 아닌 날짜를 조절한 독립 DB 통합 테스트로 검증했다.

![고객 진단 이력](assets/review-2026-10-27/09-local-history.jpg)

### 10. 기존 웹 진단 작전실 — 임시 환경

URL·진단 허가·범위 안내·본인 이벤트·AI 비활성 안내를 확인했다. 이번 촬영에서 외부 사이트 진단 요청은 보내지 않았다.

![기존 웹 진단 화면](assets/review-2026-10-27/10-local-web-room.jpg)

### 11. 오늘 관찰한 정식 사이트 오류 — 운영 화면

`/signup` 이동 뒤 접속 보호 상태 확인 실패 JSON을 관찰했다. 과거의 보호 지연 보완을 근본 해결 완료라고 쓰지 않기 위한 현재 증거다. 단일 관찰이며 원인·전체 장애 범위는 미확정이다.

![운영 접속 보호 오류](assets/review-2026-10-27/11-production-protection-error.jpg)

### 12. 회원가입 폼·현재 고객 권한 안내 — 임시 환경

가입 후 본인 진단 이용 안내와 비밀번호 정책을 확인했다. 폼 제출로 운영 계정을 만들지 않았다.

![현재 회원가입 안내](assets/review-2026-10-27/12-local-signup.jpg)

## 9. 이번 실행 검증과 과거 기록의 구분

| 항목 | 이번 결과 | 범위 |
|---|---|---|
| 단위·보안·회귀 | 105개 통과, 실패 0 | SSRF·권한·IP·파일·모듈·보관 인증·동의/취소·AI 등 |
| production 빌드 | 통과 | `.next-verify`, TypeScript 검사 포함. 운영 배포를 변경하지 않음 |
| 전체 API/DB 통합 | 통과 | 임시 PG: 일반 010/Prisma 006, 일반 고객 진단·격리·이력·집계·보관·롤백·복구 |
| 지연 보호 조회 | 통과 | 임시 DB 6초 지연에서 기존 5초 실패·범위 한정 10초 성공 |
| 보안 HTTP smoke | 통과 | 보안 헤더·미인증·교차 Origin 거절 |
| 6개 언어 smoke | 통과 | SSR·API 오류·설정 지속·위조 국가 힌트 거절 |
| 브라우저 | 확인 | 일반 회원 로그인, 파일 없음 오류, Linux 경고/개선, VMX/GNS3 저장, 이력·웹/가입 화면 |
| GNS3 미지원 버전 | 허용됨을 재현 | R05로 기록; 수정 완료 아님 |
| 정식 사이트 | 공개 로그인 확인·가입 경로 오류 관찰 | 운영 전체 회귀·로그 분석·DB 점검을 대신하지 않음 |

과거 문서의 실제 VMware VMX·GNS3 VPCS ping 검증은 [10/23 기록](INFRASTRUCTURE_CHECKS.md)에 있다. 이번에는 장비를 켜거나 접속하지 않았다. Kali 접속/유효 정책·Mac 서명·실물 앱 설치·실행의 미완료 상태를 과거 합성 검사로 덮지 않는다.

## 10. 다음 작업 우선순위

1. R01 운영 보호 오류의 요청 시각과 서버·제공자 지표 대조, 정상 사용자 접근 복구 확인.
2. R02 관리형 DB 최소 권한·비밀 유출/복구 경계 검토.
3. R05 GNS3 지원 버전 검증과 R07 앱/schema 호환 readiness 보완.
4. R03 CSP 강화·R04 로그인/가입 한도의 정상 사용자 영향 검토.
5. R06 prompt·PHASE2·PROJECT_STATUS를 최신 권한·VMX/GNS3 범위로 정리.
6. 다른 컴퓨터 Linux 유효 설정, 실제 Mac·모바일·장비 검증을 대상별로 기록하고 2단계 완료 조건을 판단.

이번 산출물은 보고서·스크린샷·검증 근거이며 제품 기능 코드·운영 계정·환경변수·배포·migration을 변경하지 않았다. 기능 검토와 회귀 통과는 무취약점 인증이나 모든 장비의 안전 보증이 아니다.


## 11. 후속 검증 — R01~R07·취약/보완 더미 파일 (2026-10-27)

앞의 1~10절은 HEAD 7565d4f 시점의 최초 검토 기록이다. 이 절은 **그 이후 로컬 작업본의 실제 코드 수정과 재검증**이다. 이전 R05 미지원 버전 허용 관찰은 과거 재현 기록으로 보존하며 아래 결과로 수정 상태를 구분한다. 이번 수정은 아직 Git 업로드·운영 배포하지 않았다. 운영 응답 재조회는 기존 배포를 관찰한 것이며 로컬 수정의 운영 적용 증거가 아니다.

### 11.1 항목별 조치와 잔여 위험

| 항목 | 이번 작업·증거 | 판단 |
|---|---|---|
| R01 | Vercel 요청 로그 17개 조회. 2026-10-26 23:59:34.230 UTC(한국 10/27 08:59:34) signup 503, 10/27 00:32:07.700 UTC(09:32:07) signup 200. 두 요청 WAF allow. health/ready/root도 200 재관찰 | 복구 응답 관찰. Hobby runtime 로그가 요청한 2시간 범위를 보존하지 않아 HTTP 400으로 조회 불가. DB 제공자 지표·오류 당시 runtime 원인·다른 실제 기기 로그인/진단의 영구 복구는 미확정 |
| R02 | 자체 PG 역할 분리·관리형 앱 SQL 차단/소유자 조건·비밀 노출/복구 경계 검토. 별도 DB 복구 절차 작성 | 제공자 실제 최소 권한·백업 복구·유출 키 폐기 실증은 남음. 앱 차단 검사는 탈취 자격의 직접 DB 접속을 제한하지 못함 |
| R03 | Proxy가 요청마다 새 nonce를 발급하고 request CSP/x-nonce와 response CSP를 설정. Next/MUI에 전달. script unsafe-inline 제거, production unsafe-eval 없음 | HTML의 모든 script nonce 일치·요청별 교체 smoke 통과. 실제 로그인·라우팅·파일 Worker 정상, 브라우저 warn/error 0 관찰. style unsafe-inline은 호환성 경계로 유지 |
| R04 | 로그인: 출처30/분→전체300/분→계정5/5분. 가입: 출처10/10분→전체100/10분→계정3/시간. Vercel 공식 IP 또는 로컬 gateway HMAC 서명 peer만 사용 | 서로 다른 신뢰 peer의 bucket 분리/위조 거절 단위 검증, 임시 API의 계정 한도/다른 정상 계정 로그인 통과. 공유 NAT는 출처 예산을 공유하며 글로벌 회로 예산도 남음. 운영 부하 실험은 하지 않음 |
| R05 | GNS3 version이 2.x 형식이어야 입력 허용. 모듈 v1.0.1로 변경. 2.2.61 합성 입력 저장 및 3.0.0 UI/API 거절 | 입력 버전 게이트 수정·회귀 통과. 실제 GNS3 앱의 모든 2.x 릴리스 호환 인증은 아님. 미지원 입력 실패 시 이전 성공 기록 유지 |
| R06 | prompt/PHASE2/PROJECT_STATUS의 일반 회원 권한·VMX/GNS3 범위 모순 수정 | 현재 문서 정합성 보완. 과거 기록은 당시 상태로 구분 |
| R07 | readiness에서 검증된 assessment_assets_module_id_check와 레지스트리 9종 ID의 호환 확인. 누락/이전/미검증 제약 거절 | 새 DATABASE_MODULE_SCHEMA_NOT_READY와 정상 통합 검증 통과. 적용된 migration 내용은 변경하지 않음 |

근거: [운영 재관찰](assets/phase2-fixtures-2026-10-27/r01-observation.json), [비밀/개인정보를 제외한 요청 기록](assets/phase2-fixtures-2026-10-27/r01-request-correlation.json), [관리형 DB·유출 복구 경계](DB_SECRET_RECOVERY.md). WAF allow는 앱 내부 보호 성공을 뜻하지 않으며, 200 한 번으로 간헐적 DB 장애가 해결됐다고 하지 않는다.

### 11.2 더미 파일과 검사 결과

[더미 파일 사용법](../tests/fixtures/phase2/README.md). 총 16개 파일은 합성 입력이며 실행·설치·실제 OS 설정 적용·VM/GNS3 실행용이 아니다. PE/Mach-O/APK/IPA는 최소 구조 입력으로 정상 실행/설치 가능한 앱이 아니다. 악성코드 샘플을 사용하지 않았다. 원본 운영 DB와 분리한 임시 PostgreSQL·loopback 서버에서 AI 호출 없이 일반 회원으로 확인했다.

설정 4종은 저장한 파일 내용을 직접 입력했고 PE/Mach-O/APK/IPA 4종은 실제 파일 선택→읽기 동의→Worker 검사→소유 동의→요약 저장으로 확인했다. 파일 읽기/취소 동의의 기존 자동 회귀도 유지했다. 설정 파일 선택 UI 자체의 전후 실장비 검증까지 대신하는 것은 아니다.

| 대상 | 취약 선언 경고 | 보완 선언 경고 | 보완 후 기본 통과 / 참고 / 미검사 |
|---|---:|---:|---|
| linux | 5 | 0 | 5 / 0 / 0 |
| windows | 6 | 0 | 6 / 0 / 0 |
| vmware | 6 | 0 | 5 / 1 / 0 |
| gns3 | 2 | 0 | 1 / 2 / 1 |
| windows-pe | 3 | 0 | 0 / 5 / 1 |
| macos-macho | 3 | 0 | 0 / 5 / 4 |
| android | 3 | 0 | 0 / 5 / 3 |
| ios | 1 | 0 | 0 / 2 / 3 |

전후 비교에서 warning→pass만 '개선 관찰'로 계산한다. 파일 선언의 warning→info는 '변경'이며 안전 인증으로 승격하지 않는다. VMX는 개선5·변경1, GNS3는 개선1·변경1·비교불가1이다. IPA는 ATS 선언 외에 패키지 크기도 달라져 변경2가 표시되며 보안 개선 두 개를 뜻하지 않는다. 미검사가 같은 상태로 남아도 비교불가로 표시한다.

[실제 파일 파서·검사 결과와 SHA-256](assets/phase2-fixtures-2026-10-27/fixture-results.json), [일부 화면의 구조화 관찰](assets/phase2-fixtures-2026-10-27/browser-results.json), [다운로드한 저장 결과](assets/phase2-fixtures-2026-10-27/gns3-browser-download.json), [독립 결과와의 교차 대조](assets/phase2-fixtures-2026-10-27/cross-check.json), [파일/사진 무결성 목록](assets/phase2-fixtures-2026-10-27/manifest.json).

### 11.3 전후 스크린샷

총 18장 추가. 아래 사진은 모두 임시 로컬 검증 서버의 실제 화면이며 운영 배포 화면이 아니다. 임시 계정·합성 입력만 사용했다. 주소/기기 OS·실제 장비 검증을 증명하는 사진과 혼동하지 않는다.

![파일 선택 후에도 읽기 동의 전에는 검사 불가](assets/phase2-fixtures-2026-10-27/01-file-consent-before.jpg)

#### windows-pe — 취약 선언 / 보완 선언

![windows-pe 취약 선언](assets/phase2-fixtures-2026-10-27/02-pe-vulnerable.jpg)

![windows-pe 보완 선언](assets/phase2-fixtures-2026-10-27/03-pe-remediated.jpg)

#### linux — 취약 선언 / 보완 선언

![linux 취약 선언](assets/phase2-fixtures-2026-10-27/04-linux-vulnerable.jpg)

![linux 보완 선언](assets/phase2-fixtures-2026-10-27/05-linux-remediated.jpg)

#### windows — 취약 선언 / 보완 선언

![windows 취약 선언](assets/phase2-fixtures-2026-10-27/06-windows-vulnerable.jpg)

![windows 보완 선언](assets/phase2-fixtures-2026-10-27/07-windows-remediated.jpg)

#### macos-macho — 취약 선언 / 보완 선언

![macos-macho 취약 선언](assets/phase2-fixtures-2026-10-27/08-macos-vulnerable.jpg)

![macos-macho 보완 선언](assets/phase2-fixtures-2026-10-27/09-macos-remediated.jpg)

#### android — 취약 선언 / 보완 선언

![android 취약 선언](assets/phase2-fixtures-2026-10-27/10-android-vulnerable.jpg)

![android 보완 선언](assets/phase2-fixtures-2026-10-27/11-android-remediated.jpg)

#### ios — 취약 선언 / 보완 선언

![ios 취약 선언](assets/phase2-fixtures-2026-10-27/12-ios-vulnerable.jpg)

![ios 보완 선언](assets/phase2-fixtures-2026-10-27/13-ios-remediated.jpg)

#### vmware — 취약 선언 / 보완 선언

![vmware 취약 선언](assets/phase2-fixtures-2026-10-27/14-vmx-vulnerable.jpg)

![vmware 보완 선언](assets/phase2-fixtures-2026-10-27/15-vmx-remediated.jpg)

#### gns3 — 취약 선언 / 보완 선언

![gns3 취약 선언](assets/phase2-fixtures-2026-10-27/16-gns3-vulnerable.jpg)

![gns3 보완 선언](assets/phase2-fixtures-2026-10-27/17-gns3-remediated.jpg)

#### GNS3 3.0.0 입력 거절

오류 안내 후 기존 2.2.61의 성공 결과/시각이 유지됨을 확인했다. 지원하지 않는 입력으로 성공 기록을 덮지 않는다.

![미지원 GNS3 버전 거절](assets/phase2-fixtures-2026-10-27/18-gns3-unsupported-rejected.jpg)

### 11.4 회귀·코드 검토·교차 확인

- 전체 자동 테스트 **117개 통과, 실패0**, 취약/보완 파일 8쌍 회귀 포함. R05/R07/CSP/신뢰 peer 경계의 새 검증 포함.
- production 검증 빌드 TypeScript 포함 통과. 최초 제한 환경의 빌드 디렉터리 EPERM 후 권한을 갖춘 재실행으로 해결. 추가 fixture 테스트의 암시적 배열 타입 오류를 명시적 AssessmentReport[]로 수정한 뒤 빌드/테스트 재통과.
- 실제 사용자 DB를 사용하지 않는 전체 API/DB 통합 통과: 회원 권한·계정 격리·저장·전후 비교·집계·보관·롤백·비밀번호 복구·일반/관리형 스키마. 관리형 테스트는 자체 임시 PG이므로 제공자 ACL 검증이 아님.
- HTTP 보안 smoke 통과: 모든 script의 응답 nonce 일치·새 문서 nonce 교체·미인증·교차 Origin 거절. 6개 언어 smoke 통과.
- 브라우저 8쌍의 경고 수가 독립 파일 파서/엔진 결과와 일치. GNS3의 실제 다운로드한 DB 저장 결과 findings/moduleVersion이 독립 결과와 완전히 같음을 확인.
- 모든 사진은 CUA로 실제 페이지를 촬영했다. 파일 선택 도구 이벤트/대기 시간 오류가 몇 차례 있어 현재 UI를 다시 확인한 뒤 정상 완료했으며 이를 제품 입력 실패라고 집계하지 않았다. 최종 파일 검사/저장은 정상 완료했다.
- 검토한 제품 변경: proxy/layout/보안 헤더, 로그인·가입/로컬 gateway peer, GNS3 parser, readiness. 기존 인증 UI·SSRF·IP 차단 우회·운영 자격·적용된 migration은 수정하지 않았다. 스타일 inline 및 관리형 권한 경계는 잔여 위험이다.

### 11.5 실제 대상별 상태와 2단계 판단

| 대상 | 이번 완료한 것 | 별도 컴퓨터에서 필요한 것 |
|---|---|---|
| Linux | 5지시어 합성 전후·API·브라우저 | 실제 배포판/OpenSSH, Include/Match, sshd -T 유효 설정과 사용자 조건 대조·다른 컴퓨터 로그인/저장 |
| Windows | 정책/PE 합성 전후, 기존 실제 PE 구조 이력은 이전 문서 | 실효 정책/GPO/예외·OS 서명 도구·실제 승인 파일 대조 |
| macOS | 브라우저 Mach-O 합성 전후, unknown4 유지 | 실제 Mac의 codesign/Gatekeeper/entitlement 및 로컬 도구 대조 |
| Android/iOS | APK/IPA 선언 합성 전후 | 승인된 실제 앱·플랫폼 분석 도구 대조. 설치/런타임·서명은 별도 범위 |
| VMware/GNS3 | 정적 VMX/GNS3 합성 전후·미지원 버전 거절 | 실제 저장 파일과 설치 버전, 격리 실습의 통신/설정 대조. 10/23 과거 실습은 재검증과 구분 |
| 운영 | 현재 공개 경로 200 재관찰·이전503 요청 대조 | 당시 runtime/DB 지표·다른 실제 기기 계정 흐름·간헐적 오류 추적 |

**판단: 1단계 완료·2단계 진행 중을 유지한다.** 지원 파서와 사이트 흐름의 합성 교차 검증은 완료했지만 실제 플랫폼 검증·R01 근본 원인·R02 제공자 권한/복구 확인은 남았다. 실제 검증이 없는 항목을 더미 자료로 완료 처리하지 않는다. Cloud/Container/IoT·전체 장비 진단은 여전히 미구현이다.

다음 컴퓨터에서 전달할 실행 프롬프트는 [PHASE2_OTHER_COMPUTER_PROMPT.md](PHASE2_OTHER_COMPUTER_PROMPT.md)에 있다. 환경이 있는 대상만 읽기 전용으로 검증하고, 없는 대상은 설치/추정하지 말고 사유를 기록하도록 정리했다.

## 12. 현재 PC 실환경 후속 검증 — 소스 e195d85

사용자가 지정한 PHASE2_OTHER_COMPUTER_PROMPT.md를 기준으로 이어서 검증했다. 이전 1~11절은 당시 결과로 보존한다. 이번 시작 시 작업 트리는 깨끗했으며 제품 코드·운영 DB·배포 설정을 변경하지 않았다.

### 12.1 이번 실행과 설치 상태 정정

- 현재 소스에서 자동 테스트 **117개 통과 / 실패 0**를 재확인했다. 11절의 빌드·임시 DB·브라우저 검증은 이전 근거이며 이번 재실행으로 표기하지 않는다.
- VMware Workstation **16.1.2 build-17966106**, GNS3 서버 실행 파일 **2.2.61**, Tera Term **4.80** 설치를 확인했다. “설치되지 않아 불가”가 아니다. 초기 실행 VM 0대에서 이후 CentOS 1대 실행, 더 늦게 VM 프로세스 2개 관찰로 상태가 바뀌었다. VMware UI에서 Kali·Ubuntu·GNS3 VM 등 등록 항목도 확인했다.
- 사용자가 연결한 뒤 프로세스에서 Kali root SSH Tera Term 창을 확인했다. Windows SSH와 Tera Term은 인증/known_hosts를 자동 공유하지 않는다. 기존 CLI 경로로 StrictHostKeyChecking + BatchMode 접속을 시도했으나 호스트 키 미등록으로 접속 전 중단했다. 호스트 확인 해제·새 키 저장·SSH 설정 변경은 하지 않았다.

### 12.2 실제 파일·플랫폼 교차 확인

- 기존 Linux VM의 **실제 VMX 3개**, 기존 **GNS3 프로젝트 2개**를 현재 엔진으로 검사했다. VMX는 누락된 공유/격리/VNC 5항목을 미검사로 유지하고 네트워크 선언은 info로 표시했다. GNS3 프로젝트 버전 **2.2.55 / 2.2.61**을 모듈 **1.0.1**이 수용했다. 콘솔 주소 누락과 장비 실효 정책은 미검사로 유지했다. 실제 ping·장비 ACL·격리 검증을 완료한 것은 아니다.
- 실제 Windows 시스템 PE를 읽기 전용으로 검사했다. 64bit, 360448바이트, W+X 0. 독립 OS 서명 조회는 **Valid**였지만 로컬 도구의 Windows PowerShell 자식 프로세스는 서명 모듈 자동 로드에 실패해 **unknown**을 반환했다. 권한 있는 재실행도 같은 결과였다. 엔진은 서명을 **not_assessed**로 유지했으며 unknown을 강제로 통과시키지 않았다. 서명 유효성은 악성코드 부재를 보증하지 않는다.
- Windows 정책 exporter는 현 실행 정책으로 차단됐다. 정책 JSON은 생성되지 않았으며 정책 우회나 Windows 보안 설정 변경을 하지 않았다. WSL 실행 환경·기본 Android SDK는 없고 실제 Mac/모바일 검증도 미완료다.

### 12.3 산출물과 남은 검증

익명화한 [실환경 검증 기록](validation/2026-10-27-local-environment/README.md)과 [파서/엔진 관찰 JSON](validation/2026-10-27-local-environment/observations.json)을 추가했다. 원본 설정·개인 경로·주소·계정·해시는 보고서에 넣지 않았다. 로컬 원본 snapshot은 Git 제외 work/에만 둔다.

| 상태 | 결과 |
|---|---|
| 구현 검증 완료 | 117개 회귀, 실제 VMX/GNS3 파일 처리, 실제 PE 구조와 미검사 보존 |
| 실환경 검증 완료 | Windows OS/도구/독립 서명, VMware 실행 상태, 실제 저장 파일 관찰 |
| 보류 | Linux sshd -t/-T/Include/Match 및 조건별 비교, Windows 정책/서명 도구 환경 차이, GNS3 통신·격리, 다른 실제 기기의 계정별 저장/조회, Mac/모바일 실환경, R01·R02 잔여 확인 |

Linux 읽기 전용 명령을 사용자에게 전달하고 결과를 기다리고 있다. 제품 장애로 확인되지 않은 환경 제한은 코드 수정으로 숨기지 않았다. **1단계 완료·2단계 진행 중**을 유지하며 Git push·운영 배포·DB 변경은 하지 않았다.

### 12.4 Kali 실제 콘솔 출력 수신 후 교차 검증

위 결과 대기 상태 이후 사용자가 기존 Kali SSH 콘솔의 읽기 전용 명령 출력을 제공했다. **사용자 제공 실환경 출력**이며 에이전트가 직접 수집한 게스트 출력과 구분한다. 기록 시각은 2026-10-27 07:20:42 UTC / 16:20:42 KST이며 게스트 자체 실행 시각은 제공되지 않았다.

- Kali GNU/Linux Rolling **2026.1**, **OpenSSH_10.3p1 Debian-1**, OpenSSL **3.5.5 27 Jan 2026**. `sshd -t` 종료 코드 **0**으로 해당 실행의 설정 문법 검증 통과.
- `sshd -T`의 지원하는 다섯 값만 별도 검토용 사본으로 현재 `linux.ssh` 1.0.0 엔진에 입력하고 기대 판정과 assertion으로 대조했다.

| 유효 지시어 | 관찰값 | 엔진 결과 |
|---|---|---|
| PermitRootLogin | yes | warning |
| PasswordAuthentication | yes | warning |
| PermitEmptyPasswords | no | pass |
| PubkeyAuthentication | yes | pass |
| MaxAuthTries | 6 | warning — 모듈 검토 기준 1~4 초과 |

**경고 3개 / 통과 2개**, 기대 결과와 일치했다. 문법 통과는 보안 정책 통과가 아니며 공개키 인증 활성 선언은 승인 키/복구 접속의 실제 성공을 증명하지 않는다. 현재 root 비밀번호 SSH 접근을 바로 끄면 접속을 잃을 수 있으므로 실제 설정을 변경하거나 서비스를 재시작하지 않았다.

출력에 `Include` 존재를 확인했다. 원본 전체와 재귀 Include 대상, 연결 조건별 `sshd -T -C`는 검증하지 않았다. 제공된 검색 출력에 Match가 없다는 사실만으로 모든 포함 파일의 조건부 설정 부재를 확정하지 않는다. 별도 구성한 **비식별 Include 표식 + 다섯 값**은 파서 경계 시험에서 5개 모두 not_assessed임을 확인했다. 이것은 원본 파일 업로드 검증이 아니다.

근거: [Linux 유효 설정 대조 JSON](validation/2026-10-27-local-environment/linux-effective.json). Linux의 배포판/버전·문법·기본 유효 다섯 값 대조는 사용자 제공 출력 기반으로 완료했다. 원본/조건별 설정·다른 기기 계정 저장·조회는 계속 보류이며 2단계 전체 완료로 변경하지 않는다.

## 13. 모든 파일 입력 검사 — 서버 수신 입력과 결과 연결

사용자 요청에 따라 클라이언트 요약을 검증된 원본 결과처럼 취급하지 않도록 신뢰 경계를 추가했다.

- PE/Mach-O/모바일 패키지: 원본 전송 별도 동의를 받는 **서버 원본 검증 · 최대 2 MiB** 선택 모드 추가. 서버가 수신 바이트를 재분석하고 직접 계산한 SHA-256·크기를 저장한다. 클라이언트 snapshot이나 integrity 주장을 함께 보내면 거절한다. 입력 실행·AI 전송·원본 DB 저장 없음.
- 기존 원본 미전송/로컬 JSON은 `unverified-summary`. 파일 일치 미검증 경고를 표시하고 서버 검증으로 승격하지 않는다. 최대 8 GiB 브라우저 부분 검사 기능은 유지한다. 대용량 서버 원본 검증은 지원하지 않는다.
- Linux/Windows 정책/VMX/GNS3는 서버가 이미 분석하던 **수신 UTF-8 텍스트**에 해시·바이트 수를 추가했다. 디코딩된 텍스트 해시이며 로컬 원본 파일 바이트의 증명과 구분한다. 기존 APK 서버 모드에도 수신 바이트 근거를 추가했다.
- 검증 상태/입력 근거가 다른 이력은 자동 개선·악화 비교를 하지 않는다. 과거 메타데이터 없는 파일 결과는 원본 검증으로 간주하지 않는다. UI의 준비 상태와 서버 검증 완료를 구분하고 파일/모드 변경·취소 시 원본 준비 상태와 동의를 초기화한다.
- **검증 한계:** 서버 수신 파일에 결과를 연결할 뿐 기기의 다른 파일, 배포자 진위, OS 서명 체인, 악성코드 부재를 보증하지 않는다. 사용자 제공 원본 자체가 다른 파일이면 그 파일의 새로운 해시/분석 결과가 생성된다. 서버가 모르는 기기 원본을 알고 있다고 주장하지 않는다.

검증: 자동 테스트 **118/118 통과**, 타입 검사 통과. 실제 PE/Mach-O/APK fixture 바이트 재분석·해시 대조, 조작 snapshot/검증 표시·미동의 플래그·손상·크기 초과 거절, 설정 4종 수신 텍스트 해시 대조, 검증 방식 혼합 비교 차단을 확인했다. loopback 임시 PostgreSQL의 실제 HTTP 통합에서 일반 회원 원본 저장·서버 해시·위조 거절 후 기존 이력 보존·타 계정 404·원본 base64 미저장을 확인했고 전체 통합도 통과했다. 사용자 DB와 운영 배포는 변경하지 않았다. 브라우저에서 새 모드의 실제 클릭 흐름 재검증은 아직 하지 않았다. 최초 제한 환경 빌드 EPERM 후 분리된 검증 빌드는 통과했으며 최종 추가 변경의 분리 production 빌드도 통과했다.

## 14. 클라이언트 비신뢰 경계 추가 검토

공통 JSON 요청 파서에 전체 본문 읽기 10초 제한·중단 시 스트림 취소·잘못된 UTF-8 거절을 추가했다. 검사 요청의 알려진 문자열 필드도 잘못된 타입을 조용히 무시하지 않고 거절한다. 원본/결과/계정/검증 주장을 클라이언트가 섞어 보내는 입력을 거절한다.

검사 API에 기존 계정별 5회/분과 별도로 신뢰 출처별 60회/분·글로벌 300회/분을 적용했다. 기존 Vercel 신뢰 주소 또는 로컬 서명 peer를 사용하고 임의 IP 헤더는 신뢰하지 않는다. 직접 next 실행처럼 신뢰 peer가 없으면 공통 미확인 출처 버킷을 사용한다. 공유 NAT와 글로벌 예산으로 정상 사용자도 제한될 수 있다.

추가 후 자동 테스트 119개와 타입/검증 빌드 통과, 분리된 실제 임시 DB 전체 통합 재통과. 세션·소유자 조건·runtime DB 권한·Origin·SSRF·로그아웃·계정 격리·잘못된 요청 거절의 기존 통합을 유지했다. 모든 보안이 해결됐다는 판단은 하지 않는다. 도메인 소유권은 기존처럼 사용자 선언이며, 기기 원본 증명·서버 자체 침해·제공자 ACL·R01 원인·인증된 장비 수집·맬웨어 분석·운영 탐지는 별도 잔여 범위다.

## 15. 웹 기술 관찰·PHP2Shell 및 프레임워크 권고

2026-10-27 공식 출처를 조회해 PHP2Shell 두 CVE를 확인하고 [기술/보안 권고 문서](WEB_TECHNOLOGY_ADVISORIES.md)의 카탈로그를 추가했다. 기존 HEAD 응답에서 PHP/Python/Django/Java/Spring/JavaScript·TypeScript/Next.js/RSC/.NET/Ruby/Node.js/Go 흔적을 분류한다. 기존 웹 기본 결과와 전용 웹 PC/모바일 결과 양쪽에 표시하며 moduleVersion 1.1.0으로 이전 결과와 자동 비교 경계를 유지한다.

PHP2Shell 2개 CVE·Django SQL injection·Spring4Shell의 확인한 분기 버전을 대조하며 Next.js/RSC는 패키지 버전 미확인으로 React2Shell 적용 여부를 미검사로 남긴다. 범위 밖 버전은 안전 통과가 아니며 숫자 버전 일치도 실제 공격 성공이나 백포트 미적용을 증명하지 않는다. 다른 제품별 전체 CVE 피드/서버 내부 의존성 확인은 미구현으로 표시한다. 숨김 기술은 미검사다.

PHP 분기 경계·버전 충돌/미확인·비밀 배너 제외·오류 응답 미검사·프레임워크 구분을 회귀에 추가했다. 모의 HTTPS transport → 실제 scanner → PC/모바일 엔진까지 PHP2Shell 4개 경고를 대조했다. 공격/추가 탐색 요청은 보내지 않는다. 전체 자동 테스트는 122개 통과, 최신 제품 빌드 통과. 이후 충돌 처리 보완의 관련 회귀/타입/최종 빌드도 확인한다. 실제 새 UI 클릭/운영 배포는 아직 수행하지 않았다.

## 16. 차단 정책 재확인과 관리자 IP 해제 관리

현재 IP 정책은 **5분 임시 차단 5회, 해제 후 6번째 위반에 영구 IP 블랙리스트**다. 차단 중의 요청은 누적하지 않는다. 정해진 URL 탐색/삽입/경로 이탈 패턴만 감지하며, 모든 공격 판별·공격자의 실명/원래 IP 역추적을 구현한 것은 아니다. 신뢰 peer/Vercel의 접속 IP를 기준으로 한다. VPN/프록시/공유 NAT와 공격자 신원은 별개다. `/api/health`, `/api/ready`는 보호 상태 조회 예외이며 보호 DB 오류는 503으로 닫힌다.

기존 PostgreSQL `public.ip_blocks`를 그대로 사용한다. 일반 PG migration 005, 관리형 스키마 001에 존재한다. 이번 기능은 새 DB 테이블이나 migration 없이 구현했다. 실제 운영 DB 카탈로그를 이번에 직접 재조회한 것은 아니다.

이전에는 관리자 로컬 복구 스크립트만 있었으나, 관리자 웹 기본 작전실의 위험 접근 패널에 **IP 차단·누적 경고 해제** 버튼과 `/api/admin/ip-blocks` POST를 추가했다. 서버에서 관리자 현재 역할·세션·Origin·요청 타입/필드·IP·요청 한도를 검증한다. 일반 회원/비로그인/교차 출처/클라이언트가 주장하는 관리자 ID는 수락하지 않는다.

해제는 삭제가 아니라 누적 0·영구 차단 false·만료 null·manual_reset 변경이다. 기존 events에 실제 관리자 user_id·DB 생성 시각·정규화된 대상 IP의 SHA-256 감사 식별자를 같은 SQL 문으로 남긴다. 감사 쓰기가 실패하면 해제도 롤백한다. 대상 IP는 기존 차단 테이블에 남고 감사 category에는 원문 IP를 넣지 않는다. 자동 일괄 해제는 없다. 관리자 자신의 접속 IP가 차단된 경우 웹 우회 예외는 만들지 않았으며 기존 승인된 별도 접속 경로나 로컬 복구 스크립트가 필요하다.

**계정 ID 블랙리스트는 아직 미구현**이다. 로그인 입력 아이디만으로 계정을 자동 차단하면 타인 계정 차단 공격이 가능하므로 추가하지 않았다. 요구한 계정 단위 정책을 완성하려면 별도 보관 테이블/migration·유효 세션에 귀속된 근거·로그인 차단/기존 세션 폐기·관리자 해제를 함께 설계/검증해야 한다. IP 해제로 계정까지 해제된다고 표시하지 않는다.

자동 테스트 123개·타입·관리 API를 포함한 production 검증 빌드 통과. 기존 임시 DB의 5회/6번째·동시성·차단 중 비누적·로컬 해제·계정 격리 통합은 통과했다. 새 관리자 API의 실제 HTTP 권한/감사/롤백/영구 해제 통합도 별도 실행한다. 운영 차단을 직접 해제하거나 배포하지 않았다.

## 17. 후속 완료: 계정 블랙리스트와 관리자 복구

이하 내용은 16절의 당시 미구현/예정 상태를 갱신한다. 기준은 e195d85 이후 로컬 작업본이며 운영 배포나 운영 DB 변경은 하지 않았다.

일반 PostgreSQL 011 / 관리형 007 migration에 account_blocks를 추가했다. 새 IP 위반이 발생했을 때 서버가 유효한 세션으로 확인한 계정에만 위반을 귀속한다. 위조·만료·중복 쿠키나 입력한 이메일만으로 다른 고객을 차단하지 않는다. 계정 자체 누적 6번째에 영구 차단하며 기존 세션 폐기, 로그인 거절, 요청별 차단 상태 확인을 함께 적용했다. 익명 상태의 과거 IP 위반은 로그인 계정으로 이전하지 않는다.

관리자만 IP 및 계정 누적/차단을 해제할 수 있다. 계정 해제 후 새 로그인이 필요하며 IP 차단은 별도다. 관리자 역할·Origin·엄격한 본문·한도를 서버에서 확인한다. 해제와 감사 입력은 원자적으로 처리하며 감사 실패 시 해제도 롤백한다. 임시 PostgreSQL/HTTP에서 동시성, 5회 임시/6번째 영구, 세션 폐기, 해제 후 로그인, 회원의 관리 API 거절을 검증했다. 테스트 관리자 브라우저에서도 실제 해제와 목록 갱신을 확인했다.

## 18. 민감정보 노출 경계와 서버 참조

일반 PG 012 / 관리형 008 migration으로 차단 행별 management_id를 추가했다. 관리자 응답에도 원문 IP/계정 UUID를 보내지 않고 마스킹된 주소·이메일과 관리 참조만 보낸다. 해제 요청은 blockId로 보내며 서버가 실제 대상을 조회하고 권한을 다시 확인한다. 참조값 자체는 인증 수단이 아니다.

일반 사용자 프로필은 마스킹 이메일·역할만 직렬화한다. 원문을 CSS로 감추거나 hidden/aria/RSC/JSON에 함께 넣는 방식이 아니다. 감사 대상 해시는 대시보드에서 고정 분류로 정규화한다. 실제 검사 결과·파일 해시·사용자 본인 자산 결과는 정확성을 유지하며 고객별 서버 소유권으로 보호한다. 세션 쿠키는 브라우저 인증을 위해 존재하되 HttpOnly 등으로 보호하며, 고객 본인 연동 토큰은 발급 시 전달이 필요하다. DB 자격과 혼동하지 않는다.

근거: [노출 경계](DATA_EXPOSURE_BOUNDARY.md), [관리 정책](BLACKLIST_MANAGEMENT.md), [마스킹 화면](validation/2026-10-27-local-environment/admin-masked-management.png), [관리자 해제 성공](validation/2026-10-27-local-environment/admin-reference-release-success.png).

## 19. 일반 고객 기능 교차 검증과 잔여 범위

관리자가 아닌 실제 신규 가입 viewer 계정을 사용했다. 일반 회원도 지원하는 고객 진단 기능에 접근하도록 유지했다. 관리자용 차단 목록/해제는 403이며 다른 고객 데이터 접근도 거절한다.

- Linux SSH, Windows 정책, PE, Mach-O, APK/IPA 패키지, 기존 APK, VMX, GNS3: 8개 고유 오프라인 모듈을 9개 fixture 사례의 개선 전후 18회 저장으로 검증했다. 같은 자산 재검증 이력·서버 계산 해시·다른 계정 접근 거절을 확인했다. 기존 APK의 미검사 항목을 안전 통과로 바꾸지 않았다.
- 일반 회원 브라우저: 파일 없음 오류, 읽기 동의 전 검사 비활성, 파일 분석·저장·상태 초기화, JSON 다운로드와 미검증 요약 경고를 확인했다. 관리자 브라우저에서는 별도 동의 후 원본 서버 재분석과 SHA-256도 확인했다. 파일은 임시 로컬 서버에서만 테스트했다.
- 일반 회원 웹 비교: PC/모바일 공개 루트 HEAD 200, 기술 흔적·버전 미확인·CVE 적용 여부 미검사를 표시했다. 기본 웹 검사도 본인 결과 저장과 타 계정 격리를 확인했다.
- 일반 회원 본인 연동 토큰 발급/교체, 이전 토큰 거절, 새 토큰 집계 2회, 기록에 원문 토큰 없음, 타 계정 교체 거절을 확인했다. AI는 실제 외부 제공자 대신 로컬 모형에서 본인 결과·캐시·타 계정 거절을 검증했다.
- 실제 5회/분 제한에 도달하면 60초 대기 후 검사를 이어갔다. 한도를 우회해 통과시키지 않았다.

기본 웹 검사에서 일시 400이 관찰된 후 재시도는 200이었다. 최초 원인을 확정하지 않았다. 별도로 통제된 6.5초 지연 HEAD 회귀는 기존 5초 제한에서 실패했고, 헤더 대기를 15초(전체 검사 20초)로 조정한 후 통과했다. DNS/SSRF/인증서 검증은 유지했다. 실패 로그는 고정 사유만 남긴다. 이 결과만으로 운영 PROTECTION_UNAVAILABLE 원인이 해결됐다고 단정하지 않는다.

최신 자동 회귀 127/127, TypeScript, 분리 production 빌드 통과. 실제 DB/HTTP 통합은 최종 재실행 로그를 별도로 확인한다. 일반 회원 서비스 증거: [검증 JSON](validation/2026-10-27-local-environment/member-services.json), [회원 홈](validation/2026-10-27-local-environment/member-home.png), [회원 파일 결과](validation/2026-10-27-local-environment/member-browser-result.png).

Cloud/IoT/Container는 준비 중이며 고객·관리자 모두 완성 기능으로 표시하지 않는다. 실제 macOS/모바일 기기 검증, Windows 정책 추출 제한, 관리형 제공자 ACL, 전체 언어/전체 CVE, 운영 접속 오류 원인은 잔여 범위다. 공개 웹의 헤더만으로 숨겨진 모든 언어나 실제 취약성을 확정할 수 없다. 브라우저 요약/서버 수신 바이트 검증도 고객 기기의 원본 파일 진정성을 증명하지 않는다.

**운영 반영 전:** 해당 DB 종류의 신규 migration(일반 011·012 또는 관리형 007·008), runtime 권한, readiness를 먼저 확인해야 한다. 현재 단계는 Phase 1 완료 / Phase 2 진행 중이다. 이 후속 작업에서는 커밋·푸시·운영 migration·배포를 하지 않았다.

마지막 UX 점검에서 Linux/Windows 설정 파일 선택 직후 읽기 흐름을 수정했다. 파일 선택은 내용 읽기를 시작하지 않고, 선택한 파일별 읽기 동의와 '허용한 설정 읽기'가 필요하다. 파일 변경·직접 입력·모듈 변경 시 읽기/진단 동의를 초기화한다. 이 추가 수정은 타입·최종 빌드로 확인하며 앞의 브라우저 파일 동의 실증은 PE 경로에 대한 것이다. Linux/Windows 새 동의 UI 자체의 브라우저 재실행은 별도 확인 범위로 남긴다.

| 대상 | 판정 | 근거 / 남은 확인 |
|---|---|---|
| 일반 회원의 지원 진단·저장·조회·재검증·고객별 격리 | 구현 검증 완료 | 임시 DB/HTTP 모듈 행렬 및 회원 브라우저 PE·웹 비교 |
| 서버 수신 원본 해시·요약 미검증 구분 | 구현 검증 완료 | 위조 혼합 요청 거절·원문 미보관·원본/요약 브라우저 결과 |
| IP/계정 차단·관리자 해제·민감 식별자 마스킹 | 구현 검증 완료 | 임시 DB 동시성/감사 롤백 및 관리자 브라우저 |
| 실제 VMware/GNS3 설치·제공 설정 관찰 | 실환경 검증 완료（기록된 범위） | 12절. 게스트 실효 설정 전체/네트워크 전체 검증은 아님 |
| Kali SSH 지원 지시어 | 실환경 검증 완료（제공 출력 범위） | 사용자 제공 유효 출력과 정적 엔진 대조. 원본 전체 업로드 아님 |
| Linux/Windows 추가 읽기 동의 UI | 구현 확인 / 브라우저 보류 | 타입·최종 빌드 통과, 두 UI의 선택→동의→읽기 실클릭 재확인 필요 |
| 실제 macOS/모바일·Windows 정책 전체 | 보류 | 해당 기기/도구·승인된 정책 추출 필요 |
| 운영 migration·배포 후 일반 회원 점검 | 보류 | 운영 변경 미실행. migration·권한·readiness 후 별도 점검 |
| R01 운영 간헐 오류·R02 제공자 권한 | 보류 | 발생 시각의 runtime/DB 근거 및 제공자 권한 점검 필요 |
| Cloud·IoT·Container | 보류 | 준비 중 기능으로 표시, 완성된 고객 진단으로 포함하지 않음 |

최종 재실행 결과: 임시 PostgreSQL/HTTP 통합 전체 종료 코드 0, 일반 PG·관리형 스키마 검증 및 30일 보관/백업·계정 격리·감사 롤백 통과. [비밀 없는 통합 결과](validation/2026-10-27-local-environment/final-integration.txt)에 PASS 항목을 보존했다. 마지막 읽기 동의 수정 후에도 타입 검사·production 빌드·127/127 회귀가 통과했다. 임시 브라우저 서버와 PostgreSQL을 종료했으며 운영 서비스에는 적용하지 않았다.

## 20. 사용자 후속 요청에 따른 운영 migration 적용

사용자가 개발 도구 없이 대신 진행해 달라고 요청하여, 검토 결과를 제시한 뒤의 운영 반영 작업을 이어갔다. 기존 로컬 운영 설정으로 DB 식별 일치를 확인했으며 비밀 값은 출력하지 않았다. 관리형 Prisma Postgres에 001~006이 적용된 상태였다.

첫 신규 migration 시도는 제공자의 `restricted superuser cannot grant or revoke privileges` 제한(42501)으로 전체 롤백됐다. 운영에 아직 적용되지 않은 신규 관리형 007의 REVOKE를 제공자 프로필에 맞게 제외했다. 일반 PostgreSQL 011의 REVOKE는 유지했다. 이후 관리형 007·008 적용 성공을 확인했다. 재조회에서 account_blocks와 IP/계정 management_id, migration 이력 8개, account_blocks의 PUBLIC 테이블 권한 없음이 확인됐다. 이는 제공자 관리 자격 자체의 과도한 권한 문제까지 해결했다는 뜻은 아니다.

기존 고객 결과 삭제·차단 해제·비밀번호 변경은 하지 않았다. 앞 절의 운영 migration 미실행 문구는 당시 상태이며 이 절로 갱신한다. 코드 업로드와 운영 배포 후 점검 결과는 아래에 후속 기록한다.

### 운영 배포 결과

기존 GitHub main에 코드 커밋 `5a4c521`을 정상 푸시했다. Vercel GitHub 상태가 `success / Deployment has completed`인 것을 확인했다. 배포 ID는 `DWuB6S44yRcetPLAox3yL1fJLX2r`이다. 운영 `/api/health`, `/api/ready`는 200, 새 관리 API 두 경로의 GET은 405(POST 전용), 동일 출처 비로그인 POST는 각각 401이었다. 실제 운영 차단 해제나 고객 결과 작성은 하지 않았다.

운영 로그인 세션을 사용한 고객 전체 시나리오는 이 배포에서 새로 수행하지 않았다. 앞 절의 일반 회원 전체 행렬은 격리된 로컬 환경의 검증이다. R01 최초 간헐 오류 원인·R02 제공자 권한과 실제 macOS/모바일 검증도 여전히 잔여 범위다. 고객이 사용할 개발 도구 없이도 기존 설정과 Git 연동으로 migration·푸시·배포 확인까지 대행했다.
