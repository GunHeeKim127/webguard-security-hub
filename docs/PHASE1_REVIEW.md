# 1단계 전체 코드 검토·기능 검증

기준일: 2026-10-17 / Asia-Seoul. 기준은 `prompt.md` 13절과 [PHASE1.md](PHASE1.md)입니다.

## 판단과 검토 범위

공개 웹 기본 진단 MVP로 정의한 1단계의 7개 항목을 구현하고 아래 시험으로 검증했습니다. 발견한 실패는 수정 후 재확인했습니다. 프로젝트 소유의 앱·라이브러리·운영 스크립트·SQL·테스트·설정·문서를 검토했습니다. node_modules, 생성된 빌드, Git 내부, 실제 비밀 환경 파일 원문은 공개 검토 자료에서 제외합니다. 의존성 내부 전체를 수작업 감사했다는 뜻은 아니며 lockfile은 설치 버전과 npm 공식 감사 결과를 확인했습니다. 모든 입력·장애·공격에 오류가 없다는 보증은 아닙니다.

## 실행 검증

| 검사 | 결과와 확인 범위 |
|---|---|
| `npm test` | 72개 통과. URL·IP·혼합 DNS·연결 고정·취소·TLS·헤더 규칙·쿠키 원문 제거·권한·JSON·비밀번호·언어·AI 전환·Vercel 보호·DB 설정 |
| 타입 검사 / production build | TypeScript와 Next.js 16.4.2 webpack 빌드 통과. Node Proxy 포함, 별도 `.next-verify` 사용 |
| `test:smoke` | 실제 HTTP 앱 shell 200, 보안 응답 헤더, 비로그인 401, 위조 Origin 403, 진단·AI 비로그인 거절 |
| `test:locale` | 6개 SSR 언어·가입 화면·API 오류, 수동 언어 쿠키, 위조 국가 헤더 거절·인증된 국가 힌트 우선순위 통과 |
| `test:integration` | 임시 loopback PostgreSQL 전체 통과. 가입·viewer 강제·중복 계정 보존·다중 기기·세션 만료·로그아웃·SSRF API·NDJSON·upsert·동시 갱신·실패 보존·AI 모형·캐시/예산/한도·디코이·5분 차단/6회 블랙리스트·복구·권한·계정 이전 |
| Prisma 스키마 회귀 | 임시 DB에 제공자용 SQL을 적용해 viewer 등록·SQL 검사·결과 갱신·캐시 확인. 실제 Prisma ACL 제약까지 로컬 PG가 재현하는 것은 아님 |
| 실제 Prisma 풀 | 검증 TLS, readiness `READY / provider-managed`, 앱 쿼리를 확인 후 롤백. 실제 계정·결과 보존, 외부 AI 호출 없음 |
| 실제 공개 진단 | 사용자 예제 `auth-security-lab-game.vercel.app`에 HEAD 1회, HTTP 200, assessmentVersion 2, 8개 항목과 TLS 기본 검사 통과. 응답 본문·쿠키 값 수집 없음 |
| 브라우저 | 별도 임시 DB/계정에서 로그인, 헤더 가입 링크 0개, 주소+허가 체크 후 버튼 활성화, 실제 진단·저장 완료, 개선안 펼치기/접기, JSON 다운로드. 공식 로그인 화면의 모바일 너비에서 가로 넘침 없음 |
| 로그 초기화·파일 | 주소 변경 시 작전실/현재 로그 제거·허가 체크 해제·버튼 비활성, 저장 결과 유지. 다운로드는 `webguard-scan-log-v1`, success, HTTP 200, 로그 8개·상세 항목 8개 확인 |
| 의존성 감사 | npm 공식 레지스트리에서 보고된 취약점 0개. 미공개 취약점이나 앱 로직 안전성까지 뜻하지 않음 |

PowerShell 재현 명령:

```powershell
npm test
npm run typecheck
$env:WEBGUARD_VERIFY='true'
npm run build
npm run test:smoke
npm run test:locale
npm run test:integration
Remove-Item Env:WEBGUARD_VERIFY
```

시험용 DB는 기존 사용자 DB와 분리하고 사용 후 중단합니다. work/의 자료는 Git 제외입니다. 실제 운영 IP를 공격하거나 사용자의 비밀번호를 읽어 시험하지 않았습니다. 외부 LLM 생성은 로컬 모형·단위 테스트로 검증했고 이번 검토에서 실제 LLM 토큰은 소비하지 않았습니다.

## 이번 검토에서 수정한 내용

1. **로컬 production 보호 서버의 Prisma 비호환 옵션:** 앱만 고쳐져 있고 `serve.ts`에 시작 옵션이 남아 있었습니다. `runtime-pool-config.ts`로 통합하고 제공자별 timeout을 검사합니다. idle 연결 오류도 고정 문구로 처리합니다.
2. **운영 설정이 테스트에 섞임:** 검증 서버의 DB 제공자·플랫폼 모드·공개 가입·AI 키를 명시해 운영 DB/AI와 분리했습니다.
3. **JSON MIME 오인:** jsonp 등도 받던 startsWith 검사를 정확한 MIME 검사로 변경했습니다. charset·대소문자를 정상 처리하고 읽기 락도 해제합니다.
4. **DNS 대기 중 취소 지연·정리 누락:** 취소 시 즉시 대기를 끝내고 timer/listener를 정리합니다. OS DNS 조회 자체를 취소하는 것은 아니지만 늦게 끝나도 HTTPS 연결을 열지 않습니다.
5. **변형된 비밀번호 해시 허용:** 추가 필드를 무시하지 않고 정확한 salt:hash 형식만 검증합니다. 정상 계정·비밀번호는 바꾸지 않습니다.
6. **일반 PostgreSQL 권한 점검 누락:** REPLICATION·BYPASSRLS 역할도 grant 도구와 readiness에서 거절합니다. 임시 DB에서 실제 플래그를 바꿔 시험한 뒤 원복했습니다.
7. **비밀 출력 경로 제한 부족:** 새 자격증명 출력은 프로젝트 안의 Git 제외 `.env.production.*` 또는 work/로 제한합니다. 기존 파일은 덮어쓰지 않습니다.
8. **다른 결과로 이동한 뒤 이전 AI 응답 표시 가능:** 요청 세대가 달라진 응답·오류를 현재 화면에 적용하지 않습니다.
9. **오래된 테스트·안내:** 영어 제목 의존 smoke 단언, 이전 AI 모델 고정 설명, DB TLS query 옵션, 운영 배포 대기 상태를 수정했습니다. 공식 배포에서도 나오던 로컬 미리보기 표시는 MVP로 바꿨습니다. README에 단계별 구현·문제·해결 내역을 추가했습니다.

이전에 완료한 로그인 헤더 제거·오른쪽 보안 SVG·로그인 후 가입 링크 숨김도 브라우저에서 확인했습니다.

## 남은 제약

- 단일 조직입니다. viewer도 조직 전체 결과를 읽습니다. 고객별 격리·가입 승인·실제 자산 소유권 증명은 미구현입니다.
- Prisma는 별도 SQL 앱 역할을 만들 수 없습니다. SQL 보조 검사는 넓은 제공자 키의 DB 권한을 줄이거나 키 탈취 후 접근을 막지 못합니다.
- 현재 Production의 공개 가입·외부 AI는 비활성입니다. 시험 성공이 운영에서 자동 활성화됐다는 뜻은 아닙니다.
- 계정/전역 요청 제한은 대규모 사용·분산 공격·전역 한도 악용·공유 IP 오탐을 모두 해결하는 WAF/DDoS 보호가 아닙니다.
- nonce CSP, MFA·이메일 인증·계정 복구, 백업 복원·부하·장애 검증, 이벤트 자동 정리는 남아 있습니다.
- PC/모바일 비교·로그인 후/GET/다른 경로 진단·개선 전후 비교·전체 이력·정식 보고서·외부 트래픽·봇 판정·격리 허니팟·앱/서버/네트워크 분석은 다음 단계입니다.

보안 경계는 [SECURITY_POLICY.md](../SECURITY_POLICY.md)에 자세히 정리했습니다. 참고 API: [node-postgres](https://node-postgres.com/apis/client), [Node DNS](https://nodejs.org/api/dns.html), [PostgreSQL 역할](https://www.postgresql.org/docs/current/role-attributes.html). Next.js는 설치된 `node_modules/next/dist/docs/`의 route·layout·환경변수·custom server 안내를 확인했습니다.

## 파일별 검토 대상

Git 관리 대상과 이번 신규 파일 119개를 기준으로 목록을 확인했습니다. 각 코드는 관련 기능별로 읽고 테스트와 대조했습니다. 번역은 사전 키·문구 유무·언어 HTTP 시험, 설정은 빌드와 실행 경로, SQL은 임시 DB 검증으로 확인했습니다. package-lock은 JSON·설치 버전·npm audit 대상으로 확인했습니다. 이 목록은 줄 단위 정형 증명이나 외부 의존성 소스 감사가 아닙니다.

### 설정·환경 예시·의존성 · 14개

```text
.env.example
.env.migration.example
.gitattributes
.gitignore
compose.yaml
deploy/migration.production.env.example
deploy/prisma.vercel.env.example
deploy/vercel.env.example
next.config.ts
package-lock.json
package.json
proxy.ts
tsconfig.json
vercel.json
```

### 기획·운영 문서 · 14개

```text
AGENTS.md
README.md
SECURITY_POLICY.md
VALIDATION.md
docs/ACCESS_DEFENSE.md
docs/LANGUAGES.md
docs/OPERATIONS_UI.md
docs/PC_SHARING.md
docs/PHASE1.md
docs/PHASE1_REVIEW.md
docs/PROJECT_DATABASES.md
docs/PROJECT_STATUS.md
docs/VERCEL_DEPLOYMENT.md
prompt.md
```

### 화면·API · 22개

```text
app/[...probe]/route.ts
app/api/ai/route.ts
app/api/dashboard/route.ts
app/api/health/route.ts
app/api/locale/route.ts
app/api/login/route.ts
app/api/logout/route.ts
app/api/ready/route.ts
app/api/register/route.ts
app/api/scans/route.ts
app/assessment-panel.tsx
app/decoy/route.ts
app/defense-panel.tsx
app/error.tsx
app/home-client.tsx
app/layout.tsx
app/login-illustration.tsx
app/not-found.tsx
app/operations-panel.tsx
app/page.tsx
app/signup/page.tsx
app/signup/signup-client.tsx
```

### 공통 로직·번역 · 39개

```text
lib/access-origins.ts
lib/advice-cache.ts
lib/ai-budget.ts
lib/ai-chain.ts
lib/ai-error-copy.ts
lib/ai-provider-error.ts
lib/ai-providers.ts
lib/assessment-copy.ts
lib/database-pool.ts
lib/database-provider.ts
lib/db.ts
lib/defense-copy.ts
lib/deployment-readiness.ts
lib/errors-i18n.ts
lib/geo-country.ts
lib/ingress-guard.ts
lib/inspection.ts
lib/local-advice.ts
lib/locale.ts
lib/messages.ts
lib/operations-messages.ts
lib/password.ts
lib/project-database.ts
lib/registration-copy.ts
lib/registration.ts
lib/request-locale.ts
lib/request.ts
lib/runtime-pool-config.ts
lib/runtime-sql.ts
lib/scan-policy.ts
lib/scan-run.ts
lib/scan-store.ts
lib/scan-ui.ts
lib/scanner.ts
lib/security.ts
lib/traffic.ts
lib/tunnel-gateway.ts
lib/vercel-protection.ts
lib/web-assessment.ts
```

### 운영·실행 도구 · 11개

```text
scripts/copy-production-data.ts
scripts/create-user.ts
scripts/grant-runtime.ts
scripts/integration.ts
scripts/locale-smoke.ts
scripts/migrate.ts
scripts/serve.ts
scripts/setup-production.ts
scripts/share.ts
scripts/smoke.ts
scripts/unblock-ip.ts
```

### SQL·migration · 11개

```text
sql/maintenance.sql
sql/migrations/001_initial.sql
sql/migrations/002_registration.sql
sql/migrations/003_latest_scan.sql
sql/migrations/004_advice_cache.sql
sql/migrations/005_ip_blocks.sql
sql/migrations/prisma-postgres/001_initial.sql
sql/runtime-grants.example.sql
sql/setup/00_create_roles.sql
sql/setup/01_create_database.sql
sql/setup/02_restrict_database.sql
```

### 회귀 테스트 · 8개

```text
tests/access.test.ts
tests/deployment.test.ts
tests/i18n.test.ts
tests/ingress.test.ts
tests/inspection.test.ts
tests/security.test.ts
tests/tunnel.test.ts
tests/web-assessment.test.ts
```
