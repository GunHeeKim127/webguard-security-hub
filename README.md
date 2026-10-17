# WebGuard Security Hub

소유·진단 허가를 확인한 공개 웹사이트의 기본 진단, 계정별 접근 이벤트와 AI 개선안을 한 화면에서 확인하는 **계정별 진단 MVP**입니다. Next.js / TypeScript / MUI / PostgreSQL을 사용합니다. 전체 취약점 진단기나 외부 사이트의 WAF는 아직 아닙니다.

**정식 배포 주소: https://webguard-security-hub.vercel.app/**. Vercel에서 화면과 API를 실행하고 Prisma Postgres에 연결합니다. 기존 계정과 최신 결과를 이전했으며 PC를 끄더라도 이 정식 배포와 외부 DB가 실행 중이면 이용할 수 있습니다. `/api/ready`에서 준비 상태를 확인합니다. 환경 구성과 제공자 권한 제약은 [Vercel 배포 안내](docs/VERCEL_DEPLOYMENT.md)를 참고하세요.

## 현재 진행 상태 · 2026-10-17

`prompt.md` 13절의 **1단계(1주 차)는 공개 웹 기본 진단 MVP 범위에서 구현하고 검증했습니다.** 그 범위는 아래 7개 항목입니다. 전체 통합 보안 플랫폼, 모든 취약점 검사 또는 공개 운영의 보안 보증을 완료했다는 뜻은 아닙니다.

| 1단계 항목 | 구현 내용 | 확인 방법 |
|---|---|---|
| 프로젝트 기본 구조 | Next.js 16 / TypeScript / MUI, 서버 API, 공식 Vercel 배포 | 타입 검사·production 빌드·HTTP 응답 |
| 인증·권한 관리 | 회원가입 viewer 강제, 로그인·로그아웃, admin/analyst/viewer, 다중 기기 세션 | 임시 DB에서 실제 HTTP·역할 거절·만료·로그아웃 |
| PostgreSQL 연결 | 개발 DB와 Prisma 운영 DB 구분, 서버 전용 TLS 풀 | 프로젝트 식별·인증서 검증·readiness·실제 Prisma 연결 |
| SQL migrations | 체크섬·트랜잭션·잠금, 일반/Prisma 별도 이력, 로컬 앱·migrator 구분 | 임시 DB의 반복 적용·권한·이전 결과 확인 |
| SSRF 방어 | HTTPS/443 루트, 모든 DNS 공개 IP 검증, IP 고정, TLS·시간 제한, 리디렉션 미추적 | 우회 URL·혼합 DNS·메타데이터 IP·취소·TLS 실패 테스트 |
| 웹 보안 진단 엔진 | CSP/HSTS/nosniff/Referrer-Policy, TLS·인증서, 쿠키·CORS·정보 노출 기본 검사 | 규칙 회귀·전송 모형·사용자 예제 사이트 실제 HEAD 1회 |
| 기본 진단 결과 화면 | 단계별 작전실·현재 로그·JSON 다운로드, 근거·심각도·접는 개선안, 최신 결과 덮어쓰기 | 브라우저 확인·스트림 파서·DB 동시 갱신·실패 보존 |

1단계 외에 일부 선행한 기능은 6개 언어, API 없는 기본 개선안, 선택적 AI 제공자 전환·캐시·비용 제한, Hub 자체의 위험 URL/IP 차단과 제한된 디코이입니다. **2·3단계 전체가 완료된 것은 아닙니다.** PC/모바일 비교, 로그인 후 진단, 개선 전후 비교·전체 이력·정식 보고서, 외부 트래픽·WAF·봇 판별·격리형 허니팟은 남아 있습니다.

Production은 **일반 회원가입과 로그인을 활성화**합니다. 신규 계정은 viewer이며 자신의 저장 결과만 조회할 수 있습니다. 진단 실행은 admin/analyst 권한이 필요합니다. 진단 목록·개수·이벤트·AI 요청과 캐시는 계정별로 분리하고 같은 주소의 덮어쓰기도 동일 계정 안에서만 적용합니다. 관리자도 다른 회원의 진단을 자동 열람하지 않습니다. 이전 결과의 보존 기준과 관리자 운영 정보 예외는 [계정별 데이터 분리](docs/ACCOUNT_ISOLATION.md)를 참고하세요. 외부 AI는 현재 비활성이고 기본 개선안은 사용할 수 있습니다.

## 발견했던 문제와 해결

| 문제 | 원인·해결 |
|---|---|
| Vercel 로그인 실패 | `localhost` DB 주소와 실제 배포 Origin 불일치. 외부 Prisma DB·공식 APP_ORIGIN·정확한 Host 검사로 전환하고 기존 계정 해시·결과 이전 |
| Prisma 역할 생성·GRANT 실패 | 제공자 제한. 별도 managed 프로필·migration을 사용하고 DB 역할 격리의 제약을 명시. 앱 SQL 검사는 DB ACL의 대체물이 아님 |
| Prisma 풀의 upstream 연결 실패 | 시작 옵션 `statement_timeout` 비호환. 앱과 로컬 보호 서버가 같은 제공자별 풀 설정을 사용하도록 통합 |
| 정상 결과 저장·캐시 쿼리 거절 | SQL 보조 검사가 정상 `UPDATE SET`, `ON CONFLICT DO UPDATE`까지 거절. 정상 DML 허용과 DDL·여러 문장 거절 회귀 검사 추가 |
| 진단 버튼 비활성·같은 주소 결과 중복 | 공개 모드의 주소·권한 체크·역할 기준을 정리하고, 도메인 유일성 제약과 원자적 upsert 적용. 실패 시 이전 결과 유지 |
| 과도한 AI 호출·한도 오류 | 자동 재시도 제거, 출력 400토큰·20초 제한, 24시간 캐시·중복 예약·공유 계정 예산·제공자별 대기·Groq→Gemini→기본 안내 적용 |
| 주소를 바꾼 뒤 이전 AI 응답 표시 가능 | 요청 시작 시점의 화면 세대와 현재 세대를 비교해 오래된 응답·오류를 표시하지 않도록 수정 |
| DNS 대기 중 진단 취소 지연 | 취소 신호로 즉시 대기를 끝내고 DNS 시간 제한·이벤트 리스너를 정리. 연결 자체는 열지 않음 |
| 잘못된 요청·비밀번호 해시 처리 | JSON MIME을 정확히 검사하고 charset·대소문자를 정상 처리. 크기 초과·파싱 실패·변형된 해시는 거절 |
| 관리용 출력 파일·권한 검사 부족 | 비밀 출력은 Git 제외 환경 파일 또는 work/로 제한. 일반 PostgreSQL 역할의 REPLICATION·BYPASSRLS도 거절 |
| 테스트가 운영 설정·영어 문구에 의존 | 검증 DB 제공자·Vercel 모드·AI 키를 명시적으로 격리하고, 화면 shell 검사를 언어와 무관하게 수정 |
| 로그인 화면에 불필요한 헤더·가입 링크 | 로그인 헤더 제거, 폼 내부 언어 선택·오른쪽 보안 SVG 추가. 로그인 후 헤더에는 회원가입 링크 미표시 |

이번 검토의 실행 근거·파일 범위와 남은 제한은 [1단계 검토 기록](docs/PHASE1_REVIEW.md), 누적 이력은 [VALIDATION.md](VALIDATION.md)에 기록합니다. 운영 계정·기존 DB를 대상으로 침입·부하·파괴 시험을 수행하지 않습니다.

## 현재 가능한 일

- 이메일 회원가입·로그인·로그아웃, admin/analyst/viewer 권한 구분. 신규 가입자는 viewer입니다.
- 사전 등록 없는 공개 HTTPS 원점에서 CSP·HSTS·nosniff·Referrer-Policy의 기본 정책값, 실제 TLS 연결의 신뢰·협상 버전·인증서 만료일, 관찰된 쿠키 속성, CORS 및 서버 식별 헤더를 검사합니다. 상세 범위는 [1단계 진단 명세](docs/PHASE1.md)를 참고하세요.
- 결과별 판정·심각도·근거와 접고 펼칠 수 있는 개선안. 기존 기본·AI 개선안도 추가 API 호출 없이 접고 펼칠 수 있습니다.
- 실제 서버 단계가 전달되는 진단 작전실, 진행 단계 점멸, 주소 변경 시 현재 요청·화면 로그 초기화, JSON 로그 다운로드.
- 같은 계정·도메인의 성공 결과를 최신 결과로 갱신합니다. 다른 계정의 같은 주소는 별도로 보관하며 실패하면 이전 결과를 유지합니다. 상세 진행 로그는 브라우저에서만 보관합니다.
- API 호출 없는 기본 개선안. 선택한 경우에만 외부 AI를 요청하며 Groq → Gemini → 기본 안내로 전환합니다.
- 한국어·영어·일본어·중국어 간체·스페인어·프랑스어 UI와 오류 안내.
- 허브 자체의 로그인 실패·진단 거부·의심 경로·최소 디코이 접근 이벤트 확인. 외부 트래픽은 수집하지 않습니다.
- 실제 접속 IP의 정해진 위험 URL 패턴을 감지해 5분 차단, 5차례 임시 차단 후 6번째 위반에 블랙리스트 등록. 관리자 IP 현황과 로컬 해제 도구를 제공합니다. [적용 범위·복구 방법](docs/ACCESS_DEFENSE.md)을 참고하세요.

계정·DB의 실제 권한, 진단 허용 범위, 공격 시 차단·복구와 미구현 사항은 [보안 권한·대응 정책](SECURITY_POLICY.md)에 정리했습니다. 기획 대비 구현 상태와 남은 작업은 [프로젝트 현황 분석](docs/PROJECT_STATUS.md), 실제 검증 기록은 [VALIDATION.md](VALIDATION.md)를 참고하세요.

## 로컬 시작

Node.js 20.9 이상과 PostgreSQL 15 이상이 필요합니다. DBeaver는 DB 관리 도구이며, Prisma 확장 설치만으로 ORM이 필요한 것은 아닙니다. 현재 구현은 pg와 SQL migration을 사용합니다.

1. [프로젝트별 DB 설정](docs/PROJECT_DATABASES.md)에 따라 sql/setup의 역할·DB 생성 스크립트를 순서대로 실행합니다. CREATE DATABASE는 Auto-commit에서 별도로 실행합니다. 기존 다른 프로젝트 DB는 변경하지 않습니다.
2. `npm ci`를 실행합니다.
3. `.env.example`을 `.env.local`, `.env.migration.example`을 `.env.migration.local`로 복사합니다. 이미 파일이 있으면 덮어쓰지 말고 새 항목만 추가합니다.
4. 앱 환경 파일에는 app 역할의 DATABASE_URL, migration 환경 파일에는 migrator 역할의 MIGRATION_DATABASE_URL을 입력합니다. URL의 비밀번호 특수문자는 percent encoding합니다.
5. `npm run db:migrate`, `npm run db:grant`를 실행합니다.
6. 최초 관리자는 migration 환경 파일의 BOOTSTRAP_EMAIL/PASSWORD/ROLE을 로컬에서 설정한 뒤 `npm run user:create`로 생성합니다. 비밀번호는 14~128자이며 생성 후 BOOTSTRAP_PASSWORD를 비웁니다.
7. `npm run dev` 후 http://localhost:3000 에서 로그인합니다. 이후 일반 사용자는 `/signup`에서 가입할 수 있습니다.

AI 키가 없어도 로그인·진단·무료 기본 개선안은 사용할 수 있습니다. 기본 `SCAN_TARGET_POLICY=public`은 공개 도메인 주소와 사용자 권한 확인 체크를 받으며 사전 등록을 요구하지 않습니다. 체크는 소유권 증명이 아닙니다. 주소 변경 시 체크를 초기화하며 내부망·SSRF 제한은 유지합니다. `SCAN_TARGET_POLICY=approved`로 바꾸면 `ALLOWED_SCAN_HOSTS`의 정확한 목록을 적용하고 빈 목록은 진단을 차단합니다.

`npm run dev`/`npm start`는 IP 보호 서버를 포함합니다. 보호 상태 확인에 DB가 필요하므로 migration과 권한을 먼저 적용하세요. 새 보호 기능은 005 migration을 사용합니다. 기본 직접 접속에는 추가 IP 비밀 설정이 필요 없습니다.

## AI 설정과 비용 제어

`AI_ENABLED=true`, `AI_PROVIDER=auto`이면 다음 순서를 사용합니다.

| 순서 | 키 | 모델 설정 |
|---|---|---|
| 1 | GROQ_API_KEY | OPENAI_MODEL=openai/gpt-oss-120b |
| 2 | GEMINI_API_KEY | GEMINI_MODEL=gemini-3.5-flash-lite |
| 3 | 필요 없음 | 고정 기본 개선안 |

없는 키는 건너뜁니다. 성공하면 종료하고, 제공자의 한도·인증·모델·연결 오류일 때 다음 제공자를 시도합니다. `AI_PROVIDER=groq` 또는 `gemini`로 한 제공자만 선택할 수 있습니다. 유료 OpenAI는 `AI_PROVIDER=openai`를 명시적으로 선택한 경우에만 OPENAI_API_KEY와 해당 OPENAI_MODEL을 사용합니다. 자동 체인에는 포함하지 않습니다. 각 제공자 계정의 무료 플랜·요금 조건은 별도 확인해야 합니다.

대상 HTML·도메인·쿠키·IP·DB 자격증명은 보내지 않고 서버가 만든 네 헤더의 이름·존재 여부만 전송합니다. 각 제공자당 최대 한 번 시도하며 자동 재시도는 없습니다. 출력 상한 400토큰, 20초 timeout을 적용합니다. 상한에는 모델의 추론 토큰도 포함될 수 있어 빈 응답이면 기본 안내로 대체합니다. AI는 서버·SQL·보안 설정을 실행하지 않습니다.

성공 답변은 제공자·모델·언어·헤더 상태별로 24시간 재사용합니다. DB의 45초 예약이 중복 생성을 방지합니다. 분당 10회 시도 보호와 계정당 시간당 3회 성공 한도를 적용하고, 실패하면 해당 성공 한도를 반환합니다. 계정 한도는 제공자 간 공유하므로 전환으로 우회하지 않습니다. 한도 오류 30분, 요청 제한 60초, 키/모델 오류 10분, 기타 오류 30초 동안 해당 제공자·키를 쉬게 합니다. 화면에는 실제 제공자와 모델, 답변 출처를 표시합니다. 캐시에는 답변·토큰 수·만료 시각만 저장하며 만료 행은 다음 요청 때 덮어씁니다.

## SQL과 저장 결과

sql/migrations는 번호 순으로 적용하며 적용된 파일을 변경하지 않습니다. checksum 이력·트랜잭션·advisory lock으로 중복 적용을 방지합니다. 일반 PostgreSQL에서는 앱과 migrator 계정을 분리하며 앱 계정은 DB 구조를 변경하지 못합니다. 역할별 권한은 `npm run db:grant`로 부여합니다. Prisma Postgres는 `DATABASE_PROVIDER=prisma-postgres`와 별도 migration 경로를 사용하며 제공자 계정의 SQL 역할 분리는 지원하지 않습니다. 앱의 SQL 보조 검사는 DB 권한 격리를 대신하지 않습니다. 자세한 제약은 [보안 정책](SECURITY_POLICY.md)을 참고하세요. 자동 down migration은 미구현입니다.

동일 계정의 같은 HTTPS 원점은 ID를 유지한 채 결과·진단 시각을 갱신합니다. 다른 계정은 별도 결과를 저장합니다. 006(Prisma 002) migration은 계정·도메인 복합 유일성 및 개인 이벤트를 추가하며 기존 결과의 소유자를 보존합니다. DB 유일성 제약으로 동시 요청도 중복을 만들지 않습니다. 003 migration은 기존 중복의 최신 결과를 남기고 이전 행은 앱이 읽을 수 없는 scan_duplicate_archive에 보관합니다. 진단 결과와 성공 감사 이벤트는 함께 저장합니다.

## 보안 경계와 미구현

- 비밀번호 scrypt+salt, 256-bit 세션, DB의 세션 해시, 8시간 만료, HttpOnly/SameSite=Strict 쿠키. HTTPS APP_ORIGIN에서는 Secure를 사용합니다. 로그아웃은 세션을 폐기합니다.
- 변경 API의 정확한 Origin 검사, 4KiB JSON 본문 제한, 파라미터 DB 쿼리, 역할별 접근 제한을 적용합니다.
- SSRF는 HTTPS/443/원점 제한, 전체 DNS 응답의 공개 unicast 검사, 검증 IP로 연결 고정, 원래 호스트의 TLS 인증서 확인, 리디렉션 미추적, DNS/요청 timeout으로 방어합니다. 승인 전용 모드에서는 정확한 도메인 allowlist도 적용합니다. 운영에서는 egress 방화벽도 필요합니다.
- **진단과 개인 이벤트는 로그인 계정별로 분리합니다.** 조직/팀별 공유·권한 위임·가입 승인·실제 자산 소유 확인은 미구현입니다. 관리자용 IP 차단 목록은 운영 정보로 별도 유지합니다. DB RLS/사용자별 DB를 제공하는 격리는 아닙니다.
- 이메일 인증·비밀번호 찾기·MFA/SSO·관리자 권한 변경 UI는 미구현입니다.
- SQLi/XSS 공격 검증, 포트 스캔, TLS 전체 프로토콜·암호군 등급, 인증서 폐기 조회, 브라우저 CSP 실행 검증은 미구현입니다. 현재는 공개 루트 HEAD 응답 한 번에 대한 정적 기본 검사입니다. 로그인 후·다른 경로·GET·모바일 비교 진단은 하지 않습니다.
- 외부 사이트 트래픽 수집, WAF, 봇/AI 판정, 더미 사이트 이동·실시간 알림은 미구현입니다. 이 허브의 정해진 URL 공격 패턴만 IP 차단합니다. `/decoy`는 제한된 이벤트 기록 후 404로 종료합니다. 공격자 신원 역추적이나 역공격은 하지 않습니다.
- 언어는 수동 선택 → 브라우저 언어 → 인증된 게이트웨이의 국가 힌트 → 기본 언어 순서입니다. 로컬에서 실제 IP 국가를 조회하지 않습니다.
- CSP는 Next.js/MUI 호환을 위해 inline을 허용합니다. 운영 nonce CSP, HTTPS/HSTS 프록시, 백업·복원 검증, 이벤트 보존·정리 스케줄러는 추가 작업입니다.

실제 .env 파일은 Git에서 제외됩니다. **.gitignore는 OneDrive 동기화를 막지 않습니다.** 공개 운영 시 비밀은 동기화 밖의 비밀 저장소나 프로세스 환경변수로 주입하세요. work/의 테스트 DB, 로그와 빌드 결과도 업로드하지 않습니다. 선택적 compose.yaml은 별도 로컬 DB용이며 기존 DB를 사용한다면 실행하지 않아도 됩니다.

## 검증

### 등록 계정의 비밀번호가 맞지 않을 때

DBeaver에서 실제 운영 DB를 확인하려면 [운영 Prisma 연결 안내](docs/DBEAVER_PRODUCTION.md)를 참고하세요. 웹 주소와 DB 주소, DB 접속 계정과 웹 로그인 계정은 서로 구분됩니다.

웹 로그인 비밀번호는 PostgreSQL 계정 비밀번호나 DATABASE_URL과 별개입니다. 등록된 이메일이라도 입력한 비밀번호가 저장된 해시와 맞지 않으면 401을 반환합니다. 같은 이메일로 다시 가입해도 기존 비밀번호는 변경하지 않습니다.

프로젝트 폴더의 직접 열린 터미널에서 `npm run user:password:production -- 계정이메일`을 실행하면 기존 Prisma 계정의 비밀번호를 복구할 수 있습니다. 로컬 DB는 `npm run user:password -- 계정이메일`입니다. 각 명령은 Git 제외 migration 환경 파일의 관리용 DB 연결을 사용합니다. 새 비밀번호(14~128자)를 두 번 입력하며 화면에 표시하거나 파일·명령 인자로 저장하지 않습니다. `#` 등 특수문자도 그대로 입력합니다. 성공 시 기존 세션과 해당 계정 로그인 제한을 초기화하고 감사 이벤트를 남깁니다. 계정 ID·역할·진단 기록은 유지하며 존재하지 않는 계정을 새로 만들지 않습니다. 브라우저의 이메일 인증 기반 비밀번호 찾기는 별도 미구현입니다.

2026-10-17 기준 단위·회귀 테스트 **72개**, 타입 검사, production 빌드, HTTP smoke, 6개 언어 검사와 임시 PostgreSQL 통합 검사가 통과했습니다. 브라우저에서 로그인·진단 버튼·실제 진단·저장 결과·개선안 토글·주소 초기화·다운로드 JSON을 확인했습니다. npm 보안 감사의 보고된 취약점은 0개였습니다. 외부 AI는 모형으로 검사했고 실제 LLM 토큰은 사용하지 않았습니다. 파일별 범위·수정 사항·제약은 [검토 기록](docs/PHASE1_REVIEW.md)에 있습니다.

`npm run share`는 선택적 PC 개발용 도구입니다. 정식 Vercel 배포·로그인에는 사용하지 않습니다. 과거 `PC_APP_ORIGIN` 이동 설정은 제거했습니다.

`npm test`, `npm run typecheck`, `npm run build`를 사용합니다. 실제 HTTP 서버 검증은 `npm run test:smoke`, `npm run test:locale`입니다. `npm run test:integration`은 PostgreSQL native 도구로 임시 loopback DB를 생성해 검사합니다. 기본 PG_BIN은 `C:/Program Files/PostgreSQL/15/bin`이며 기존 운영 DB는 사용하지 않습니다. 테스트용 API는 로컬 모형으로 대체합니다.

실행 중인 개발 캐시를 보존하려면 PowerShell에서 `$env:WEBGUARD_VERIFY='true'` 후 build 및 start 기반 검증을 실행하면 `.next-verify`를 사용합니다. 작업 후 해당 환경변수를 제거하면 기본 `.next`로 돌아갑니다.
