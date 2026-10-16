# WebGuard Security Hub

승인된 웹사이트의 보안 헤더, 허브 접근 이벤트와 AI 개선안을 한 화면에서 확인하는 **단일 조직용 로컬 MVP**입니다. Next.js / TypeScript / MUI / PostgreSQL을 사용합니다. 전체 취약점 진단기나 외부 사이트의 WAF는 아직 아닙니다.

## 현재 가능한 일

- 이메일 회원가입·로그인·로그아웃, admin/analyst/viewer 권한 구분. 신규 가입자는 viewer입니다.
- 승인된 공개 HTTPS 원점의 헤더 4종(CSP, HSTS, X-Content-Type-Options, Referrer-Policy) 존재 여부 확인. 헤더 값의 적절성을 평가하지 않습니다.
- 실제 서버 단계가 전달되는 진단 작전실, 진행 단계 점멸, 주소 변경 시 현재 요청·화면 로그 초기화, JSON 로그 다운로드.
- 같은 도메인의 성공 결과를 최신 결과로 갱신. 실패하면 이전 저장 결과를 유지합니다. 상세 진행 로그는 브라우저에서만 보관합니다.
- API 호출 없는 기본 개선안. 선택한 경우에만 외부 AI를 요청하며 Groq → Gemini → 기본 안내로 전환합니다.
- 한국어·영어·일본어·중국어 간체·스페인어·프랑스어 UI와 오류 안내.
- 허브 자체의 로그인 실패·진단 거부·의심 경로·최소 디코이 접근 이벤트 확인. 외부 트래픽은 수집하지 않습니다.

기획 대비 구현 상태와 남은 작업은 [프로젝트 현황 분석](docs/PROJECT_STATUS.md), 실제 검증 기록은 [VALIDATION.md](VALIDATION.md)를 참고하세요.

## 로컬 시작

Node.js 20.9 이상과 PostgreSQL 15 이상이 필요합니다. DBeaver는 DB 관리 도구이며, Prisma 확장 설치만으로 ORM이 필요한 것은 아닙니다. 현재 구현은 pg와 SQL migration을 사용합니다.

1. [프로젝트별 DB 설정](docs/PROJECT_DATABASES.md)에 따라 sql/setup의 역할·DB 생성 스크립트를 순서대로 실행합니다. CREATE DATABASE는 Auto-commit에서 별도로 실행합니다. 기존 다른 프로젝트 DB는 변경하지 않습니다.
2. `npm ci`를 실행합니다.
3. `.env.example`을 `.env.local`, `.env.migration.example`을 `.env.migration.local`로 복사합니다. 이미 파일이 있으면 덮어쓰지 말고 새 항목만 추가합니다.
4. 앱 환경 파일에는 app 역할의 DATABASE_URL, migration 환경 파일에는 migrator 역할의 MIGRATION_DATABASE_URL을 입력합니다. URL의 비밀번호 특수문자는 percent encoding합니다.
5. `npm run db:migrate`, `npm run db:grant`를 실행합니다.
6. 최초 관리자는 migration 환경 파일의 BOOTSTRAP_EMAIL/PASSWORD/ROLE을 로컬에서 설정한 뒤 `npm run user:create`로 생성합니다. 비밀번호는 14~128자이며 생성 후 BOOTSTRAP_PASSWORD를 비웁니다.
7. `npm run dev` 후 http://localhost:3000 에서 로그인합니다. 이후 일반 사용자는 `/signup`에서 가입할 수 있습니다.

AI 키가 없어도 로그인·진단·무료 기본 개선안은 사용할 수 있습니다. ALLOWED_SCAN_HOSTS에는 소유하거나 진단 허가를 받은 도메인만 쉼표로 등록합니다. 기본 빈 목록은 모든 진단을 차단합니다. 입력창에 주소를 쓴 것만으로 승인되지는 않습니다.

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

sql/migrations는 번호 순으로 적용하며 적용된 파일을 변경하지 않습니다. checksum 이력·트랜잭션·advisory lock으로 중복 적용을 방지합니다. 앱과 migrator 계정을 분리하며 앱 계정은 DB 구조를 변경하지 못합니다. 역할별 권한은 `npm run db:grant`로 부여합니다. 자동 down migration은 미구현입니다.

같은 HTTPS 원점은 ID를 유지한 채 결과·최종 실행자·진단 시각을 갱신합니다. DB 유일성 제약으로 동시 요청도 중복을 만들지 않습니다. 003 migration은 기존 중복의 최신 결과를 남기고 이전 행은 앱이 읽을 수 없는 scan_duplicate_archive에 보관합니다. 진단 결과와 성공 감사 이벤트는 함께 저장합니다.

## 보안 경계와 미구현

- 비밀번호 scrypt+salt, 256-bit 세션, DB의 세션 해시, 8시간 만료, HttpOnly/SameSite=Strict 쿠키. HTTPS APP_ORIGIN에서는 Secure를 사용합니다. 로그아웃은 세션을 폐기합니다.
- 변경 API의 정확한 Origin 검사, 4KiB JSON 본문 제한, 파라미터 DB 쿼리, 역할별 접근 제한을 적용합니다.
- SSRF는 정확한 도메인 allowlist, HTTPS/443/원점 제한, 전체 DNS 응답의 공개 unicast 검사, 검증 IP로 연결 고정, 원래 호스트의 TLS 인증서 확인, 리디렉션 미추적, DNS/요청 timeout으로 방어합니다. 운영에서는 egress 방화벽도 필요합니다.
- **현재는 단일 조직용입니다. 회원가입한 viewer도 허브 전체의 진단 기록을 조회할 수 있습니다.** 외부 고객에게 공개하기 전 가입 승인·사용자/조직별 데이터 분리·자산 소유 확인이 필요합니다.
- 이메일 인증·비밀번호 찾기·MFA/SSO·관리자 권한 변경 UI는 미구현입니다.
- SQLi/XSS 공격 검증, 포트 스캔, TLS 등급, CSP 정책 내용 검증은 미구현입니다.
- 외부 사이트 트래픽 수집, WAF, 봇/AI 판정, 자동 차단·더미 사이트 이동, 알림·자동 보안 조치는 미구현입니다. 의심 경로와 `/decoy`는 제한된 이벤트 기록 후 고정 404로 종료합니다. 방문자의 자원을 소모시키지 않습니다.
- 언어는 수동 선택 → 브라우저 언어 → 인증된 게이트웨이의 국가 힌트 → 기본 언어 순서입니다. 로컬에서 실제 IP 국가를 조회하지 않습니다.
- CSP는 Next.js/MUI 호환을 위해 inline을 허용합니다. 운영 nonce CSP, HTTPS/HSTS 프록시, 백업·복원 검증, 이벤트 보존·정리 스케줄러는 추가 작업입니다.

실제 .env 파일은 Git에서 제외됩니다. **.gitignore는 OneDrive 동기화를 막지 않습니다.** 공개 운영 시 비밀은 동기화 밖의 비밀 저장소나 프로세스 환경변수로 주입하세요. work/의 테스트 DB, 로그와 빌드 결과도 업로드하지 않습니다. 선택적 compose.yaml은 별도 로컬 DB용이며 기존 DB를 사용한다면 실행하지 않아도 됩니다.

## 검증

`npm test`, `npm run typecheck`, `npm run build`를 사용합니다. 실제 HTTP 서버 검증은 `npm run test:smoke`, `npm run test:locale`입니다. `npm run test:integration`은 PostgreSQL native 도구로 임시 loopback DB를 생성해 검사합니다. 기본 PG_BIN은 `C:/Program Files/PostgreSQL/15/bin`이며 기존 운영 DB는 사용하지 않습니다. 테스트용 API는 로컬 모형으로 대체합니다.

실행 중인 개발 캐시를 보존하려면 PowerShell에서 `$env:WEBGUARD_VERIFY='true'` 후 build 및 start 기반 검증을 실행하면 `.next-verify`를 사용합니다. 작업 후 해당 환경변수를 제거하면 기본 `.next`로 돌아갑니다.
