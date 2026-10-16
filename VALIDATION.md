# 검증 기록 — 2026-10-16 (Asia/Seoul)

## 개발환경

| 구성 | 확인 결과 |
|---|---|
| 지정 projects 경로 | 접근 가능; 새 webguard-security-hub 생성, 기존 3개 프로젝트 보존 |
| Node.js / npm | 20.9.0 / 10.1.0; 현재 프로젝트 빌드 가능 |
| Next.js / React / MUI | lockfile에 실제 설치 버전 고정; Next.js 16.4.2 |
| PostgreSQL | 15.2 설치 및 postgresql-x64-15 서비스 실행 중 |
| PostgreSQL 도구 | initdb, pg_ctl, postgres, psql 설치 확인; PATH에는 없음 |
| DBeaver | 실행 파일 및 번들 Java 11 확인; 실제 GUI 로그인 미검증 |
| VS Code | 설치 확인, CLI 버전 1.142.0 |
| Prisma | VS Code 확장 prisma.prisma-31.12.15 설치 확인; 전역 CLI 없음; 이 프로젝트는 pg/SQL 방식이므로 추가 불필요 |
| Git | 설치 확인; 이 작업에서 init, commit, push 하지 않음 |
| Docker | 20.10.24 CLI 설치, 엔진 미실행; 로컬 PostgreSQL 경로에는 불필요 |
| OpenAI 키 | 요청·조회·저장하지 않음; 실제 외부 API 호출 미검증 |

기존 PostgreSQL 5432 포트는 0.0.0.0 / :: 에서 LISTEN 중입니다. Windows 방화벽이나 외부 노출 여부까지 판정한 것은 아닙니다. 다른 프로젝트가 사용할 수 있어 서비스/리스닝 설정을 변경하지 않았습니다. 외부 공개 전 이 DB의 접근 정책을 확인하세요.

## 통과한 검증

- `npm test`: 11개 통과. SSRF IP 범위, URL 우회, salt 비밀번호, 역할, CSRF, JSON 본문 제한, 탐색 경로, 혼합 DNS 거부, DNS 연결 pinning, 리디렉션 미추적.
- `npm run typecheck`: 통과.
- `npm run build`: Webpack 프로덕션 빌드 통과. Windows 링크 생성 제한 때문에 Turbopack 대신 Webpack을 기본 명령에 명시.
- `npm run test:smoke`: 실제 프로덕션 HTTP 서버의 화면·보안 헤더·비로그인 접근·변경 요청 Origin 검사 통과.
- `npm run test:integration`: 별도 임시 PostgreSQL 15.2에서 migration 적용/재실행, 계정 생성, 로그인, 세션 해시 저장, viewer 권한 거부, 메타데이터 SSRF 거부, 키 없는 AI 비활성화, 허니팟/탐색 기록, 로그인 제한, 세션 만료, 로그아웃 폐기 통과.
- 패키지 설치 시 npm audit: 알려진 취약점 0개 보고. 이는 애플리케이션 전체의 무결점 보장이 아님.

최종 지정 경로에서도 build, 보안 테스트 11개, HTTP smoke, PostgreSQL 통합 검증을 통과했습니다. 통합 검증에 사용한 DB는 기존 5432 서버와 별도의 loopback 임의 포트였으며 테스트 후 종료했습니다. 테스트 암호는 실행 중 메모리에서만 생성했고 실제 서비스 자격증명을 읽지 않았습니다. 테스트 데이터는 각 테스트 실행 폴더의 무시된 work/에 남으며 소스 ZIP에는 포함하지 않습니다.

## 아직 수행하지 않은 검증/설정

- 사용자 운영 DB 전용 계정/DB/권한 생성 및 .env.local 구성. 기존 DB 비밀번호를 추측하거나 다른 프로젝트의 비밀을 읽지 않음.
- 사용자가 승인한 실제 외부 도메인 진단. 테스트에서는 외부 대상에 네트워크 요청하지 않음.
- 실제 OpenAI 모델/키로 API 응답 확인. 서버 측 호출 코드는 구현하되 기본 비활성.
- DBeaver GUI에서 운영 DB 접속, 브라우저의 대화형 조작/시각 QA, 공인 HTTPS 배포.
- README에 명시한 MFA, 실시간 WAF/외부 트래픽 연동, 자동 차단 등 운영 기능.

`README.md`의 로컬 DB 연결 및 계정 생성 절차를 완료하면 앱의 인증된 화면을 사용할 수 있습니다. 현재 프로젝트는 비밀키 없는 소스 상태로 제공됩니다.
