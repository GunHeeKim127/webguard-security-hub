# Vercel 정식 배포

공식 주소는 **https://webguard-security-hub.vercel.app/** 입니다. 화면·로그인·진단 API는 Vercel에서 실행하고 PostgreSQL은 외부 관리형 DB에 연결합니다. PC를 끄더라도 Vercel과 외부 DB가 가동 중이면 서비스할 수 있습니다. 임시 PC 주소로 이동하지 않습니다. 과거 `PC_APP_ORIGIN` 변수는 사용하지 않으며 남아 있어도 무시됩니다.

현재 코드 준비와 실제 운영 연결은 구분합니다. **Production 환경변수 적용·재배포·로그인 확인 전에는 로그인 완료 상태가 아닙니다.** 로컬 `localhost:5432`를 Vercel에 넣으면 그 PC에 연결되지 않습니다. 웹 HTTPS 주소도 DB 주소가 아닙니다.

## 현재 선택한 Prisma Postgres

Prisma Postgres의 공식 TCP 연결은 기존 `pg` 라이브러리로 사용할 수 있으므로 Prisma ORM 전환은 필요하지 않습니다. 제공자가 발급한 자격증명을 사용하고 직접 연결과 풀 연결의 호스트를 구분합니다. [공식 연결 안내](https://www.prisma.io/docs/postgres/database/connecting-to-your-database).

실제 확인한 서비스는 별도 역할 생성과 GRANT/REVOKE를 거절합니다. 따라서 `DATABASE_PROVIDER=prisma-postgres`를 명시한 별도 프로필과 `sql/migrations/prisma-postgres/`를 사용합니다. **일반 PostgreSQL 프로필의 독립 앱 역할 격리는 이 프로필에 적용되지 않습니다.** 앱의 SQL 보조 검사는 자격증명 탈취 후 DB 접근을 막지 못합니다. [실제 권한과 대응 정책](../SECURITY_POLICY.md)을 참고하세요.

1. Git에서 제외된 `.env.migration.production.local`에 `DATABASE_PROVIDER=prisma-postgres`, `PROJECT_DATABASE=postgres`, `MIGRATION_DATABASE_URL=제공자의 직접 연결 URL`을 저장합니다. 직접 호스트는 `db.prisma.io`이며 실제 DB 이름이 다르면 그 이름을 사용합니다. `DIRECT_URL`도 직접 연결 변수의 대안으로 지원합니다.
2. `npm run db:setup:production`은 직접 URL의 호스트를 `pooled.db.prisma.io`로 바꾼 runtime 설정을 `.env.production.local`에 생성합니다. 기존 파일은 덮어쓰지 않으며 실제 비밀값을 출력하지 않습니다. TLS 인증서를 검증합니다. 역할 생성은 시도하지 않습니다.
3. `npm run db:migrate:production`을 실행합니다. 별도 Prisma 스키마를 적용하며 기존 일반 migration 이력과 혼합하지 않습니다. **Prisma에서는 `db:grant:production`을 실행하지 않습니다.**
4. 아래의 기존 계정 이전 절차를 사용합니다. 대상에 계정이나 결과가 있으면 복사를 거절합니다.
5. Vercel → 프로젝트 → Settings → Environment Variables → **Production**에 `.env.production.local`을 가져옵니다. `DATABASE_PROVIDER=prisma-postgres`, `PROJECT_DATABASE=postgres`, **풀 호스트의 `DATABASE_URL`**, 공식 `APP_ORIGIN`이 필요합니다. 이전 `PROJECT_RUNTIME_ROLE`은 이 프로필에서 사용하지 않습니다. migration 파일 자체는 올리지 않습니다.
6. 최신 커밋을 재배포한 뒤 `/api/ready`의 HTTP 200, `code: READY`, `permissionModel: provider-managed`와 실제 로그인을 확인합니다. 환경변수 수정만으로 기존 배포가 갱신되지는 않습니다.

샘플은 `deploy/prisma.vercel.env.example`입니다. 이후 1~2절은 **독립 SQL 역할을 지원하는 일반 PostgreSQL**을 선택했을 때만 적용합니다. Prisma에서는 위 순서를 사용하세요.

실제 풀 연결 검증에서 시작 매개변수 `statement_timeout`을 넣으면 upstream 연결 실패가 재현됐습니다. Prisma 앱 풀은 해당 매개변수를 보내지 않고 클라이언트 대기 제한 `query_timeout=5000`을 사용합니다. 이는 서버 쿼리 취소를 보장하지 않습니다. 일반 PostgreSQL의 서버 statement timeout은 유지합니다.

## 1. 외부 PostgreSQL 만들기

Vercel 프로젝트 → **Storage → Marketplace의 PostgreSQL(예: Neon)** 에서 이 프로젝트 전용 DB를 생성·연결합니다. 요금제·서비스 약관은 사용자가 확인하고 선택합니다. 기존 다른 프로젝트 DB를 재사용하거나 삭제하지 않습니다. DBeaver에도 새 연결로 추가해 관리할 수 있습니다.

제공자의 Connect 화면에서 **직접 연결용 owner URL**, DB 이름, 선택적으로 **pooler 호스트**를 확인합니다. 이 정보와 비밀번호·키는 채팅에 보내지 마세요. Marketplace가 자동으로 넣은 DB URL이 owner 계정이면 아래의 최소 권한 runtime URL로 교체해야 합니다.

일반 `DATABASE_PROVIDER=postgresql` 프로필은 SQL로 별도 역할과 권한을 만들 수 있는 PostgreSQL을 요구합니다. Prisma Postgres는 위의 명시적인 제공자 관리 프로필을 사용합니다. Prisma ORM·VS Code 확장과 Prisma Postgres 호스팅 서비스는 별개입니다.

## 2. PC에서 새 DB 준비

`deploy/migration.production.env.example`을 프로젝트의 `.env.migration.production.local`로 복사합니다. 기존 `.env.local`·`.env.migration.local`은 수정하지 않습니다.

- `PROJECT_DATABASE`: 새 외부 DB의 실제 이름. Neon 기본 예시는 `neondb`입니다.
- `PROJECT_RUNTIME_ROLE`: `webguard_hub_prod_app`.
- `MIGRATION_DATABASE_URL`: 제공자가 발급한 **직접 연결용 owner URL**. TLS 매개변수 `sslmode=require` 또는 `sslmode=verify-full`과 `channel_binding=require`를 지원합니다.
- `CLOUD_RUNTIME_HOST`: 같은 DB의 pooler 호스트가 있다면 호스트만 입력합니다. 없으면 비워 두며 직접 연결을 사용합니다.

이후 프로젝트 터미널에서 순서대로 실행합니다.

```powershell
npm run db:setup:production
npm run db:migrate:production
npm run db:grant:production
```

첫 명령은 별도 앱 역할과 무작위 비밀번호를 만들어 **Git에서 제외된 `.env.production.local`에만 기록**합니다. 기존 역할·파일이 있으면 덮어쓰지 않고 중단합니다. 비밀을 터미널에 출력하지 않습니다. Migration owner URL은 이 출력 파일에 포함되지 않습니다. 이후 두 명령은 기존 001~005 SQL migration과 최소 권한을 새 DB에 적용합니다. 앱 역할은 DB 소유·DDL·관리 권한이 없습니다.

## 3. 기존 계정과 결과 유지

새 DB가 비어 있을 때 실행합니다. 이 작업 중에는 PC의 회원가입·진단 입력을 잠시 멈추세요.

```powershell
npm run db:copy:production
```

기존 로컬 `webguard_hub_dev`의 계정 ID·이메일·비밀번호 해시·역할과 최신 진단 결과를 트랜잭션으로 복사합니다. **기존 비밀번호를 그대로 사용합니다.** 원본은 읽기 전용으로 보존하고 대상에 계정·결과가 있으면 덮어쓰지 않습니다. 기존 세션·차단 IP·AI 캐시·과거 이벤트는 이전하지 않으므로 다시 로그인해야 하며 과거 기록은 로컬에 남습니다. 10,000개를 넘는 계정/결과는 별도 백업·복원 검토가 필요합니다.

기존 계정을 이전하지 않고 새로 시작하려면 복사 명령을 실행하지 말고, `.env.migration.production.local`에 본인이 정한 `BOOTSTRAP_EMAIL`, `BOOTSTRAP_PASSWORD`, `BOOTSTRAP_ROLE=admin`을 입력한 뒤 `npm run user:create:production`을 실행합니다. 이 비밀번호도 채팅에 보내지 말고 완료 후 bootstrap 변수를 비웁니다.

## 4. Vercel Production 변수

프로젝트 → **Settings → Environment Variables → Production** 에 생성된 `.env.production.local`의 값을 설정합니다. `.env.local`의 localhost URL을 복사하지 않습니다.

| 변수 | 값 |
|---|---|
| `APP_ORIGIN` | `https://webguard-security-hub.vercel.app` |
| `PROJECT_DATABASE` | 새 DB의 실제 이름 |
| `DATABASE_PROVIDER` | Prisma는 `prisma-postgres`, 일반 PostgreSQL은 `postgresql` |
| `PROJECT_RUNTIME_ROLE` | 일반 PostgreSQL만 `webguard_hub_prod_app`; Prisma에서는 사용하지 않음 |
| `DATABASE_URL` | 생성 파일의 runtime URL. Prisma는 `pooled.db.prisma.io`, 일반 PostgreSQL은 별도 앱 역할 |
| `PUBLIC_REGISTRATION_ENABLED` | `false` — 기존 조직 계정만 사용 |
| `SCAN_TARGET_POLICY` | `public` |
| `AI_ENABLED` | 우선 `false` |
| `DEFAULT_LOCALE` | `ko` |

`MIGRATION_DATABASE_URL`·owner 비밀번호·`BOOTSTRAP_PASSWORD`는 Vercel에 올리지 않습니다. `TRUSTED_PROXY_IPS`, `WEBGUARD_PROXY_SECRET`, `GEOIP_PROXY_SECRET`은 로컬 프록시용이므로 Vercel에 복사할 필요가 없습니다. Preview에는 Production DB를 자동 공유하지 말고 별도 DB·변수·허용 출처를 지정하세요.

GitHub의 최신 main 커밋으로 **Redeploy**합니다. Framework는 Next.js, build는 `npm run build`입니다. `npm start`의 PC 전용 HTTP 서버를 Vercel에서 실행하지 않습니다. 코드의 `vercel.json`과 route 제한이 배포에 사용됩니다. Migration은 build에서 자동 실행하지 않습니다.

## 5. 확인

1. `/api/health`: 프로세스 생존 확인만 하며 DB 성공을 뜻하지 않습니다.
2. **`https://webguard-security-hub.vercel.app/api/ready`**: `status: ready`, `code: READY`와 HTTP 200이어야 합니다. localhost 설정·미적용 migration·권한·연결 실패는 고정 코드와 503으로 표시하며 URL·비밀번호·제공자 오류를 노출하지 않습니다.
3. 공식 주소에서 이전한 기존 계정으로 로그인하고 진단·결과 조회·로그아웃을 확인합니다. PC 전원을 끈 상태에서도 같은 주소를 확인합니다.

## 보안·실행 범위

- Vercel에서는 Next.js Node Proxy가 플랫폼 공식 IP 헤더를 사용해 DB의 5분 차단·블랙리스트를 적용합니다. IP가 없거나 보호 DB를 확인할 수 없으면 503으로 거절합니다. 로컬 서버에서는 이 헤더를 신뢰하지 않고 기존 소켓 IP 방어를 사용합니다.
- `pg` 풀은 인스턴스당 최대 2개, idle 5초와 Vercel 공식 `attachDatabasePool`을 사용합니다. 외부 연결은 인증서 검증을 끄지 않습니다. 제공자의 TLS 옵션을 추출한 뒤 DB/user/host 우회 매개변수는 거절합니다.
- 단일 조직용입니다. 회원별·고객별 데이터 격리, 가입 승인 UI, MFA·이메일 인증, 운영 백업 복원 훈련·부하 검증은 별도 작업입니다.

참고: [Vercel PostgreSQL](https://vercel.com/docs/postgres), [Vercel 연결 풀](https://vercel.com/kb/guide/efficiently-manage-database-connection-pools-with-fluid-compute), [node-postgres SSL](https://node-postgres.com/features/ssl), [Neon 역할·권한](https://neon.com/docs/manage/roles).
