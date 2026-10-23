# 프로젝트별 PostgreSQL 관리

하나의 PostgreSQL 서버(localhost:5432)를 쓰되 프로젝트·환경마다 DB, migration 계정, 앱 계정, migration 이력을 분리합니다. DBeaver는 이 연결들을 한곳에서 관리합니다.

| 항목 | WebGuard 개발 환경 | 다음 프로젝트 예시 |
|---|---|---|
| DB | webguard_hub_dev | portfolio_dev |
| 구조 변경 전용 계정 | webguard_hub_dev_migrator | portfolio_dev_migrator |
| 앱 실행 전용 계정 | webguard_hub_dev_app | portfolio_dev_app |
| SQL 기준 | 이 프로젝트 sql/migrations | 해당 프로젝트 sql/migrations |
| migration 이력 | 각 DB의 schema_migrations | 각 DB에서 별도 보관 |

운영 환경은 `_prod` 등으로 별도 분리합니다. 다른 프로젝트는 각각 자체 권한 목록을 작성해야 하며 WebGuard의 테이블 권한을 그대로 적용하면 안 됩니다. 기존 프로젝트 DB/계정에는 이번 설정을 자동 적용하지 않습니다.

## 지금 DBeaver에서 할 일

1. 현재 `postgres` 관리자 연결에서 `sql/setup/00_create_roles.sql`의 DO 블록 전체를 실행합니다.
2. Auto-commit을 켠 상태로 `01_create_database.sql`의 CREATE DATABASE 한 문장만 실행합니다.
3. `02_restrict_database.sql`의 두 문장을 실행합니다.
4. 연결을 새로고침하고 Roles에서 새 migrator/app 계정에 서로 다른 비밀번호를 설정합니다. SQL 파일/채팅에 비밀번호를 적지 않습니다.
5. 기존 연결을 유지한 채 DBeaver에 새 PostgreSQL 연결 2개를 추가합니다. 둘 다 host localhost, port 5432, database webguard_hub_dev. 하나는 migrator 계정, 다른 하나는 app 계정입니다.
6. DBeaver 폴더를 `WebGuard / DEV`로 만들고 두 연결 이름을 `WebGuard DEV - migration`, `WebGuard DEV - app`으로 구분합니다. `postgres` 관리자 연결은 관리 작업에만 사용합니다.

앞서 안내한 `webguard_hub` 계정/DB를 이미 만들었다면 지우거나 재사용하지 않아도 됩니다. 이번 설정은 별도 이름으로 만들며 이름이 이미 있으면 중단합니다. 기존 데이터 이전은 자동 수행하지 않습니다.

## 프로젝트 설정

[환경 설정 안내](CONFIGURATION.md)에 따라 `.env.local`에 PROJECT_DATABASE·PROJECT_RUNTIME_ROLE과 app 계정 DATABASE_URL을 설정합니다. `.env.migration.local`에는 별도 migration 계정 URL 및 최초 앱 사용자 생성 값을 설정합니다. 환경 예제도 Git에서 제외하며 migration 자격증명은 앱 환경 파일에 넣지 않습니다. 두 파일은 OneDrive 동기화 밖에서 관리하는 것이 권장됩니다. Git 제외는 동기화를 막지 않습니다.

`npm run db:migrate` → `npm run db:grant` → `npm run user:create` 순서입니다. 사용자 생성 후 BOOTSTRAP_PASSWORD를 지웁니다. migration 이후 필요한 새 테이블 권한은 명시적으로 grant 도구에 추가합니다. 미래의 모든 테이블에 일괄 권한을 부여하지 않습니다.

`npm run dev`는 app 계정을 사용합니다. 프로젝트 DB 이름과 URL의 DB가 다르면 연결을 거부합니다. migration 계정을 앱 실행에 넣는 것도 거부합니다.

연결 URL에서는 TLS용 `sslmode=require|verify-full`, `channel_binding=require`만 명시적으로 처리하며 DB·사용자·host 우회나 중복 옵션을 거절합니다. 외부 DB는 인증서를 검증하는 TLS를 사용합니다. Prisma의 별도 프로필과 권한 제약은 [Vercel 배포](VERCEL_DEPLOYMENT.md)를 참고하세요.

## 경계와 기존 프로젝트

이 DB에서는 PUBLIC 접속을 제거하고 전용 역할만 허용합니다. 기존 다른 DB의 PUBLIC CONNECT 권한은 바꾸지 않으므로 서버 전체의 완전한 상호 격리까지 자동으로 완료한 것은 아닙니다. 기존 DB도 담당 계정과 사용 현황을 확인한 뒤 개별적으로 같은 정책을 적용해야 합니다. PostgreSQL superuser는 모든 DB를 관리할 수 있습니다. 더 강한 자원/관리자 격리가 필요하면 서버/클러스터도 분리합니다.

참고: https://www.postgresql.org/docs/15/ddl-priv.html
