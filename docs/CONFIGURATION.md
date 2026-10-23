# 로컬·운영 환경 설정

환경 설정 파일은 예제까지 Git에 올리지 않습니다. `.env*`, `env`, `env.*`, `*.env`, `*.env.*`는 모든 하위 폴더에서 제외합니다. 기존 로컬 파일은 보존하고 프로젝트 루트에 필요한 파일을 직접 만드세요.

로컬 앱 `.env.local`: `DATABASE_PROVIDER=postgresql`, `PROJECT_DATABASE=webguard_hub_dev`, `PROJECT_RUNTIME_ROLE=webguard_hub_dev_app`, 전용 app 계정의 `DATABASE_URL`, `APP_ORIGIN=http://localhost:3000`을 지정합니다. migration 파일 `.env.migration.local`은 같은 DB 이름과 별도 migrator 계정의 `MIGRATION_DATABASE_URL`을 사용합니다.

Prisma 운영 앱은 `DATABASE_PROVIDER=prisma-postgres`, `PROJECT_DATABASE=postgres`, `APP_ORIGIN=https://webguard-security-hub.vercel.app`, pooled.db.prisma.io의 `DATABASE_URL`을 Vercel에 설정합니다. 운영 migration은 로컬 `.env.migration.production.local`에 같은 제공자·DB 이름과 db.prisma.io의 `MIGRATION_DATABASE_URL`을 지정합니다. Prisma가 발급한 기존 연결 값을 사용하고 TLS 인증서 검증을 유지합니다. 직접 연결과 풀 연결을 혼동하지 마세요.

실제 비밀번호·연결 URL·API 키를 문서, Git, 채팅에 넣지 않습니다. 기존 파일은 자동 덮어쓰지 않습니다. 공개 가입과 본인 진단은 `PUBLIC_REGISTRATION_ENABLED=true`, `SCAN_TARGET_POLICY=public`으로 설정하며 외부 AI 활성화는 별도 운영 설정입니다. 30일 이관은 Vercel의 비밀 `CRON_SECRET`을 사용합니다.

2026-10-23: Git에 추적되던 환경 예제 5개도 추적 해제했습니다. 이는 현재 브랜치의 제거이며 공유 Git 이력을 강제 재작성하지 않습니다.
