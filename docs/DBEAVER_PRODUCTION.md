# DBeaver에서 운영 PostgreSQL 연결하기

현재 Vercel 앱의 데이터는 외부 Prisma Postgres에 있습니다. Vercel 웹 주소 대신 해당 DB의 직접 연결을 사용합니다. 기존 localhost 연결은 보존하고 새 연결을 추가하세요.

1. DBeaver → 새 데이터베이스 연결 → PostgreSQL을 선택합니다.
2. 연결 방식(Connect by)을 URL로 선택합니다.
3. URL에는 `jdbc:postgresql://db.prisma.io:5432/postgres?sslmode=require`를 입력합니다.
4. 프로젝트의 Git 제외 파일 `.env.migration.production.local`을 로컬 편집기로 열고 `MIGRATION_DATABASE_URL`의 사용자명과 비밀번호를 각각 Username/Password에 입력합니다. 파일이나 전체 URL을 채팅에 보내지 마세요.
5. Test Connection을 누르고 드라이버 설치가 필요하면 PostgreSQL 드라이버를 설치합니다. 성공하면 완료를 누릅니다.
6. 연결 이름은 `WebGuard 운영 Prisma`처럼 로컬 연결과 구분되게 저장합니다.

직접 연결의 구성은 `postgresql://USER:PASSWORD@db.prisma.io:5432/postgres?sslmode=require`입니다. 호스트는 db.prisma.io, 포트는 5432, DB 이름은 postgres, SSL 모드는 require입니다. USER/PASSWORD는 Prisma가 발급한 값이며 로컬 postgres 계정이나 WebGuard 로그인 이메일/비밀번호가 아닙니다. URL에 퍼센트 인코딩된 문자가 있다면 개별 입력란에는 원래 값을 사용합니다. 예: 비밀번호의 `%23`은 `#`입니다. 앱의 pooled.db.prisma.io 설정은 바꾸지 않습니다.

접속 후 `Databases → postgres → Schemas → public → Tables`에서 users·scans·events·sessions 등을 확인할 수 있습니다. 다음은 등록 여부만 확인하는 읽기 쿼리입니다.

```sql
SELECT email, role FROM public.users
WHERE email = '확인할이메일';
```

이 연결은 실제 운영 DB이므로 수정은 서비스 데이터에 직접 반영됩니다. 웹 비밀번호 변경은 password_hash에 평문을 입력하지 말고 README의 `user:password:production` 관리 명령을 사용하세요. 기존 역할·결과를 유지하고 비밀번호 해시/세션/감사 기록을 함께 처리합니다.

출처: [Prisma 공식 DBeaver 연결 안내](https://www.prisma.io/docs/guides/postgres/viewing-data#2c-connect-to-prisma-postgres-using-dbeaver).
