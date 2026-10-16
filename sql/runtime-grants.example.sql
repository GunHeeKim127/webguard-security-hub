-- 운영 migration 소유자로 실행. 로그인 계정 생성/비밀번호는 비밀 관리 도구로 별도 처리.
-- webguard_runtime 역할이 이미 존재한다고 가정하며 실제 비밀을 이 파일에 넣지 않습니다.
GRANT CONNECT ON DATABASE webguard TO webguard_runtime;
GRANT USAGE ON SCHEMA public TO webguard_runtime;
GRANT SELECT ON users TO webguard_runtime;
GRANT SELECT, INSERT, DELETE ON sessions TO webguard_runtime;
GRANT SELECT, INSERT ON scans, events TO webguard_runtime;
GRANT SELECT, INSERT, UPDATE ON rate_limits TO webguard_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO webguard_runtime;
-- 런타임 역할은 테이블/스키마 소유자가 아니어야 하며 SUPERUSER/CREATEDB/CREATEROLE 권한 금지.
