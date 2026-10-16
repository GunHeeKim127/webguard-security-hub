-- 운영자 스케줄러에서 실행. 최소 30일 보존 정책 예시; 조직 정책에 맞게 조정.
DELETE FROM sessions WHERE expires_at < now();
DELETE FROM rate_limits WHERE reset_at < now() - interval '1 day';
DELETE FROM events WHERE created_at < now() - interval '30 days';
-- scans 보존/삭제는 별도 승인된 정책에 따라 운영자가 수행.
