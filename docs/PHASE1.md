# 1단계 구현 범위

기준: `prompt.md` 13절의 1주 차. 기존 프로젝트 구조, 계정·역할, PostgreSQL 연결과 SQL migrations, SSRF 방어, 기본 결과 화면에 웹 정적 진단을 보강합니다. 이 문서의 완료 범위는 공개 웹의 비인증 기본 검사이며 전체 취약점 감사가 아닙니다.

## 검사 항목

| 항목 | 구현된 기본 검사 | 한계 |
|---|---|---|
| CSP | 강제 정책 유무, default/script 제한, 광범위한 script 소스·unsafe 지시자, object·base·frame 제한 | 복수 정책 교집합, nonce/hash/strict-dynamic, 브라우저 실행·우회 여부는 수동 검토. Report-Only는 강제 정책으로 인정하지 않음 |
| HSTS | max-age 숫자·중복·따옴표 구문, 180일 미만 검토 표시, includeSubDomains 관찰 | 180일은 이 앱의 기본 검토 기준. 하위 도메인·preload 자동 권고나 등록 확인은 하지 않음 |
| nosniff | 값이 nosniff인지 확인 | 실제 본문 Content-Type과 브라우저 동작 미검사 |
| Referrer-Policy | 알려진 토큰 중 마지막 유효 정책, 상세 URL 노출 가능 정책 표시 | HTML meta·개별 요소·브라우저 구현 미검사 |
| TLS·인증서 | 플랫폼 신뢰 체인·호스트명 검증, TLS 1.2 이상 연결, 협상된 버전, leaf 만료일과 30일 이내 만료 안내 | 인증서 검증 실패 시 연결 종료, 무검증 재시도 없음. 전체 구형 버전 지원·암호군·OCSP/CRL·CT 등급 미검사 |
| 쿠키 | 관찰된 Set-Cookie의 Secure·HttpOnly·SameSite, __Secure-/__Host- 접두사 및 Partitioned 조건, 중복 속성 | 인증 여부를 알 수 없어 HttpOnly 미설정은 검토 항목. 쿠키 미관찰은 안전이 아니라 확인 불가. 최대 32개 검사 후 초과 안내 |
| CORS | 예약 시험 출처에 대한 Allow-Origin·Credentials·Vary 응답, 잘못된 조합 | 공개 * 허용 자체는 취약점 아님. 단일 시험으로 출처 반사·인증 데이터 유출·프리플라이트 안전성을 입증하지 않음 |
| 정보 노출 | Server·X-Powered-By·X-AspNet-Version 존재 관찰 | 식별 헤더만으로 취약점 확정하지 않으며 원문 제품명·버전 저장하지 않음 |

## 요청·보관 경계

- 공개 HTTPS 원점의 루트 `/`, 포트 443, HEAD **1회**만 요청합니다. 기본 공개 모드는 사용자 소유·진단 허가 선언을 받고 사전 등록을 요구하지 않습니다. 승인 전용 모드는 별도 선택할 수 있습니다. `Origin: https://webguard-probe.invalid`를 보내 CORS 응답을 관찰합니다. 로그인·쿠키·자격증명을 보내지 않으며 응답 본문 수집·크롤링·리디렉션 추적·추가 요청은 없습니다.
- SSRF 방어를 유지합니다: 전체 DNS 공개 IP 검증, 검증한 IP로 고정 연결, 원래 호스트 인증서 검증, 최소 TLS 1.2, DNS 3초·요청 5초 제한, 응답 헤더 최대 16KiB. 운영망 egress 차단은 별도 운영 구성입니다. Hub 자체에 들어오는 위험 요청의 IP 차단은 [접속 보호 명세](ACCESS_DEFENSE.md)와 구분합니다.
- 2xx가 아닌 리디렉션/오류/HEAD 미지원 응답은 TLS 외 항목을 확인 불가로 표시합니다. 애플리케이션의 정상 페이지 보안 정책으로 해석하지 않습니다.
- 쿠키 이름·값·Domain/Path 원문과 전체 응답 헤더를 DB·진행 로그·다운로드·AI에 남기지 않습니다. 속성 플래그·쿠키 번호·정해진 정책 분류와 인증서 날짜만 저장합니다.
- 기존 `checks`와 함께 JSONB `assessmentVersion: 2`, `assessment`를 저장합니다. DB 스키마 변경이 없어 추가 migration이 필요하지 않습니다. 이전 결과는 재진단 안내를 표시하며 임의 보정하지 않습니다.
- 같은 도메인의 최신 결과 덮어쓰기, 실패 시 이전 결과 보존, 실시간 단계 로그와 JSON 다운로드를 유지합니다. 상세 결과도 다운로드에 포함됩니다.
- 규칙 개선안은 외부 API 없이 제공하며 각 항목에서 접고 펼칩니다. 기존 AI는 **헤더 4종의 존재 여부만** 전달받는 보조 안내입니다. 새로운 상세 결과를 AI가 분석했다고 표시하지 않습니다.

## 3단계 일정에서 현재 위치

1단계의 실행 가능한 공개 웹 기본 진단 범위를 구현했습니다. 인증·권한·DB·migrations·SSRF 방어·기본 진단 엔진·결과 화면이 연결되어 있습니다. Vercel 정식 배포와 Prisma DB·기존 계정 이전도 완료했습니다. 모든 공격에 대한 안전 보증을 의미하지 않습니다. 현재 단일 조직용이므로 회원별 자산 격리, 이메일 인증·계정 복구, 백업 복원·부하·장애 대응 검증은 남아 있습니다. 2026-10-17의 전체 검토 결과는 [PHASE1_REVIEW.md](PHASE1_REVIEW.md)를 참고하세요.

2단계의 PC/모바일 비교, 로그인 후 검사, 개선 전후 비교, 외부 트래픽 수집과 3단계의 WAF·봇 대응·격리형 허니팟은 별도 작업입니다. 전체 진단 이력과 정식 보고서 또한 미구현입니다.

## 규칙 참고 자료

- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [MDN: HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [Node.js: TLS](https://nodejs.org/api/tls.html)

보안 헤더 정책에 대한 보수적인 기본 규칙이며, 표준 전체를 구현한 파서나 취약점 확정 엔진으로 취급하지 않습니다.
