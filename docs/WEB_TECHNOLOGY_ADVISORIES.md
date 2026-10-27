# 웹 기술 흔적과 공식 보안 권고 대조

규칙 검토일: 2026-10-27. 카탈로그 `2026-10-27.1`, web.compare 모듈 1.1.0. 기존 루트 HEAD/TLS 요청의 응답만 사용한다. 추가 경로 열거·취약점 공격·서버 부하 유발·코드 실행은 하지 않는다. 정식 사이트에 자동 배포하지 않았다.

## 관찰과 판정

PHP, Next.js/React RSC, Django/Python, Spring/Java, Java servlet, ASP.NET/.NET, Rails/Ruby, Node.js/Express, Go의 **명시적 응답 헤더 흔적**을 분류한다. JavaScript/TypeScript를 서로 구분하거나 실제 백엔드 언어를 확정하지 않는다. CDN·프록시·위조 헤더·숨김 기술·여러 서비스 구성으로 실제 서버와 다를 수 있다. 2xx가 아닌 응답에서는 제품을 판정하지 않는다. 충돌/불완전/벤더 접미 버전은 유효 패치 버전으로 추정하지 않는다.

임의 배너·쿠키 값·호스트·경로는 저장하지 않는다. 고정 제품/언어 분류와 제한된 숫자 버전만 저장한다. 원래 웹 기본 진단과 전용 PC/모바일 웹 작전실 양쪽에 반영한다.

| 규칙 | 대조 근거 | 판정 한계 |
|---|---|---|
| PHP2Shell CVE-2026-109618 / CVE-2026-109619 | [PHP 공식 공지](https://www.php.net/archive/2026.php), [PHP Foundation](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 미만인 해당 분기 숫자 버전에 warning. 공급자 백포트와 실효 패키지는 별도 확인. 이전/새로운 미등록 분기는 미검사 |
| React2Shell CVE-2025-55182 | [React 공식 공지](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) | Next.js/RSC 흔적은 구성요소 버전 증명이 아니므로 applicability 미검사. 프런트엔드 React 전체를 RSC 취약점으로 판정하지 않음 |
| Django CVE-2025-64459 | [Django 공식 공지](https://www.djangoproject.com/weblog/2025/nov/05/security-releases/) | 4.2.26 / 5.1.14 / 5.2.8 미만인 해당 분기 버전은 검토 경고. 실제 쿼리 구성/입력 경로 미확인 |
| Spring4Shell CVE-2022-22965 | [Spring 공식 공지](https://spring.io/security/cve-2022-22965/) | 5.2.20 / 5.3.18 미만인 해당 분기 버전은 검토 경고. JDK·WAR·Tomcat·의존성 조건 미검증 |
| .NET/Ruby/Node.js/Go/Java servlet 일반 흔적 | 고정 제품 식별만 지원 | 제품별 모든 CVE 대조는 미구현이며 미검사 표시. Java 흔적만으로 Spring을 확정하지 않음 |

분기 내 수정 버전 이상은 참고(info)이며 안전(pass)을 부여하지 않는다. 조건·버전 미확인은 not_assessed이며 기술 흔적 자체를 취약점으로 확정하지 않는다. 모든 결과에 관찰 범위 미검사 항목이 남는다. 침해 여부나 PHP2Shell 공격 성공을 검사하는 기능이 아니다.

## 유지보수와 남은 범위

이것은 검토된 소규모 카탈로그이며 실시간/전체 CVE 피드가 아니다. 새 권고·수정 범위는 공식 출처를 재확인하고 경계값 테스트와 catalogVersion을 함께 갱신해야 한다. 정식 사이트에 원본 코드·키·환경변수를 수집하지 않는다. 숨겨진 언어/버전·전체 의존성을 정확히 확인하려면 소유 서버의 배포 목록/SBOM 및 인증된 별도 수집 경로가 필요하며 이번에 구현한 것으로 간주하지 않는다.

검증: PHP 네 분기의 수정 경계, 버전 없음/벤더 접미/미등록 분기/충돌, 오류·리디렉션 응답, 비밀 배너 미보관, Next.js를 RSC 버전으로 오인하지 않음, Django/Spring 경계, 다른 언어의 미검사 보존. 모의 DNS/HTTPS 전송에서 실제 scanner → PC/모바일 엔진까지 PHP2Shell 경고 4개(프로필별 2개)를 대조했다. 실제 취약 서버에 공격하지 않았다.
