# 다국어와 IP 국가 정보

지원 언어: 한국어(ko), English(en), 日本語(ja), 简体中文(zh), Español(es), Français(fr). 중국어는 간체 번역입니다. 미지원 언어는 기본 영어로 표시하며 DEFAULT_LOCALE로 지원 언어 중 기본값을 지정할 수 있습니다. 모든 국가/언어 번역을 제공하는 것은 아닙니다.

적용 범위: 최초 HTML lang·페이지 제목·로그인·입력 검증·진단 화면·역할/이벤트/헤더 설명·날짜/숫자·API 오류·없는 경로·AI 개선안 출력 언어. 서비스명, 도메인, HTTP 상태값과 기술 식별자는 번역하지 않습니다. AI 제공자·모델은 서버 설정을 사용하며 자동 모드는 Groq → Gemini → 기본 안내입니다. 번역을 위해 외부 번역 API를 호출하지 않습니다.

선택 순서: 사용자의 언어 선택(wg_locale 쿠키) → 브라우저 Accept-Language의 지원 언어(q값 순서) → 신뢰된 게이트웨이의 IP 국가 힌트 → 기본 언어. 사용자가 직접 고른 언어를 국가로 덮어쓰지 않습니다. 국가 코드는 언어 추정의 보조 정보이며 국적/실제 언어를 확정하지 않습니다. 지원되지 않는 국가를 모두 영어권으로 분류하는 것도 아닙니다. 국가 매핑이 없으면 기본 언어로 돌아갑니다. 국가 정보를 인증·권한·차단 판단에 사용하지 않습니다.

쿠키는 언어 코드만 저장하며 HttpOnly/SameSite=Lax/Path=/, 유효기간 1년입니다. HTTPS 앱 origin이면 Secure가 붙습니다. 변경 API는 같은 Origin과 JSON/4KiB 입력 제한을 적용합니다. 쿠키가 위조되어도 지원하는 언어 코드 외의 값은 무시합니다.

## 현재 로컬 환경

localhost/127.0.0.1은 방문자의 국가를 식별할 수 있는 공개 IP가 아닙니다. 현재는 브라우저 언어와 수동 선택으로 작동합니다. IP를 외부 조회 서비스에 전송하거나 IP 위치 DB를 다운로드하지 않았습니다. 실제 IP 국가 판별은 공개 배포 시 신뢰된 IP 위치 제공자의 연동이 필요합니다.

## 공개 배포 시 IP 국가 힌트 연결

Cloudflare 등 IP 위치를 판별하는 게이트웨이가 실제 요청의 국가 코드(예: KR, JP)를 서버에 전달하도록 설정합니다. 예를 들어 Cloudflare의 IP Geolocation은 CF-IPCountry 헤더를 제공합니다. 원본 서버가 직접 인터넷 요청을 받지 않도록 제한하고 HTTPS 게이트웨이 연결을 구성하세요.

서버 환경 변수:

~~~dotenv
DEFAULT_LOCALE=en
GEOIP_COUNTRY_HEADER=cf-ipcountry
GEOIP_PROXY_SECRET=
~~~

GEOIP_PROXY_SECRET에는 게이트웨이와 앱 서버만 아는 32~256자의 무작위 비밀을 배포 환경에서 주입합니다. 게이트웨이는 외부에서 들어온 x-webguard-geo-token과 국가 헤더를 제거/덮어쓰고, 자체 IP 위치 판별 결과와 x-webguard-geo-token: <같은 비밀>을 원본 서버로 보냅니다. 비밀을 브라우저 응답이나 공개 코드에 넣지 않습니다. 국가 헤더 이름이 다르면 GEOIP_COUNTRY_HEADER로 지정합니다. 일부 Worker/다른 origin 경로에서는 CF-IPCountry 전달 방식이 달라질 수 있으므로 게이트웨이에서 확인된 국가 값을 별도 헤더에 명시적으로 설정하세요.

비밀이 없거나 짧거나 토큰이 일치하지 않으면 국가 헤더를 무시합니다. 사용자 제공 X-Forwarded-For, X-Real-IP만으로 국가를 판별하지 않습니다. XX/T1 등 미확인 국가는 무시합니다. 현재는 실제 게이트웨이나 도메인이 설정되어 있지 않아 이 연동은 활성화하지 않았습니다. 게이트웨이 환경은 이 기능을 사용할 배포에서 별도로 구성·검증해야 합니다.

개인정보: 이 기능 자체는 원본 IP나 국가 코드를 저장하거나 외부 API로 전송하지 않습니다. API는 선택된 언어와 선택 원인만 반환합니다. 사용자별 오류/언어 응답은 no-store이며 언어별 오류에 Content-Language와 안정적인 errorCode를 함께 제공합니다. 내부 예외나 DB 오류 원문을 번역해 노출하지 않습니다.

## 검증

npm test에 언어 사전 완전성, q값·지역 태그, 수동 선택 우선순위, 잘못된 쿠키, 지원 밖 언어, 위조 국가 헤더 차단, 인증된 국가 힌트, 번역된 오류를 포함합니다. 브라우저/HTTP 확인은 별도 테스트에서 수행합니다. 번역은 초기 제품 번역으로, 정식 공개 전 각 언어의 사용자 검토를 권장합니다.

공식 참고: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Language

공식 참고: https://developers.cloudflare.com/network/ip-geolocation/
