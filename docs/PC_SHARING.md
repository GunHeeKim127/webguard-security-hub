# PC를 켠 동안 외부 접속

## Vercel 고정 주소를 입구로 사용

Vercel 프로젝트의 **Settings → Environment Variables**에 아래 변수를 **Production** 범위로 추가하고 **Redeploy**합니다.

```dotenv
PC_APP_ORIGIN=https://현재-공유-주소.trycloudflare.com
```

실제 값은 `npm run share` 출력 또는 로컬 `work/share-url.txt`의 전체 HTTPS 주소입니다. Vercel `/`와 `/signup`에서 해당 PC 주소로 임시 이동합니다. **주소창은 PC 공유 주소로 바뀌며 실제 로그인과 DB 처리는 PC에서 수행합니다.** Vercel 주소를 유지하는 역방향 프록시는 아닙니다. API·쿠키·비밀번호를 Vercel에서 PC로 전달하지 않습니다. 기존 Vercel 로그인 화면은 새로고침해야 이동합니다.

PC의 `.env.local`에 있는 `DATABASE_URL`은 기존 localhost PostgreSQL 그대로 유지합니다. Vercel의 `DATABASE_URL`에 PC의 localhost를 넣어도 PC에 연결되지 않으며, 이 이동 방식은 Vercel DB 연결을 사용하지 않습니다. 기존 Vercel 변수를 삭제하거나 비밀번호를 바꿀 필요는 없습니다. `APP_ORIGIN`은 Vercel에서는 Vercel HTTPS 주소, 로컬에서는 localhost 주소로 유지합니다.

PC 공유를 다시 실행해 주소가 바뀌면 `PC_APP_ORIGIN`도 새 주소로 수정하고 Redeploy해야 합니다. PC 종료·절전 또는 공유 종료 시 도착한 사이트에 접속할 수 없습니다. `PC_APP_ORIGIN`을 비우고 재배포하면 일반 Vercel 앱 모드로 돌아가며 그 모드에는 별도의 접근 가능한 DB가 필요합니다.

상시 호스팅 대신 현재 Windows PC의 PostgreSQL·계정을 그대로 사용합니다. PC 종료·절전·인터넷 끊김·공유 프로그램 종료 시 외부 접속이 중단됩니다. DBeaver를 열어 둘 필요는 없지만 PostgreSQL 서비스는 실행되어야 합니다.

프로젝트 터미널에서:

```powershell
npm run share
```

프로덕션 빌드를 만든 뒤 `External HTTPS address:` 뒤의 주소를 휴대폰·다른 PC에서 엽니다. 같은 계정으로 각각 로그인할 수 있으며 한 기기의 로그아웃이 다른 기기의 세션을 종료하지 않습니다. 로컬 개발 서버 `http://localhost:3000`도 계속 사용할 수 있습니다. 외부 주소의 쿠키는 별도이므로 외부에서 다시 로그인해야 합니다.

프로그램을 종료하려면 해당 터미널에서 **Ctrl+C**를 누릅니다. 다시 실행하면 주소가 바뀌므로 새 주소를 전달해야 합니다. 현재 주소는 Git에서 제외된 `work/share-url.txt`에도 기록됩니다. 이 파일에 주소가 있어도 프로그램이 종료되었다면 접속되지 않습니다. 자동 시작이나 Windows 서비스는 설치하지 않습니다.

HTTP로 접속하면 같은 주소·경로의 HTTPS로 자동 이동합니다. HTTPS 응답에는 해당 호스트에만 적용되는 하루 HSTS를 설정하며 로그인 쿠키의 Secure·출처 검증을 유지합니다. 다른 컴퓨터에서도 최신 주소를 사용해야 합니다. HTTPS 로그인 요청이 403이면 공유 터미널에 출처의 프로토콜·호스트와 목적지 호스트만 기록합니다. 이메일·비밀번호·쿠키·요청 본문은 기록하지 않습니다.

중계기만 수정했고 현재 `.next-verify` 빌드를 재사용하려면 `npm run share -- --skip-build`를 사용할 수 있습니다. 앱 코드를 변경했다면 기본 명령으로 다시 빌드하세요.

## 접속 구조

Cloudflare 임시 HTTPS 주소 → 이 PC의 loopback 중계기 → IP 방어가 적용된 프로덕션 WebGuard → 기존 로컬 PostgreSQL입니다. 공유기 포트 포워딩·인바운드 방화벽 개방·DB 외부 공개는 하지 않습니다. 최초 연결에는 외부 통신이 필요합니다.

연결 도구는 공식 Cloudflare 2026.10.1 Windows x64 실행 파일입니다. 최초 다운로드와 매 실행 때 SHA256 `4d2490e74082c5d48dbfedaf92576fa5bd1702379ab88eb7faa0cfbe8dc891b6`를 확인합니다. 실제 비밀은 코드에 넣지 않으며 중계 인증용 난수는 매 실행 생성하여 자식 서버의 환경변수로만 전달합니다. `.env.local`은 바꾸지 않습니다.

중계기는 발급된 Host만 허용하고, Cloudflare의 `CF-Connecting-IP`를 정규화한 뒤 자체 인증 헤더를 덮어씁니다. 임의 XFF·사용자 제공 WebGuard 인증 헤더는 신뢰하지 않습니다. guard 서버는 loopback 중계 IP와 난수 비밀이 일치할 때만 전달 IP를 채택합니다. 일반 로컬 개발 서버는 기존 소켓 IP 방식을 유지합니다. 이 PC에 이미 접근 가능한 다른 로컬 프로그램까지 격리하는 보안 경계는 아닙니다.

현재는 단일 조직의 공유 대시보드이므로 **외부 공유 서버의 회원가입은 비활성화**합니다. 기존 계정은 기존 권한 그대로 사용합니다. 신규 계정은 로컬에서 준비하세요. 외부 화면에 회원가입 폼이 표시되더라도 서버가 가입 요청을 거부합니다. 고객별 데이터 분리와 가입 승인 UI는 미구현입니다.

## 범위와 한계

- 임시 주소는 공개 인터넷에서 접근할 수 있습니다. 주소를 아는 사람에게 로그인 화면이 보이며 HTTPS는 Cloudflare에서 종료됩니다. 계정 접근 제어와 기존 IP 방어를 유지합니다.
- Quick Tunnel은 테스트·개발용으로 가용성 보장이 없고, 주소가 매 실행 바뀌며 동시 처리 제한이 있습니다. SSE·WebSocket은 지원 대상으로 삼지 않습니다. 현재 진단은 NDJSON HTTP 응답을 사용합니다.
- 국가 정보는 이 공유 프로필에서 별도 신뢰하지 않습니다. 수동 선택·브라우저 언어·기본 언어가 적용됩니다.
- 현재 로그인 시도 제한은 계정 단위입니다. 대규모 서비스용 보호·고정 주소·상시 운영은 별도 작업입니다.
- 재빌드 중인 `.next-verify`를 다른 검증 서버가 사용하지 않도록 공유 프로그램을 먼저 종료하세요.

근거: [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/), [Cloudflare 요청 헤더](https://developers.cloudflare.com/fundamentals/reference/http-headers/).
