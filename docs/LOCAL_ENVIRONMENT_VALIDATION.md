# 현재 Windows·VMware 환경 검토 — 2026-10-22

기준 소스: `83096b2`. 기존 Markdown 문서와 구현을 대조하고 현재 PC에서 회귀 검증을 다시 수행했다. **1단계 완료·2단계 진행 중**을 유지한다. 아래 결과는 과거 PC의 DB/브라우저 검증을 이번 PC에서 재현했다고 뜻하지 않는다.

## 환경과 보존 범위

| 항목 | 이번 확인 |
|---|---|
| 현재 체크아웃 | `D:\gun\새 폴더\webguard-security-hub` |
| 이전 개발 경로 | prompt.md의 OneDrive 경로는 이전 PC의 경로이며 이번 실행 경로와 구분 |
| 의존성 | 처음에는 node_modules와 npm이 없었음. 제공된 pnpm으로 npm 실행기를 사용해 `npm ci --no-audit --no-fund` 수행. package.json/package-lock.json 변경 없음 |
| 실행 버전 | Node.js 24.19.0 / 설치된 Next.js 16.4.2 |
| 로컬 DB | 사용자가 SQL을 설정하지 않았다고 확인. PostgreSQL 기본 도구 경로와 실제 환경 파일도 없음. DB·계정·migration을 새로 만들지 않음 |
| VMware | `123_Kali 26.1` 실행 및 로그인된 데스크톱, VMware Tools running 확인 |
| 게스트 메타데이터 | VMware가 보고한 Kali GNU/Linux 2026.1, kernel 6.18.12+kali-amd64. 게스트의 `/etc/os-release`로 독립 대조하지 못함 |
| 다른 VM | Ubuntu 22.04, Debian 11.6 등 라이브러리 등록 확인. 실제 부팅·버전·설정 검증은 하지 않음 |
| Tera Term | 설치 확인. 사용자 설명은 SSH/root. 두 차례 열린 창 목록에는 해당 세션이 나타나지 않음 |

기존 화면·검사 엔진·인증·보호 기능·SQL migration은 수정하지 않았다. 운영 DB 쓰기·계정 생성/권한 변경·배포·SSH 서비스 변경/재시작·파일 실행은 수행하지 않았다. 검증 빌드는 `.next-verify`, 로컬 산출물은 Git 제외 `work/`에 분리했다. Next.js의 설치 문서(custom server, distDir, TypeScript)와 관리 블록 생성 파일을 확인했다.

## 이번에 실행한 검증

| 검사 | 결과·범위 |
|---|---|
| 전체 단위·회귀 | package.json의 test에 지정된 10개 파일, 94개 모두 통과 |
| production 빌드 | `WEBGUARD_VERIFY=true`, `next build --webpack` 통과. 검사 선택·전용 작전실·API·Proxy 포함 |
| 독립 타입 검사 | 빌드 완료 후 `tsc --noEmit` 통과 |
| 보안 HTTP smoke | 화면·보안 헤더·미인증 거절·위조 Origin 거절 통과 |
| 언어 HTTP smoke | 6개 SSR 언어·가입 화면·번역 오류·언어 선택 유지·위조 국가 헤더 거절 통과 |
| Linux 합성 대조 | 기존 엔진 직접 호출: 검토 필요 5개 경고, 개선 복사본 5개 통과, 전후 개선 5개, Include 사례 5개 미검사 |
| Windows 실제 파일 | 기존 로컬 도구로 이 PC의 `C:\Windows\System32\notepad.exe`를 읽기 전용 점검. PE64, 360448 bytes, W+X 섹션 0개, SHA-256 생성. 대상 실행·업로드 없음 |
| Windows 요약 처리 | 생성 JSON을 기존 application.pe 입력 검증·결과 생성에 통과시킴. 파일명/경로 비포함, 구조 관찰은 info, 서명 unknown은 not_assessed 확인 |

HTTP smoke 두 개는 처음 샌드박스에서 서버 Ready 후 loopback 요청 대기가 실패했다. 동일 빌드와 스크립트를 허용된 외부 실행으로 재검증해 통과했다. 이를 제품 코드 결함으로 판정하거나 보호 설정을 완화하지 않았다.

Windows의 `--native` 실행 결과는 샌드박스 안팎 모두 `signature=unknown`이었다. 별도 상태 조회는 실행 승인이 거절되어 수행하지 않았다. **서명 검증 성공으로 기록하지 않는다.** 로컬 결과는 `work/windows-notepad-20261022.json`, `work/windows-notepad-native-20261022.json`에 있으며 파일이 Git 제외이므로 다른 체크아웃에 자동 전달되지는 않는다.

Linux 합성 검사의 실제 필드는 `moduleVersion=1.0.0`, `ruleVersion=2026-10-19.1`이었다. 모듈 버전과 규칙 버전을 혼동하지 않는다. OpenSSH의 첫 명시값 우선 규칙과 Include/Match 한계는 [공식 설명](https://man.openbsd.org/sshd_config)을 대조했다. 합성 결과는 실제 Kali 설정·유효 정책·저장 이력 검증을 대신하지 않는다.

## 정식 서비스의 읽기 전용 확인

공식 주소의 첫 `/api/ready` 조회에서 `not_ready / DATABASE_CONNECTION_OR_PERMISSIONS_FAILED` 응답을 관찰했다. 후속 조회에서 `/api/health`는 HTTP 200/up, `/api/ready`는 HTTP 200/READY, `permissionModel=provider-managed`로 회복했다.

단일 실패의 근본 원인은 확인하지 못했다. 로컬 SQL 미설치는 Vercel의 외부 Prisma DB와 별개다. 기존 2026-10-19 보호 DB 시간 초과와 같은 원인이라고 확정하지 않는다. 반복 시 해당 시각의 Vercel/DB 고정 오류 로그를 별도로 대조해야 한다. 이번에는 실제 계정 로그인·운영 결과 저장·AI 호출을 수행하지 않았다.

## 실제 Kali 검증의 남은 조건

1. VMware 화면 관찰은 가능했지만 입력 시도에 파일 관리자가 열리지 않아 자동 조작을 계속하지 않았다.
2. VMware Tools의 게스트 주소로 사용자가 알려 준 root SSH 연결을 한 번 시도했다. 서버에 도달했으나 현재 실행 환경의 키·에이전트 인증은 `Permission denied (publickey,password)`로 거절됐다. 비밀번호 추측·인증 설정 변경은 하지 않았다. 호스트 키는 Git 제외 `work/kali-known-hosts`에 보관했다.
3. 따라서 OpenSSH 실제 버전, 실제 sshd_config, Include/Match의 실제 존재, 유효 정책과 결과 대조는 **미검증**이다. SSH/root라는 접속 정보만으로 로그인 권한을 확보했다고 보지 않는다.
4. 인증된 읽기 경로 또는 사용자가 제공한 허가된 검토용 설정 복사본이 확보되면 [기존 실환경 절차](REMOTE_ENVIRONMENT_VALIDATION.md)를 이어간다. 비밀번호·개인키를 채팅이나 문서에 적지 않는다.

로컬 PostgreSQL 통합, 실제 다른 기기 세션·계정 분리, Kali 브라우저의 로그인→진단→저장→재조회, macOS OS 도구·실물 모바일 검증도 이번에는 수행하지 않았다. 기존 자동/운영 검증 이력은 보존하되 이번 실환경 완료 체크로 옮기지 않는다.
