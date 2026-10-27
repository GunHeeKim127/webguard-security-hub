# 2026-10-27 현재 PC 실환경 후속 검증

기준 소스: `e195d85`. 실행 환경: Windows 11 Pro 10.0.26200 / 64bit, Node 24.22.1. 관찰 시각은 observations.json의 UTC를 기준으로 하며 한국 시각은 +09:00이다. 과거 10/23 실습과 11절의 합성 검증을 오늘의 실환경 실행으로 재집계하지 않았다.

## 예상과 실제

| 대상 | 예상 | 실제 / 판단 |
|---|---|---|
| 자동 회귀 | 현재 구현의 회귀 없음 | 117/117 통과, 실패 0 |
| VMware | 설치 여부와 실행 여부 구분 | Workstation 16.1.2 build-17966106 설치. 초기 실행 VM 0대, 후속 조회 CentOS 1대, 이후 VM 프로세스 2개 관찰. 실행 상태는 시간에 따라 달라짐 |
| 실제 VMX 3개 | 명시 값만 평가 | 3개 모두 공유/복사/붙여넣기/드래그/VNC 5항목 not_assessed, 네트워크 info. 누락 기본값을 pass로 추정하지 않음 |
| GNS3 | 설치 버전과 파일 버전 별도 기록 | 서버 실행 파일 2.2.61. 기존 저장 프로젝트 2개: 2.2.55 / 2.2.61, 파서 모듈 1.0.1로 수용. 프로젝트 실행·ping은 이번에 하지 않음 |
| GNS3 미검사 경계 | 장비 정책/콘솔 누락은 미검사 | 두 프로젝트 모두 consoleBinding/devicePolicy not_assessed. 외부 노드 없음은 info이며 격리 증명이 아님 |
| 실제 Windows PE | 구조·서명 교차 확인 | OS 기본 PE 360448바이트, 64bit, W+X 0. 독립 Get-AuthenticodeSignature는 Valid. 로컬 도구 --native는 unknown, 엔진 local:signature는 not_assessed 유지 |
| Windows 서명 차이 | 도구 실패를 서명 성공으로 변경하지 않음 | 도구와 동일한 Windows PowerShell 자식 프로세스에서 Microsoft.PowerShell.Security 모듈 자동 로드 실패 재현. 권한 있는 재실행도 unknown. 실행 셸별 차이가 있으며 Windows 보안 설정을 변경하지 않음 |
| Windows 정책 exporter | 읽기 전용 내보내기 | 실행 정책으로 .ps1 차단. 결과 JSON 미생성. ExecutionPolicy Bypass/설정 변경 안 함 |
| Tera Term | 설치와 실제 접속 구분 | 4.80 설치. 초기 세션 미관찰 후 사용자 연결 완료 통보 및 Kali root SSH 창 제목을 프로세스에서 확인. 로그인 성공에 대한 게스트 명령 검증은 별도 |
| Linux CLI | 기존 인증 경로만 사용 | 동일 접속 대상에 BatchMode + StrictHostKeyChecking SSH 시도. Windows SSH known_hosts에 호스트 키가 없어 접속 전 중단. Tera Term 인증은 CLI에 자동 공유되지 않음 |
| 기타 플랫폼 | 없는 도구로 완료 처리 안 함 | WSL 실행 환경 미설치, 기본 Android SDK 없음. 실제 Mac/iOS/Android 검증 보류 |

## 근거와 재검증

- `observations.json`: 실제 로컬 파일을 현재 파서/엔진에 넣은 결과. 원본 경로·이름·UUID·계정·주소·SHA-256은 제외했다. VMX 3개와 GNS3 2개는 기존 파일이며 합성 fixture가 아니다.
- 전체 PE snapshot과 검증 보조 스크립트는 Git 제외 `work/`에만 보관. 입력 실행·설치·운영 사이트 업로드 없음.
- 재검증: 현재 소스의 테스트 목록 실행 → 승인된 파일을 로컬 도구 `--consent --native`로 새 출력 파일에 검사 → executableSnapshot 검증 → runAssessment 비교. 서명 unknown을 수동으로 valid로 바꾸지 않는다.
- Linux는 기존 콘솔에서 배포판/OpenSSH, `sshd -t` 종료 코드, `sshd -T`의 다섯 지원 지시어와 Include/Match 존재 여부를 확인해야 한다. 원본 Include/Match 검사는 미검사, 유효 다섯 값의 검토용 사본은 별도 근거로 대조한다. 사용자에게 읽기 전용 명령을 전달했으며 결과 대기 중이다.
- Tera Term 자동 명령 입력은 사용한 computer-use 스킬의 `Do not automate terminal applications` 규칙으로 수행하지 않았다. CLI 연결도 호스트 검증을 우회하지 않았다.

## 상태

| 분류 | 범위 |
|---|---|
| 구현 검증 완료 | 117개 회귀, 실제 VMX/GNS3 파일의 파서·엔진 처리, Windows PE 구조 및 unknown 보존 |
| 실환경 검증 완료 | 현재 Windows OS·도구 버전·VM 실행 상태·기존 저장 파일 관찰, 독립 Windows 서명 조회. 실효 정책 전체나 게스트 보안 완료를 뜻하지 않음 |
| 보류 | Linux sshd 실효 값/조건 비교, Windows 정책 export 및 자식 PowerShell 서명 모듈 문제, GNS3 격리 통신, 다른 기기 계정 저장·격리, Mac/모바일 실제 도구, R01 runtime/DB 원인, R02 제공자 권한·복구 |

**1단계 완료 / 2단계 진행 중.** 운영 DB 변경·배포·Git push를 수행하지 않았다.

## 후속: Kali 출력 수신

기록 2026-10-27 07:20:42 UTC / 16:20:42 KST. 사용자가 제공한 기존 SSH 콘솔 출력으로 Kali 2026.1 / OpenSSH_10.3p1 Debian-1 / OpenSSL 3.5.5, sshd -t 종료 0을 확인했다. 게스트 명령 실행 시각은 제공되지 않았다. 위 Linux 결과 대기 표기는 이 후속으로 갱신한다.

`linux-effective.json`에 비식별 근거를 추가했다. 유효 출력 다섯 값의 별도 검토용 사본을 현재 엔진으로 대조한 결과 PermitRootLogin yes / PasswordAuthentication yes / MaxAuthTries 6은 warning, PermitEmptyPasswords no / PubkeyAuthentication yes는 pass로 **경고 3개·통과 2개**가 기대와 일치했다. 별도 구성한 Include 경계 입력은 5개 모두 미검사였다. 원본 설정 파일 자체를 검사한 것으로 간주하지 않는다.

Linux 기본 유효 다섯 값 대조는 사용자 제공 실환경 출력 기반 완료, 원본 Include/Match 해석·sshd -T -C 조건별 출력·실제 인증·다른 기기 저장은 보류다. 설정 변경·SSH 재시작·운영 업로드는 없었다.

## 후속 기능 검증

검토 보고서 17~19절에 최신 계정 차단·마스킹·일반 회원 검증을 정리했다. member-services.json은 실제 임시 서비스의 회원 API 결과이며 토큰 원문은 포함하지 않는다. member-home.png / member-browser-result.png는 일반 회원, admin-masked-management.png / admin-reference-release-success.png는 별도 테스트 관리자 화면이다. server-original-browser.png는 별도 동의 후 서버 원본 검증 결과다. 운영 데이터/계정 변경이나 배포 증거가 아니다.
