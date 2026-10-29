# 실행 파일·모바일 패키지 점검

별도 웹 소스 검사(2026-10-28): 웹 작전실에서 PHP/JS/TS/JSX/TSX/SQL 및 지원 JSON 파일 한 개를 최대 64 KiB까지 명시적 동의 후 서버 메모리로 보내 정적으로 검토한다. 실행 파일·모바일의 아래 크기/원본 검증 방식과는 별도다. 소스·결과는 저장하지 않고 수신 UTF-8 해시만 현재 결과에 표시한다. SQL 사용 단서와 부족 자료는 [웹 검토 범위](WEB_TECHNOLOGY_ADVISORIES.md)를 따른다.

최신 2026-10-27 서버 원본 검증·수신 텍스트 해시 범위는 이 문서 마지막 추가 절을 우선한다.

2026-10-20. `/workbench`의 파일 모듈에서 사용합니다. 긴 설명은 화면의 두 안내 토글에 들어 있습니다.

## 사용자 절차와 읽기 허용

2026-10-22 보완: 파일 없이 점검하면 파일 선택 오류, 빈 파일은 빈 파일 오류를 표시합니다. 선택만으로 읽지 않고 미동의 파일은 점검하지 않습니다. Worker 시작/실행 실패는 손상 파일과 별도로 안내합니다. 결과에는 warning 개수와 미검사 개수를 함께 표시합니다. 검증용 파일은 배포하지 않으며 선택한 실제 파일 대신 자동 샘플을 검사하지 않습니다. [검증 근거](PRODUCTION_REVIEW_2026-10-22.md)를 참고하세요.

1. Windows·macOS·모바일 모듈과 파일을 선택합니다. **선택만으로 파일 내용을 읽지 않습니다.**
2. 선택한 파일을 이번 검사에서 읽는 데 동의한 다음 `허용한 파일 점검`을 누릅니다. 브라우저 Worker에서 읽습니다. 취소하면 Worker를 종료합니다. 파일·모드·모듈 변경, 로그아웃 시 허용과 요약을 초기화하며 허용은 저장하지 않습니다.
3. 전송될 요약을 펼쳐 확인합니다. 별도의 소유/진단 허가 확인 뒤 `요약 전송·결과 저장`을 누를 때만 요약을 서버로 보냅니다. 파일 이름·경로·원문은 요약에 포함하지 않습니다. 자산 이름에는 비밀을 넣지 마세요.

이는 선택한 File 객체를 읽는 앱 내 동의입니다. OS 전체 디스크·폴더 접근 권한, 브라우저 보안 우회나 영구 접근 권한을 요청하지 않습니다. 서버·LLM에 원본을 올리지 않습니다. 기존 APK 2 MiB 서버 모드는 원본을 전송하는 별도 기존 기능이며 화면에 이를 표시합니다.

## 지원 범위

| 대상 | 실제 확인 | 미검사 |
|---|---|---|
| Windows EXE/DLL | PE32/PE32+ ASLR·NX 선언, W+X 섹션, 인증서 테이블 관찰 | 전체 내용 무결성, 로더 동작, 악성코드, MSI |
| macOS Mach-O/Universal·dylib | 실행 파일 PIE 선언, 실행 스택 요청, W+X 세그먼트, 서명 명령 관찰 | 실제 대상 OS 확정, 전체 앱·의존성, 서명·공증 신뢰, DMG/PKG |
| Android APK | ZIP 목록, 제한된 바이너리 AXML의 명시적 debuggable·allowBackup·usesCleartextTraffic, 요청 권한 수 | 리소스 해석, 기본값, 네트워크 예외 정책, 권한 필요성·실제 승인, exported, 서명·DEX 취약점 |
| iOS IPA | Payload 앱 구조, 제한된 XML/binary Info.plist의 명시적 NSAllowsArbitraryLoads | ATS 예외 전체, entitlement·provisioning, 코드·서명·설치 가능성 |
| Android AAB | base Manifest 위치와 패키지 목록 | protobuf Manifest 해독, 배포 APK 생성·설정·서명 |
| Android APKS/XAPK | toc.pb/manifest.json과 내부 APK 목록 | 중첩 APK 해제·설정·서명 |

확장자만 신뢰하지 않고 내부 형식을 검사합니다. 지원하지 않거나 손상된 파일은 거절하고, 읽지 못한 설정은 기본값으로 추측하지 않고 미검사로 남깁니다. ZIP 목록/헤더 관찰은 CRC·전체 무결성 검증이나 설치 가능한 패키지라는 보증이 아닙니다.

macOS `.app`은 폴더입니다. 브라우저에서는 패키지 내용 보기 → Contents → MacOS의 실행 파일 하나를 선택합니다. 앱 전체 경로를 이용한 OS 서명 검사는 아래 로컬 도구를 사용합니다. Mach-O 형식만으로 macOS용임을 독립 증명하지 않습니다.

## 대용량과 제한

- 파일 최대 8 GiB. 브라우저는 헤더/명령/중앙 목록을 범위별로 읽으며 읽기 총량 최대 8 MiB, ZIP 중앙 목록 최대 4 MiB/50,000개, Mach-O 최대 16슬라이스/4,096명령입니다. 파일 전체를 arrayBuffer/base64로 만들지 않습니다.
- 모바일 설정 파일은 압축 전후 각 1 MiB 이하, 압축 비율 제한, 해제 출력 상한을 적용합니다. 파일 시스템으로 해제하거나 중첩 패키지를 실행하지 않습니다. ZIP64·분할·암호화 ZIP은 지원하지 않습니다. 큰 모바일 패키지가 ZIP64를 사용하면 8 GiB 이하라도 거절됩니다.
- Worker가 20초 안에 끝나지 않으면 중단합니다. 기기 메모리·브라우저의 deflate-raw 지원에 따라 설정 해독은 미검사가 될 수 있습니다.
- 브라우저는 전체 파일 해시를 계산하지 않습니다. 원본을 서버가 보지 않으므로 결과는 **변경 가능한 자기 보고**이며 독립 검증·원격 증명이 아닙니다. 정상 관찰도 `참고`로 표시하고, 원본 검사와 비교 가능한 서버 안전 판정을 만들지 않습니다.

## 선택형 로컬 심화 도구

Node.js 20 이상이 설치된 Windows/Mac에서 `/tools/executable-inspector.mjs`를 내려받아 내용을 확인한 뒤 실행합니다. 별도 패키지를 설치하지 않습니다.

```powershell
node executable-inspector.mjs "C:\Apps\example.exe" "windows-report.json" --consent --native
```

```sh
node executable-inspector.mjs "/Applications/Example.app" "mac-report.json" --consent --native
```

- `--consent` 없이는 읽기 검사를 시작하지 않습니다. 지정한 파일의 제한된 구조 검사와 주 실행 파일의 전체 SHA-256 계산에 동의하는 옵션입니다. 해시는 1 MiB씩 읽으며 큰 파일은 오래 걸릴 수 있습니다.
- `--native`는 별도 선택 옵션입니다. Windows에서는 Get-AuthenticodeSignature, Mac에서는 codesign·spctl과 일부 서명 표시 정보를 조회합니다. OS 신뢰/폐기 확인 서비스에 네트워크 조회가 생길 수 있습니다. 원본을 우리 서버에 자동 전송하지 않습니다.
- 대상 파일 실행·설치, 디스크 이미지 마운트, 보안 설정 변경, 인증서 설치는 하지 않습니다. 시스템 도구의 고정 경로와 별도 인자/환경 변수를 사용합니다. 파일 경로를 셸 코드에 삽입하지 않습니다.
- Mac `.app`은 Info.plist가 지정한 주 실행 파일을 읽고 해당 경로가 앱 내부인지 확인합니다. 파일 해시는 **주 실행 파일만** 해당하며 앱 전체 해시가 아닙니다. 서명은 앱 경로를 대상으로 확인합니다. Gatekeeper 허용을 별도 공증 검증 완료로 표시하지 않습니다.
- OS/도구 불일치·실패·판정 불명은 미검사입니다. 로컬 결과는 사용자 제공값이며 유효 서명도 악성코드 없음의 증명이 아닙니다. 결과에 경로·파일명·서명자 개인정보·명령 원문을 넣지 않습니다.
- 파일이 검사 중 바뀌면 거절하고 기존 결과 파일을 덮어쓰지 않습니다. 생성된 JSON(최대 64 KiB)을 `로컬 결과 가져오기`에서 선택하고 읽기 허용 후 확인·저장합니다. 이 도구는 Windows/macOS 실행 파일용이며 모바일 서명 심화 도구는 아직 제공하지 않습니다.

## DB·운영

일반 PG `008_local_file_inspection.sql`, Prisma `004_local_file_inspection.sql`은 자산 모듈 허용 목록만 확장합니다. 계정·기존 실행·원문을 변경하지 않습니다. 새 실행은 기존 계정별 저장·조회 권한을 따릅니다. 서버는 요약 필드·형식·범위·출처를 다시 검사하고 임의 경로·원문·추가 속성을 거절합니다. 자산 이름은 여전히 사용자 입력입니다.

원본 저장소·분할 업로드·격리된 서버 분석기·실행 샌드박스·백신 엔진·자동 수정은 추가하지 않았습니다. 대용량 파일 전부가 분석되는 것으로 표현하면 안 됩니다.

## 기준 문서

- [Microsoft PE 형식](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows 서명 조회](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
- [Apple Mach-O 정의](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [Apple 코드 서명](https://developer.apple.com/library/archive/technotes/tn2206/)
- [Android application 설정](https://developer.android.com/guide/topics/manifest/application-element)
- [Apple NSAllowsArbitraryLoads](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads)
# 2026-10-27 추가: 파일 입력과 결과의 연결 검증

실행 파일·모바일 패키지에 선택형 **서버 원본 검증** 모드를 추가했다. 별도 원본 전송 동의 후 저장할 때 최대 2 MiB 전체 바이트를 서버로 보내며 서버가 제한된 파서를 다시 실행하고 SHA-256/바이트 수를 결과에 기록한다. 원본은 앱 DB에 저장하거나 실행하지 않는다. 클라이언트 snapshot·검증 표시를 함께 보낸 요청은 거절한다. OS 서명 신뢰·악성코드 부재·기기의 다른 파일과의 동일성은 검증하지 않는다.

기존 원본 미전송/로컬 JSON은 유지하되 `unverified-summary`로 표시한다. 일반 회원의 참고용 저장은 가능하지만 서버 원본 검증 결과로 승격하지 않는다. 과거 검증 메타데이터 없는 파일 결과도 미검증으로 표시한다. 검증 방식이 다르면 개선/악화를 자동 비교하지 않는다.

Linux SSH·Windows 정책·VMX·GNS3 파일/붙여넣기는 기존 서버 분석에 수신 UTF-8 텍스트의 SHA-256/바이트 수를 연결한다. 텍스트 디코딩·개행·BOM에 따라 로컬 파일 바이트와 다를 수 있으므로 `received-utf8-text`로 구분한다. 기존 APK 서버 예비 점검도 수신 파일 바이트 해시를 기록한다. 모든 표시는 서버가 부여하며 요청에서 integrity 필드는 수락하지 않는다. 기존 원본 미전송 설명은 브라우저/로컬 요약 모드에 해당한다.

## 2026-10-29 단일 파일 정책 — 로컬 검증본

모든 파일 선택 경로는 한 번에 최대 1개다. 여러 파일이 전달되면 처음 것만 처리하지 않고 선택/동의/결과를 초기화해 오류를 표시한다. 서버의 배열·배치 입력도 거절한다. 각 모드의 크기 제한·읽기 허용·원본 전송 여부는 기존과 같다. 로컬 검증을 완료한 변경이며 [검토 보고서 30절](PROJECT_REVIEW_2026-10-27.md)을 따른다.
