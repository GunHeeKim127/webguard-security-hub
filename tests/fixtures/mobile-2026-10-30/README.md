# 모바일 합성 검증 파일

실행·설치 불가능한 파서/브라우저 시험 입력입니다. 악성코드 샘플이나 정상 배포 앱이 아닙니다. 원본 앱이나 iOS 실기기 검증을 대체하지 않습니다.

- IPA vulnerable/remediated: Info.plist의 NSAllowsArbitraryLoads true/false. 경고 1→0을 기대하되 보완 후에도 안전 인증/통과로 표시하지 않습니다.
- AAB/APKS/XAPK vulnerable/remediated: 변형 이름 및 중첩 합성 APK 선언이 다릅니다. 현재 모듈은 목록만 검사하므로 두 파일 모두 설정·서명·중첩 앱은 미검사여야 합니다. AAB/toc.pb의 내용은 유효한 protobuf 빌드 산출물이 아닙니다.
- reject-*.ipa: 경로 탈출 ZIP 또는 확장자만 IPA인 텍스트로, 검사 실패 및 저장 비활성을 기대합니다.

로그인→Mobile→같은 자산 이름으로 취약 선언 파일 선택→읽기 동의→점검→별도 분석 동의→저장→보완 선언 파일로 반복→결과 비교→JSON 다운로드 순서로 확인합니다. 파일 선택/변경만으로 읽지 않아야 하며 취소하면 동의가 초기화돼야 합니다.

재생성: node node_modules/tsx/dist/cli.mjs scripts/generate-mobile-review-fixtures.ts. 기존 파일 내용이 다르면 덮어쓰지 않습니다. manifest.json에 SHA-256·기대 분석값을 기록합니다.
