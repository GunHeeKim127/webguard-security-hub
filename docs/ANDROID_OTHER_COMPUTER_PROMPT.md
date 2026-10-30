# Android 완료 범위와 다른 PC의 후속 작업 — 2026-10-30

최신 전체 인계는 [PROGRESS_HANDOFF_2026-10-30.md](PROGRESS_HANDOFF_2026-10-30.md)다. Android 작업을 처음부터 다시 진행하라는 이전 프롬프트를 현재 지시로 사용하지 않는다. **실제 APK/가상 브라우저/합성 사용자 흐름은 확인된 범위에서 완료했고 2단계 전체는 진행 중**이다.

## 완료한 내용

| 항목 | 현재 상태 | 근거/제한 |
|---|---|---|
| 실제 APK 2개 명시 설정/권한 수 | 독립 대조 완료 | APK Analyzer/AAPT2와 파서 일치. 모든 Manifest/서명/실행은 아님 |
| 실제 APK A 사용자 흐름 | 완료 | 일반 회원 선택·읽기 동의·검사·별도 동의·저장·조회·다운로드·재검증 |
| Android Chrome 실제 파일 검사 | 가상 Android 16·Chrome 133 완료 | 실물 Android 완료는 아님 |
| 파일 변경/읽기 동의 취소 | 초기화 확인 | 큰 파일 실행 중 취소 경합은 별도 |
| PC 같은 계정·타 계정 | 교차 확인 완료 | 같은 자산 조회, 타인 404·빈 목록 |
| IPA/AAB/APKS/XAPK 합성 파일 8개 | PC 사용자 순서 완료 | 형식별 JSON/DB 보고서 일치. 정상 앱/실기기 검증은 아님 |
| 잘못된 입력 2개 | 거부·저장 차단 | 경로 탈출 ZIP·확장자 위장 텍스트 |
| 회귀 | 178개 중 177 통과·실패 0·건너뜀 1 | 링크 생성 제약 1개. 타입 검사 통과 |

## 남아 있는 Android·iOS 후속

1. 허가된 **실제 AAB/APKS/XAPK**를 확보한 경우 목록/구조를 독립 도구와 비교한다. 현재 사이트는 AAB protobuf나 중첩 APK를 해독하지 않으므로 설정·서명 미검사를 유지한다. 합성 변형의 이름만으로 취약/보완 상태를 탐지했다고 표시하지 않는다.
2. 실물 Android Chrome/Safari 등 해당 환경이 준비되면 실제 파일 선택·동의·검사·저장·재검증을 확인한다. 파일을 설치/실행할 필요는 없으며 APK 정적 검증 때문에 USB·개발자 설정을 강제로 켜지 않는다.
3. 큰 파일 Worker 처리 중 취소·변경 시 결과 오염이 없는지, 제한된 읽기량과 타임아웃을 계측한다. 파일 선택만으로 읽지 않는 기본값과 최대 1파일을 보존한다.
4. iOS 실기기/Safari·서명/entitlement/provisioning/설치/런타임은 Mac/Xcode 또는 해당 승인 환경에서 별도로 검증한다. Android Studio를 iOS Simulator로 사용하지 않는다. Windows의 합성 IPA Info.plist 검증은 완료한 범위로 유지한다.

## 다음 PC에 전달할 프롬프트

> docs/PROGRESS_HANDOFF_2026-10-30.md와 이 문서를 읽고 준비된 환경의 후속 작업을 진행해 주세요. 이미 끝난 실제 APK·Android 가상 브라우저·모바일 합성 검증은 이유 없이 반복하지 마세요. R01/R02 또는 실제 플랫폼 검증 중 해당 PC에서 가능한 것을 먼저 확인하세요. AGENTS.md 및 관련 설치 Next 문서를 읽고 기존 변경·계정·데이터 분리·로그인 화면·테마를 보존하세요. 원본 앱·비밀·캡처를 Git에 올리지 말고 실제/합성·완료/미검사/미지원을 구분해 최신 인계에 기록하세요. Git push/운영 배포는 해당 세션 지시 범위에서만 진행하세요.

## 재현 자료와 환경 차이

- [실제 APK·가상 Android 검증](validation/2026-10-30-android/README.md)
- [모바일 더미 사용자 흐름](validation/2026-10-30-mobile-dummy/README.md), [합성 파일](../tests/fixtures/mobile-2026-10-30/README.md)
- [도구 보안·Stable/LTS 검토](ANDROID_TOOLCHAIN_SECURITY_2026-10-30.md)
- npm run fixtures:mobile / npm run test:mobile:fixtures / npm test / npm run typecheck

Android Studio/SDK/JBR 업데이트·다운로드·AVD는 이 PC의 환경 작업이므로 Git pull로 설치되지 않는다. 새 PC의 도구 버전과 공식 공지를 별도로 확인한다. 실제 APK·Manifest·원본 JSON·캡처·환경 파일은 Git에서 제공하지 않는다. 시험 서버/DB/가상기기는 종료했고 새 시험은 별도 격리 환경에서 준비한다. 합성 결과를 운영에 저장하지 않는다.
