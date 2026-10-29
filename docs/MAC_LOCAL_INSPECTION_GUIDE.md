# Mac 로컬 검사 실행 안내 — 경로 선택 방식

Windows 로컬 검증을 마친 도구의 사용 안내다. Mac의 파일 선택 창·codesign/spctl 실검증은 담당자가 수행해야 한다.

## 사용 순서

1. Mac 터미널에서 `node --version`으로 Node.js 20 이상을 확인한다.
2. Endpoint 검사 폼 상단의 **검사 도구 다운로드** 영역에서 .mjs와 Mac용 .command 두 버튼을 누른다. 사용법을 펼칠 필요는 없다.
3. 터미널에 `/bin/zsh `를 입력하고 실행 안내 파일을 끌어놓은 뒤 Enter를 누른다.
4. 실제 앱/실행 파일 하나 또는 선택한 폴더의 후보 하나를 고른다.
5. 읽기 허용·검사 방식을 고르고 새 JSON 저장 위치를 선택한다.
6. 사이트에서 결과 JSON 하나를 읽기 허용 후 확인한다.

도구와 실행 안내가 다른 폴더에 있어도 선택할 수 있다. 예전 도구가 같이 있으면 버전을 확인해 새 도구 선택을 요청한다. 현재 폴더·특정 다운로드 위치·예시 앱의 존재를 가정하지 않는다. 전체 디스크 자동 탐색·후보 전체 자동 검사·앱 실행·원본 업로드는 하지 않는다.

## 오류 구분

| 표시/상태 | 의미와 다음 행동 |
| --- | --- |
| Node의 MODULE_NOT_FOUND | 검사 도구를 시작하지 못한 단계다. 앱 보안 판정이 아니다. 실행 안내 파일로 실제 도구를 선택한다. |
| TOOL_NOT_FOUND / TOOL_OUTDATED | 두 도구를 새로 내려받고 실제 검사 도구를 선택한다. |
| NODE_NOT_FOUND / NODE_VERSION_UNSUPPORTED | 설치된 Node.js 20 이상 실행 파일을 선택하거나 준비한다. |
| NO_CANDIDATES | 선택한 범위에서 이름/메타데이터상 후보가 없다. 실제 파일을 직접 선택할 수 있다. |
| SEARCH_INCOMPLETE | 검색 한도/접근 실패가 있었다. 더 가까운 폴더나 실제 파일을 선택한다. |
| TARGET_NOT_FOUND / ACCESS_DENIED | 선택 파일의 현재 위치·접근 허용을 확인한다. |
| APP_METADATA_NOT_FOUND / APP_EXECUTABLE_NOT_FOUND | 앱 번들 구조나 선언된 주 실행 파일을 확인한다. 이름이 .app이라는 이유로 정상 앱으로 판정하지 않는다. |
| OUTPUT_FOLDER_NOT_FOUND / OUTPUT_EXISTS | 존재하는 저장 폴더와 새 결과 이름을 고른다. 덮어쓰지 않는다. |

파일 선택 취소는 검사 실패/보안 경고로 표시하지 않는다. 경로 이름 자체는 보안 판정이 아니다. 후보 목록에는 로컬 경로가 보이지만 최종 검사 요약에는 경로·파일명을 넣지 않는다.

## 확인한 범위와 남은 검증

Windows의 격리 일반 회원 브라우저에서 6단계 안내·두 다운로드·JSON 단계 전환·최대 1개 선택을 확인했다. CLI는 다른 작업 폴더/공백/다운로드 중복 번호/Windows 짧은 경로, 없는 대상/출력 폴더·기존 출력 거절, 선택 범위 탐색·링크 생략·탐색 한도와 실제 PE 구조 검사를 확인했다. 전체 회귀 159개·타입·production 빌드·클라이언트 경계 검사 통과. Mac 실행 창/zsh/osascript·실제 앱 서명은 이 결과로 대신하지 않는다.

담당자는 도구/Node/대상/출력의 실제 위치를 선택해 실행하고 정상·취소·누락·권한·중복 출력·서명 결과를 확인한다. OS/도구 버전과 실제 수행 범위, 개인정보를 가린 오류 코드, 결과 JSON을 전달하면 대조할 수 있다. 비밀번호·키·개인 경로 전체를 채팅에 보낼 필요는 없다.

참고: [Apple 파일/폴더 선택](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/PromptforaFileorFolder.html), [저장 위치 선택](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/PromptforaFileName.html).

## 2026-10-29.2: 앱 검사 단계별 진단 (로컬 수정본)

Mac 담당자가 실행 안내를 시작하고 .app을 선택한 뒤 기존 통합 오류를 전달했다. 도구 시작 성공은 확인됐지만 주 실행 파일 구조/서명 검사는 완료로 판정하지 않는다. 원인 확정 없이 앱 손상·파일 부재·경로 문제라고 표시하지 않는다.

수정본은 앱 메타데이터 전체의 JSON 변환 대신 CFBundleExecutable 문자열만 plutil로 추출한다. 관련 없는 plist 값/전체 출력 크기의 영향을 줄이지만 이것이 사용자 오류의 원인이었다고 확정한 것은 아니다. 오류 시 경로·파일명·원문 없이 도구 버전·검사 단계·고정 코드·형식·플랫폼의 Diagnostic JSON 한 줄을 출력한다.

- APP_METADATA_READ_FAILED: 앱에서 주 실행 파일 이름을 읽지 못함. 메타데이터/OS 도구 호환 확인이 필요하다.
- MAIN_EXECUTABLE_IS_SCRIPT: 주 실행 파일이 스크립트다. 정상 앱일 수 있으나 현재 Mach-O/PE 구조 검사의 지원 범위 밖이다.
- UNSUPPORTED_EXECUTABLE_FORMAT / STRUCTURE_INVALID_OR_UNSUPPORTED: 현재 지원 형식/구조로 해석하지 못함. 악성 또는 손상 확정이 아니다.
- APP_EXECUTABLE_OUTSIDE_BUNDLE: 주 실행 파일이 앱 외부를 가리킨다. 자동으로 범위 밖 파일을 읽지 않는다.
- FILE_CHANGED_DURING_INSPECTION: 검사 중 파일 메타데이터가 바뀌었다. 안정된 사본으로 재검사가 필요하다.

새 버전은 실행 안내와 검사 도구 두 파일을 함께 다시 받아야 한다. 실제 Mac 재실행 후 Diagnostic 한 줄만 전달하면 된다. 정상/취소/원인 미확정 여부를 구분하고 비밀번호·키·전체 경로를 요청하지 않는다. 관련 검사18개·전체161개와 타입 검증을 로컬에서 확인했으며 실제 Mac 원인은 후속 출력 전까지 미확정이다.
