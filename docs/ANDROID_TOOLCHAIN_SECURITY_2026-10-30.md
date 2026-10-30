# Android 도구 업데이트·보안·지원 정책 검토

확인일: 2026-10-30, 한국 시간. 웹사이트의 Android 검사 검증과 개발 도구 자체의 보안을 구분한다.

## 대상과 확인 결과

| 구성 | 기존 | 이번 확인/준비 |
|---|---|---|
| Android Studio | AI-202.7660.26.42.7351085 | Rabbit 2 2026.2.2, AI-262.10968.63.2622.16730706 |
| Emulator | 30.6.5 | SDK 안정 채널 37.2.13.0 |
| Platform-Tools | 31.0.2 | 37.0.1 |
| 새 Studio 전용 Java | 해당 없음 | OpenJDK 25.0.4+-16339643-b508.27 |

새 IDE는 공식 릴리스 페이지의 Windows ZIP을 받아 별도 사용자 폴더에 배치했다. 실행 파일의 Authenticode 상태 Valid, 게시자 Google LLC를 확인했다. 기존 IDE·프로젝트·Gradle·기존 AVD는 삭제하거나 덮어쓰지 않았다. 기존 시작 메뉴/바로가기가 자동으로 새 IDE를 가리킨다는 뜻은 아니다. 새 실행 경로는 로컬 작업 기록에 보관한다. 서명 유효성은 공급자 확인의 근거이며 모든 취약점 부재를 증명하지 않는다.

## 안정 채널과 LTS의 차이

Google은 현재 Rabbit 2를 안정 채널로 안내하며 패치·SDK Manager 업데이트를 제공한다. 확인한 문서에서는 이 IDE 버전 자체에 대한 다년 LTS 보안 패치 보장/정확한 보안 지원 종료일을 찾지 못했다. 따라서 특정 버전의 장기 고정을 권장하지 않는다.

- 공식 문서의 **3년**은 Android Gradle Plugin 호환 범위다. IDE 보안 패치 제공 기간이 아니다.
- **10개월**은 Gemini/Firebase 등 클라우드 서비스 연동의 호환 창이다. 이 기간이 IDE의 보안 지원 SLA라는 뜻도 아니다.
- NDK 등 별도 구성요소의 LTS 표기를 Android Studio 전체에 적용하지 않는다.
- 운영 방침: 안정 채널 후속 패치를 확인하고 IDE·Emulator·Platform-Tools·시스템 이미지·번들 Java·플러그인 버전을 각각 기록한다. 업그레이드 전 APK 분석/파일 동의/저장 흐름을 재검증한다. 이 문서는 자동 업데이트나 주기 감시 작업을 등록한 것이 아니다.

근거: [안정 릴리스와 AGP/클라우드 호환 정책](https://developer.android.com/studio/releases), [IDE/SDK 업데이트 안내](https://developer.android.com/studio/intro/update).

## 공개 취약점과 번들 런타임의 실제 점검

확인한 Google 공지에서 Rabbit 2의 미수정 IDE 취약점을 특정하지 못했다. 검색 결과 부재를 무취약점 인증으로 해석하지 않는다. 과거 Google은 GitHub 플러그인의 토큰 노출 문제와 Jellyfish Patch 2의 수정을 공식 공지했다. 이 사례를 현재 IDE가 동일 취약점에 영향받는다는 뜻으로 쓰지 않는다. IntelliJ/Oracle 등의 버전 숫자만으로 Android Studio의 영향/패치를 확정하지 않는다.

이번 다운로드에 포함된 Java는 25.0.4였다. Oracle의 2026-10-21 **CVE-2026-91403** 공지 및 공식 완화 지침을 대조했으며, 새 JBR의 신뢰 저장소에 지침에서 열거한 루트 별칭 4개가 존재함을 확인했다. 최신 IDE라는 이유로 이 신호를 무시하지 않았다.

Oracle의 권고에 따라 **새 IDE 전용 JBR의 cacerts만 백업**한 뒤 아래 루트들을 신뢰 목록에서 제외했다. 조치 후 4개 별칭이 모두 조회되지 않음을 확인했고 새 SDK Manager의 HTTPS 목록 조회/SDK 다운로드가 정상 동작했다. 시스템 인증서·Windows 보안 설정·기존 IDE·기존 Java의 인증서는 변경하지 않았다. TLS 검증을 끄거나 임의 CA를 추가하지 않았다.

- emsignrootcag1 [jdk]
- emsignrootcag2 [jdk]
- emsigneccrootcag3 [jdk]
- comodoaaaca [jdk]

이것은 해당 인증서 위험에 대한 완화다. Java 25.0.4의 모든 CPU 보안 수정이 적용됐다는 판정이나 모든 JetBrains Runtime 취약점의 해결 확인은 아니다. 추후 Google 번들/JetBrains 런타임 보안 릴리스를 따라가고, 새 번들로 교체할 때 이 조치가 유지되는지 다시 확인해야 한다. 파일 백업은 버전 관리 저장소에 넣지 않는다.

근거: [Google의 과거 보안 패치 공지](https://androidstudio.googleblog.com/2024/06/?hl=en), [Oracle CVE-2026-91403 공지](https://www.oracle.com/security-alerts/alert-cve-2026-91403.html), [Oracle의 인증서 점검·완화 지침](https://ops.java/emudhra), [Java 25.0.5 릴리스 공지](https://www.oracle.com/java/technologies/javase/25-0-5-relnotes.html).

## 가상기기 업데이트 확인

기존 Emulator 30.6.5에서는 가속 검사 실패, 소프트웨어 모드의 Vulkan/CPU 경고 및 ADB offline을 관찰했다. 37.2.13 업데이트 후 `WHPX(10.0.26200) is installed and usable`을 확인했고 기존 Android 11 가상기기의 부팅 완료·공유 저장소·Chrome 설치를 확인했다. Windows 기능/BIOS 설정을 변경해서 통과시킨 것이 아니다. Android 11 이미지의 Chrome 83은 오래된 브라우저이므로 현대 웹 흐름을 검증할 별도 Android 16 이미지를 준비한다.

이는 이번 PC의 호환성 복구 확인이지 모든 GPU/Windows/Android 조합의 보증은 아니다. 최신 에뮬레이터의 Android 게스트 및 브라우저 검증 결과는 별도의 Android 실제 검증 문서에 기록한다.

근거: [에뮬레이터 릴리스 노트](https://developer.android.com/studio/releases/emulator), [Windows 가속 안내](https://developer.android.com/studio/run/emulator-acceleration).
