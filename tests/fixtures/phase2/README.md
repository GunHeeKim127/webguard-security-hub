# 2단계 합성 검증 파일

취약 선언(vulnerable)과 보완 선언(remediated)을 비교하는 **더미 입력**입니다. 악성코드 샘플이 아닙니다. 실행·설치·VM/GNS3 시작·실제 OS 설정 적용을 하지 마세요. EXE/Mach-O/APK/IPA는 최소 파서 입력이며 정상 프로그램이나 설치 가능한 앱이 아닙니다. 보완 파일도 안전 인증을 뜻하지 않습니다.

작전실에서 해당 검사 종류를 선택하고 같은 자산 이름으로 두 파일을 차례로 검사한 뒤 실행 이력을 비교하세요. 실행 파일·모바일 패키지는 선택 파일 읽기에 별도 동의해야 검사합니다. Linux/Windows/VMX/GNS3는 설정 텍스트를 선택합니다.

생성: node + tsx scripts/generate-review-fixtures.ts. 결과와 SHA-256: [검증 근거](../../../docs/assets/phase2-fixtures-2026-10-27/fixture-results.json). OS 서명·현재 장비·실제 통신·설치 여부는 미검사로 유지합니다. GNS3 2.x 구조만 지원하며 실제 GNS3 앱/장비 버전 호환성을 증명하지 않습니다.
