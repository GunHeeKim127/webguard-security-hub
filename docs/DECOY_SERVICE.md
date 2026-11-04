# 독립 디코이 서비스

이 서비스는 소유한 Linux VM의 loopback에서 계속 실행할 수 있는 고정 응답 디코이입니다. VM 밖의 고객 요청은 받지 않습니다. 기존 5분 시험이 namespace 내부에서만 응답을 확인했다면, 새 검증은 VM 원래 네트워크의 수신 소켓으로 접속해 격리된 작업 프로세스의 응답을 확인합니다.

## 파일과 검증

- [서비스 도구 다운로드](https://securitywebguard.vercel.app/tools/isolated-decoy-service.py)
- [systemd 단위 파일 다운로드](https://securitywebguard.vercel.app/tools/velthara-decoy.service)
- [신규 설치·검증 도구 다운로드](https://securitywebguard.vercel.app/tools/manage-decoy-service.py)
- 도구 SHA-256: `6f51e8a264ec5f438ddea42a2db8e1ca02a388c003c933b47ef9a32b53196beb`
- 단위 파일 SHA-256: `db46e6685a0f9cb58d985398373aa1fb873d62f941f2dda81564a3286f1a3f6c`
- 설치·재검증 도구 SHA-256: `9205c106be83b9acce2bc988a32d4cc684fa0824e3d3deb8589de2c5ef5e5506`

Linux root와 Python 3, `ip`, `unshare`가 필요합니다. 다운로드 해시 확인 후 `python3 -I -S isolated-decoy-service.py --check`로 약 1분의 실제 수신·응답·중지 시험을 실행합니다. 성공 결과는 `hostNamespaceIngress`, `isolatedWorker`, `sampleEgressDenied`, `listenerClosed`가 true, `checks`가 17, `cleanup`이 `complete`여야 합니다. 2026-11-04 사용자가 실제 Kali에서 해시 일치·17개 요청·격리·소켓 종료·정리 성공을 전달했습니다. 기존 namespace 내부 시험과 구분한 실제 수신 경계 검증 완료입니다.

## 실행과 중지

직접 실행은 `python3 -I -S isolated-decoy-service.py --serve --port 8765`입니다. 해당 VM의 다른 터미널에서 `curl --noproxy '*' -i http://127.0.0.1:8765/`로 고정 404 응답을 확인할 수 있습니다. 디코이의 404는 진단 사이트 장애를 의미하지 않습니다. `--seconds 300`을 붙이면 5분 후 자동 종료하고, 생략하면 Ctrl+C로 중지할 때까지 실행합니다. 동일 포트가 이미 사용 중이면 실패하며 기존 프로세스를 종료하지 않습니다.

systemd 파일은 도구를 `/opt/velthara-decoy/isolated-decoy-service.py`에 배치한 환경용입니다. 운영자 검토 후 새 전용 서비스로 설치하고 `systemd-analyze verify`와 시작·응답·중지·재시작을 확인한 뒤에만 부팅 시 활성화해야 합니다. 기존 동명 서비스가 있다면 덮어쓰지 말고 내용을 먼저 비교하세요. 실제 Kali 신규 설치·시작/중지/재시작과 부팅 자동 시작 설정 성공을 사용자 실행 결과로 확인했습니다. 실제 재부팅 후 재검증은 별도로 진행합니다.

설치 도구는 해시 확인 후 root로 `python3 -I -S manage-decoy-service.py --install`을 실행하는 명시적 신규 설치 방식입니다. 기존 동명 서비스·파일·사용 중인 포트가 있으면 덮어쓰거나 종료하지 않습니다. 고정된 HTTPS 배포본 두 개의 해시를 대조하고, 실제 프로세스의 UID·실효 권한·namespace·빈 루트·비밀 환경 변수 미주입과 시작·중지·재시작을 확인합니다. 실패하면 자신이 새로 만든 설치를 되돌리며, 중지 실패 시 파일을 지워 성공처럼 처리하지 않습니다. 실제 설치 검증에서 모든 작업 프로세스 확인값이 true이고 서비스가 VM loopback에서 실행 중인 결과를 받았습니다.

`--install --enable`은 같은 검증 이후 VM 부팅 시 자동 시작도 활성화합니다. 비용이나 공개 접속은 추가하지 않지만 VM에 지속 실행 서비스를 만드는 변경입니다. `enabledAtBoot`와 실제 재부팅 시험 `actualRebootTested`는 별개입니다. 설치 후 `--verify`로 설정 변경 없이 현재 작업 프로세스를 재검증할 수 있습니다. 중지는 `systemctl stop velthara-decoy.service`, 부팅 자동 실행 해제는 `systemctl disable velthara-decoy.service`입니다. 도구는 다른 서비스를 관리하지 않습니다.

재부팅 후 최신 도구의 `--verify`는 설치 파일이 현재 부팅보다 이전에 존재했는지, 서비스가 부팅 후 120초 이내에 활성화됐는지, 자동 시작이 활성화돼 있는지도 읽기 전용으로 대조합니다. 세 값과 작업 프로세스 검증이 통과해야 재부팅 후 근거를 성공으로 봅니다. 부팅이 느리거나 시계 보정이 있었으면 확인 불가일 수 있으며 보호를 해제해 통과시키지 않습니다. 원격 증명이나 관리자에 의한 조작 방어를 뜻하지 않습니다.

## 경계

작업 프로세스는 별도 네트워크 namespace, 빈 루트, 일반 사용자 권한으로 실행합니다. 접속키나 DB 환경 변수를 주입하지 않습니다. 고정 응답과 집계 개수만 출력하고 원본 주소·경로·헤더·본문을 로그에 남기지 않습니다. 본문은 최대 4KiB를 2초 내 폐기하고 쓰기를 거절합니다. 샘플 외부 연결 거절과 실제 수신 소켓의 정리도 시험합니다. systemd 구성은 추가 자원·권한 제한을 제공하지만 해당 Linux에서 별도 검증해야 합니다.

이 도구는 운영 공격 요청을 전달하거나 공격자를 자동 격리하지 않습니다. 외부 수신·운영 연결은 별도의 경계 설계와 검증이 필요한 잔여 항목입니다. 모든 DDoS·커널 취약점·탈출 기법 방어를 보장하지 않습니다.

## 개발 검증

`python3 tests/decoy-service.test.py`는 실제 loopback HTTP로 고정 응답·원본 미반사/미기록·쓰기 거절·본문 모호성 거절·느린 연결과 본문 후 복구를 확인합니다. 현재 6개 통과이며 Linux namespace·systemd 시험을 대체하지 않습니다.

실행 환경 제한은 [systemd 실행 환경 문서](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html), 종료·재시작 정책은 [서비스 문서](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)에 근거하며 실제 커널·systemd 버전에서의 검증을 우선합니다.
