# 독립 디코이 서비스

이 서비스는 소유한 Linux VM의 loopback에서 계속 실행할 수 있는 고정 응답 디코이입니다. VM 밖의 고객 요청은 받지 않습니다. 기존 5분 시험이 namespace 내부에서만 응답을 확인했다면, 새 검증은 VM 원래 네트워크의 수신 소켓으로 접속해 격리된 작업 프로세스의 응답을 확인합니다.

## 파일과 검증

- [서비스 도구 다운로드](https://webguard-security-hub.vercel.app/tools/isolated-decoy-service.py)
- [systemd 단위 파일 다운로드](https://webguard-security-hub.vercel.app/tools/velthara-decoy.service)
- 도구 SHA-256: `6f51e8a264ec5f438ddea42a2db8e1ca02a388c003c933b47ef9a32b53196beb`
- 단위 파일 SHA-256: `7c24fed259fca284e44d152ea657d6ad509ebbec02201849dd2cc45a64d1a059`

Linux root와 Python 3, `ip`, `unshare`가 필요합니다. 다운로드 해시 확인 후 `python3 -I -S isolated-decoy-service.py --check`로 약 1분의 실제 수신·응답·중지 시험을 실행합니다. 성공 결과는 `hostNamespaceIngress`, `isolatedWorker`, `sampleEgressDenied`, `listenerClosed`가 true, `checks`가 17, `cleanup`이 `complete`여야 합니다. 기존 namespace 내부 시험과 별도 검증이며 Linux 결과를 받기 전에는 완료로 기록하지 않습니다.

## 실행과 중지

직접 실행은 `python3 -I -S isolated-decoy-service.py --serve --port 8765`입니다. 해당 VM의 다른 터미널에서 `curl --noproxy '*' -i http://127.0.0.1:8765/`로 고정 404 응답을 확인할 수 있습니다. 디코이의 404는 진단 사이트 장애를 의미하지 않습니다. `--seconds 300`을 붙이면 5분 후 자동 종료하고, 생략하면 Ctrl+C로 중지할 때까지 실행합니다. 동일 포트가 이미 사용 중이면 실패하며 기존 프로세스를 종료하지 않습니다.

systemd 파일은 도구를 `/usr/local/lib/velthara/isolated-decoy-service.py`에 배치한 환경용입니다. 운영자 검토 후 새 전용 서비스로 설치하고 `systemd-analyze verify`와 시작·응답·중지·재시작을 확인한 뒤에만 부팅 시 활성화해야 합니다. 기존 동명 서비스가 있다면 덮어쓰지 말고 내용을 먼저 비교하세요. 현재는 단위 파일 준비 상태이며 실제 설치·부팅 재시작 검증을 완료한 상태가 아닙니다.

## 경계

작업 프로세스는 별도 네트워크 namespace, 빈 루트, 일반 사용자 권한으로 실행합니다. 접속키나 DB 환경 변수를 주입하지 않습니다. 고정 응답과 집계 개수만 출력하고 원본 주소·경로·헤더·본문을 로그에 남기지 않습니다. 본문은 최대 4KiB를 2초 내 폐기하고 쓰기를 거절합니다. 샘플 외부 연결 거절과 실제 수신 소켓의 정리도 시험합니다. systemd 구성은 추가 자원·권한 제한을 제공하지만 해당 Linux에서 별도 검증해야 합니다.

이 도구는 운영 공격 요청을 전달하거나 공격자를 자동 격리하지 않습니다. 외부 수신·운영 연결은 별도의 경계 설계와 검증이 필요한 잔여 항목입니다. 모든 DDoS·커널 취약점·탈출 기법 방어를 보장하지 않습니다.

## 개발 검증

`python3 tests/decoy-service.test.py`는 실제 loopback HTTP로 고정 응답·원본 미반사/미기록·쓰기 거절·본문 모호성 거절·느린 연결과 본문 후 복구를 확인합니다. 현재 6개 통과이며 Linux namespace·systemd 시험을 대체하지 않습니다.
