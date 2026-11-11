# PathGuard — Linux Endpoint Protection Agent

지정한 파일 시스템에서 **실행 파일을 실행 직전에 검사하고 허용·차단한 뒤, 판단 근거를 기록하고 탐지 파일을 격리**하는 경량 에이전트입니다.
C++17, fanotify(`FAN_OPEN_EXEC_PERM`), libyara, SHA-256(OpenSSL libcrypto), Unix domain socket, systemd를 사용합니다. 커널 모듈은 없습니다.

> 첫 버전의 보장 범위는 **감시 대상 파일 시스템의 일반 실행 파일**입니다. 스크립트(인터프리터가 읽는 파일), 메모리 기반 실행, 컨테이너 전체 보호, root 공격자에 대한 자기 보호는 범위 밖입니다. → [한계](#한계와-후속-과제)

## 구조

```
           execve() on watched fs
                    │
      ┌─────────────▼─────────────┐  FAN_OPEN_EXEC_PERM + fd
      │ kernel fanotify group     ├──────────────────────────┐
      └─────────────▲─────────────┘                          │
                    │ FAN_ALLOW / FAN_DENY (요청당 1회)        │
┌───────────────────┴──────────────────────────────────────────▼──────┐
│ pathguardd (root, CAP_SYS_ADMIN) — 단일 스레드 이벤트 루프            │
│  이벤트 수신 → 캐시 조회 → 큐(상한) → 워커 배정 → 기한 감시 → 정책 판단 → 응답 │
│  ├─ 감사 기록부: JSON Lines + 크기 기반 순환                            │
│  ├─ 격리 스레드: 응답 후 비동기 격리 (응답 경로와 분리)                 │
│  └─ 관리 스레드: /run/pathguard/control.sock (SO_PEERCRED 권한 검사)   │
└───────┬───────────────────────────────────────────────▲─────────────┘
        │ SCM_RIGHTS로 파일 fd 전달 (SOCK_SEQPACKET)       │ 결과
┌───────▼───────────────────────────────────────────────┴─────────────┐
│ 검사 워커 × N (pathguardd --worker, fork+exec)                       │
│  규칙 컴파일 후 권한 하강: uid=pathguard, groups 없음, NO_NEW_PRIVS,   │
│  RLIMIT_AS/NOFILE/FSIZE=0/NPROC=0 — 전달받은 fd만 읽음                │
│  SHA-256 + YARA, 검사 전후 fstat 비교 → clean / match / error         │
└─────────────────────────────────────────────────────────────────────┘
pathguardctl ── status · reload · quarantine list/restore · scan(오프라인) · hash
```

| 구성 요소 | 파일 |
|---|---|
| 이벤트 수신·실행 통제·워커 풀·기한 | `src/agent/agent.cpp` |
| 검사 워커 (권한 하강) | `src/agent/worker_main.cpp` |
| 검사 엔진 (SHA-256 + YARA) | `src/scanner/scanner.cpp` |
| 정책 엔진 | `src/policy/policy.cpp` |
| 격리 저장소 / 비동기 격리 | `src/quarantine/store.cpp`, `src/agent/quarantine_worker.cpp` |
| 감사 기록부 | `src/common/audit_log.cpp` |
| 관리 소켓 / CLI | `src/agent/control.cpp`, `src/cli/main.cpp` |
| 서비스 구성 | `packaging/pathguard.service`, `scripts/install.sh` |

## 동작 원칙

**판단 우선순위:** 해시 차단 목록 > 해시 허용 목록(예외) > YARA 일치 > 정상.
검사 오류는 절대 "정상"으로 취급하지 않고, `scan_result: "error"`로 따로 기록한 뒤 `on_error` 정책을 따릅니다.

| 상황 | 동작 |
|---|---|
| 검사 근거 | 커널이 준 fd만 사용합니다. 경로는 기록용이라 경로를 다시 열지 않습니다. 검사 전후 `dev/ino/size/mtime/ctime`이 다르면 `changed_during_scan` 오류로 처리합니다. |
| 응답 1회 보장 | 모든 요청은 `pending_` 표에 들어갑니다. `finish()`가 표에서 꺼내면서 정확히 한 번 응답하고, 기록과 격리는 응답한 뒤에 합니다. |
| 처리 기한 | `scan_timeout_ms`는 커널 이벤트 수신 시점부터 잽니다. 큐 대기 시간도 포함돼요. 기한을 넘기면 에이전트가 `on_error` 정책대로 직접 응답하고, 멈춘 워커는 SIGKILL로 정리한 뒤 새로 띄웁니다. |
| 큐 초과 | `queue_max`를 넘으면 `on_overflow` 정책대로 즉시 응답하고, 보호 상태를 `degraded`(`queue_overflow_recent`)로 표시합니다. 커널 `FAN_Q_OVERFLOW`도 따로 기록합니다. |
| 워커 장애 | 처리 중이던 요청은 `worker_crashed` 오류로 처리합니다. 30초에 5회 넘게 죽으면 재시작 간격을 늘리고 `worker_crash_loop`로 표시합니다. |
| 규칙 변경 | `reload`를 하면 새 워커 세대가 규칙을 컴파일합니다. 모든 워커가 준비를 마쳐야 교체하고, 하나라도 실패하면 기존 규칙을 유지하며 `reload_failed`를 기록합니다. 규칙 버전은 `sha256(YARA 파일 + 해시 목록)` 앞 16자입니다. |
| 캐시 | `(dev, ino, size, mtime, ctime)`를 키로 검사 결과를 저장합니다. 판단은 매번 현재 정책으로 다시 합니다. 최근 2초 안에 바뀐 파일은 캐시하지 않고, 규칙이 바뀌면 캐시를 비웁니다. |
| 격리 | 응답한 뒤 별도 스레드에서 처리합니다. ① fd 상태가 검사 시점과 같은지 확인 → ② 경로가 아직 같은 inode인지 확인 → ③ fd 내용을 복사하면서 해시 검증 → ④ 메타데이터 저장 → ⑤ inode를 다시 확인하고 `unlinkat`. 자동 삭제는 하지 않습니다. |
| 복원 | `O_EXCL`로 만들기 때문에 기존 파일을 덮어쓰지 않습니다. 복원 후 해시를 검증하고 owner와 mode를 되돌리되, set-id 비트는 제외합니다. |
| 에이전트 종료 | 실행 중에는 heartbeat를 기록합니다. 다시 시작할 때 이전 종료가 정상이었는지(`agent_stopped`) 비정상이었는지(`agent_crashed_or_killed`)와 보호 공백 시간을 `protection_gap`으로 남깁니다. |

> **장애 시 차단(fail-closed)을 보장하지 않습니다.** 에이전트 프로세스가 죽어 fanotify 그룹이 닫히면 커널은 대기 중인 요청과 이후의 실행을 모두 허용합니다. systemd `Restart=always`로 1초 안에 다시 감시를 등록하고 공백을 기록할 뿐입니다. E2E 테스트 [8]에서 이 동작을 직접 확인합니다.

## 빌드

Ubuntu 22.04 / 24.04:

```bash
sudo apt install build-essential cmake pkg-config libyara-dev libssl-dev
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure        # 단위 테스트 (root 불필요)
```

Windows 등에서 Docker로 컴파일만 확인할 때:

```bash
docker build -t pathguard-build -f docker/Dockerfile docker
docker run --rm -v "$PWD:/src:ro" pathguard-build bash -c \
  "cmake -S /src -B /build && cmake --build /build -j && ctest --test-dir /build"
```

## 설치·실행·제거

```bash
sudo tests/vm/setup_testfs.sh             # 실습용 전용 파일 시스템 /mnt/pg-test (loop ext4)
sudo scripts/install.sh                   # 바이너리, /etc/pathguard, 사용자 pathguard, systemd unit
sudo pathguardd --check                   # 설정·해시 목록·규칙·감시 경로 검증
sudo systemctl enable --now pathguard
sudo pathguardctl status
sudo scripts/uninstall.sh                 # 설정·로그·격리 보관 유지 (--purge 시 모두 삭제)
```

`watch_path`는 **마운트 지점이어야 하고 루트 파일 시스템이면 안 됩니다.** filesystem/mount mark는 그 아래 디렉터리 트리 전체를 감시하므로, 엉뚱한 경로를 지정하면 범위가 조용히 넓어질 수 있어서 기본값으로 거부합니다(`allow_non_mountpoint`, `allow_root_filesystem`으로 해제 가능).

### 관리 CLI

```bash
pathguardctl status                              # 보호 상태, degraded 사유, 카운터, 지연 p50/p95
pathguardctl reload                              # (root) 설정·목록·규칙 재적용
pathguardctl quarantine list
pathguardctl quarantine restore <id> [--to PATH] # (root) 덮어쓰기 없음
pathguardctl scan FILE...                        # 오프라인 검사 — 종료 코드: 0 허용, |1 차단, |2 검사 오류
pathguardctl hash FILE...                        # 목록 파일 형식으로 SHA-256 출력
```

권한은 다음과 같습니다. root는 모든 명령을 쓸 수 있습니다. `pathguard-admin` 그룹 구성원은 `status`와 `quarantine list`만 쓸 수 있습니다. 그 밖의 사용자는 소켓 권한(0660) 단계와 `SO_PEERCRED` 검사 단계에서 모두 거부됩니다.

### 감사 로그 (`/var/log/pathguard/audit.jsonl`)

```json
{"ts":"2026-11-07T12:21:00.412Z","type":"exec_decision","event_id":7,"decision":"deny","policy_decision":"deny",
 "reason":"yara_match","detail":"PathGuard_Test_Marker","mode":"enforce","source":"scan",
 "path":"/mnt/pg-test/pg-tests/marked","pid":349,"process_exe":"/usr/bin/bash","comm":"bash",
 "dev":1792,"ino":14,"size":15968,"scan_result":"match","sha256":"…","matches":["PathGuard_Test_Marker"],
 "scan_us":41,"latency_us":118,"queue_wait_us":9,"worker_pid":271,"rule_version":"f307e25e5b840581"}
```

`source`는 판단 경로입니다: `scan`, `cache`, `precheck`, `timeout`, `overflow`, `worker_crash`, `shutdown`.
운영 기록: `agent_start`, `self_check`, `rules_activated`, `reload_failed`, `rule_drift`, `quarantine`, `quarantine_failed`, `worker_exit`, `worker_timeout`, `queue_overflow`, `kernel_queue_overflow`, `protection_state`, `protection_gap`, `agent_stop`.

## 테스트

| 종류 | 명령 | 내용 |
|---|---|---|
| 단위 | `ctest --test-dir build` | SHA-256 벡터, JSON, 설정·목록 파서, 정책 우선순위·audit 모드, 스캐너(일치·정상·크기 초과·규칙 오류), 격리·복원 충돌 |
| E2E (VM, root) | `sudo tests/vm/e2e.sh` | 개발 단계 1~5 전체, 47개 검사 |
| 성능 (VM, root) | `sudo ITER=200 tests/vm/bench.sh` | 크기별 실행 지연 p50/p95, 에이전트 내부 지연, CPU, 최대 RSS → `bench-results.md` |

E2E 항목: 오프라인 검사 종료 코드 · `--check` · 워커 비특권 실행 · 정상 실행 허용 · YARA·해시 차단(EPERM) · 하위 디렉터리 포함 · 캐시 · 격리 및 원본 제거 · 복원 덮어쓰기 거부·해시 일치·재복원 거부 · audit 모드 · 잘못된 규칙 reload 거부 · 워커 정지 시 기한 내 응답(on_error=allow/deny) · 워커 강제 종료 후 재기동 · 큐 상한 초과(300개 동시 실행) · 에이전트 강제 종료 시 허용됨(한계 확인) · 재시작 후 `protection_gap` 기록.

### 측정 예시

Docker Desktop(WSL2 커널 6.18, 22 CPU) privileged 컨테이너의 loop ext4에서 측정했습니다. 목표 환경인 Ubuntu VM 결과가 아니므로 VM에서 `bench.sh`로 다시 측정하세요. 각 항목 100회, 크기 패딩은 0으로 채웠습니다.

| 파일 크기 | 기준 p50 (µs) | 첫 실행·검사 p50 / p95 (µs) | 캐시 p50 (µs) | 에이전트 판단 지연 p50 (µs) |
|---|---|---|---|---|
| 16 KB | 402 | 514 / 650 | 421 | 100 |
| 1 MB | 416 | 2,111 / 2,664 | 425 | 1,637 |
| 10 MB | 395 | 16,932 / 18,290 | 471 | 16,082 |
| 50 MB | 384 | 97,189 / 109,110 | 546 | 96,168 |

메모리 사용량(최대 RSS)은 에이전트 약 8 MB, 워커 약 78 MB입니다. 50 MB 파일 버퍼가 포함된 값입니다. 검사 비용은 파일 크기에 비례해 약 1.9 ms/MB이고, 캐시에 적중하면 판단 지연이 25~40 µs입니다.

## systemd

- `Type=notify`이므로 감시를 등록한 뒤에 `READY=1`을 보냅니다. `WatchdogSec=15` 동안 heartbeat가 없으면 systemd가 재시작합니다.
- `ExecStartPre`에서 `--check`를 실행하므로 잘못된 설정으로는 서비스가 시작되지 않습니다.
- 마운트 네임스페이스를 만드는 sandboxing 옵션(`ProtectSystem=`, `PrivateTmp=` 등)은 일부러 쓰지 않습니다. `mark_type = mount`일 때 서비스의 사설 네임스페이스 안 마운트 사본에만 mark가 걸리기 때문입니다. 대신 `CapabilityBoundingSet`과 `NoNewPrivileges`로 권한을 제한하고, 파일 내용을 해석하는 작업은 비특권 워커에서 합니다.

## 한계와 후속 과제

- **장애 시 차단 없음**: 에이전트가 죽으면 실행이 허용됩니다(위 참고). root 공격자가 에이전트를 종료하거나 설정을 바꾸는 것도 막지 않습니다.
- **스크립트 미보호**: `bash script.sh`, `python x.py`처럼 인터프리터가 읽는 파일은 exec 이벤트가 아닙니다. 또 `memfd_create`, `ld.so`로 직접 실행하는 경우, 감시 범위 밖 파일 시스템도 다루지 않습니다.
- **격리 경쟁 조건**: inode 재확인과 `unlinkat` 사이에 짧은 TOCTOU 구간이 남아 있습니다. 하드 링크가 여러 개면 다른 링크는 남습니다(`removal_error`에 기록).
- **캐시 키**: 커널 타임스탬프는 세밀하지 않아서, 같은 tick 안에서 내용만 바뀌면 키가 같을 수 있습니다. 최근 2초 안에 바뀐 파일을 캐시하지 않는 것으로 완화했습니다.
- **같은 파일 동시 실행**: 같은 파일을 동시에 여러 번 실행하면 각각 따로 검사합니다(합치기 없음).
- **워커 추가 격리**: seccomp 필터는 아직 없습니다.
- **후속 과제**: 중앙 관리 서버, 행위 기반 탐지, `FAN_OPEN_PERM` 기반 스크립트 검사, 서명된 정책 배포.
