#!/usr/bin/env bash
# End-to-end test of PathGuard on a real Linux kernel (Ubuntu VM, root).
#   sudo tests/vm/setup_testfs.sh && sudo tests/vm/e2e.sh
# Covers development stages 1-5: offline scan, exec blocking, error/timeout
# handling, overflow, reload, quarantine/restore, restart gap detection.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-/tmp/pathguard-e2e}
source "$ROOT/tests/vm/lib.sh"

PASS=0
FAIL=0
check() {
    local name=$1
    shift
    if "$@"; then
        echo "  PASS  $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $name"
        FAIL=$((FAIL + 1))
    fi
}
denied() { [[ $RC -eq 126 && $OUT == *"Operation not permitted"* ]]; }
log_has() { grep -F "$1" "$LOG" >/dev/null; }

cleanup() {
    stop_agent
    rm -rf "$MNT/pg-tests"
}
trap cleanup EXIT

pg_require
pg_prepare
rm -rf "$MNT/pg-tests"
echo "kernel $(uname -r), protected filesystem $MNT, work dir $WORK"

# ---------------------------------------------------------------------------
echo "[1] offline scan (pathguardctl scan)"
ctl --config "$CONF" scan "$SAMPLES/clean" >/dev/null;   RC=$?; check "clean sample -> exit 0" test $RC -eq 0
ctl --config "$CONF" scan "$SAMPLES/marked" >/dev/null;  RC=$?; check "YARA match -> exit 1" test $RC -eq 1
ctl --config "$CONF" scan "$SAMPLES/blocked" >/dev/null; RC=$?; check "blocklisted hash -> exit 1" test $RC -eq 1
ctl --config "$CONF" scan "$WORK/does-not-exist" >/dev/null 2>&1; RC=$?; check "unreadable -> exit 2 (error, not clean)" test $RC -eq 2

# ---------------------------------------------------------------------------
echo "[2] agent start and self check"
"$AGENT" --check --config "$CONF" >/dev/null; RC=$?; check "pathguardd --check" test $RC -eq 0
start_agent
check "status protection ok" test "$(status protection)" = ok
check "self_check record" log_has '"type":"self_check"'
check "workers run as unprivileged user" test "$(ps -o user= -p "$(status workers.pids.0)" | tr -d ' ')" != root

# ---------------------------------------------------------------------------
echo "[3] execution control"
f=$(fresh_copy "$SAMPLES/clean" clean)
run_exec "$f"
check "clean program runs" test $RC -eq 0 -a "$OUT" = "pathguard clean sample"
check "clean decision logged with latency" bash -c "grep -F '\"path\":\"$f\"' '$LOG' | grep -q '\"decision\":\"allow\".*\"latency_us\"'"

f=$(fresh_copy "$SAMPLES/marked" marked)
run_exec "$f"
check "YARA-matched program is denied (EPERM)" denied
check "deny reason yara_match" bash -c "[[ \$(grep -F '\"path\":\"$f\"' '$LOG' | grep -F exec_decision | tail -1) == *'\"reason\":\"yara_match\"'* ]]"

f=$(fresh_copy "$SAMPLES/blocked" blocked)
run_exec "$f"
check "blocklisted program is denied" denied
check "deny reason hash_blocklist" bash -c "[[ \$(grep -F '\"path\":\"$f\"' '$LOG' | grep -F exec_decision | tail -1) == *'\"reason\":\"hash_blocklist\"'* ]]"

f=$(fresh_copy "$SAMPLES/marked" deep/a/b/c/marked)
run_exec "$f"
check "subdirectories are covered (filesystem mark)" denied

f=$(fresh_copy "$SAMPLES/clean" cached)
sleep 3   # files changed in the last 2s are not cached
run_exec "$f"; run_exec "$f"
check "second run served from cache" bash -c "grep -F '\"path\":\"$f\"' '$LOG' | grep -q '\"source\":\"cache\"'"

# ---------------------------------------------------------------------------
echo "[4] quarantine and restore"
sleep 1
check "denied files were removed from the protected path" test ! -e "$MNT/pg-tests/marked" -a ! -e "$MNT/pg-tests/blocked"
check "quarantine records written" log_has '"type":"quarantine"'
QID=$(ctl quarantine list | python3 -c '
import json, sys
for e in json.load(sys.stdin)["entries"]:
    if e["original_path"].endswith("/pg-tests/marked"): print(e["id"])')
check "quarantine list has the marked sample" test -n "$QID"
echo "occupied" > "$MNT/pg-tests/marked"
ctl quarantine restore "$QID" >/dev/null; RC=$?
check "restore refuses to overwrite an existing file" test $RC -ne 0
check "existing file untouched" test "$(cat "$MNT/pg-tests/marked")" = occupied
ctl quarantine restore "$QID" --to "$MNT/pg-tests/marked.restored" >/dev/null; RC=$?
check "restore to another path" test $RC -eq 0
check "restored content hash matches" test "$(sha256sum < "$MNT/pg-tests/marked.restored")" = "$(sha256sum < "$SAMPLES/marked")"
check "restored mode kept (executable)" test -x "$MNT/pg-tests/marked.restored"
ctl quarantine restore "$QID" --to "$MNT/pg-tests/again" >/dev/null; RC=$?
check "second restore is refused" test $RC -ne 0
run_exec "$MNT/pg-tests/marked.restored"
check "restored file is detected again" denied

# ---------------------------------------------------------------------------
echo "[5] reload: audit mode, broken rules"
GEN=$(status workers.generation)
conf_set mode audit
check "reload to audit mode" test "$(reload_wait)" -gt "$GEN"
f=$(fresh_copy "$SAMPLES/marked" marked-audit)
run_exec "$f"
check "audit mode allows but records would-deny" bash -c "[[ $RC -eq 0 ]] && grep -F '\"path\":\"$f\"' '$LOG' | grep -q '\"decision\":\"allow\",\"policy_decision\":\"deny\"'"
conf_set mode enforce
reload_wait >/dev/null

VER=$(status rule_version)
GEN=$(status workers.generation)
echo 'rule Broken { condition: no_such_identifier }' > "$WORK/rules/zz_broken.yar"
reload_wait >/dev/null
check "broken rules rejected, old rules kept" test "$(status rule_version)" = "$VER" -a "$(status workers.generation)" = "$GEN"
check "reload_failed record" log_has '"type":"reload_failed"'
rm -f "$WORK/rules/zz_broken.yar"
f=$(fresh_copy "$SAMPLES/marked" marked-after-bad-reload)
run_exec "$f"
check "protection unchanged after failed reload" denied

# ---------------------------------------------------------------------------
echo "[6] worker stall -> deadline -> on_error"
TIMEOUT_MS=1500
for p in $(status workers.pids | tr -d '[],'); do kill -STOP "$p"; done
f=$(fresh_copy "$SAMPLES/clean" clean-stall)
t0=$(date +%s%N)
run_exec "$f"
elapsed=$(( ($(date +%s%N) - t0) / 1000000 ))
check "stalled scan answered by deadline (on_error=allow, ${elapsed}ms)" test $RC -eq 0 -a $elapsed -ge $((TIMEOUT_MS * 9 / 10)) -a $elapsed -lt $((TIMEOUT_MS * 3))
check "timeout recorded" bash -c "grep -F '\"path\":\"$f\"' '$LOG' | grep -q '\"source\":\"timeout\"'"
for p in $(pgrep -f 'pathguardd --worker'); do kill -CONT "$p" 2>/dev/null; done
conf_set on_error deny
reload_wait >/dev/null
for p in $(status workers.pids | tr -d '[],'); do kill -STOP "$p"; done
f=$(fresh_copy "$SAMPLES/clean" clean-stall-deny)
run_exec "$f"
check "on_error=deny blocks when the scan cannot finish" denied
for p in $(pgrep -f 'pathguardd --worker'); do kill -CONT "$p" 2>/dev/null; done
conf_set on_error allow
reload_wait >/dev/null
check "workers replaced and ready" wait_workers_ready

WPID=$(status workers.pids.0)
kill -KILL "$WPID"
sleep 0.3
check "crashed worker respawned" wait_workers_ready
check "new worker pid" test "$(status workers.pids)" != "[$WPID]" -a "$(status workers.pids | grep -c "\b$WPID\b")" -eq 0
check "worker_exit recorded" log_has "\"type\":\"worker_exit\",\"worker_pid\":$WPID"
run_exec "$(fresh_copy "$SAMPLES/marked" marked-after-crash)"
check "protection continues after worker crash" denied

# ---------------------------------------------------------------------------
echo "[7] burst beyond queue_max"
conf_set queue_max 4
conf_set workers 1
reload_wait >/dev/null
mkdir -p "$MNT/pg-tests/burst"
for i in $(seq 1 300); do cp "$SAMPLES/clean" "$MNT/pg-tests/burst/c$i"; done
pids=()
for i in $(seq 1 300); do "$MNT/pg-tests/burst/c$i" >/dev/null 2>&1 & pids+=($!); done
bfail=0
for p in "${pids[@]}"; do wait "$p" || bfail=$((bfail + 1)); done
check "queue overflow detected" test "$(status counters.queue_overflows)" -gt 0
check "on_overflow=allow: all 300 programs ran ($bfail failed)" test $bfail -eq 0
degraded_by_overflow() { ctl status | grep -q queue_overflow_recent; }
check "status shows degraded" degraded_by_overflow
check "agent still responsive" ctl status >/dev/null
conf_set queue_max 256
conf_set workers 2
reload_wait >/dev/null

# ---------------------------------------------------------------------------
echo "[8] agent crash -> protection gap"
kill -KILL "$AGENT_PID"
wait "$AGENT_PID" 2>/dev/null
AGENT_PID=""
pkill -KILL -f 'pathguardd --worker' 2>/dev/null
run_exec "$(fresh_copy "$SAMPLES/marked" marked-while-down)"
check "without the agent, execution is NOT blocked (documented limitation)" test $RC -eq 0
start_agent
check "restart records protection_gap" log_has '"cause":"agent_crashed_or_killed"'
run_exec "$(fresh_copy "$SAMPLES/marked" marked-after-restart)"
check "protection restored after restart" denied
stop_agent
check "clean stop recorded" log_has '"type":"agent_stop"'

# ---------------------------------------------------------------------------
echo
echo "result: $PASS passed, $FAIL failed"
echo "audit log: $LOG   agent output: $WORK/agent.out"
[[ $FAIL -eq 0 ]]
