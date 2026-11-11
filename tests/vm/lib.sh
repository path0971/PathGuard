# Shared helpers for the VM tests (sourced by e2e.sh and bench.sh).
# Needs: ROOT (repo), set before sourcing. Overridable: BUILD, MNT, WORK.

BUILD=${BUILD:-$ROOT/build}
MNT=${MNT:-/mnt/pg-test}
WORK=${WORK:-/tmp/pathguard-test}
AGENT=$BUILD/pathguardd
CTL=$BUILD/pathguardctl
CONF=$WORK/pathguard.conf
SOCK=$WORK/control.sock
LOG=$WORK/audit.jsonl
SAMPLES=$WORK/samples
AGENT_PID=""

die() { echo "error: $*" >&2; exit 1; }

pg_require() {
    [[ $EUID -eq 0 ]] || die "run as root (fanotify permission events need CAP_SYS_ADMIN)"
    [[ -x $AGENT && -x $CTL ]] || die "build first: cmake -S $ROOT -B $BUILD && cmake --build $BUILD -j"
    command -v python3 >/dev/null || die "python3 is required"
    command -v cc >/dev/null || die "a C compiler (cc) is required"
    mountpoint -q "$MNT" || die "$MNT is not a mount point; run tests/vm/setup_testfs.sh first"
}

# Builds samples, rules, hash lists and a test configuration in $WORK.
pg_prepare() {
    rm -rf "$WORK"
    mkdir -p "$WORK/rules" "$SAMPLES"
    local s
    for s in clean marked blocked exec_timer; do
        cc -O2 -o "$SAMPLES/$s" "$ROOT/tests/vm/samples/$s.c"
    done
    cp "$ROOT"/rules/*.yar "$WORK/rules/"
    sha256sum "$SAMPLES/blocked" | awk '{print $1 "  test blocklist sample"}' > "$WORK/blocklist.sha256"
    : > "$WORK/allowlist.sha256"
    local wuser=pathguard
    id pathguard >/dev/null 2>&1 || wuser=nobody
    cat > "$CONF" <<EOF
mode = enforce
on_error = allow
on_overflow = allow
watch_path = $MNT
mark_type = filesystem
workers = 2
queue_max = 256
scan_timeout_ms = 1500
max_file_size = 64M
worker_memory_limit = 512M
worker_user = $wuser
blocklist = $WORK/blocklist.sha256
allowlist = $WORK/allowlist.sha256
yara_rules = $WORK/rules
log_file = $LOG
log_max_bytes = 50M
quarantine = true
quarantine_dir = $WORK/quarantine
state_file = $WORK/state
control_socket = $SOCK
admin_group = root
EOF
}

conf_set() { sed -i "s|^$1 = .*|$1 = $2|" "$CONF"; }

ctl() { "$CTL" --socket "$SOCK" "$@"; }

# jget <dotted.path>  reads JSON on stdin
jget() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if isinstance(d, list) else d[k]
print(json.dumps(d) if isinstance(d, (list, dict)) else d)' "$1"
}

status() { ctl status | jget "$1"; }

start_agent() {
    "$AGENT" --config "$CONF" >>"$WORK/agent.out" 2>&1 &
    AGENT_PID=$!
    local i
    for i in $(seq 1 100); do
        if ctl status >/dev/null 2>&1; then return 0; fi
        kill -0 "$AGENT_PID" 2>/dev/null || { cat "$WORK/agent.out" >&2; die "agent exited during startup"; }
        sleep 0.1
    done
    die "agent did not become ready"
}

stop_agent() {
    [[ -n $AGENT_PID ]] || return 0
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    AGENT_PID=""
}

wait_workers_ready() {
    local i
    for i in $(seq 1 100); do
        [[ $(status workers.ready) == "$(status workers.target)" ]] && return 0
        sleep 0.1
    done
    return 1
}

# Triggers a reload and waits until it either activated or failed.
# Prints the resulting generation.
reload_wait() {
    ctl reload >/dev/null || true
    local i
    for i in $(seq 1 200); do
        [[ $(status workers.reload_in_progress) == "False" ]] && break
        sleep 0.1
    done
    wait_workers_ready || true
    status workers.generation
}

# run_exec FILE -> sets RC and OUT
run_exec() {
    RC=0
    OUT=$("$1" 2>&1) || RC=$?
}

# last exec_decision record for an exact path
decision_for() { grep -F "\"path\":\"$1\"" "$LOG" | grep -F '"type":"exec_decision"' | tail -1; }

# fresh_copy SRC NAME -> new inode on the protected filesystem (never cached)
fresh_copy() {
    local dst="$MNT/pg-tests/$2"
    mkdir -p "$(dirname "$dst")"
    cp "$1" "$dst"
    echo "$dst"
}
