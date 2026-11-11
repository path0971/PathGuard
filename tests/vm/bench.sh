#!/usr/bin/env bash
# Execution-latency benchmark (development stage 6).
#   sudo tests/vm/setup_testfs.sh && sudo ITER=200 tests/vm/bench.sh
# For each file size it measures fork+exec+exit wall time:
#   baseline  agent not running
#   scan      agent running, first execution of each file (full SHA-256 + YARA)
#   cache     agent running, same files again (scan cache hit)
# and the agent's own decision latency (from the audit log), CPU time and peak RSS.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-/tmp/pathguard-bench}
source "$ROOT/tests/vm/lib.sh"

ITER=${ITER:-100}
SIZES=${SIZES:-"native 1M 10M 50M"}
OUTFILE=${OUTFILE:-$WORK/bench-results.md}
BENCH=$MNT/pg-bench

pg_require
pg_prepare
trap 'stop_agent; rm -rf "$BENCH"' EXIT

# Unique files per phase so "scan" never hits the cache.
echo "creating $ITER files per size and phase in $BENCH ..."
rm -rf "$BENCH"
for size in $SIZES; do
    for phase in baseline agent; do
        d=$BENCH/$size/$phase
        mkdir -p "$d"
        for i in $(seq 1 "$ITER"); do
            cp "$SAMPLES/clean" "$d/f$i"
            [[ $size == native ]] || truncate -s "$size" "$d/f$i"   # trailing data does not affect ELF execution
        done
    done
done
sync
sleep 3   # older than the cache's minimum file age

files() { ls -1 "$BENCH/$1/$2"/f* | sort -V; }

cpu_ticks() {  # utime+stime of the agent and its current workers
    local total=0 p
    for p in "$AGENT_PID" $(pgrep -f 'pathguardd --worker' || true); do
        [[ -r /proc/$p/stat ]] || continue
        total=$((total + $(awk '{print $14 + $15}' "/proc/$p/stat")))
    done
    echo "$total"
}

declare -A R
for size in $SIZES; do
    R[$size,baseline]=$("$SAMPLES/exec_timer" $(files "$size" baseline))
done

start_agent
HZ=$(getconf CLK_TCK)
for size in $SIZES; do
    t0=$(cpu_ticks)
    R[$size,scan]=$("$SAMPLES/exec_timer" $(files "$size" agent))
    t1=$(cpu_ticks)
    R[$size,cache]=$("$SAMPLES/exec_timer" $(files "$size" agent))
    t2=$(cpu_ticks)
    R[$size,cpu_scan]=$(awk -v t="$((t1 - t0))" -v hz="$HZ" -v n="$ITER" 'BEGIN{printf "%.2f", t / hz * 1000 / n}')
    R[$size,cpu_cache]=$(awk -v t="$((t2 - t1))" -v hz="$HZ" -v n="$ITER" 'BEGIN{printf "%.2f", t / hz * 1000 / n}')
done

rss_agent=$(awk '/VmHWM/{print $2}' "/proc/$AGENT_PID/status")
rss_worker=0
for p in $(pgrep -f 'pathguardd --worker'); do
    r=$(awk '/VmHWM/{print $2}' "/proc/$p/status")
    (( r > rss_worker )) && rss_worker=$r
done
STATUS=$(ctl status)
stop_agent

field() { sed -n "s/.*$2=\([0-9]*\).*/\1/p" <<<"$1"; }

{
    echo "# PathGuard benchmark"
    echo
    echo "- date: $(date -u +%Y-%m-%dT%H:%M:%SZ), kernel: $(uname -r), CPUs: $(nproc)"
    echo "- iterations per cell: $ITER, workers: 2, filesystem: $(findmnt -no FSTYPE "$MNT")"
    echo "- rule version: $(jget rule_version <<<"$STATUS"), YARA rules: $(jget yara_rules <<<"$STATUS")"
    echo
    echo "## fork+exec+exit wall time (us)"
    echo
    echo "| size | baseline p50 | baseline p95 | scan p50 | scan p95 | cache p50 | cache p95 | failures |"
    echo "|---|---|---|---|---|---|---|---|"
    for size in $SIZES; do
        b=${R[$size,baseline]} s=${R[$size,scan]} c=${R[$size,cache]}
        echo "| $size | $(field "$b" p50_us) | $(field "$b" p95_us) | $(field "$s" p50_us) | $(field "$s" p95_us) | $(field "$c" p50_us) | $(field "$c" p95_us) | $(( $(field "$b" failures) + $(field "$s" failures) + $(field "$c" failures) )) |"
    done
    echo
    echo "## agent decision latency from the audit log (us, event -> response)"
    echo
    python3 - "$LOG" "$BENCH" $SIZES <<'PY'
import json, sys
log, bench, sizes = sys.argv[1], sys.argv[2], sys.argv[3:]
rows = {}
for line in open(log):
    r = json.loads(line)
    if r.get("type") != "exec_decision" or not r["path"].startswith(bench + "/"):
        continue
    size = r["path"][len(bench) + 1:].split("/")[0]
    rows.setdefault((size, r["source"]), []).append((r["latency_us"], r.get("scan_us", 0)))
def pct(v, p):
    v = sorted(v)
    return v[(len(v) - 1) * p // 100] if v else 0
print("| size | source | n | latency p50 | latency p95 | scan p50 | scan p95 |")
print("|---|---|---|---|---|---|---|")
for s in sizes:
    for src in ("scan", "cache", "timeout", "overflow"):
        v = rows.get((s, src))
        if v:
            lat, scan = [x[0] for x in v], [x[1] for x in v]
            print(f"| {s} | {src} | {len(v)} | {pct(lat,50)} | {pct(lat,95)} | {pct(scan,50)} | {pct(scan,95)} |")
PY
    echo
    echo "## resources"
    echo
    echo "| size | agent+worker CPU per exec, scan (ms) | ... cache (ms) |"
    echo "|---|---|---|"
    for size in $SIZES; do
        echo "| $size | ${R[$size,cpu_scan]} | ${R[$size,cpu_cache]} |"
    done
    echo
    echo "- peak RSS: agent ${rss_agent} kB, largest worker ${rss_worker} kB"
    echo "- counters: $(jget counters <<<"$STATUS")"
} | tee "$OUTFILE"
echo
echo "saved to $OUTFILE"
