#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/result/cpu_overhead}"
SUMMARY_CSV="${SUMMARY_CSV:-$OUT_DIR/summary.csv}"

TARGET_URL="${TARGET_URL:-http://127.0.0.1:9080}"
RATE="${RATE:-400}"
CONNECTIONS="${CONNECTIONS:-20}"
DURATION="${DURATION:-3s}"
BOOK_COUNT="${BOOK_COUNT:-100}"
ID_MODE="${ID_MODE:-random}"
SEED="${SEED:-42}"
MARK_PREFIX="${MARK_PREFIX:-cpu-$(date +%Y%m%d_%H%M%S)}"
MODES="${MODES:-baseline pcap ebpf}"
REPEAT="${REPEAT:-1}"
BETWEEN_RUN_SECONDS="${BETWEEN_RUN_SECONDS:-8}"

TCPDUMP_IFACE="${TCPDUMP_IFACE:-any}"
TCPDUMP_FILTER="${TCPDUMP_FILTER:-tcp port 9080}"
EBPF_COLLECTOR="${EBPF_COLLECTOR:-$ROOT_DIR/collector/ebpf/cgroup_net/target/release/cgroup}"
EBPF_CAPTURE_PORTS="${EBPF_CAPTURE_PORTS:-9080}"
EBPF_IGNORED_PORTS="${EBPF_IGNORED_PORTS:-14250,16686}"
EBPF_COLLECTOR_PROTOCOL="${EBPF_COLLECTOR_PROTOCOL:-http1}"
TLS_UPROBE_COLLECTOR="${TLS_UPROBE_COLLECTOR:-$ROOT_DIR/collector/ebpf/tls_uprobe/target/release/tls-uprobe}"
TLS_UPROBE_ARGS="${TLS_UPROBE_ARGS:-}"
DEEPFLOW_AGENT_NAME="${DEEPFLOW_AGENT_NAME:-deepflow-agent}"

CAPTURE_PID=""
CAPTURE_LABEL=""

log() {
  printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1" >&2
    exit 1
  fi
}

duration_to_seconds() {
  python3 - "$1" <<'PY'
import sys
value = sys.argv[1].strip().lower()
if value.endswith("ms"):
    print(float(value[:-2]) / 1000.0)
elif value.endswith("s"):
    print(float(value[:-1]))
elif value.endswith("m"):
    print(float(value[:-1]) * 60.0)
else:
    print(float(value))
PY
}

read_host_cpu() {
  python3 - <<'PY'
with open("/proc/stat", encoding="utf-8") as f:
    fields = f.readline().split()[1:]
values = [int(v) for v in fields]
idle = values[3] + (values[4] if len(values) > 4 else 0)
print(sum(values), idle)
PY
}

read_proc_cpu_ticks() {
  local pid="$1"
  python3 - "$pid" <<'PY'
import os
import sys

root = int(sys.argv[1])
if root <= 0:
    print(0)
    raise SystemExit

children = {}
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    pid = int(name)
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            stat = f.read()
    except OSError:
        continue
    close = stat.rfind(")")
    parts = stat[close + 2 :].split()
    if len(parts) < 15:
        continue
    ppid = int(parts[1])
    children.setdefault(ppid, []).append(pid)

stack = [root]
seen = set()
while stack:
    pid = stack.pop()
    if pid in seen:
        continue
    seen.add(pid)
    stack.extend(children.get(pid, ()))

ticks = 0
for pid in seen:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            stat = f.read()
    except OSError:
        continue
    close = stat.rfind(")")
    parts = stat[close + 2 :].split()
    if len(parts) >= 15:
        ticks += int(parts[11]) + int(parts[12])
print(ticks)
PY
}

read_proc_rss_kb() {
  local pid="$1"
  python3 - "$pid" <<'PY'
import os
import sys

root = int(sys.argv[1])
if root <= 0:
    print(0)
    raise SystemExit

children = {}
for name in os.listdir("/proc"):
    if not name.isdigit():
        continue
    pid = int(name)
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            stat = f.read()
    except OSError:
        continue
    close = stat.rfind(")")
    parts = stat[close + 2 :].split()
    if len(parts) < 2:
        continue
    ppid = int(parts[1])
    children.setdefault(ppid, []).append(pid)

stack = [root]
seen = set()
while stack:
    pid = stack.pop()
    if pid in seen:
        continue
    seen.add(pid)
    stack.extend(children.get(pid, ()))

rss_kb = 0
for pid in seen:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb += int(line.split()[1])
                    break
    except OSError:
        continue
print(rss_kb)
PY
}

read_proc_rss_kb_sudo() {
  local pid="$1"
  sudo -n awk '/^VmRSS:/ {print $2; found=1} END {if (!found) print 0}' "/proc/$pid/status" 2>/dev/null \
    || echo 0
}

sample_collector_memory() {
  local mode="$1"
  local pid="$2"
  local output="$3"
  : > "$output"
  if [[ -z "$pid" || "$pid" == "0" ]]; then
    echo 0 >> "$output"
    return 0
  fi
  while true; do
    if [[ "$mode" == "deepflow" ]]; then
      sudo -n kill -0 "$pid" 2>/dev/null || break
      read_proc_rss_kb_sudo "$pid" >> "$output" || true
      sleep 0.2
    else
      kill -0 "$pid" 2>/dev/null || break
      read_proc_rss_kb "$pid" >> "$output" || true
      sleep 0.2
    fi
  done
}

container_main_pid() {
  local name_filter="$1"
  docker ps --filter "name=$name_filter" --format '{{.ID}}' | head -n1 | xargs -r docker inspect --format '{{.State.Pid}}'
}

stop_capture() {
  if [[ -n "${CAPTURE_PID:-}" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
    log "Stopping $CAPTURE_LABEL capture pid=$CAPTURE_PID"
    sudo -n kill -INT "$CAPTURE_PID" 2>/dev/null || kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
  fi
  CAPTURE_PID=""
  CAPTURE_LABEL=""
}

cleanup() {
  stop_capture
}
trap cleanup EXIT INT TERM

start_capture() {
  local mode="$1"
  local run_dir="$2"
  CAPTURE_PID=""
  CAPTURE_LABEL="$mode"
  case "$mode" in
    baseline)
      ;;
    pcap)
      sudo -n tcpdump -i "$TCPDUMP_IFACE" -s 0 -U -w "$run_dir/traffic.pcap" "$TCPDUMP_FILTER" \
        >"$run_dir/pcap_capture.log" 2>&1 &
      CAPTURE_PID=$!
      sleep 1
      ;;
    ebpf)
      sudo -n "$EBPF_COLLECTOR" \
        --output "$run_dir/ebpf_output.bin" \
        --protocol "$EBPF_COLLECTOR_PROTOCOL" \
        --port "$EBPF_CAPTURE_PORTS" \
        --ignored-port "$EBPF_IGNORED_PORTS" \
        --quiet \
        >"$run_dir/ebpf_capture.log" 2>&1 &
      CAPTURE_PID=$!
      sleep 1
      ;;
    tls-uprobe)
      if [[ -z "$TLS_UPROBE_ARGS" ]]; then
        echo "TLS_UPROBE_ARGS must be set for mode=tls-uprobe" >&2
        exit 1
      fi
      # shellcheck disable=SC2086
      sudo -n "$TLS_UPROBE_COLLECTOR" $TLS_UPROBE_ARGS --output "$run_dir/tls_uprobe_output.csv" \
        >"$run_dir/tls_uprobe_capture.log" 2>&1 &
      CAPTURE_PID=$!
      sleep 1
      ;;
    deepflow)
      CAPTURE_PID="$(container_main_pid "$DEEPFLOW_AGENT_NAME" || true)"
      if [[ -z "$CAPTURE_PID" ]]; then
        echo "Could not find DeepFlow agent container matching name=$DEEPFLOW_AGENT_NAME" >&2
        exit 1
      fi
      log "Monitoring DeepFlow agent pid=$CAPTURE_PID; assuming it is already running"
      ;;
    *)
      echo "Unsupported mode=$mode; use baseline, pcap, ebpf, tls-uprobe, or deepflow" >&2
      exit 1
      ;;
  esac
}

run_load() {
  local mode="$1"
  local repeat_idx="$2"
  local run_dir="$3"
  python3 "$ROOT_DIR/services/bookinfo/uniform_bookinfo_load.py" \
    "$TARGET_URL" \
    -c "$CONNECTIONS" \
    -R "$RATE" \
    -d "$DURATION" \
    --book-count "$BOOK_COUNT" \
    --id-mode "$ID_MODE" \
    --seed "$((SEED + repeat_idx))" \
    --mark-prefix "$MARK_PREFIX-$mode-r$repeat_idx" \
    --json-out "$run_dir/loadgen.json" \
    >"$run_dir/loadgen.log" 2>&1
}

append_summary() {
  local mode="$1"
  local repeat_idx="$2"
  local collector_pid="$3"
  local host_total_before="$4"
  local host_idle_before="$5"
  local host_total_after="$6"
  local host_idle_after="$7"
  local proc_ticks_before="$8"
  local proc_ticks_after="$9"
  local run_dir="${10}"
  local rss_samples="${11}"

  python3 - "$SUMMARY_CSV" "$RATE" "$mode" "$repeat_idx" "$collector_pid" \
    "$host_total_before" "$host_idle_before" "$host_total_after" "$host_idle_after" \
    "$proc_ticks_before" "$proc_ticks_after" "$run_dir/loadgen.json" "$DURATION" "$rss_samples" <<'PY'
import csv
import json
import os
import sys

summary, rate, mode, repeat_idx, collector_pid = sys.argv[1:6]
host_total_before, host_idle_before, host_total_after, host_idle_after = map(float, sys.argv[6:10])
proc_ticks_before, proc_ticks_after = map(float, sys.argv[10:12])
loadgen_path, duration_text, rss_samples_path = sys.argv[12:15]

host_delta = max(host_total_after - host_total_before, 1.0)
host_busy_delta = max((host_total_after - host_idle_after) - (host_total_before - host_idle_before), 0.0)
host_busy_pct = host_busy_delta / host_delta * 100.0

def duration_to_seconds(value: str) -> float:
    value = value.strip().lower()
    if value.endswith("ms"):
        return float(value[:-2]) / 1000.0
    if value.endswith("s"):
        return float(value[:-1])
    if value.endswith("m"):
        return float(value[:-1]) * 60.0
    return float(value)

elapsed = duration_to_seconds(duration_text)
clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
proc_cpu_pct = max(proc_ticks_after - proc_ticks_before, 0.0) / clk_tck / max(elapsed, 1e-9) * 100.0

loadgen = {}
if os.path.exists(loadgen_path):
    with open(loadgen_path, encoding="utf-8") as f:
        loadgen = json.load(f)

rss_values = []
if os.path.exists(rss_samples_path):
    with open(rss_samples_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rss_values.append(float(line) / 1024.0)

latency = loadgen.get("latency_ms") or {}
start_lag = loadgen.get("start_lag_ms") or {}
request_latencies = [
    float(item.get("latency_ms", 0.0))
    for item in loadgen.get("requests", [])
    if item.get("latency_ms") is not None
]
latency_mean_ms = sum(request_latencies) / len(request_latencies) if request_latencies else 0.0
row = {
    "rate": rate,
    "mode": mode,
    "repeat": repeat_idx,
    "collector_pid": collector_pid,
    "host_busy_pct": f"{host_busy_pct:.3f}",
    "collector_process_cpu_pct": f"{proc_cpu_pct:.3f}",
    "collector_rss_peak_mb": f"{max(rss_values) if rss_values else 0.0:.3f}",
    "collector_rss_mean_mb": f"{sum(rss_values) / len(rss_values) if rss_values else 0.0:.3f}",
    "requests": loadgen.get("total_requests", loadgen.get("ok_requests", "")),
    "ok_requests": loadgen.get("ok_requests", ""),
    "errors": loadgen.get("errors", ""),
    "actual_requests_sec": f"{float(loadgen.get('actual_requests_sec', 0.0)):.3f}",
    "latency_mean_ms": f"{latency_mean_ms:.3f}",
    "latency_p50_ms": f"{float(latency.get('p50', 0.0)):.3f}",
    "latency_p90_ms": f"{float(latency.get('p90', 0.0)):.3f}",
    "latency_p99_ms": f"{float(latency.get('p99', 0.0)):.3f}",
    "start_lag_p99_ms": f"{float(start_lag.get('p99', 0.0)):.3f}",
}

exists = os.path.exists(summary) and os.path.getsize(summary) > 0
with open(summary, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(row))
    if not exists:
        writer.writeheader()
    writer.writerow(row)
print(row)
PY
}

main() {
  need_cmd python3
  need_cmd curl
  need_cmd sudo
  mkdir -p "$OUT_DIR"

  if [[ "$MODES" == *"pcap"* ]]; then
    need_cmd tcpdump
  fi
  if [[ "$MODES" == *"deepflow"* ]]; then
    need_cmd docker
  fi
  if [[ "$MODES" == *"ebpf"* && ! -x "$EBPF_COLLECTOR" ]]; then
    echo "Missing executable eBPF collector: $EBPF_COLLECTOR" >&2
    exit 1
  fi
  if [[ "$MODES" == *"tls-uprobe"* && ! -x "$TLS_UPROBE_COLLECTOR" ]]; then
    echo "Missing executable TLS uprobe collector: $TLS_UPROBE_COLLECTOR" >&2
    exit 1
  fi

  log "Checking workload target: $TARGET_URL"
  curl -fsS --max-time 5 "$TARGET_URL/productpage?id=0" >/dev/null
  sudo -n true 2>/dev/null || sudo -v

  : > "$SUMMARY_CSV"
  for repeat_idx in $(seq 1 "$REPEAT"); do
    for mode in $MODES; do
      local run_dir="$OUT_DIR/${mode}_r${repeat_idx}"
      mkdir -p "$run_dir"
      log "=== mode=$mode repeat=$repeat_idx ==="
      start_capture "$mode" "$run_dir"
      local collector_pid="${CAPTURE_PID:-0}"
      read -r host_total_before host_idle_before < <(read_host_cpu)
      local proc_ticks_before=0
      if [[ -n "$collector_pid" && "$collector_pid" != "0" ]]; then
        proc_ticks_before="$(read_proc_cpu_ticks "$collector_pid")"
      fi
      local rss_samples="$run_dir/collector_rss_kb.samples"
      local rss_sampler_pid=""
      sample_collector_memory "$mode" "$collector_pid" "$rss_samples" &
      rss_sampler_pid=$!
      run_load "$mode" "$repeat_idx" "$run_dir"
      if [[ -n "$rss_sampler_pid" ]]; then
        kill "$rss_sampler_pid" 2>/dev/null || true
        wait "$rss_sampler_pid" 2>/dev/null || true
      fi
      read -r host_total_after host_idle_after < <(read_host_cpu)
      local proc_ticks_after=0
      if [[ -n "$collector_pid" && "$collector_pid" != "0" ]]; then
        proc_ticks_after="$(read_proc_cpu_ticks "$collector_pid")"
      fi
      if [[ "$mode" != "deepflow" ]]; then
        stop_capture
      else
        CAPTURE_PID=""
        CAPTURE_LABEL=""
      fi
      append_summary "$mode" "$repeat_idx" "$collector_pid" \
        "$host_total_before" "$host_idle_before" "$host_total_after" "$host_idle_after" \
        "$proc_ticks_before" "$proc_ticks_after" "$run_dir" "$rss_samples"
      sleep "$BETWEEN_RUN_SECONDS"
    done
  done
  log "Wrote $SUMMARY_CSV"
}

main "$@"
