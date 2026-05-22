#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOTEL_DIR="$ROOT_DIR/services/hotelReservation_http1.1"
RUN_DEEPFLOW="${RUN_DEEPFLOW:-0}"
for arg in "$@"; do
  case "$arg" in
    deepflow|--deepflow)
      RUN_DEEPFLOW=1
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/run_hotel_http1_exp.sh [deepflow|--deepflow]

Environment variables:
  CAPTURE_MODE=pcap|ebpf
  EBPF_CAPTURE_PORTS=$HOTEL_HTTP1_PORTS          # adds 27017 automatically when EBPF_ENABLE_DB_ROWS=1
  EBPF_ENABLE_DB_ROWS=0|1
  OUT_DIR=result/hotel_http1_exp
  CONNECTIONS_LIST="1 2 5 10 20 50 100"
  RATE=500
  RATE_LIST=""                  # when set, paired with CONNECTIONS_LIST
  DURATION=5s
  TARGET_URL=http://127.0.0.1:5000
  CAPTURE_DRAIN_SECONDS=5
  CLEAN_HOTEL_STACK=1        # docker compose down -v before docker compose up
  REBUILD_STACK=1            # legacy alias for CLEAN_HOTEL_STACK
  RESTART_SERVICES_AT_START=1  # start consul and restart app services before workload
  RUN_TRACEWEAVER=1|0
  RUN_DEEPFLOW=0|1
  DEEPFLOW_API_URL=http://127.0.0.1:20416/v1/query/
  DEEPFLOW_APP_URL=http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing
  DEEPFLOW_EVAL_MODE=api|local
  DEEPFLOW_APP_SOURCE=baseline/deepflow/deepflow-app-source
  DEEPFLOW_SERVICE_MAP=$OUT_DIR/service_map.json
  DEEPFLOW_GENERATE_SERVICE_MAP=1
  DEEPFLOW_L7_HTTP_PORTS=$HOTEL_HTTP1_PORTS   # must be set before starting deepflow_stack_capture.sh
  DEEPFLOW_L7_HTTP2_PORTS=$HOTEL_HTTP1_PORTS  # must be set before starting deepflow_stack_capture.sh
  DEEPFLOW_TRACE_CONCURRENCY=8
  DEEPFLOW_LOCAL_PROCESS_WORKERS=8
  DEEPFLOW_WAIT_MODE=adaptive
  DEEPFLOW_LOCAL_FLUSH_SECONDS=10
  DEEPFLOW_MIN_WAIT_SECONDS=5
  DEEPFLOW_MAX_WAIT_SECONDS=45
  DEEPFLOW_INGEST_POLL_SECONDS=3
  DEEPFLOW_INGEST_EXPECTED_RATIO=1.0

The script runs one shared Hotel HTTP/1.1 workload per connection/RPS pair.
Lineage and TraceWeaver read the same pcap-derived CSV. DeepFlow, when
enabled, is scored with its native L7FlowTracing API against the same X-Mark
load report.
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Use --help for usage." >&2
      exit 1
      ;;
  esac
done

OUT_DIR="${OUT_DIR:-$ROOT_DIR/result/hotel_http1_exp}"
SUMMARY_CSV="${SUMMARY_CSV:-$OUT_DIR/summary.csv}"
TRACEFUSION="${TRACEFUSION:-$ROOT_DIR/src/tracefusion.py}"
CAPTURE_MODE="${CAPTURE_MODE:-pcap}"
CONNECTIONS_LIST="${CONNECTIONS_LIST:-1 2 5 10 20 50 100}"
DURATION="${DURATION:-5s}"
RATE="${RATE:-500}"
RATE_LIST="${RATE_LIST:-}"
RUN_TRACEWEAVER="${RUN_TRACEWEAVER:-1}"
SEED="${SEED:-42}"
WARMUP_SECONDS="${WARMUP_SECONDS:-40}"
BETWEEN_RUN_SECONDS="${BETWEEN_RUN_SECONDS:-5}"
CAPTURE_DRAIN_SECONDS="${CAPTURE_DRAIN_SECONDS:-5}"
TARGET_URL="${TARGET_URL:-http://127.0.0.1:5000}"
MARK_PREFIX="${MARK_PREFIX:-hotel-http1-$(date +%Y%m%d_%H%M%S)}"
REBUILD_STACK="${REBUILD_STACK:-1}"
CLEAN_HOTEL_STACK="${CLEAN_HOTEL_STACK:-$REBUILD_STACK}"
RESTART_SERVICES_AT_START="${RESTART_SERVICES_AT_START:-1}"
EXPECTED_TRACE_COUNT="${EXPECTED_TRACE_COUNT:-0}"
SPAN_FORM="${SPAN_FORM:-rpc}"

TCPDUMP_IFACE="${TCPDUMP_IFACE:-any}"
HOTEL_HTTP1_PORTS="${HOTEL_HTTP1_PORTS:-5000,8081,8082,8083,8084,8085,8086,8087,8088,8089}"
HOTEL_TCPDUMP_FILTER="${HOTEL_TCPDUMP_FILTER:-tcp port 5000 or tcp port 8081 or tcp port 8082 or tcp port 8083 or tcp port 8084 or tcp port 8085 or tcp port 8086 or tcp port 8087 or tcp port 8088 or tcp port 8089}"
EBPF_COLLECTOR="${EBPF_COLLECTOR:-$ROOT_DIR/collector/ebpf/cgroup_net/target/release/cgroup}"
EBPF_IGNORED_PORTS="${EBPF_IGNORED_PORTS:-14250,16686}"
EBPF_COLLECTOR_PROTOCOL="${EBPF_COLLECTOR_PROTOCOL:-http1}"
EBPF_COLLECTOR_QUIET="${EBPF_COLLECTOR_QUIET:-1}"
EBPF_ENABLE_DB_ROWS="${EBPF_ENABLE_DB_ROWS:-0}"
if [[ -z "${EBPF_CAPTURE_PORTS:-}" ]]; then
  if [[ "$EBPF_ENABLE_DB_ROWS" == "1" ]]; then
    EBPF_CAPTURE_PORTS="$HOTEL_HTTP1_PORTS,27017"
  else
    EBPF_CAPTURE_PORTS="$HOTEL_HTTP1_PORTS"
  fi
fi

DEEPFLOW_API_URL="${DEEPFLOW_API_URL:-http://127.0.0.1:20416/v1/query/}"
DEEPFLOW_APP_URL="${DEEPFLOW_APP_URL:-http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing}"
DEEPFLOW_EVAL_MODE="${DEEPFLOW_EVAL_MODE:-local}"
DEEPFLOW_APP_SOURCE="${DEEPFLOW_APP_SOURCE:-$ROOT_DIR/baseline/deepflow/deepflow-app-source}"
DEEPFLOW_SERVICE_MAP="${DEEPFLOW_SERVICE_MAP:-$OUT_DIR/service_map.json}"
DEEPFLOW_GENERATE_SERVICE_MAP="${DEEPFLOW_GENERATE_SERVICE_MAP:-1}"
DEEPFLOW_DB="${DEEPFLOW_DB:-flow_log}"
DEEPFLOW_TABLE="${DEEPFLOW_TABLE:-l7_flow_log}"
DEEPFLOW_NAMESPACE="${DEEPFLOW_NAMESPACE:-hotel-http1}"
DEEPFLOW_MAX_ITERATION="${DEEPFLOW_MAX_ITERATION:-6}"
DEEPFLOW_TRACE_CONCURRENCY="${DEEPFLOW_TRACE_CONCURRENCY:-8}"
DEEPFLOW_LOCAL_PROCESS_WORKERS="${DEEPFLOW_LOCAL_PROCESS_WORKERS:-8}"
DEEPFLOW_WINDOW_PADDING_SECONDS="${DEEPFLOW_WINDOW_PADDING_SECONDS:-30}"
DEEPFLOW_WAIT_SECONDS="${DEEPFLOW_WAIT_SECONDS:-45}"
DEEPFLOW_WAIT_MODE="${DEEPFLOW_WAIT_MODE:-adaptive}"
DEEPFLOW_LOCAL_FLUSH_SECONDS="${DEEPFLOW_LOCAL_FLUSH_SECONDS:-10}"
DEEPFLOW_MIN_WAIT_SECONDS="${DEEPFLOW_MIN_WAIT_SECONDS:-5}"
DEEPFLOW_MAX_WAIT_SECONDS="${DEEPFLOW_MAX_WAIT_SECONDS:-$DEEPFLOW_WAIT_SECONDS}"
DEEPFLOW_INGEST_POLL_SECONDS="${DEEPFLOW_INGEST_POLL_SECONDS:-3}"
DEEPFLOW_INGEST_EXPECTED_RATIO="${DEEPFLOW_INGEST_EXPECTED_RATIO:-1.0}"
DEEPFLOW_EXPECTED_ROWS_PER_OCCURRENCE="${DEEPFLOW_EXPECTED_ROWS_PER_OCCURRENCE:-2}"
DEEPFLOW_ANCHOR_EDGE="${DEEPFLOW_ANCHOR_EDGE:-frontend->search}"
DEEPFLOW_L7_HTTP_PORTS="${DEEPFLOW_L7_HTTP_PORTS:-$HOTEL_HTTP1_PORTS}"
DEEPFLOW_L7_HTTP2_PORTS="${DEEPFLOW_L7_HTTP2_PORTS:-$HOTEL_HTTP1_PORTS}"

CAPTURE_PID=""

log() {
  printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$*"
}

stop_capture() {
  if [[ -n "${CAPTURE_PID:-}" ]] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
    log "Stopping ${CAPTURE_MODE} capture pid=$CAPTURE_PID"
    sudo kill -INT "$CAPTURE_PID" 2>/dev/null || kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
  fi
  CAPTURE_PID=""
}

cleanup() {
  stop_capture
}
trap cleanup EXIT INT TERM

restart_hotel_services() {
  log "Ensuring Hotel Consul is running"
  (
    cd "$HOTEL_DIR"
    docker compose up -d consul
  )

  log "Restarting Hotel application services for fresh Consul registration"
  (
    cd "$HOTEL_DIR"
    docker compose restart \
      frontend \
      profile \
      search \
      geo \
      rate \
      recommendation \
      user \
      reservation
  )
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1" >&2
    exit 1
  fi
}

wait_for_frontend() {
  local deadline=$((SECONDS + WARMUP_SECONDS))
  while (( SECONDS < deadline )); do
    if curl -fsS "$TARGET_URL/hotels?inDate=2015-04-10&outDate=2015-04-11&lat=37.7879&lon=-122.4075" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Hotel frontend did not become reachable at $TARGET_URL within ${WARMUP_SECONDS}s" >&2
  return 1
}

wait_for_deepflow() {
  local deadline=$((SECONDS + WARMUP_SECONDS))
  while (( SECONDS < deadline )); do
    if python3 - "$DEEPFLOW_API_URL" "$DEEPFLOW_APP_URL" "$DEEPFLOW_DB" "$DEEPFLOW_TABLE" >/dev/null 2>&1 <<'PY'
import json
import sys
import urllib.parse
import urllib.request

api_url, app_url, db, table = sys.argv[1:5]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
body = urllib.parse.urlencode({"db": db, "sql": "SELECT time FROM l7_flow_log LIMIT 1"}).encode()
request = urllib.request.Request(api_url, data=body, method="POST")
with opener.open(request, timeout=3) as response:
    data = json.loads(response.read().decode())
if data.get("OPT_STATUS") != "SUCCESS":
    raise SystemExit(1)

payload = {
    "_id": "0",
    "time_start": 0,
    "time_end": 1,
    "database": db,
    "table": table,
    "has_attributes": 1,
    "max_iteration": 1,
    "network_delay_us": 50000,
}
request = urllib.request.Request(
    app_url,
    data=json.dumps(payload).encode(),
    method="POST",
    headers={"Content-Type": "application/json"},
)
with opener.open(request, timeout=3) as response:
    data = json.loads(response.read().decode())
if data.get("OPT_STATUS") not in {"SUCCESS", "PARTIAL_RESULT"}:
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 2
  done
  echo "DeepFlow endpoints are not reachable: $DEEPFLOW_API_URL / $DEEPFLOW_APP_URL" >&2
  return 1
}

wait_for_deepflow_ingestion() {
  local label="$1"
  local loadgen_report="$2"
  local mark_prefix="$3"
  local expected_count="$4"

  if [[ "$RUN_DEEPFLOW" != "1" ]]; then
    return 0
  fi

  if [[ "$DEEPFLOW_EVAL_MODE" == "local" ]]; then
    log "=== $label: waiting ${DEEPFLOW_LOCAL_FLUSH_SECONDS}s for DeepFlow agent flush ==="
    sleep "$DEEPFLOW_LOCAL_FLUSH_SECONDS"
    return 0
  fi

  if [[ "$DEEPFLOW_WAIT_MODE" == "fixed" ]]; then
    log "=== $label: waiting ${DEEPFLOW_WAIT_SECONDS}s for DeepFlow ingestion ==="
    sleep "$DEEPFLOW_WAIT_SECONDS"
    return 0
  fi

  log "=== $label: waiting for DeepFlow ingestion (min=${DEEPFLOW_MIN_WAIT_SECONDS}s max=${DEEPFLOW_MAX_WAIT_SECONDS}s prefix=$mark_prefix) ==="
  python3 - \
    "$DEEPFLOW_API_URL" \
    "$DEEPFLOW_DB" \
    "$loadgen_report" \
    "$mark_prefix" \
    "$expected_count" \
    "$DEEPFLOW_WINDOW_PADDING_SECONDS" \
    "$DEEPFLOW_MIN_WAIT_SECONDS" \
    "$DEEPFLOW_MAX_WAIT_SECONDS" \
    "$DEEPFLOW_INGEST_POLL_SECONDS" \
    "$DEEPFLOW_INGEST_EXPECTED_RATIO" <<'PY'
import json
import math
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

api_url, db, loadgen_report, mark_prefix = sys.argv[1:5]
expected_count = int(sys.argv[5])
padding = int(float(sys.argv[6]))
min_wait = max(0.0, float(sys.argv[7]))
max_wait = max(min_wait, float(sys.argv[8]))
poll_seconds = max(0.5, float(sys.argv[9]))
expected_ratio = max(0.0, float(sys.argv[10]))

report = json.loads(Path(loadgen_report).read_text())
requests = report.get("requests") or []
if not requests or not mark_prefix or expected_count <= 0:
    time.sleep(min_wait)
    raise SystemExit(0)

start_ts = int(min(float(item["start_time"]) for item in requests)) - padding
end_ts = int(max(float(item["end_time"]) for item in requests)) + padding
target = max(1, math.ceil(expected_count * expected_ratio))
prefix = mark_prefix.replace("'", "''").replace("\\", "\\\\")
sql = (
    "SELECT count(1) AS matched_rows FROM l7_flow_log "
    f"WHERE time >= {start_ts} AND time <= {end_ts} "
    f"AND (attribute LIKE '%{prefix}%' OR request_resource LIKE '%{prefix}%')"
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def query_count() -> int:
    body = urllib.parse.urlencode({"db": db, "sql": sql}).encode()
    request = urllib.request.Request(api_url, data=body, method="POST")
    with opener.open(request, timeout=5) as response:
        data = json.loads(response.read().decode())
    if data.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError(data.get("DESCRIPTION") or json.dumps(data)[:500])
    values = ((data.get("result") or {}).get("values") or [])
    if not values or not values[0]:
        return 0
    return int(values[0][0] or 0)

deadline = time.time() + max_wait
time.sleep(min_wait)
last_count = 0
while True:
    try:
        last_count = query_count()
    except Exception as exc:
        print(f"DeepFlow ingestion poll failed: {exc}", file=sys.stderr)
    if last_count >= target:
        print(f"DeepFlow ingestion ready: matched_rows={last_count}, target={target}")
        raise SystemExit(0)
    if time.time() >= deadline:
        print(f"DeepFlow ingestion wait timed out: matched_rows={last_count}, target={target}", file=sys.stderr)
        raise SystemExit(0)
    time.sleep(poll_seconds)
PY
}

loadgen_request_count() {
  local loadgen_report="$1"
  python3 - "$loadgen_report" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
requests = report.get("requests") or []
count = len(requests) or report.get("completed") or report.get("completed_requests") or report.get("count") or report.get("target_requests") or 0
print(int(count))
PY
}

generate_hotel_service_map() {
  local output="$1"
  mkdir -p "$(dirname "$output")"
  python3 - "$output" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

output = Path(sys.argv[1])
excluded = {
    "consul",
    "mongodb-geo",
    "mongodb-profile",
    "mongodb-rate",
    "mongodb-recommendation",
    "mongodb-reservation",
    "mongodb-user",
    "memcached-profile",
    "memcached-rate",
    "memcached-reserve",
}
service_map = {}
ids = subprocess.check_output(["docker", "ps", "-q"], text=True).splitlines()
for cid in ids:
    data = json.loads(subprocess.check_output(["docker", "inspect", cid], text=True))[0]
    networks = (data.get("NetworkSettings") or {}).get("Networks") or {}
    if "hotelreservation-net" not in networks:
        continue
    labels = (data.get("Config") or {}).get("Labels") or {}
    service = labels.get("com.docker.compose.service") or data.get("Name", "").lstrip("/")
    if service in excluded:
        continue
    ip = networks["hotelreservation-net"].get("IPAddress")
    if ip:
        service_map[ip] = {"service": service, "namespace": "hotel-http1"}
if not service_map:
    raise SystemExit("could not generate Hotel service map; no app containers on hotelreservation-net")
output.write_text(json.dumps(service_map, indent=2, sort_keys=True) + "\n")
print(f"wrote {output} with {len(service_map)} entries")
PY
}

generate_expected_edges() {
  local cleaned_csv="$1"
  local service_map="$2"
  local expected_edges_out="$3"
  local expected_counts_out="$4"
  python3 - "$cleaned_csv" "$service_map" "$expected_edges_out" "$expected_counts_out" "$DEEPFLOW_EXPECTED_ROWS_PER_OCCURRENCE" <<'PY'
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

cleaned_csv, service_map_path, edges_out, counts_out, rows_per_occurrence = sys.argv[1:6]
rows_per_occurrence = int(rows_per_occurrence)
raw_map = json.loads(Path(service_map_path).read_text())
service_by_ip = {ip: value["service"] if isinstance(value, dict) else str(value) for ip, value in raw_map.items()}

by_trace = defaultdict(Counter)
with open(cleaned_csv, newline="") as f:
    for row in csv.DictReader(f):
        if row.get("msg_type") != "Request" or not row.get("trace_id"):
            continue
        client_ip = row.get("client", "").split(":")[0]
        server_ip = row.get("server", "").split(":")[0]
        client = service_by_ip.get(client_ip)
        server = service_by_ip.get(server_ip)
        if not client or not server:
            continue
        by_trace[row["trace_id"]][(client, server)] += 1

all_edges = sorted({edge for counts in by_trace.values() for edge in counts})
if not all_edges:
    raise SystemExit("could not derive expected Hotel edges from cleaned CSV and service map")
edge_counts = {}
for edge in all_edges:
    values = [counts[edge] for counts in by_trace.values()]
    mode_count = Counter(values).most_common(1)[0][0]
    edge_counts[edge] = mode_count * rows_per_occurrence

Path(edges_out).write_text(",".join(f"{a}->{b}" for a, b in all_edges) + "\n")
Path(counts_out).write_text(",".join(f"{a}->{b}={edge_counts[(a, b)]}" for a, b in all_edges) + "\n")
print(f"expected_edges={len(all_edges)} traces={len(by_trace)} rows_per_occurrence={rows_per_occurrence}")
PY
}

write_traceweaver_failure_report() {
  local output="$1"
  local status="$2"
  python3 - "$output" "$status" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({
    "status": "failed",
    "exit_status": int(sys.argv[2]),
    "end_to_end_accuracy": {
        "correct": 0,
        "total": 0,
        "accuracy_pct": 0.0,
        "full_trace_accuracy_pct": 0.0,
        "full_trace_accuracy_ok": 0,
        "full_trace_accuracy_total": 0,
        "trace_assignment_accuracy_pct": 0.0,
        "trace_assignment_accuracy_ok": 0,
        "trace_assignment_accuracy_total": 0,
        "span_accuracy_pct": 0.0,
        "span_accuracy_ok": 0,
        "span_accuracy_total": 0,
        "coverage_pct": 0.0,
        "coverage_ok": 0,
        "coverage_total": 0,
        "parent_child_edge_precision_pct": 0.0,
        "parent_child_edge_recall_pct": 0.0,
        "parent_child_edge_f1_pct": 0.0,
        "parent_child_edge_correct": 0,
        "parent_child_edge_predicted": 0,
        "parent_child_edge_ground_truth": 0,
    },
}, indent=2) + "\n")
PY
}

extract_metrics() {
  python3 - "$@" <<'PY'
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

rate, connections, cleaned_path, lineage_path, traceweaver_path, loadgen_path, deepflow_path = sys.argv[1:8]
cleaned_path = Path(cleaned_path)
lineage = json.loads(Path(lineage_path).read_text())
traceweaver = json.loads(Path(traceweaver_path).read_text()) if Path(traceweaver_path).exists() else {}
tw_e2e = traceweaver.get("end_to_end_accuracy", {})
loadgen = json.loads(Path(loadgen_path).read_text())
deepflow = json.loads(Path(deepflow_path).read_text()) if Path(deepflow_path).exists() else {}

rows = list(csv.DictReader(cleaned_path.open(newline="")))
traces = {row["trace_id"] for row in rows if row.get("trace_id")}
fmt = "%Y-%m-%d %H:%M:%S.%f"
server_hosts = {row["server"].split(":")[0] for row in rows if row.get("server")}
client_hosts = {row["client"].split(":")[0] for row in rows if row.get("client")}
external_clients = client_hosts - server_hosts
root_counter = Counter()
for row in rows:
    if row.get("msg_type") == "Request":
        client = row.get("client", "").split(":")[0]
        server = row.get("server", "").split(":")[0]
        if client in external_clients and server:
            root_counter[server] += 1
root_ip = root_counter.most_common(1)[0][0] if root_counter else ""

by_trace = defaultdict(list)
for row in rows:
    if row.get("trace_id"):
        by_trace[row["trace_id"]].append(row)
intervals = []
for trace_rows in by_trace.values():
    starts = []
    ends = []
    for row in trace_rows:
        if row.get("msg_type") not in {"Request", "Response"}:
            continue
        client = row.get("client", "").split(":")[0]
        server = row.get("server", "").split(":")[0]
        if client not in external_clients or server != root_ip:
            continue
        ts = datetime.strptime(row["timestamp"], fmt).timestamp() * 1_000_000
        (starts if row["msg_type"] == "Request" else ends).append(ts)
    if starts and ends:
        intervals.append((min(starts), max(ends)))

points = []
durations_ms = []
for start, end in intervals:
    points.append((start, 1))
    points.append((end, -1))
    durations_ms.append((end - start) / 1000.0)
points.sort()
current = 0
max_concurrency = 0
for _, delta in points:
    current += delta
    max_concurrency = max(max_concurrency, current)

def percentile(values, q):
    if not values:
        return 0.0
    values = sorted(values)
    return values[int((len(values) - 1) * q)]

row = {
    "rate": rate,
    "connections": connections,
    "root_ip": root_ip,
    "root_trace_count": len(traces),
    "root_max_concurrency": max_concurrency,
    "root_duration_p50_ms": round(percentile(durations_ms, 0.5), 3),
    "lineage_full_accuracy_pct": lineage.get("accuracy_pct", 0.0),
    "lineage_full_correct": lineage.get("accuracy_ok", 0),
    "lineage_total": lineage.get("root_trace_count", 0),
    "lineage_trace_assignment_accuracy_pct": lineage.get("trace_assignment_accuracy_pct", ""),
    "lineage_trace_assignment_correct": lineage.get("trace_assignment_accuracy_ok", ""),
    "lineage_trace_assignment_total": lineage.get("trace_assignment_accuracy_total", ""),
    "lineage_root_direct_accuracy_pct": lineage.get("root_direct_accuracy_pct", ""),
    "lineage_span_accuracy_pct": lineage.get("edge_accuracy_pct", ""),
    "lineage_span_correct": lineage.get("edge_accuracy_ok", ""),
    "lineage_span_total": lineage.get("edge_accuracy_total", ""),
    "lineage_coverage_pct": lineage.get("coverage_pct", ""),
    "lineage_coverage_correct": lineage.get("coverage_ok", ""),
    "lineage_coverage_total": lineage.get("coverage_total", ""),
    "lineage_parent_child_edge_precision_pct": lineage.get("parent_child_edge_precision_pct", ""),
    "lineage_parent_child_edge_recall_pct": lineage.get("parent_child_edge_recall_pct", ""),
    "lineage_parent_child_edge_f1_pct": lineage.get("parent_child_edge_f1_pct", ""),
    "lineage_parent_child_edge_correct": lineage.get("parent_child_edge_correct", ""),
    "lineage_parent_child_edge_predicted": lineage.get("parent_child_edge_predicted", ""),
    "lineage_parent_child_edge_ground_truth": lineage.get("parent_child_edge_ground_truth", ""),
    "traceweaver_status": traceweaver.get("status", "ok" if traceweaver else ""),
    "traceweaver_full_accuracy_pct": tw_e2e.get("accuracy_pct", ""),
    "traceweaver_correct": tw_e2e.get("correct", ""),
    "traceweaver_total": tw_e2e.get("total", ""),
    "traceweaver_trace_assignment_accuracy_pct": tw_e2e.get("trace_assignment_accuracy_pct", ""),
    "traceweaver_trace_assignment_correct": tw_e2e.get("trace_assignment_accuracy_ok", ""),
    "traceweaver_trace_assignment_total": tw_e2e.get("trace_assignment_accuracy_total", ""),
    "traceweaver_span_accuracy_pct": tw_e2e.get("span_accuracy_pct", ""),
    "traceweaver_span_correct": tw_e2e.get("span_accuracy_ok", ""),
    "traceweaver_span_total": tw_e2e.get("span_accuracy_total", ""),
    "traceweaver_coverage_pct": tw_e2e.get("coverage_pct", ""),
    "traceweaver_coverage_correct": tw_e2e.get("coverage_ok", ""),
    "traceweaver_coverage_total": tw_e2e.get("coverage_total", ""),
    "traceweaver_parent_child_edge_precision_pct": tw_e2e.get("parent_child_edge_precision_pct", ""),
    "traceweaver_parent_child_edge_recall_pct": tw_e2e.get("parent_child_edge_recall_pct", ""),
    "traceweaver_parent_child_edge_f1_pct": tw_e2e.get("parent_child_edge_f1_pct", ""),
    "traceweaver_parent_child_edge_correct": tw_e2e.get("parent_child_edge_correct", ""),
    "traceweaver_parent_child_edge_predicted": tw_e2e.get("parent_child_edge_predicted", ""),
    "traceweaver_parent_child_edge_ground_truth": tw_e2e.get("parent_child_edge_ground_truth", ""),
    "loadgen_actual_requests_sec": loadgen.get("actual_requests_sec", ""),
    "loadgen_errors": loadgen.get("errors", ""),
    "loadgen_ok_requests": loadgen.get("ok_requests", ""),
    "loadgen_target_requests": loadgen.get("target_requests", ""),
    "deepflow_trace_exact_pct": deepflow.get("trace_exact_pct_of_requested", ""),
    "deepflow_trace_exact": deepflow.get("trace_exact_count", ""),
    "deepflow_requested": deepflow.get("requested_count", ""),
    "deepflow_success": deepflow.get("deepflow_trace_success_count", ""),
    "deepflow_full_accuracy_pct": deepflow.get("full_trace_accuracy_pct", deepflow.get("trace_exact_pct_of_requested", "")),
    "deepflow_full_correct": deepflow.get("full_trace_accuracy_ok", deepflow.get("trace_exact_count", "")),
    "deepflow_full_total": deepflow.get("full_trace_accuracy_total", deepflow.get("requested_count", "")),
    "deepflow_trace_assignment_accuracy_pct": deepflow.get("trace_assignment_accuracy_pct", ""),
    "deepflow_trace_assignment_correct": deepflow.get("trace_assignment_accuracy_ok", ""),
    "deepflow_trace_assignment_total": deepflow.get("trace_assignment_accuracy_total", ""),
    "deepflow_span_accuracy_pct": deepflow.get("span_accuracy_pct", ""),
    "deepflow_span_correct": deepflow.get("span_accuracy_ok", ""),
    "deepflow_span_total": deepflow.get("span_accuracy_total", ""),
    "deepflow_coverage_pct": deepflow.get("coverage_pct", ""),
    "deepflow_coverage_correct": deepflow.get("coverage_ok", ""),
    "deepflow_coverage_total": deepflow.get("coverage_total", ""),
    "deepflow_parent_child_edge_precision_pct": deepflow.get("parent_child_edge_precision_pct", ""),
    "deepflow_parent_child_edge_recall_pct": deepflow.get("parent_child_edge_recall_pct", ""),
    "deepflow_parent_child_edge_f1_pct": deepflow.get("parent_child_edge_f1_pct", ""),
    "deepflow_parent_child_edge_correct": deepflow.get("parent_child_edge_correct", ""),
    "deepflow_parent_child_edge_predicted": deepflow.get("parent_child_edge_predicted", ""),
    "deepflow_parent_child_edge_ground_truth": deepflow.get("parent_child_edge_ground_truth", ""),
    "deepflow_anchors": deepflow.get("anchor_marks_found", ""),
    "deepflow_business_span_distribution": json.dumps(deepflow.get("business_span_count_distribution", {}), sort_keys=True),
    "deepflow_span_capture_missing_traces": deepflow.get("span_capture_missing_trace_count", ""),
    "deepflow_span_capture_missing_spans": deepflow.get("span_capture_missing_total_spans", ""),
    "deepflow_span_pairing_error_traces": deepflow.get("span_pairing_error_trace_count", ""),
    "deepflow_span_pairing_missing_spans": deepflow.get("span_pairing_missing_total_spans", ""),
    "deepflow_span_pairing_extra_spans": deepflow.get("span_pairing_extra_total_spans", ""),
    "deepflow_wrong_mark_spans": deepflow.get("wrong_mark_span_count", ""),
    "deepflow_elapsed_seconds": deepflow.get("elapsed_seconds", ""),
}
writer = csv.DictWriter(sys.stdout, fieldnames=list(row), lineterminator="\n")
writer.writerow(row)
PY
}

run_one() {
  local connections="$1"
  local rate="$2"
  local label="conn_${connections}_rps_${rate}"
  local run_dir="$OUT_DIR/$label"
  mkdir -p "$run_dir"

  local pcap_path="$run_dir/traffic.pcap"
  local ebpf_raw_csv="$run_dir/ebpf_output.bin"
  local cleaned_csv="$run_dir/cleaned_data.csv"
  local capture_log="$run_dir/${CAPTURE_MODE}_capture.log"
  local parse_log="$run_dir/${CAPTURE_MODE}_to_cleaned.log"
  local lineage_log="$run_dir/lineage.log"
  local traceweaver_log="$run_dir/traceweaver.log"
  local deepflow_log="$run_dir/deepflow.log"
  local lineage_json="$run_dir/lineage_report.json"
  local traceweaver_json="$run_dir/traceweaver_baseline_report.json"
  local loadgen_log="$run_dir/loadgen.log"
  local loadgen_json="$run_dir/loadgen_report.json"
  local deepflow_json="$run_dir/deepflow_report.json"
  local expected_edges_file="$run_dir/deepflow_expected_edges.txt"
  local expected_counts_file="$run_dir/deepflow_expected_edge_counts.txt"
  local run_mark_prefix="${MARK_PREFIX}-${label}"

  log "=== $label: starting $CAPTURE_MODE capture ==="
  rm -f "$pcap_path" "$ebpf_raw_csv" "$cleaned_csv" "$lineage_json" "$traceweaver_json" "$deepflow_json" "$loadgen_json"
  if [[ "$CAPTURE_MODE" == "pcap" ]]; then
    (
      cd "$ROOT_DIR"
      exec sudo tcpdump -i "$TCPDUMP_IFACE" -s 0 -U -w "$pcap_path" "$HOTEL_TCPDUMP_FILTER"
    ) >"$capture_log" 2>&1 &
  else
    ebpf_args=(
      --output "$ebpf_raw_csv"
      --port "$EBPF_CAPTURE_PORTS"
      --ignored-port "$EBPF_IGNORED_PORTS"
      --protocol "$EBPF_COLLECTOR_PROTOCOL"
    )
    if [[ "$EBPF_COLLECTOR_QUIET" == "1" ]]; then
      ebpf_args+=(--quiet)
    fi
    (
      cd "$ROOT_DIR"
      exec sudo -n "$EBPF_COLLECTOR" "${ebpf_args[@]}"
    ) >"$capture_log" 2>&1 &
  fi
  CAPTURE_PID=$!
  sleep 2

  log "=== $label: running Hotel loadgen (-c $connections -R $rate -d $DURATION) ==="
  set +e
  python3 "$ROOT_DIR/services/hotelReservation_http1.1/uniform_hotel_load.py" \
    -c "$connections" \
    -d "$DURATION" \
    -R "$rate" \
    --seed "$SEED" \
    --mark-prefix "$run_mark_prefix" \
    --json-out "$loadgen_json" \
    "$TARGET_URL" \
    >"$loadgen_log" 2>&1
  local loadgen_status=$?
  set -e
  if [[ "$loadgen_status" -ne 0 ]]; then
    log "=== $label: loadgen exited with status $loadgen_status; continuing with captured data ==="
  fi

  if [[ "$CAPTURE_DRAIN_SECONDS" != "0" ]]; then
    log "=== $label: waiting ${CAPTURE_DRAIN_SECONDS}s before stopping capture ==="
    sleep "$CAPTURE_DRAIN_SECONDS"
  fi
  stop_capture

  log "=== $label: parsing $CAPTURE_MODE capture to cleaned CSV ==="
  if [[ "$CAPTURE_MODE" == "pcap" ]]; then
    python3 "$ROOT_DIR/src/pcap_to_cleaned.py" \
      --pcap "$pcap_path" \
      --cleaned-out "$cleaned_csv" \
      --expected-trace-count "$EXPECTED_TRACE_COUNT" \
      --span-form "$SPAN_FORM" \
      --http1-ports "$HOTEL_HTTP1_PORTS" \
      --http2-ports "" \
      >"$parse_log" 2>&1
  else
    ebpf_to_cleaned_args=(
      --input "$ebpf_raw_csv"
      --cleaned-out "$cleaned_csv"
      --expected-trace-count "$EXPECTED_TRACE_COUNT"
      --span-form "$SPAN_FORM"
    )
    if [[ "$EBPF_ENABLE_DB_ROWS" == "1" ]]; then
      ebpf_to_cleaned_args+=(--enable-db-rows)
    fi
    python3 "$ROOT_DIR/src/ebpf_to_cleaned.py" \
      "${ebpf_to_cleaned_args[@]}" \
      >"$parse_log" 2>&1
  fi

  log "=== $label: running lineage ==="
  python3 "$TRACEFUSION" \
    --csv-path "$cleaned_csv" \
    --json-out "$lineage_json" \
    >"$lineage_log" 2>&1

  if [[ "$RUN_TRACEWEAVER" == "1" ]]; then
    log "=== $label: running TraceWeaver baseline ==="
    set +e
    python3 "$ROOT_DIR/baseline/traceweaver/traceweaver_baseline.py" \
      --csv "$cleaned_csv" \
      --report-out "$traceweaver_json" \
      --quiet \
      >"$traceweaver_log" 2>&1
    local traceweaver_status=$?
    set -e
    if [[ "$traceweaver_status" -ne 0 ]]; then
      log "=== $label: TraceWeaver exited with status $traceweaver_status ==="
      write_traceweaver_failure_report "$traceweaver_json" "$traceweaver_status"
    fi
  else
    log "=== $label: skipping TraceWeaver baseline ==="
    write_traceweaver_failure_report "$traceweaver_json" 0
  fi

  if [[ "$RUN_DEEPFLOW" == "1" ]]; then
    generate_expected_edges "$cleaned_csv" "$DEEPFLOW_SERVICE_MAP" "$expected_edges_file" "$expected_counts_file"
    local deepflow_count
    deepflow_count="$(loadgen_request_count "$loadgen_json")"
    wait_for_deepflow_ingestion "$label" "$loadgen_json" "$run_mark_prefix" "$deepflow_count"
    if [[ "$DEEPFLOW_EVAL_MODE" == "local" ]]; then
      log "=== $label: running DeepFlow local batch L7FlowTracing accuracy (count=$deepflow_count) ==="
      python3 "$ROOT_DIR/baseline/deepflow/evaluate_deepflow_local_trace.py" \
        --load-report "$loadgen_json" \
        --output "$deepflow_json" \
        --api-url "$DEEPFLOW_API_URL" \
        --db "$DEEPFLOW_DB" \
        --namespace "$DEEPFLOW_NAMESPACE" \
        --mark-prefix "$run_mark_prefix" \
        --service-map "$DEEPFLOW_SERVICE_MAP" \
        --expected-edges "$(cat "$expected_edges_file")" \
        --expected-edge-counts "$(cat "$expected_counts_file")" \
        --anchor-edge "$DEEPFLOW_ANCHOR_EDGE" \
        --count "$deepflow_count" \
        --max-iteration "$DEEPFLOW_MAX_ITERATION" \
        --trace-concurrency "$DEEPFLOW_TRACE_CONCURRENCY" \
        --process-workers "$DEEPFLOW_LOCAL_PROCESS_WORKERS" \
        --window-padding-seconds "$DEEPFLOW_WINDOW_PADDING_SECONDS" \
        --deepflow-app-source "$DEEPFLOW_APP_SOURCE" \
        >"$deepflow_log" 2>&1
    else
      log "=== $label: running DeepFlow native L7FlowTracing accuracy (count=$deepflow_count) ==="
      python3 "$ROOT_DIR/baseline/deepflow/evaluate_deepflow_trace.py" \
        --load-report "$loadgen_json" \
        --output "$deepflow_json" \
        --api-url "$DEEPFLOW_API_URL" \
        --deepflow-app-url "$DEEPFLOW_APP_URL" \
        --db "$DEEPFLOW_DB" \
        --table "$DEEPFLOW_TABLE" \
        --namespace "$DEEPFLOW_NAMESPACE" \
        --mark-prefix "$run_mark_prefix" \
        --service-map "$DEEPFLOW_SERVICE_MAP" \
        --expected-edges "$(cat "$expected_edges_file")" \
        --expected-edge-counts "$(cat "$expected_counts_file")" \
        --anchor-edge "$DEEPFLOW_ANCHOR_EDGE" \
        --count "$deepflow_count" \
        --max-iteration "$DEEPFLOW_MAX_ITERATION" \
        --trace-concurrency "$DEEPFLOW_TRACE_CONCURRENCY" \
        --window-padding-seconds "$DEEPFLOW_WINDOW_PADDING_SECONDS" \
        >"$deepflow_log" 2>&1
    fi
  fi

  extract_metrics "$rate" "$connections" "$cleaned_csv" "$lineage_json" "$traceweaver_json" "$loadgen_json" "$deepflow_json" >> "$SUMMARY_CSV"
  log "=== $label: done ==="
  log "run dir: $run_dir"
  sleep "$BETWEEN_RUN_SECONDS"
}

need_cmd sudo
need_cmd python3
need_cmd curl
if [[ "$CLEAN_HOTEL_STACK" == "1" || "$RESTART_SERVICES_AT_START" == "1" || "$RUN_DEEPFLOW" == "1" ]]; then
  need_cmd docker
fi

case "$CAPTURE_MODE" in
  pcap)
    need_cmd tcpdump
    need_cmd tshark
    ;;
  ebpf)
    if [[ ! -x "$EBPF_COLLECTOR" ]]; then
      echo "Missing executable eBPF collector: $EBPF_COLLECTOR" >&2
      exit 1
    fi
    ;;
  *)
    echo "Unsupported CAPTURE_MODE=$CAPTURE_MODE; use pcap or ebpf" >&2
    exit 1
    ;;
esac

mkdir -p "$OUT_DIR"

if [[ "$CLEAN_HOTEL_STACK" == "1" ]]; then
  log "Clean rebuilding hotelReservation_http1.1 containers (docker compose down -v)"
  (
    cd "$HOTEL_DIR"
    docker compose down -v
    docker compose up -d --build
  )
else
  log "Using existing hotelReservation_http1.1 containers"
fi

if [[ "$RESTART_SERVICES_AT_START" == "1" ]]; then
  restart_hotel_services
fi

log "Checking Hotel frontend at $TARGET_URL"
wait_for_frontend

if [[ "$RUN_DEEPFLOW" == "1" ]]; then
  log "Expected DeepFlow L7 HTTP port filter: HTTP=$DEEPFLOW_L7_HTTP_PORTS HTTP2=$DEEPFLOW_L7_HTTP2_PORTS"
  log "Note: these filters only take effect if set before deepflow_stack_capture.sh starts the agent"
  if [[ "$DEEPFLOW_GENERATE_SERVICE_MAP" == "1" ]]; then
    log "Generating DeepFlow service map at $DEEPFLOW_SERVICE_MAP"
    generate_hotel_service_map "$DEEPFLOW_SERVICE_MAP"
  elif [[ ! -s "$DEEPFLOW_SERVICE_MAP" ]]; then
    echo "DeepFlow service map does not exist: $DEEPFLOW_SERVICE_MAP" >&2
    exit 1
  fi
  log "Checking DeepFlow SQL/API endpoints"
  wait_for_deepflow
fi

log "Capture mode: $CAPTURE_MODE"

log "Refreshing sudo credentials for capture"
sudo -n true 2>/dev/null || sudo -v

printf 'rate,connections,root_ip,root_trace_count,root_max_concurrency,root_duration_p50_ms,lineage_full_accuracy_pct,lineage_full_correct,lineage_total,lineage_trace_assignment_accuracy_pct,lineage_trace_assignment_correct,lineage_trace_assignment_total,lineage_root_direct_accuracy_pct,lineage_span_accuracy_pct,lineage_span_correct,lineage_span_total,lineage_coverage_pct,lineage_coverage_correct,lineage_coverage_total,lineage_parent_child_edge_precision_pct,lineage_parent_child_edge_recall_pct,lineage_parent_child_edge_f1_pct,lineage_parent_child_edge_correct,lineage_parent_child_edge_predicted,lineage_parent_child_edge_ground_truth,traceweaver_status,traceweaver_full_accuracy_pct,traceweaver_correct,traceweaver_total,traceweaver_trace_assignment_accuracy_pct,traceweaver_trace_assignment_correct,traceweaver_trace_assignment_total,traceweaver_span_accuracy_pct,traceweaver_span_correct,traceweaver_span_total,traceweaver_coverage_pct,traceweaver_coverage_correct,traceweaver_coverage_total,traceweaver_parent_child_edge_precision_pct,traceweaver_parent_child_edge_recall_pct,traceweaver_parent_child_edge_f1_pct,traceweaver_parent_child_edge_correct,traceweaver_parent_child_edge_predicted,traceweaver_parent_child_edge_ground_truth,loadgen_actual_requests_sec,loadgen_errors,loadgen_ok_requests,loadgen_target_requests,deepflow_trace_exact_pct,deepflow_trace_exact,deepflow_requested,deepflow_success,deepflow_full_accuracy_pct,deepflow_full_correct,deepflow_full_total,deepflow_trace_assignment_accuracy_pct,deepflow_trace_assignment_correct,deepflow_trace_assignment_total,deepflow_span_accuracy_pct,deepflow_span_correct,deepflow_span_total,deepflow_coverage_pct,deepflow_coverage_correct,deepflow_coverage_total,deepflow_parent_child_edge_precision_pct,deepflow_parent_child_edge_recall_pct,deepflow_parent_child_edge_f1_pct,deepflow_parent_child_edge_correct,deepflow_parent_child_edge_predicted,deepflow_parent_child_edge_ground_truth,deepflow_anchors,deepflow_business_span_distribution,deepflow_span_capture_missing_traces,deepflow_span_capture_missing_spans,deepflow_span_pairing_error_traces,deepflow_span_pairing_missing_spans,deepflow_span_pairing_extra_spans,deepflow_wrong_mark_spans,deepflow_elapsed_seconds\n' > "$SUMMARY_CSV"

read -r -a CONNECTION_VALUES <<< "$CONNECTIONS_LIST"
if [[ -n "$RATE_LIST" ]]; then
  read -r -a RATE_VALUES <<< "$RATE_LIST"
  if [[ "${#CONNECTION_VALUES[@]}" -ne "${#RATE_VALUES[@]}" ]]; then
    echo "CONNECTIONS_LIST and RATE_LIST must have the same length for paired sweep." >&2
    echo "CONNECTIONS_LIST has ${#CONNECTION_VALUES[@]} entries; RATE_LIST has ${#RATE_VALUES[@]} entries." >&2
    exit 1
  fi
  log "Sweeping Hotel HTTP/1.1 paired connections/rate: CONNECTIONS_LIST=($CONNECTIONS_LIST), RATE_LIST=($RATE_LIST)"
  for i in "${!CONNECTION_VALUES[@]}"; do
    run_one "${CONNECTION_VALUES[$i]}" "${RATE_VALUES[$i]}"
  done
else
  log "Sweeping Hotel HTTP/1.1 connections at fixed rate=$RATE: $CONNECTIONS_LIST"
  for connections in "${CONNECTION_VALUES[@]}"; do
    run_one "$connections" "$RATE"
  done
fi

log "Hotel HTTP/1.1 sweep complete"
log "summary csv: $SUMMARY_CSV"
