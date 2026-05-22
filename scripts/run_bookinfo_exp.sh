#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOKINFO_DIR="$ROOT_DIR/services/bookinfo"
RUN_DEEPFLOW="${RUN_DEEPFLOW:-0}"
for arg in "$@"; do
  case "$arg" in
    deepflow|--deepflow)
      RUN_DEEPFLOW=1
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/run_bookinfo_exp.sh [deepflow|--deepflow]

Environment variables:
  CAPTURE_MODE=pcap|ebpf
  EBPF_CAPTURE_PORTS=9080
  EBPF_ENABLE_DB_ROWS=0|1
  OUT_DIR=result/bookinfo
  CONNECTIONS_LIST="50 100 150 250 300"
  DURATION=5s
  RATE=300
  RATE_LIST="50 100 150 250 300"
  RUN_DEEPFLOW=0|1
  TARGET_URL=http://127.0.0.1:9080
  DEEPFLOW_TARGET_URL=http://127.0.0.1:19081
  DEEPFLOW_API_URL=http://127.0.0.1:20416/v1/query/
  DEEPFLOW_APP_URL=http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing
  DEEPFLOW_EVAL_MODE=local|api
  DEEPFLOW_APP_SOURCE=baseline/deepflow/deepflow-app-source
  DEEPFLOW_DB=flow_log
  DEEPFLOW_TABLE=l7_flow_log
  DEEPFLOW_SERVICE_MAP=$OUT_DIR/service_map.json
  DEEPFLOW_GENERATE_SERVICE_MAP=1
  DEEPFLOW_L7_HTTP_PORTS=9080,9081,9082,9083   # must be set before starting deepflow_stack_capture.sh
  DEEPFLOW_L7_HTTP2_PORTS=9080,9081,9082,9083  # must be set before starting deepflow_stack_capture.sh
  DEEPFLOW_RECONFIGURE_AGENT=1                 # apply the port filter before the workload
  DEEPFLOW_VERIFY_PORTS=1                      # send one X-Mark canary and wait for l7_flow_log
  DEEPFLOW_LOCAL_FLUSH_SECONDS=10
  DEEPFLOW_LOCAL_PROCESS_WORKERS=8
  MARK_PREFIX=bookinfo-YYYYmmdd_HHMMSS
  CAPTURE_DRAIN_SECONDS=5
  PCAP_TARGET=host|minikube
  CLEAN_BOOKINFO_STACK=1          # docker compose down -v before docker compose up
  SERVICE_START_WAIT_SECONDS=30   # wait after restarting service containers

TARGET_URL is the Docker Compose Bookinfo endpoint used for pcap/eBPF,
lineage, TraceWeaver, and DeepFlow.

When deepflow is enabled, the script sends one Bookinfo load run only. The same
X-Mark request set is captured by pcap/eBPF and DeepFlow, then all three
algorithms are evaluated from that shared load report. DEEPFLOW_TARGET_URL is
kept only for older wrappers; set TARGET_URL to the endpoint that DeepFlow sees.
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

CAPTURE_MODE="${CAPTURE_MODE:-pcap}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/result/bookinfo}"
SUMMARY_CSV="${SUMMARY_CSV:-$OUT_DIR/summary.csv}"
TRACEFUSION="${TRACEFUSION:-$ROOT_DIR/src/tracefusion.py}"

CONNECTIONS_LIST="${CONNECTIONS_LIST:-50 100 150 250 300}"
DURATION="${DURATION:-5s}"
RATE="${RATE:-300}"
BOOK_COUNT="${BOOK_COUNT:-100}"
ID_MODE="${ID_MODE:-random}"
SEED="${SEED:-42}"
WARMUP_SECONDS="${WARMUP_SECONDS:-20}"
BETWEEN_RUN_SECONDS="${BETWEEN_RUN_SECONDS:-10}"
CAPTURE_DRAIN_SECONDS="${CAPTURE_DRAIN_SECONDS:-5}"
TARGET_URL="${TARGET_URL:-http://127.0.0.1:9080}"
DEEPFLOW_TARGET_URL="${DEEPFLOW_TARGET_URL:-$TARGET_URL}"
MARK_PREFIX="${MARK_PREFIX:-bookinfo-$(date +%Y%m%d_%H%M%S)}"
CLEAN_BOOKINFO_STACK="${CLEAN_BOOKINFO_STACK:-1}"
SERVICE_START_WAIT_SECONDS="${SERVICE_START_WAIT_SECONDS:-30}"
TCPDUMP_IFACE="${TCPDUMP_IFACE:-any}"
TCPDUMP_FILTER="${TCPDUMP_FILTER:-tcp port 9080}"
PCAP_TARGET="${PCAP_TARGET:-host}"
EBPF_COLLECTOR="${EBPF_COLLECTOR:-$ROOT_DIR/collector/ebpf/cgroup_net/target/release/cgroup}"
EBPF_IGNORED_PORTS="${EBPF_IGNORED_PORTS:-14250,16686}"
EBPF_COLLECTOR_PROTOCOL="${EBPF_COLLECTOR_PROTOCOL:-http1}"
EBPF_COLLECTOR_QUIET="${EBPF_COLLECTOR_QUIET:-1}"
EBPF_ENABLE_DB_ROWS="${EBPF_ENABLE_DB_ROWS:-0}"
EBPF_CAPTURE_PORTS="${EBPF_CAPTURE_PORTS:-9080}"
EXPECTED_TRACE_COUNT="${EXPECTED_TRACE_COUNT:-8}"
SPAN_FORM="${SPAN_FORM:-rpc}"
HTTP1_PORTS="${HTTP1_PORTS:-auto}"
HTTP2_PORTS="${HTTP2_PORTS:-}"
RUN_TOPOLOGY="${RUN_TOPOLOGY:-1}"
DEEPFLOW_API_URL="${DEEPFLOW_API_URL:-http://127.0.0.1:20416/v1/query/}"
DEEPFLOW_APP_URL="${DEEPFLOW_APP_URL:-http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing}"
DEEPFLOW_EVAL_MODE="${DEEPFLOW_EVAL_MODE:-local}"
DEEPFLOW_APP_SOURCE="${DEEPFLOW_APP_SOURCE:-$ROOT_DIR/baseline/deepflow/deepflow-app-source}"
DEEPFLOW_SERVICE_MAP="${DEEPFLOW_SERVICE_MAP:-$OUT_DIR/service_map.json}"
DEEPFLOW_GENERATE_SERVICE_MAP="${DEEPFLOW_GENERATE_SERVICE_MAP:-1}"
DEEPFLOW_DB="${DEEPFLOW_DB:-flow_log}"
DEEPFLOW_TABLE="${DEEPFLOW_TABLE:-l7_flow_log}"
DEEPFLOW_NAMESPACE="${DEEPFLOW_NAMESPACE:-bookinfo}"
DEEPFLOW_MAX_ITERATION="${DEEPFLOW_MAX_ITERATION:-6}"
DEEPFLOW_TRACE_CONCURRENCY="${DEEPFLOW_TRACE_CONCURRENCY:-8}"
DEEPFLOW_LOCAL_PROCESS_WORKERS="${DEEPFLOW_LOCAL_PROCESS_WORKERS:-8}"
DEEPFLOW_WINDOW_PADDING_SECONDS="${DEEPFLOW_WINDOW_PADDING_SECONDS:-20}"
DEEPFLOW_EXPECTED_SPANS_PER_EDGE="${DEEPFLOW_EXPECTED_SPANS_PER_EDGE:-4}"
DEEPFLOW_ANCHOR_EDGE="${DEEPFLOW_ANCHOR_EDGE:-productpage->details}"
DEEPFLOW_EXPECTED_EDGES="${DEEPFLOW_EXPECTED_EDGES:-productpage->details,productpage->reviews,reviews->ratings}"
DEEPFLOW_L7_HTTP_PORTS="${DEEPFLOW_L7_HTTP_PORTS:-9080,9081,9082,9083}"
DEEPFLOW_L7_HTTP2_PORTS="${DEEPFLOW_L7_HTTP2_PORTS:-9080,9081,9082,9083}"
DEEPFLOW_RECONFIGURE_AGENT="${DEEPFLOW_RECONFIGURE_AGENT:-1}"
DEEPFLOW_STACK_PROJECT="${DEEPFLOW_STACK_PROJECT:-}"
DEEPFLOW_STACK_OUT_DIR="${DEEPFLOW_STACK_OUT_DIR:-}"
DEEPFLOW_RECONFIGURE_POST_READY_SECONDS="${DEEPFLOW_RECONFIGURE_POST_READY_SECONDS:-5}"
DEEPFLOW_VERIFY_PORTS="${DEEPFLOW_VERIFY_PORTS:-1}"
DEEPFLOW_PORT_VERIFY_TIMEOUT_SECONDS="${DEEPFLOW_PORT_VERIFY_TIMEOUT_SECONDS:-90}"
DEEPFLOW_PORT_VERIFY_POLL_SECONDS="${DEEPFLOW_PORT_VERIFY_POLL_SECONDS:-3}"
DEEPFLOW_WAIT_SECONDS="${DEEPFLOW_WAIT_SECONDS:-30}"
DEEPFLOW_LOCAL_FLUSH_SECONDS="${DEEPFLOW_LOCAL_FLUSH_SECONDS:-10}"

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

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1" >&2
    exit 1
  fi
}

wait_for_bookinfo() {
  local target_url="${1:-$TARGET_URL}"
  local label="${2:-Bookinfo}"
  local deadline=$((SECONDS + WARMUP_SECONDS))
  while (( SECONDS < deadline )); do
    if curl -fsS "$target_url/productpage?id=0" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "$label did not become reachable at $target_url within ${WARMUP_SECONDS}s" >&2
  return 1
}

clean_rebuild_bookinfo_stack() {
  log "Clean rebuilding Bookinfo containers (docker compose down -v)"
  (
    cd "$BOOKINFO_DIR"
    docker compose down -v
    docker compose up -d --build
  )
  log "Waiting ${SERVICE_START_WAIT_SECONDS}s for Bookinfo services to settle"
  sleep "$SERVICE_START_WAIT_SECONDS"
}

wait_for_deepflow() {
  local deadline=$((SECONDS + WARMUP_SECONDS))
  local api_url="$DEEPFLOW_API_URL"
  local app_url="$DEEPFLOW_APP_URL"
  local eval_mode="$DEEPFLOW_EVAL_MODE"
  while (( SECONDS < deadline )); do
    if python3 - "$api_url" "$app_url" "$DEEPFLOW_DB" "$DEEPFLOW_TABLE" "$eval_mode" >/dev/null 2>&1 <<'PY'
import json
import sys
import urllib.parse
import urllib.request

api_url = sys.argv[1]
app_url = sys.argv[2]
db = sys.argv[3]
table = sys.argv[4]
eval_mode = sys.argv[5]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

body = urllib.parse.urlencode({"db": db, "sql": "SELECT time FROM l7_flow_log LIMIT 1"}).encode()
request = urllib.request.Request(api_url, data=body, method="POST")
with opener.open(request, timeout=3) as response:
    data = json.loads(response.read().decode())
if data.get("OPT_STATUS") != "SUCCESS":
    raise SystemExit(1)

if eval_mode == "local":
    raise SystemExit(0)

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
if data.get("OPT_STATUS") != "SUCCESS":
    raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep 2
  done

  cat >&2 <<EOF
DeepFlow SQL/API tracing endpoints are not reachable within ${WARMUP_SECONDS}s.
SQL API: $DEEPFLOW_API_URL
App API: $DEEPFLOW_APP_URL

If DeepFlow is running in Kubernetes, start the port-forward first:

  kubectl -n deepflow port-forward svc/deepflow-server 20416:20416
  kubectl -n deepflow port-forward svc/deepflow-app 20418:20418

You can override the endpoints with DEEPFLOW_API_URL and DEEPFLOW_APP_URL.
EOF
  return 1
}

detect_deepflow_stack_context() {
  python3 - <<'PY'
import json
import subprocess
import sys

def run(args):
    return subprocess.check_output(args, text=True).strip()

try:
    names = run(["docker", "ps", "--filter", "name=deepflow-server", "--format", "{{.Names}}"]).splitlines()
except Exception:
    names = []

for name in names:
    if not name:
        continue
    try:
        inspect = json.loads(run(["docker", "inspect", name]))[0]
    except Exception:
        continue
    labels = inspect.get("Config", {}).get("Labels") or {}
    project = labels.get("com.docker.compose.project") or ""
    working_dir = labels.get("com.docker.compose.project.working_dir") or ""
    out_dir = ""
    suffix = "/stack/deepflow-docker-compose"
    if working_dir.endswith(suffix):
        out_dir = working_dir[: -len(suffix)]
    if not out_dir:
        marker = "/stack/deepflow-docker-compose/"
        for mount in inspect.get("Mounts") or []:
            source = mount.get("Source") or ""
            if marker in source:
                out_dir = source.split(marker, 1)[0]
                break
    if project and out_dir:
        print(project)
        print(out_dir)
        raise SystemExit(0)

raise SystemExit(1)
PY
}

reconfigure_deepflow_agent_ports() {
  if [[ "$RUN_DEEPFLOW" != "1" || "$DEEPFLOW_RECONFIGURE_AGENT" != "1" ]]; then
    return 0
  fi

  need_cmd docker
  local project="$DEEPFLOW_STACK_PROJECT"
  local stack_out="$DEEPFLOW_STACK_OUT_DIR"

  if [[ -z "$project" || -z "$stack_out" ]]; then
    local detected=""
    if detected="$(detect_deepflow_stack_context 2>/dev/null)"; then
      if [[ -z "$project" ]]; then
        project="$(sed -n '1p' <<<"$detected")"
      fi
      if [[ -z "$stack_out" ]]; then
        stack_out="$(sed -n '2p' <<<"$detected")"
      fi
    fi
  fi

  project="${project:-trace-fusion-deepflow-bookinfo}"
  stack_out="${stack_out:-$ROOT_DIR/result/deepflow_stack_bookinfo}"

  log "Reconfiguring DeepFlow agent port filter: HTTP=$DEEPFLOW_L7_HTTP_PORTS HTTP2=$DEEPFLOW_L7_HTTP2_PORTS"
  log "DeepFlow stack context: PROJECT=$project OUT_DIR=$stack_out"
  PROJECT="$project" \
    OUT_DIR="$stack_out" \
    DEEPFLOW_L7_HTTP_PORTS="$DEEPFLOW_L7_HTTP_PORTS" \
    DEEPFLOW_L7_HTTP2_PORTS="$DEEPFLOW_L7_HTTP2_PORTS" \
    AGENT_POST_READY_SECONDS="$DEEPFLOW_RECONFIGURE_POST_READY_SECONDS" \
    POST_WORKLOAD_SECONDS=0 \
    KEEP_DEEPFLOW_STACK=1 \
    KEEP_DEEPFLOW_AGENT=1 \
    "$ROOT_DIR/baseline/deepflow/deepflow_stack_capture.sh" -- true
}

verify_deepflow_bookinfo_ports() {
  if [[ "$RUN_DEEPFLOW" != "1" || "$DEEPFLOW_VERIFY_PORTS" != "1" ]]; then
    return 0
  fi

  local mark="bookinfo-deepflow-preflight-$(date +%Y%m%d_%H%M%S)-$$"
  local start_ts
  start_ts="$(date +%s)"
  log "Verifying DeepFlow Bookinfo port capture with X-Mark=$mark"

  local deadline=$((SECONDS + DEEPFLOW_PORT_VERIFY_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    curl -fsS -H "X-Mark: $mark" "$TARGET_URL/productpage?id=0" >/dev/null
    if python3 - "$DEEPFLOW_API_URL" "$DEEPFLOW_DB" "$mark" "$start_ts" >/dev/null 2>&1 <<'PY'
import json
import sys
import time
import urllib.parse
import urllib.request

api_url, db, mark, start_ts = sys.argv[1:5]
start = max(0, int(float(start_ts)) - 5)
end = int(time.time()) + 30
needle = mark.replace("'", "''")
sql = (
    "SELECT toString(_id) AS deepflow_id, attribute, request_resource FROM l7_flow_log "
    f"WHERE time >= {start} AND time <= {end} "
    f"AND (attribute LIKE '%{needle}%' OR request_resource LIKE '%{needle}%') "
    "LIMIT 1"
)
body = urllib.parse.urlencode({"db": db, "sql": sql}).encode()
request = urllib.request.Request(api_url, data=body, method="POST")
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
    payload = json.loads(response.read().decode())
if payload.get("OPT_STATUS") != "SUCCESS":
    raise SystemExit(1)
result = payload.get("result") or {}
rows = result.get("values") or payload.get("DATA") or payload.get("data") or []
raise SystemExit(0 if rows else 1)
PY
    then
      log "DeepFlow Bookinfo port capture verified"
      return 0
    fi
    sleep "$DEEPFLOW_PORT_VERIFY_POLL_SECONDS"
  done

  cat >&2 <<EOF
DeepFlow did not capture the Bookinfo X-Mark canary within ${DEEPFLOW_PORT_VERIFY_TIMEOUT_SECONDS}s.
Expected agent port filter: HTTP=$DEEPFLOW_L7_HTTP_PORTS HTTP2=$DEEPFLOW_L7_HTTP2_PORTS

Either set DEEPFLOW_RECONFIGURE_AGENT=1 so this script reapplies the agent
configuration, or restart DeepFlow manually with these port filters before
running the experiment.
EOF
  return 1
}

extract_metrics() {
  local rate="$1"
  local connections="$2"
  local cleaned_csv="$3"
  local lineage_report="$4"
  local traceweaver_report="$5"
  local loadgen_report="$6"
  local capture_mode="$7"
  local seed="$8"
  local deepflow_report="$9"
  python3 - "$rate" "$connections" "$cleaned_csv" "$lineage_report" "$traceweaver_report" "$loadgen_report" "$capture_mode" "$seed" "$deepflow_report" <<'PY'
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

rate = sys.argv[1]
connections = sys.argv[2]
cleaned_path = Path(sys.argv[3])
lineage_path = Path(sys.argv[4])
traceweaver_path = Path(sys.argv[5])
loadgen_path = Path(sys.argv[6])
capture_mode = sys.argv[7]
seed = sys.argv[8]
deepflow_path = Path(sys.argv[9])

lineage = json.loads(lineage_path.read_text())
traceweaver = json.loads(traceweaver_path.read_text())
tw_e2e = traceweaver.get("end_to_end_accuracy", {})
loadgen = json.loads(loadgen_path.read_text()) if loadgen_path.exists() else {}
deepflow = json.loads(deepflow_path.read_text()) if deepflow_path.exists() else {}

fmt = "%Y-%m-%d %H:%M:%S.%f"
rows = []
with cleaned_path.open(newline="") as f:
    rows = list(csv.DictReader(f))

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
        if row["msg_type"] == "Request":
            starts.append(ts)
        else:
            ends.append(ts)
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
    "capture_mode": capture_mode,
    "seed": seed,
    "rate": rate,
    "connections": connections,
    "root_ip": root_ip,
    "root_trace_count": len(by_trace),
    "root_max_concurrency": max_concurrency,
    "root_duration_p50_ms": round(percentile(durations_ms, 0.5), 3),
    "lineage_accuracy_pct": lineage.get("accuracy_pct", 0.0),
    "lineage_correct": lineage.get("accuracy_ok", 0),
    "lineage_total": lineage.get("root_trace_count", 0),
    "lineage_trace_assignment_accuracy_pct": lineage.get("trace_assignment_accuracy_pct", ""),
    "lineage_trace_assignment_correct": lineage.get("trace_assignment_accuracy_ok", ""),
    "lineage_trace_assignment_total": lineage.get("trace_assignment_accuracy_total", ""),
    "lineage_edge_accuracy_pct": lineage.get("edge_accuracy_pct", ""),
    "lineage_edge_correct": lineage.get("edge_accuracy_ok", ""),
    "lineage_edge_total": lineage.get("edge_accuracy_total", ""),
    "lineage_span_accuracy_pct": lineage.get("span_accuracy_pct", lineage.get("edge_accuracy_pct", "")),
    "lineage_span_correct": lineage.get("span_accuracy_ok", lineage.get("edge_accuracy_ok", "")),
    "lineage_span_total": lineage.get("span_accuracy_total", lineage.get("edge_accuracy_total", "")),
    "lineage_coverage_pct": lineage.get("coverage_pct", ""),
    "lineage_coverage_correct": lineage.get("coverage_ok", ""),
    "lineage_coverage_total": lineage.get("coverage_total", ""),
    "lineage_parent_child_edge_precision_pct": lineage.get("parent_child_edge_precision_pct", ""),
    "lineage_parent_child_edge_recall_pct": lineage.get("parent_child_edge_recall_pct", ""),
    "lineage_parent_child_edge_f1_pct": lineage.get("parent_child_edge_f1_pct", ""),
    "lineage_parent_child_edge_correct": lineage.get("parent_child_edge_correct", ""),
    "lineage_parent_child_edge_predicted": lineage.get("parent_child_edge_predicted", ""),
    "lineage_parent_child_edge_ground_truth": lineage.get("parent_child_edge_ground_truth", ""),
    "traceweaver_full_accuracy_pct": tw_e2e.get("accuracy_pct", 0.0),
    "traceweaver_correct": tw_e2e.get("correct", 0),
    "traceweaver_total": tw_e2e.get("total", 0),
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
    "loadgen_start_gap_p50_ms": loadgen.get("start_gap_ms", {}).get("p50", ""),
    "loadgen_start_gap_p99_ms": loadgen.get("start_gap_ms", {}).get("p99", ""),
    "loadgen_start_gap_stdev_ms": loadgen.get("start_gap_ms", {}).get("stdev", ""),
    "loadgen_start_lag_p99_ms": loadgen.get("start_lag_ms", {}).get("p99", ""),
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
writer = csv.DictWriter(sys.stdout, fieldnames=list(row.keys()), lineterminator="\n")
writer.writerow(row)
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

generate_bookinfo_service_map() {
  local output="$1"
  mkdir -p "$(dirname "$output")"
  python3 - "$output" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

output = Path(sys.argv[1])
containers = {
    "bookinfo-productpage": "productpage",
    "bookinfo-details": "details",
    "bookinfo-reviews": "reviews",
    "bookinfo-ratings": "ratings",
}
service_map = {}
missing = []

for container, service in containers.items():
    try:
        raw = subprocess.check_output(
            ["docker", "inspect", container],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except subprocess.CalledProcessError:
        missing.append(container)
        continue

    data = json.loads(raw)[0]
    networks = (data.get("NetworkSettings") or {}).get("Networks") or {}
    ips = [
        info.get("IPAddress")
        for info in networks.values()
        if info.get("IPAddress")
    ]
    if not ips:
        ip = (data.get("NetworkSettings") or {}).get("IPAddress")
        ips = [ip] if ip else []
    if not ips:
        missing.append(container)
        continue

    for ip in ips:
        service_map[ip] = {"service": service, "namespace": "bookinfo"}

if not service_map:
    raise SystemExit(
        "could not generate Bookinfo service map; no bookinfo container IPs found"
    )

output.write_text(json.dumps(service_map, indent=2, sort_keys=True) + "\n")
if missing:
    print("warning: missing Bookinfo containers: " + ", ".join(missing), file=sys.stderr)
print(f"wrote {output} with {len(service_map)} entries")
PY
}

need_cmd sudo
need_cmd python3
need_cmd curl
if [[ "$CLEAN_BOOKINFO_STACK" == "1" ]]; then
  need_cmd docker
fi

case "$CAPTURE_MODE" in
  pcap)
    need_cmd tcpdump
    need_cmd tshark
    if [[ "$PCAP_TARGET" == "minikube" ]]; then
      need_cmd minikube
      if ! minikube ssh -- 'command -v tcpdump >/dev/null 2>&1' >/dev/null 2>&1; then
        cat >&2 <<'EOF'
tcpdump is not installed inside the minikube node, so PCAP_TARGET=minikube cannot capture traffic.

Install tcpdump in minikube, or run with PCAP_TARGET=host if host capture is enough:

  minikube ssh -- sudo apt-get update
  minikube ssh -- sudo apt-get install -y tcpdump
EOF
        exit 1
      fi
    elif [[ "$PCAP_TARGET" != "host" ]]; then
      echo "Unsupported PCAP_TARGET=$PCAP_TARGET; use host or minikube" >&2
      exit 1
    fi
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

if [[ "$CLEAN_BOOKINFO_STACK" == "1" ]]; then
  clean_rebuild_bookinfo_stack
else
  log "Using existing Bookinfo containers"
fi

log "Checking Bookinfo at $TARGET_URL"
wait_for_bookinfo "$TARGET_URL" "Docker Compose Bookinfo"
if [[ "$RUN_DEEPFLOW" == "1" ]]; then
  log "Expected DeepFlow L7 HTTP port filter: HTTP=$DEEPFLOW_L7_HTTP_PORTS HTTP2=$DEEPFLOW_L7_HTTP2_PORTS"
  log "Note: these filters only take effect if set before deepflow_stack_capture.sh starts the agent"
  need_cmd docker
  reconfigure_deepflow_agent_ports
  if [[ "$DEEPFLOW_TARGET_URL" != "$TARGET_URL" ]]; then
    log "DEEPFLOW_TARGET_URL=$DEEPFLOW_TARGET_URL is ignored in single-run mode; using TARGET_URL=$TARGET_URL"
  fi
  if [[ "$DEEPFLOW_GENERATE_SERVICE_MAP" == "1" ]]; then
    log "Generating DeepFlow service map at $DEEPFLOW_SERVICE_MAP"
    generate_bookinfo_service_map "$DEEPFLOW_SERVICE_MAP"
  elif [[ ! -s "$DEEPFLOW_SERVICE_MAP" ]]; then
    echo "DeepFlow service map does not exist: $DEEPFLOW_SERVICE_MAP" >&2
    echo "Set DEEPFLOW_GENERATE_SERVICE_MAP=1 or provide DEEPFLOW_SERVICE_MAP." >&2
    exit 1
  fi
  log "Checking DeepFlow SQL API at $DEEPFLOW_API_URL"
  log "Checking DeepFlow app tracing API at $DEEPFLOW_APP_URL"
  wait_for_deepflow
  verify_deepflow_bookinfo_ports
fi

log "Capture mode: $CAPTURE_MODE"
if [[ "$CAPTURE_MODE" == "pcap" ]]; then
  log "PCAP target: $PCAP_TARGET"
fi
log "DeepFlow accuracy: $RUN_DEEPFLOW"
if [[ "$RUN_DEEPFLOW" == "1" ]]; then
  log "DeepFlow observes the shared workload at TARGET_URL=$TARGET_URL"
  log "DeepFlow service map: $DEEPFLOW_SERVICE_MAP"
fi
log "X-Mark prefix base: $MARK_PREFIX"
log "Refreshing sudo credentials for capture"
sudo -n true 2>/dev/null || sudo -v

printf 'capture_mode,seed,rate,connections,root_ip,root_trace_count,root_max_concurrency,root_duration_p50_ms,lineage_accuracy_pct,lineage_correct,lineage_total,lineage_trace_assignment_accuracy_pct,lineage_trace_assignment_correct,lineage_trace_assignment_total,lineage_edge_accuracy_pct,lineage_edge_correct,lineage_edge_total,lineage_span_accuracy_pct,lineage_span_correct,lineage_span_total,lineage_coverage_pct,lineage_coverage_correct,lineage_coverage_total,lineage_parent_child_edge_precision_pct,lineage_parent_child_edge_recall_pct,lineage_parent_child_edge_f1_pct,lineage_parent_child_edge_correct,lineage_parent_child_edge_predicted,lineage_parent_child_edge_ground_truth,traceweaver_full_accuracy_pct,traceweaver_correct,traceweaver_total,traceweaver_trace_assignment_accuracy_pct,traceweaver_trace_assignment_correct,traceweaver_trace_assignment_total,traceweaver_span_accuracy_pct,traceweaver_span_correct,traceweaver_span_total,traceweaver_coverage_pct,traceweaver_coverage_correct,traceweaver_coverage_total,traceweaver_parent_child_edge_precision_pct,traceweaver_parent_child_edge_recall_pct,traceweaver_parent_child_edge_f1_pct,traceweaver_parent_child_edge_correct,traceweaver_parent_child_edge_predicted,traceweaver_parent_child_edge_ground_truth,loadgen_actual_requests_sec,loadgen_errors,loadgen_start_gap_p50_ms,loadgen_start_gap_p99_ms,loadgen_start_gap_stdev_ms,loadgen_start_lag_p99_ms,deepflow_trace_exact_pct,deepflow_trace_exact,deepflow_requested,deepflow_success,deepflow_full_accuracy_pct,deepflow_full_correct,deepflow_full_total,deepflow_trace_assignment_accuracy_pct,deepflow_trace_assignment_correct,deepflow_trace_assignment_total,deepflow_span_accuracy_pct,deepflow_span_correct,deepflow_span_total,deepflow_coverage_pct,deepflow_coverage_correct,deepflow_coverage_total,deepflow_parent_child_edge_precision_pct,deepflow_parent_child_edge_recall_pct,deepflow_parent_child_edge_f1_pct,deepflow_parent_child_edge_correct,deepflow_parent_child_edge_predicted,deepflow_parent_child_edge_ground_truth,deepflow_anchors,deepflow_business_span_distribution,deepflow_span_capture_missing_traces,deepflow_span_capture_missing_spans,deepflow_span_pairing_error_traces,deepflow_span_pairing_missing_spans,deepflow_span_pairing_extra_spans,deepflow_wrong_mark_spans,deepflow_elapsed_seconds\n' > "$SUMMARY_CSV"

run_one() {
  local connections="$1"
  local rate="$2"
  local label="conn_${connections}_rps_${rate}"
  local run_dir="$OUT_DIR/$label"
  mkdir -p "$run_dir"

  local pcap_path="$run_dir/bookinfo.pcap"
  local ebpf_raw_csv="$run_dir/ebpf_output.bin"
  local cleaned_csv="$run_dir/cleaned_data.csv"
  local topology_png="$run_dir/topology.png"
  local capture_log="$run_dir/${CAPTURE_MODE}_capture.log"
  local parse_log="$run_dir/${CAPTURE_MODE}_to_cleaned.log"
  local topology_log="$run_dir/topology.log"
  local lineage_log="$run_dir/lineage.log"
  local traceweaver_log="$run_dir/traceweaver.log"
  local lineage_json="$run_dir/lineage_report.json"
  local traceweaver_json="$run_dir/traceweaver_baseline_report.json"
  local loadgen_log="$run_dir/loadgen.log"
  local loadgen_json="$run_dir/loadgen_report.json"
  local deepflow_log="$run_dir/deepflow.log"
  local deepflow_json="$run_dir/deepflow_report.json"
  local run_mark_prefix="${MARK_PREFIX}-${label}"

  log "=== $label: starting $CAPTURE_MODE capture ==="
  rm -f \
    "$pcap_path" \
    "$ebpf_raw_csv" \
    "$cleaned_csv" \
    "$lineage_json" \
    "$traceweaver_json" \
    "$loadgen_json" \
    "$deepflow_json"
  if [[ "$CAPTURE_MODE" == "pcap" ]]; then
    if [[ "$PCAP_TARGET" == "minikube" ]]; then
      (
        cd "$ROOT_DIR"
        exec minikube ssh -- sudo tcpdump -i "$TCPDUMP_IFACE" -s 0 -U -w - "$TCPDUMP_FILTER"
      ) >"$pcap_path" 2>"$capture_log" &
    else
      (
        cd "$ROOT_DIR"
        exec sudo tcpdump -i "$TCPDUMP_IFACE" -s 0 -U -w "$pcap_path" "$TCPDUMP_FILTER"
      ) >"$capture_log" 2>&1 &
    fi
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

  log "=== $label: running Bookinfo loadgen (-c $connections -R $rate -d $DURATION) ==="
  set +e
  python3 "$ROOT_DIR/services/bookinfo/uniform_bookinfo_load.py" \
    -c "$connections" \
    -d "$DURATION" \
    -R "$rate" \
    --book-count "$BOOK_COUNT" \
    --id-mode "$ID_MODE" \
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
      --http1-ports "$HTTP1_PORTS" \
      --http2-ports "$HTTP2_PORTS" \
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

  if [[ "$RUN_TOPOLOGY" == "1" ]]; then
    log "=== $label: generating topology graph ==="
    python3 "$ROOT_DIR/src/topology.py" \
      --csv-file "$cleaned_csv" \
      --output "$topology_png" \
      >"$topology_log" 2>&1
  fi

  log "=== $label: running lineage inference ==="
  python3 "$TRACEFUSION" \
    --csv-path "$cleaned_csv" \
    --json-out "$lineage_json" \
    >"$lineage_log" 2>&1

  log "=== $label: running TraceWeaver baseline ==="
  python3 "$ROOT_DIR/baseline/traceweaver/traceweaver_baseline.py" \
    --csv "$cleaned_csv" \
    --report-out "$traceweaver_json" \
    --quiet \
    >"$traceweaver_log" 2>&1

  if [[ "$RUN_DEEPFLOW" == "1" ]]; then
    local deepflow_count
    deepflow_count="$(loadgen_request_count "$loadgen_json")"
    local -a deepflow_eval_args
    if [[ "$DEEPFLOW_EVAL_MODE" == "local" ]]; then
      log "=== $label: waiting ${DEEPFLOW_LOCAL_FLUSH_SECONDS}s for DeepFlow agent flush ==="
      sleep "$DEEPFLOW_LOCAL_FLUSH_SECONDS"
      log "=== $label: running DeepFlow local batch L7FlowTracing accuracy on shared loadgen report (count=$deepflow_count) ==="
      deepflow_eval_args=(
        "$ROOT_DIR/baseline/deepflow/evaluate_deepflow_local_trace.py"
        --load-report "$loadgen_json"
        --output "$deepflow_json"
        --api-url "$DEEPFLOW_API_URL"
        --db "$DEEPFLOW_DB"
        --namespace "$DEEPFLOW_NAMESPACE"
        --mark-prefix "$run_mark_prefix"
        --count "$deepflow_count"
        --max-iteration "$DEEPFLOW_MAX_ITERATION"
        --trace-concurrency "$DEEPFLOW_TRACE_CONCURRENCY"
        --process-workers "$DEEPFLOW_LOCAL_PROCESS_WORKERS"
        --window-padding-seconds "$DEEPFLOW_WINDOW_PADDING_SECONDS"
        --expected-edges "$DEEPFLOW_EXPECTED_EDGES"
        --anchor-edge "$DEEPFLOW_ANCHOR_EDGE"
        --expected-spans-per-edge "$DEEPFLOW_EXPECTED_SPANS_PER_EDGE"
        --deepflow-app-source "$DEEPFLOW_APP_SOURCE"
      )
    else
      log "=== $label: waiting ${DEEPFLOW_WAIT_SECONDS}s for DeepFlow ingestion ==="
      sleep "$DEEPFLOW_WAIT_SECONDS"
      log "=== $label: running DeepFlow native L7FlowTracing accuracy on shared loadgen report (count=$deepflow_count) ==="
      deepflow_eval_args=(
        "$ROOT_DIR/baseline/deepflow/evaluate_deepflow_trace.py"
        --load-report "$loadgen_json"
        --output "$deepflow_json"
        --api-url "$DEEPFLOW_API_URL"
        --deepflow-app-url "$DEEPFLOW_APP_URL"
        --db "$DEEPFLOW_DB"
        --table "$DEEPFLOW_TABLE"
        --namespace "$DEEPFLOW_NAMESPACE"
        --mark-prefix "$run_mark_prefix"
        --count "$deepflow_count"
        --max-iteration "$DEEPFLOW_MAX_ITERATION"
        --trace-concurrency "$DEEPFLOW_TRACE_CONCURRENCY"
        --window-padding-seconds "$DEEPFLOW_WINDOW_PADDING_SECONDS"
        --expected-edges "$DEEPFLOW_EXPECTED_EDGES"
        --anchor-edge "$DEEPFLOW_ANCHOR_EDGE"
        --expected-spans-per-edge "$DEEPFLOW_EXPECTED_SPANS_PER_EDGE"
      )
    fi
    if [[ -n "$DEEPFLOW_SERVICE_MAP" ]]; then
      deepflow_eval_args+=(--service-map "$DEEPFLOW_SERVICE_MAP")
    fi
    python3 "${deepflow_eval_args[@]}" >"$deepflow_log" 2>&1
  fi

  extract_metrics "$rate" "$connections" "$cleaned_csv" "$lineage_json" "$traceweaver_json" "$loadgen_json" "$CAPTURE_MODE" "$SEED" "$deepflow_json" >> "$SUMMARY_CSV"

  log "=== $label: done ==="
  log "run dir: $run_dir"
  sleep "$BETWEEN_RUN_SECONDS"
}

read -r -a CONNECTION_VALUES <<< "$CONNECTIONS_LIST"
if [[ -n "${RATE_LIST:-}" ]]; then
  read -r -a RATE_VALUES <<< "$RATE_LIST"
  if [[ "${#CONNECTION_VALUES[@]}" -ne "${#RATE_VALUES[@]}" ]]; then
    echo "CONNECTIONS_LIST and RATE_LIST must have the same length for paired sweep." >&2
    echo "CONNECTIONS_LIST has ${#CONNECTION_VALUES[@]} entries; RATE_LIST has ${#RATE_VALUES[@]} entries." >&2
    exit 1
  fi

  log "Sweeping Bookinfo paired connections/rate: CONNECTIONS_LIST=($CONNECTIONS_LIST), RATE_LIST=($RATE_LIST)"
  for i in "${!CONNECTION_VALUES[@]}"; do
    run_one "${CONNECTION_VALUES[$i]}" "${RATE_VALUES[$i]}"
  done
else
  log "Sweeping Bookinfo connections at fixed rate=$RATE: $CONNECTIONS_LIST"
  for connections in "${CONNECTION_VALUES[@]}"; do
    run_one "$connections" "$RATE"
  done
fi

log "Bookinfo sweep complete"
log "summary csv: $SUMMARY_CSV"
