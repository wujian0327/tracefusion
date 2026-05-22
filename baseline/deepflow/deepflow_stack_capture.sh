#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/result/deepflow_stack}"
DEEPFLOW_SOURCE_DIR="${DEEPFLOW_SOURCE_DIR:-$ROOT_DIR/baseline/deepflow/deepflow-v7.1-compose}"
DEEPFLOW_VERSION="${DEEPFLOW_VERSION:-v7.1}"
AGENT_IMAGE="${AGENT_IMAGE:-registry.cn-hongkong.aliyuncs.com/deepflow-ce/deepflow-agent:$DEEPFLOW_VERSION}"
PROJECT="${PROJECT:-trace-fusion-deepflow-$$}"
AGENT_CONTAINER_NAME="${AGENT_CONTAINER_NAME:-deepflow-agent}"
QUERY_PORT="${QUERY_PORT:-20416}"
APP_PORT="${APP_PORT:-20418}"
CONTROLLER_API_PORT="${CONTROLLER_API_PORT:-30417}"
CONTROLLER_GRPC_PORT="${CONTROLLER_GRPC_PORT:-30035}"
INGESTER_PORT="${INGESTER_PORT:-30033}"
READY_TIMEOUT_SECONDS="${READY_TIMEOUT_SECONDS:-240}"
AGENT_READY_TIMEOUT_SECONDS="${AGENT_READY_TIMEOUT_SECONDS:-120}"
AGENT_POST_READY_SECONDS="${AGENT_POST_READY_SECONDS:-60}"
AGENT_CPU_LIMIT="${AGENT_CPU_LIMIT:-1}"
AGENT_MEMORY_LIMIT="${AGENT_MEMORY_LIMIT:-768m}"
POST_WORKLOAD_SECONDS="${POST_WORKLOAD_SECONDS:-30}"
SESSION_AGGREGATE_TIMEOUT="${SESSION_AGGREGATE_TIMEOUT:-10s}"
TCP_REQUEST_TIMEOUT="${TCP_REQUEST_TIMEOUT:-30s}"
UDP_REQUEST_TIMEOUT="${UDP_REQUEST_TIMEOUT:-30s}"
DEEPFLOW_L7_HTTP_PORTS="${DEEPFLOW_L7_HTTP_PORTS:-1-65535}"
DEEPFLOW_L7_HTTP2_PORTS="${DEEPFLOW_L7_HTTP2_PORTS:-1-65535}"
DEEPFLOW_L7_TLS_PORTS="${DEEPFLOW_L7_TLS_PORTS:-$DEEPFLOW_L7_HTTP_PORTS}"
DEEPFLOW_ENABLE_TLS_UPROBE="${DEEPFLOW_ENABLE_TLS_UPROBE:-0}"
DEEPFLOW_ENABLE_GOLANG_UPROBE="${DEEPFLOW_ENABLE_GOLANG_UPROBE:-0}"
DEEPFLOW_GOLANG_UPROBE_REGEX="${DEEPFLOW_GOLANG_UPROBE_REGEX:-bookinfo-http2}"
DEEPFLOW_GOLANG_UPROBE_TRACING_TIMEOUT="${DEEPFLOW_GOLANG_UPROBE_TRACING_TIMEOUT:-60s}"
DEEPFLOW_EBPF_KPROBE_BLACKLIST_PORTS="${DEEPFLOW_EBPF_KPROBE_BLACKLIST_PORTS:-}"
DEEPFLOW_EBPF_KPROBE_WHITELIST_PORTS="${DEEPFLOW_EBPF_KPROBE_WHITELIST_PORTS:-}"
LOCAL_HOST_IP="${LOCAL_HOST_IP:-127.0.0.1}"
LOCAL_HOST_NAME="${LOCAL_HOST_NAME:-$(hostname)}"
AGENT_NODE_IP_FOR_DEEPFLOW="${AGENT_NODE_IP_FOR_DEEPFLOW:-}"
KEEP_DEEPFLOW_STACK="${KEEP_DEEPFLOW_STACK:-1}"
KEEP_DEEPFLOW_AGENT="${KEEP_DEEPFLOW_AGENT:-$KEEP_DEEPFLOW_STACK}"

usage() {
  cat <<'EOF'
Usage:
  baseline/deepflow/deepflow_stack_capture.sh [--out-dir DIR] -- COMMAND...

Starts a local DeepFlow server/MySQL/ClickHouse stack, runs a normal-mode
deepflow-agent against it, applies the X-Mark agent-group config, and then runs
COMMAND. This path keeps DeepFlow's original ingestion and l7_flow_log storage
in the loop; evaluate with evaluate_deepflow_trace.py against the
DeepFlow query API and DeepFlow app's original L7FlowTracing API.

Environment variables:
  OUT_DIR=result/deepflow_stack
  DEEPFLOW_SOURCE_DIR=/tmp/deepflow-v7.1
  DEEPFLOW_VERSION=v7.1
  AGENT_IMAGE=registry.cn-hongkong.aliyuncs.com/deepflow-ce/deepflow-agent:$DEEPFLOW_VERSION
  AGENT_CONTAINER_NAME=deepflow-agent
  QUERY_PORT=20416
  APP_PORT=20418
  CONTROLLER_API_PORT=30417
  CONTROLLER_GRPC_PORT=30035
  INGESTER_PORT=30033
  READY_TIMEOUT_SECONDS=240
  AGENT_READY_TIMEOUT_SECONDS=120
  AGENT_POST_READY_SECONDS=60   # let platform data/senders settle after eBPF starts
  AGENT_CPU_LIMIT=1
  AGENT_MEMORY_LIMIT=768m
  POST_WORKLOAD_SECONDS=30
  SESSION_AGGREGATE_TIMEOUT=10s
  TCP_REQUEST_TIMEOUT=30s
  UDP_REQUEST_TIMEOUT=30s
  DEEPFLOW_L7_HTTP_PORTS=1-65535
  DEEPFLOW_L7_HTTP2_PORTS=1-65535
  DEEPFLOW_L7_TLS_PORTS=$DEEPFLOW_L7_HTTP_PORTS
  DEEPFLOW_ENABLE_TLS_UPROBE=0
  DEEPFLOW_ENABLE_GOLANG_UPROBE=0
  DEEPFLOW_GOLANG_UPROBE_REGEX=bookinfo-http2
  DEEPFLOW_GOLANG_UPROBE_TRACING_TIMEOUT=60s
  DEEPFLOW_EBPF_KPROBE_BLACKLIST_PORTS=
  DEEPFLOW_EBPF_KPROBE_WHITELIST_PORTS=
  LOCAL_HOST_IP=127.0.0.1
  LOCAL_HOST_NAME=$(hostname)
  AGENT_NODE_IP_FOR_DEEPFLOW= # optional; do not set to loopback unless intended
  KEEP_DEEPFLOW_STACK=1       # keep stack after workload for evaluation
  KEEP_DEEPFLOW_AGENT=$KEEP_DEEPFLOW_STACK

Example:
  OUT_DIR=result/deepflow_stack_bookinfo \
    baseline/deepflow/deepflow_stack_capture.sh -- \
    python3 services/bookinfo/uniform_bookinfo_load.py http://127.0.0.1:9080 \
      -c 20 -R 100 -d 5s --mark-prefix df-stack \
      --json-out result/deepflow_stack_bookinfo/load_report.json
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -d "$DEEPFLOW_SOURCE_DIR/common" ]]; then
  DEEPFLOW_COMPOSE_SOURCE_DIR="$DEEPFLOW_SOURCE_DIR"
elif [[ -d "$DEEPFLOW_SOURCE_DIR/manifests/deepflow-docker-compose/common" ]]; then
  DEEPFLOW_COMPOSE_SOURCE_DIR="$DEEPFLOW_SOURCE_DIR/manifests/deepflow-docker-compose"
elif [[ -d "$DEEPFLOW_SOURCE_DIR/deepflow-docker-compose/common" ]]; then
  DEEPFLOW_COMPOSE_SOURCE_DIR="$DEEPFLOW_SOURCE_DIR/deepflow-docker-compose"
else
  echo "DeepFlow source compose files not found under $DEEPFLOW_SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
STACK_DIR="$OUT_DIR/stack"
COMPOSE_DIR="$STACK_DIR/deepflow-docker-compose"
DATA_DIR="$STACK_DIR/data"
mkdir -p "$COMPOSE_DIR" "$DATA_DIR" "$OUT_DIR/agent-log"
cp -a "$DEEPFLOW_COMPOSE_SOURCE_DIR/common" "$COMPOSE_DIR/"
python3 - "$COMPOSE_DIR/common/config/mysql/init.sql" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
text = text.replace("{{ tpl $.Values.password . }}", "deepflow")
path.write_text(text)
PY

COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yaml"
cat >"$COMPOSE_FILE" <<EOF
services:
  mysql:
    image: registry.cn-hongkong.aliyuncs.com/deepflow-ce/mysql:8.0.31
    environment:
      MYSQL_ROOT_PASSWORD: deepflow
      MYSQL_DATABASE: grafana
      TZ: Asia/Shanghai
    volumes:
      - ./common/config/mysql/my.cnf:/etc/my.cnf:ro
      - ./common/config/mysql/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
      - $DATA_DIR/mysql:/var/lib/mysql
    networks:
      - deepflow

  clickhouse:
    image: registry.cn-hongkong.aliyuncs.com/deepflow-ce/clickhouse-server:23.8.7.24
    environment:
      TZ: Asia/Shanghai
    volumes:
      - ./common/config/clickhouse/config.xml:/etc/clickhouse-server/config.xml:ro
      - ./common/config/clickhouse/users.xml:/etc/clickhouse-server/users.xml:ro
      - $DATA_DIR/clickhouse:/var/lib/clickhouse
      - $DATA_DIR/clickhouse_storage:/var/lib/clickhouse_storage
    depends_on:
      - mysql
    networks:
      - deepflow

  deepflow-app:
    image: registry.cn-hongkong.aliyuncs.com/deepflow-ce/deepflow-app:$DEEPFLOW_VERSION
    environment:
      TZ: Asia/Shanghai
      HTTP_PROXY: ""
      HTTPS_PROXY: ""
      http_proxy: ""
      https_proxy: ""
      NO_PROXY: "localhost,127.0.0.1,::1,deepflow-server,deepflow-app,clickhouse,mysql,deepflow-agent"
      no_proxy: "localhost,127.0.0.1,::1,deepflow-server,deepflow-app,clickhouse,mysql,deepflow-agent"
    volumes:
      - ./common/config/deepflow-app/app.yaml:/etc/deepflow/app.yaml:ro
    ports:
      - "$APP_PORT:20418"
    networks:
      - deepflow

  deepflow-server:
    image: registry.cn-hongkong.aliyuncs.com/deepflow-ce/deepflow-server:$DEEPFLOW_VERSION
    environment:
      DEEPFLOW_SERVER_RUNNING_MODE: STANDALONE
      K8S_POD_IP_FOR_DEEPFLOW: 127.0.0.1
      K8S_NODE_IP_FOR_DEEPFLOW: 127.0.0.1
      K8S_NAMESPACE_FOR_DEEPFLOW: deepflow
      K8S_NODE_NAME_FOR_DEEPFLOW: deepflow-host
      K8S_POD_NAME_FOR_DEEPFLOW: deepflow-container
      TZ: Asia/Shanghai
      HTTP_PROXY: ""
      HTTPS_PROXY: ""
      http_proxy: ""
      https_proxy: ""
      NO_PROXY: "localhost,127.0.0.1,::1,deepflow-server,deepflow-app,clickhouse,mysql,deepflow-agent"
      no_proxy: "localhost,127.0.0.1,::1,deepflow-server,deepflow-app,clickhouse,mysql,deepflow-agent"
    volumes:
      - ./common/config/deepflow-server/server.yaml:/etc/server.yaml:ro
    depends_on:
      - mysql
      - clickhouse
      - deepflow-app
    ports:
      - "$QUERY_PORT:20416"
      - "$CONTROLLER_API_PORT:20417"
      - "$CONTROLLER_GRPC_PORT:20035"
      - "$INGESTER_PORT:20033"
    networks:
      - deepflow

networks:
  deepflow:
EOF

AGENT_CONFIG="$OUT_DIR/deepflow-agent.yaml"
cat >"$AGENT_CONFIG" <<EOF
controller-ips:
  - 127.0.0.1
controller-port: $CONTROLLER_GRPC_PORT
log-file: /var/log/deepflow-agent/deepflow-agent.log
override-os-hostname: "$LOCAL_HOST_NAME"
cgroups-disabled: true
EOF

UPROBE_PROCESS_MATCHERS=""
UPROBE_SOCKET_ITEMS=""
UPROBE_SOCKET_CONFIG=""
TLS_PORT_PREFILTER=""
TLS_PROTOCOL_PORT=""
if [[ "$DEEPFLOW_ENABLE_TLS_UPROBE" == "1" ]]; then
  UPROBE_PROCESS_MATCHERS+="$(cat <<'EOF_TLS_MATCHER'
    - match_regex: \bpython(\S)*( +-\S+)* +(\S*/)*([^ /]+)
      match_type: cmdline_with_args
      match_languages: []
      match_usernames: []
      only_in_container: true
      only_with_tag: false
      ignore: false
      rewrite_name: python-tls
      enabled_features:
      - proc.gprocess_info
      - ebpf.socket.uprobe.tls
EOF_TLS_MATCHER
)"
  UPROBE_PROCESS_MATCHERS+=$'\n'
  UPROBE_SOCKET_ITEMS+="$(cat <<'EOF_TLS_SOCKET'
        tls:
          enabled: true
EOF_TLS_SOCKET
)"
  UPROBE_SOCKET_ITEMS+=$'\n'
  TLS_PORT_PREFILTER="        TLS: \"$DEEPFLOW_L7_TLS_PORTS\""
  TLS_PROTOCOL_PORT="    \"TLS\": \"$DEEPFLOW_L7_TLS_PORTS\""
fi
if [[ "$DEEPFLOW_ENABLE_GOLANG_UPROBE" == "1" ]]; then
  UPROBE_PROCESS_MATCHERS+="$(cat <<EOF_GO_MATCHER
    - match_regex: $DEEPFLOW_GOLANG_UPROBE_REGEX
      match_type: process_name
      match_languages: []
      match_usernames: []
      only_in_container: true
      only_with_tag: false
      ignore: false
      rewrite_name: go-tls
      enabled_features:
      - proc.gprocess_info
      - ebpf.socket.uprobe.golang
EOF_GO_MATCHER
)"
  UPROBE_PROCESS_MATCHERS+=$'\n'
  UPROBE_SOCKET_ITEMS+="$(cat <<EOF_GO_SOCKET
        golang:
          enabled: true
          tracing_timeout: $DEEPFLOW_GOLANG_UPROBE_TRACING_TIMEOUT
EOF_GO_SOCKET
)"
  UPROBE_SOCKET_ITEMS+=$'\n'
fi
if [[ -n "$UPROBE_SOCKET_ITEMS" ]]; then
  UPROBE_SOCKET_CONFIG="$(cat <<EOF_UPROBE_SOCKET
      uprobe:
$UPROBE_SOCKET_ITEMS
EOF_UPROBE_SOCKET
)"
fi

AGENT_GROUP_CONFIG="$OUT_DIR/deepflow-agent-group-xmark.yaml"
cat >"$AGENT_GROUP_CONFIG" <<EOF
vtap_group_id: "__VTAP_GROUP_ID__"
collector_enabled: 1
l7_metrics_enabled: 1
l7_log_store_tap_types:
- 0
inputs:
  proc:
    process_matcher:
$UPROBE_PROCESS_MATCHERS
    - match_regex: .*
      enabled_features:
      - proc.gprocess_info
  ebpf:
    socket:
$UPROBE_SOCKET_CONFIG
      kprobe:
        blacklist:
          ports: "$DEEPFLOW_EBPF_KPROBE_BLACKLIST_PORTS"
        whitelist:
          ports: "$DEEPFLOW_EBPF_KPROBE_WHITELIST_PORTS"
      tunning:
        syscall_trace_id_disabled: false
      preprocess:
        out_of_order_reassembly_protocols:
        - HTTP
        - HTTP2
        segmentation_reassembly_protocols:
        - HTTP
        - HTTP2
    profile:
      on_cpu:
        disabled: true
      off_cpu:
        disabled: true
      memory:
        disabled: true
  integration:
    feature_control:
      profile_integration_disabled: true
processors:
  request_log:
    filters:
      port_number_prefilters:
        HTTP: "$DEEPFLOW_L7_HTTP_PORTS"
        HTTP2: "$DEEPFLOW_L7_HTTP2_PORTS"
$TLS_PORT_PREFILTER
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: "x-mark"
        - field_name: "x_mark"
        - field_name: "X-Mark"
        HTTP2:
        - field_name: "x-mark"
        - field_name: "x_mark"
        - field_name: "X-Mark"
static_config:
  profiler: false
  external-profile-integration-disabled: true
  os-proc-regex:
  - match-regex: .*
    match-type: process_name
    action: accept
  l7-log-session-aggr-timeout: "$SESSION_AGGREGATE_TIMEOUT"
  rrt-tcp-timeout: "$TCP_REQUEST_TIMEOUT"
  rrt-udp-timeout: "$UDP_REQUEST_TIMEOUT"
  l7-protocol-ports:
    "HTTP": "$DEEPFLOW_L7_HTTP_PORTS"
    "HTTP2": "$DEEPFLOW_L7_HTTP2_PORTS"
$TLS_PROTOCOL_PORT
  ebpf:
    disabled: false
    kprobe-blacklist:
      port-list: "$DEEPFLOW_EBPF_KPROBE_BLACKLIST_PORTS"
    kprobe-whitelist:
      port-list: "$DEEPFLOW_EBPF_KPROBE_WHITELIST_PORTS"
    on-cpu-profile:
      disabled: true
    off-cpu-profile:
      disabled: true
    memory-profile:
      disabled: true
    syscall-trace-id-disabled: false
    syscall-out-of-order-reassembly:
    - HTTP
    - HTTP2
    syscall-segmentation-reassembly:
    - HTTP
    - HTTP2
  l7-protocol-advanced-features:
    extra-log-fields:
      http:
      - field-name: "x-mark"
      - field-name: "x_mark"
      - field-name: "X-Mark"
      http2:
      - field-name: "x-mark"
      - field-name: "x_mark"
      - field-name: "X-Mark"
EOF

AGENT_GROUP_V7_CONFIG="$OUT_DIR/deepflow-agent-group-v7-xmark.yaml"
cat >"$AGENT_GROUP_V7_CONFIG" <<EOF
inputs:
  proc:
    process_matcher:
$UPROBE_PROCESS_MATCHERS
    - match_regex: .*
      enabled_features:
      - proc.gprocess_info
  ebpf:
    socket:
$UPROBE_SOCKET_CONFIG
      kprobe:
        blacklist:
          ports: "$DEEPFLOW_EBPF_KPROBE_BLACKLIST_PORTS"
        whitelist:
          ports: "$DEEPFLOW_EBPF_KPROBE_WHITELIST_PORTS"
      tunning:
        syscall_trace_id_disabled: false
      preprocess:
        out_of_order_reassembly_protocols:
        - HTTP
        - HTTP2
        segmentation_reassembly_protocols:
        - HTTP
        - HTTP2
    profile:
      on_cpu:
        disabled: true
      off_cpu:
        disabled: true
      memory:
        disabled: true
  integration:
    feature_control:
      profile_integration_disabled: true
processors:
  request_log:
    filters:
      port_number_prefilters:
        HTTP: "$DEEPFLOW_L7_HTTP_PORTS"
        HTTP2: "$DEEPFLOW_L7_HTTP2_PORTS"
$TLS_PORT_PREFILTER
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: "x-mark"
        - field_name: "x_mark"
        - field_name: "X-Mark"
        HTTP2:
        - field_name: "x-mark"
        - field_name: "x_mark"
        - field_name: "X-Mark"
outputs:
  flow_log:
    filters:
      l7_capture_network_types:
      - 0
EOF

agent_name="$AGENT_CONTAINER_NAME"

compose() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  if [[ "$KEEP_DEEPFLOW_AGENT" != "1" ]] && docker ps -a --format '{{.Names}}' | grep -qx "$agent_name"; then
    docker rm -f "$agent_name" >/dev/null 2>&1 || true
  fi
  if [[ "$KEEP_DEEPFLOW_STACK" != "1" ]]; then
    compose down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

echo "Starting DeepFlow server stack"
echo "  project: $PROJECT"
echo "  out:     $OUT_DIR"
compose up -d mysql clickhouse deepflow-app

echo "Waiting for DeepFlow MySQL"
mysql_container="${PROJECT}-mysql-1"
for _ in $(seq 1 "$READY_TIMEOUT_SECONDS"); do
  if docker exec "$mysql_container" mysqladmin ping -h127.0.0.1 -P30130 -uroot -pdeepflow >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$mysql_container" mysqladmin ping -h127.0.0.1 -P30130 -uroot -pdeepflow >/dev/null 2>&1; then
  echo "Timed out waiting for DeepFlow MySQL" >&2
  compose logs --tail=120 mysql >&2 || true
  exit 1
fi

compose up -d deepflow-server

echo "Waiting for DeepFlow controller API"
for _ in $(seq 1 "$READY_TIMEOUT_SECONDS"); do
  if python3 - "$CONTROLLER_API_PORT" <<'PY' >/dev/null 2>&1
import sys
import urllib.request
urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/v1/vtap-groups/", timeout=2).read()
PY
  then
    break
  fi
  sleep 1
done

if ! python3 - "$CONTROLLER_API_PORT" <<'PY' >/dev/null 2>&1
import sys
import urllib.request
urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/v1/vtap-groups/", timeout=3).read()
PY
then
  echo "Timed out waiting for DeepFlow controller API on port $CONTROLLER_API_PORT" >&2
  compose logs --tail=120 deepflow-server >&2 || true
  exit 1
fi

echo "Seeding local host resource for agent registration"
sql_local_host_ip="${LOCAL_HOST_IP//\'/\'\'}"
sql_local_host_name="${LOCAL_HOST_NAME//\'/\'\'}"
docker exec "$mysql_container" mysql -uroot -pdeepflow -P30130 -h127.0.0.1 deepflow \
  --protocol=tcp \
  --execute "
INSERT INTO host_device
  (type, state, name, alias, description, ip, hostname, htype, create_method,
   vcpu_num, mem_total, az, region, domain, lcuuid, synced_at, created_at, updated_at)
SELECT
  1, 2, '$sql_local_host_name', '$sql_local_host_name', 'trace-fusion local DeepFlow host',
  '$sql_local_host_ip', '$sql_local_host_name', 3, 1, 0, 0,
  'ffffffff-ffff-ffff-ffff-ffffffffffff',
  'ffffffff-ffff-ffff-ffff-ffffffffffff',
  'ffffffff-ffff-ffff-ffff-ffffffffffff',
  UUID(), NOW(), NOW(), NOW()
WHERE NOT EXISTS (
  SELECT 1 FROM host_device
  WHERE deleted_at IS NULL
    AND (ip = '$sql_local_host_ip' OR name = '$sql_local_host_name')
);
" >/dev/null

echo "Resolving default agent group"
agent_group_short_uuid=""
agent_group_lcuuid=""
read -r agent_group_short_uuid agent_group_lcuuid < <(python3 - "$CONTROLLER_API_PORT" <<'PY'
import json
import sys
import urllib.request

data = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/v1/vtap-groups/", timeout=3).read())
groups = data.get("DATA") or []
for group in groups:
    short_uuid = group.get("SHORT_UUID") or ""
    lcuuid = group.get("LCUUID") or ""
    if short_uuid and lcuuid:
        print(short_uuid, lcuuid)
        break
PY
)
if [[ -z "$agent_group_short_uuid" || -z "$agent_group_lcuuid" ]]; then
  echo "Could not resolve a DeepFlow agent group" >&2
  exit 1
fi
python3 - "$AGENT_GROUP_CONFIG" "$agent_group_short_uuid" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
short_uuid = sys.argv[2]
path.write_text(path.read_text().replace("__VTAP_GROUP_ID__", short_uuid))
PY

echo "Applying DeepFlow agent-group X-Mark config"
python3 - "$CONTROLLER_API_PORT" "$agent_group_short_uuid" "$AGENT_GROUP_CONFIG" <<'PY'
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

port, short_uuid, path = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"
body = open(path, encoding="utf-8").read().encode()

def request(method, url, data=None, content_type="application/yaml"):
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", content_type)
    return json.loads(urllib.request.urlopen(req, timeout=10).read().decode())

try:
    payload = request("POST", f"{base}/v1/vtap-group-configuration/advanced/", body)
    if payload.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError(payload.get("DESCRIPTION") or str(payload)[:1000])
    print("POST")
except Exception as exc:
    if isinstance(exc, urllib.error.HTTPError):
        text = exc.read().decode(errors="replace")
    else:
        text = str(exc)
    if "already exist" not in text:
        raise
    query = urllib.parse.urlencode({"vtap_group_id": short_uuid})
    payload = request("GET", f"{base}/v1/vtap-group-configuration/filter/?{query}", None)
    if payload.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError(payload.get("DESCRIPTION") or str(payload)[:1000])
    configs = request("GET", f"{base}/v1/vtap-group-configuration/", None)
    config_lcuuid = ""
    for item in configs.get("DATA") or []:
        if item.get("VTAP_GROUP_SHORT_UUID") == short_uuid or item.get("VTAP_GROUP_ID") == short_uuid:
            config_lcuuid = item.get("LCUUID") or ""
            break
    if not config_lcuuid:
        raise RuntimeError(f"cannot find existing config lcuuid for {short_uuid}")
    payload = request("PATCH", f"{base}/v1/vtap-group-configuration/advanced/{config_lcuuid}/", body)
    if payload.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError(payload.get("DESCRIPTION") or str(payload)[:1000])
    print("PATCH")
PY

echo "Applying DeepFlow v7 agent-group YAML config"
python3 - "$CONTROLLER_API_PORT" "$agent_group_lcuuid" "$AGENT_GROUP_V7_CONFIG" <<'PY'
import json
import sys
import urllib.request

port, group_lcuuid, path = sys.argv[1], sys.argv[2], sys.argv[3]
body = open(path, encoding="utf-8").read().encode()
req = urllib.request.Request(
    f"http://127.0.0.1:{port}/v1/agent-group-configuration/{group_lcuuid}/yaml",
    data=body,
    method="POST",
    headers={"Content-Type": "application/yaml"},
)
payload = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
if payload.get("OPT_STATUS") != "SUCCESS":
    raise RuntimeError(payload.get("DESCRIPTION") or str(payload)[:1000])
print("POST")
PY

echo "Starting normal-mode deepflow-agent"
docker rm -f "$agent_name" >/dev/null 2>&1 || true
agent_env_args=()
if [[ -n "$AGENT_NODE_IP_FOR_DEEPFLOW" ]]; then
  agent_env_args=(-e K8S_NODE_IP_FOR_DEEPFLOW="$AGENT_NODE_IP_FOR_DEEPFLOW")
fi
docker run -d \
  --name "$agent_name" \
  --restart unless-stopped \
  --network host \
  --pid host \
  --privileged \
  --cpus "$AGENT_CPU_LIMIT" \
  --memory "$AGENT_MEMORY_LIMIT" \
  -e HTTP_PROXY="" \
  -e HTTPS_PROXY="" \
  -e http_proxy="" \
  -e https_proxy="" \
  -e NO_PROXY="localhost,127.0.0.1,::1,deepflow-server,deepflow-app,clickhouse,mysql,deepflow-agent" \
  -e no_proxy="localhost,127.0.0.1,::1,deepflow-server,deepflow-app,clickhouse,mysql,deepflow-agent" \
  "${agent_env_args[@]}" \
  -v "$AGENT_CONFIG:/etc/deepflow-agent/deepflow-agent.yaml:ro" \
  -v "$OUT_DIR/agent-log:/var/log/deepflow-agent" \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  "$AGENT_IMAGE" >/dev/null

echo "Waiting for deepflow-agent registration"
agent_lcuuid=""
for _ in $(seq 1 "$AGENT_READY_TIMEOUT_SECONDS"); do
  agent_lcuuid="$(python3 - "$CONTROLLER_API_PORT" "$LOCAL_HOST_IP" <<'PY' 2>/dev/null || true
import json
import sys
import urllib.request

data = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/v1/vtaps/", timeout=3).read())
for vtap in data.get("DATA") or []:
    if vtap.get("CTRL_IP") == sys.argv[2] or vtap.get("NAME"):
        print(vtap.get("LCUUID") or "")
        break
PY
)"
  if [[ -n "$agent_lcuuid" ]]; then
    break
  fi
  sleep 1
done

if [[ -z "$agent_lcuuid" ]]; then
  echo "Timed out waiting for deepflow-agent registration" >&2
  docker logs --tail=120 "$agent_name" >&2 || true
  compose logs --tail=160 deepflow-server >&2 || true
  exit 1
fi

echo "Restarting agent to load agent-group config"
docker restart "$agent_name" >/dev/null

echo "Waiting for deepflow-agent eBPF readiness"
agent_ready_pattern="Set current state: TRACER_RUNNING|Set the status to TRACER_RUNNING|ebpf kprobe enabled|Kprobe feature has been enabled"
for _ in $(seq 1 "$AGENT_READY_TIMEOUT_SECONDS"); do
  agent_logs="$(docker logs --tail=300 "$agent_name" 2>&1 || true)"
  grep -Eq "$agent_ready_pattern" <<<"$agent_logs" && break
  sleep 1
done
agent_logs="$(docker logs --tail=300 "$agent_name" 2>&1 || true)"
if ! grep -Eq "$agent_ready_pattern" <<<"$agent_logs"; then
  echo "Timed out waiting for deepflow-agent eBPF readiness" >&2
  docker logs --tail=160 "$agent_name" >&2 || true
  exit 1
fi
if [[ "$(docker inspect -f '{{.State.Running}}' "$agent_name" 2>/dev/null || true)" != "true" ]]; then
  echo "deepflow-agent exited after config reload; starting it once more"
  docker start "$agent_name" >/dev/null
  sleep 5
fi
if [[ "$(docker inspect -f '{{.State.Running}}' "$agent_name" 2>/dev/null || true)" != "true" ]]; then
  echo "deepflow-agent is not running after readiness check" >&2
  docker logs --tail=160 "$agent_name" >&2 || true
  exit 1
fi
if [[ "$AGENT_POST_READY_SECONDS" -gt 0 ]]; then
  echo "Waiting ${AGENT_POST_READY_SECONDS}s for DeepFlow senders/platform data to settle"
  sleep "$AGENT_POST_READY_SECONDS"
fi

if [[ $# -gt 0 ]]; then
  echo "Running workload command: $*"
  "$@"
fi

if [[ "$POST_WORKLOAD_SECONDS" -gt 0 ]]; then
  sleep "$POST_WORKLOAD_SECONDS"
fi

cat >"$OUT_DIR/deepflow-stack.env" <<EOF
DEEPFLOW_QUERY_API=http://127.0.0.1:$QUERY_PORT/v1/query/
DEEPFLOW_APP_TRACING_API=http://127.0.0.1:$APP_PORT/v1/stats/querier/L7FlowTracing
DEEPFLOW_CONTROLLER_API=http://127.0.0.1:$CONTROLLER_API_PORT
DEEPFLOW_PROJECT=$PROJECT
DEEPFLOW_AGENT_CONTAINER=$agent_name
EOF

echo "DeepFlow query API: http://127.0.0.1:$QUERY_PORT/v1/query/"
echo "DeepFlow app tracing API: http://127.0.0.1:$APP_PORT/v1/stats/querier/L7FlowTracing"
echo "stack env: $OUT_DIR/deepflow-stack.env"
