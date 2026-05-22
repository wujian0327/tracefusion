# DeepFlow Startup And Native Evaluation

This is the current DeepFlow baseline path. It keeps DeepFlow's collector and
storage in the loop, and evaluates trace reconstruction by calling DeepFlow
app's original `L7FlowTracing` module.

## 1. Start Minikube

```bash
minikube start \
  --driver=docker \
  --container-runtime=containerd \
  --cpus=10 \
  --memory=16000 \
  --image-mirror-country=cn
```

## 2. Install DeepFlow v7.1

The local Docker stack is pinned to DeepFlow `v7.1`. Use the matching Helm
chart when comparing against Minikube:

```bash
helm repo update deepflow
helm search repo deepflow/deepflow --versions | head
```

The chart used here is `7.1.002` with app version `7.1`.

```bash
helm install deepflow -n deepflow deepflow/deepflow \
  --version 7.1.002 \
  --create-namespace \
  -f baseline/deepflow/values-deepflow.yaml

kubectl -n deepflow get pods -o wide
kubectl -n deepflow rollout status daemonset/deepflow-agent
```

Forward the DeepFlow SQL API:

```bash
kubectl -n deepflow port-forward svc/deepflow-server 20416:20416
```

Forward the DeepFlow app tracing API:

```bash
kubectl -n deepflow port-forward svc/deepflow-app 20418:20418
```

Forward the DeepFlow control API when updating the agent config:

```bash
kubectl -n deepflow port-forward svc/deepflow-server 30417:20417
```

Grafana is optional for manual inspection:

```bash
kubectl -n deepflow port-forward svc/deepflow-grafana 3000:80
```

## 3. Enable X-Mark Collection

For request-level correctness checks, use a marker header that DeepFlow does
not use as a trace key:

```text
X-Mark: df-xmark-000001
```

Important: configure `X-Mark` only as a custom field. Do not add it to
`tracing_tag.x_request_id`, `tracing_tag.apm_trace_id`, or
`tracing_tag.apm_span_id`.

DeepFlow v7.1 consumes the new agent-group YAML config stored behind:

```text
/v1/agent-group-configuration/<agent-group-lcuuid>/yaml
```

The older `/v1/vtap-group-configuration/advanced/` path is not enough for v7.1
because the agent reads the new `agent_group_configuration` table. The config
below mirrors the local wrapper: extract X-Mark, keep socket eBPF trace IDs,
enable HTTP/HTTP2 syscall reassembly, collect all L7 tap types, and disable
continuous profiling. For the Go TLS Bookinfo workload, it also enables the Go
TLS uprobe and matches the `bookinfo-tls-go` process so DeepFlow can attach to
`crypto/tls.(*Conn).Read` and `crypto/tls.(*Conn).Write`.

```bash
GROUP_LCUUID="$(
python3 - <<'PY'
import json
import urllib.request

data = json.loads(urllib.request.urlopen("http://127.0.0.1:30417/v1/vtap-groups/", timeout=5).read())
groups = data.get("DATA") or []
for group in groups:
    if group.get("NAME") == "default":
        print(group["LCUUID"])
        break
else:
    print(groups[0]["LCUUID"])
PY
)"

cat >/tmp/deepflow-agent-group-v7-xmark.yaml <<'EOF'
inputs:
  proc:
    process_matcher:
    - match_regex: bookinfo-tls-go
      match_type: process_name
      match_languages: []
      match_usernames: []
      only_in_container: true
      only_with_tag: false
      ignore: false
      rewrite_name: bookinfo-tls-go
      enabled_features:
      - proc.gprocess_info
      - ebpf.socket.uprobe.golang
    - match_regex: .*
      enabled_features:
      - proc.gprocess_info
  ebpf:
    socket:
      uprobe:
        golang:
          enabled: true
          tracing_timeout: 60s
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

python3 - "$GROUP_LCUUID" /tmp/deepflow-agent-group-v7-xmark.yaml <<'PY'
import json
import sys
import urllib.request

group_lcuuid, path = sys.argv[1], sys.argv[2]
body = open(path, encoding="utf-8").read().encode()
req = urllib.request.Request(
    f"http://127.0.0.1:30417/v1/agent-group-configuration/{group_lcuuid}/yaml",
    data=body,
    method="POST",
    headers={"Content-Type": "application/yaml"},
)
payload = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
if payload.get("OPT_STATUS") != "SUCCESS":
    raise SystemExit(payload)
print(payload.get("OPT_STATUS"))
PY

kubectl -n deepflow rollout restart daemonset/deepflow-agent
kubectl -n deepflow rollout status daemonset/deepflow-agent
```

Verify that the v7.1 agent loaded the intended config:

```bash
kubectl -n deepflow logs daemonset/deepflow-agent --since=10m | \
  grep -n 'Update inputs.ebpf.profile.on_cpu.disabled\|Update inputs.proc.process_matcher\|custom_fields'
```

There should be no continuous-profiler errors:

```bash
kubectl -n deepflow logs daemonset/deepflow-agent --since=10m | \
  grep -n '\[CP\]\|df_PE_python_unwind' || true
```

`X-Mark` appears in `l7_flow_log.attribute`/`attribute_names` +
`attribute_values`; it does not populate `trace_id`, `span_id`,
`parent_span_id`, `x_request_id_0`, or `x_request_id_1`, so it can be used as
ground truth after DeepFlow reconstructs the trace.

DeepFlow app trace reconstruction uses sources such as:

```text
trace_id
syscall
tcp_seq
x_request_id
dns
```

## 4. Deploy Bookinfo

This deployment keeps the official Bookinfo service shape, but uses the shared
`services/bookinfo` overrides so `X-Mark` can propagate through the downstream
calls.

```bash
eval "$(minikube docker-env)"
docker build -t trace-fusion-bookinfo-details:extended \
  services/bookinfo/overrides/details
docker build -t trace-fusion-bookinfo-ratings:extended \
  services/bookinfo/overrides/ratings
docker build -t trace-fusion-bookinfo-reviews:extended \
  services/bookinfo/overrides/reviews
docker build -t trace-fusion-bookinfo-productpage:extended \
  services/bookinfo/overrides/productpage
eval "$(minikube docker-env -u)"
```

```bash
kubectl apply -f services/bookinfo/kube/bookinfo-xmark.yaml
kubectl -n bookinfo rollout status deploy/details-v1
kubectl -n bookinfo rollout status deploy/ratings-v1
kubectl -n bookinfo rollout status deploy/reviews-v2
kubectl -n bookinfo rollout status deploy/productpage-v1
```

Expose productpage locally:

```bash
kubectl -n bookinfo port-forward svc/productpage 9080:9080
```

Manual check:

```bash
curl -H 'X-Mark: manual-check' 'http://127.0.0.1:9080/productpage?id=0'
```

## 5. Run Load

```bash
python3 services/bookinfo/uniform_bookinfo_load.py \
  http://127.0.0.1:9080 \
  -c 20 \
  -R 20 \
  --count 200 \
  --book-count 100 \
  --mark-prefix df-xmark \
  --json-out result/deepflow_xmark_200_load_report.json
```

## 6. Evaluate

```bash
python3 baseline/deepflow/evaluate_deepflow_trace.py \
  --load-report result/deepflow_xmark_200_load_report.json \
  --output result/deepflow_trace_report.json \
  --api-url http://127.0.0.1:20416/v1/query/ \
  --deepflow-app-url http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing \
  --count 200 \
  --max-iteration 6
```

The evaluator finds one anchor flow for each X-Mark, calls DeepFlow app's
original `L7FlowTracing` endpoint to get the reconstructed `_ids`, then scores
those rows:

```text
all rows in one reconstructed trace have the same X-Mark
each expected business edge has the expected number of DeepFlow observation spans
span_capture_missing: expected business spans absent from l7_flow_log for that X-Mark
span_pairing_error: captured spans that DeepFlow L7FlowTracing missed, over-selected, or mixed with another X-Mark
```

## Notes For v7.1 Comparison

Before comparing accuracy, first check that DeepFlow is actually capturing the
workload:

```bash
python3 baseline/deepflow/evaluate_deepflow_trace.py \
  --load-report result/deepflow_xmark_200_load_report.json \
  --output result/deepflow_trace_report.json \
  --api-url http://127.0.0.1:20416/v1/query/ \
  --deepflow-app-url http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing \
  --count 20 \
  --max-iteration 6

python3 - <<'PY'
import json
from pathlib import Path
r = json.loads(Path("result/deepflow_trace_report.json").read_text())
for k in [
    "query_rows",
    "anchor_marks_found",
    "deepflow_trace_success_count",
    "trace_exact_count",
    "trace_exact_pct_of_requested",
    "span_capture_missing_trace_count",
    "span_pairing_error_trace_count",
    "wrong_mark_span_count",
]:
    print(k, r.get(k))
PY
```

If `query_rows` or `anchor_marks_found` is zero, this is still a collection or
agent-config issue. If anchors are present but `trace_exact_count` is low, the
collector is working and the remaining loss is DeepFlow trace reconstruction or
span pairing.

The local Docker DeepFlow v7.1 Hotel HTTP/1.1 smoke run after the config fix:

```text
rps=100, connections=20, duration=5s
query_rows=9916
anchor_marks_found=498/500
deepflow_trace_success=498/500
trace_exact=425/500 (85.00%)
span_capture_missing_traces=6
span_pairing_error_traces=72
wrong_mark_spans=22
```

This confirms that the v7.1 collector path is active and that the remaining
error is not caused by pcap conversion or a missing local eBPF collector.

DeepFlow Distributed Trace may include four observation spans per RPC edge:

```text
c-p -> c -> s -> s-p
```

So Bookinfo's three business edges may appear as 12 business L7 spans:

```text
productpage -> details   : 4 spans
productpage -> reviews   : 4 spans
reviews -> ratings       : 4 spans
```

This is DeepFlow's observation-point model, not the usual APM two-span model.
For strict request-level checks, also verify that all rows in one reconstructed
trace have the same `X-Mark`. A trace can be structurally complete but still
wrong if `L7FlowTracing` mixes rows from two root markers, for example:

```text
df-rid-both-000004 + df-rid-both-000006
```
