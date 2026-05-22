# DeepFlow Trace Reconstruction Baseline

This directory keeps the DeepFlow baseline focused on one workflow:

1. run DeepFlow server/app/ClickHouse plus a normal-mode `deepflow-agent`;
2. deploy the shared Bookinfo validation workload from `services/bookinfo`;
3. generate requests with an `X-Mark` ground-truth marker;
4. call DeepFlow app's original `L7FlowTracing` module for each request;
5. report request-level trace accuracy.

The evaluator delegates trace reconstruction entirely to DeepFlow app.
[evaluate_deepflow_trace.py](./evaluate_deepflow_trace.py)
uses the DeepFlow query API to find and score rows, but delegates reconstruction
to DeepFlow app's `/v1/stats/querier/L7FlowTracing` endpoint.

## Files

```text
values-deepflow.yaml
  Helm values for the local DeepFlow deployment.

start.md
  End-to-end commands: start Minikube, install DeepFlow v7.1, configure X-Mark,
  deploy Bookinfo, run load, and evaluate accuracy.

evaluate_deepflow_trace.py
  Main baseline evaluator. It reads the load report, finds anchors in
  DeepFlow `l7_flow_log`, calls DeepFlow app's original `L7FlowTracing`, and
  computes exact-match accuracy.

deepflow_stack_capture.sh
  Starts a local DeepFlow server/MySQL/ClickHouse stack plus a normal-mode
  deepflow-agent. This is the preferred local path when comparing against
  original DeepFlow, because data flows through DeepFlow's real collector
  sender, ingester, ClickHouse tables, query API, and app tracing API.
  The wrapper pins the local stack to DeepFlow `v7.1`.

../../services/bookinfo/
  Shared Bookinfo deployment. It propagates `X-Mark` through
  productpage -> details/reviews -> ratings and is used by both the normal
  pcap/eBPF experiments and the DeepFlow baseline.
```

## Accuracy Definition

For each generated request, the evaluator checks:

```text
all rows in the reconstructed DeepFlow trace have the same X-Mark
each expected Bookinfo business edge appears with the expected DeepFlow spans
span_capture_missing: expected business spans absent from l7_flow_log for that X-Mark
span_pairing_error: captured spans that DeepFlow L7FlowTracing missed, over-selected, or mixed with another X-Mark
```

Expected Bookinfo business edges:

```text
productpage -> details
productpage -> reviews
reviews -> ratings
```

DeepFlow Distributed Trace may emit four observation spans for one RPC edge:

```text
c-p -> c -> s -> s-p
```

So a complete Bookinfo request can have 12 business L7 spans, not 6.

## Main Commands

See [start.md](./start.md) for the full startup flow. The final two commands
are usually:

```bash
python3 services/bookinfo/uniform_bookinfo_load.py \
  http://127.0.0.1:9080 \
  -c 20 \
  -R 20 \
  --count 200 \
  --book-count 100 \
  --mark-prefix df-xmark \
  --json-out result/deepflow_xmark_200_load_report.json

python3 baseline/deepflow/evaluate_deepflow_trace.py \
  --load-report result/deepflow_xmark_200_load_report.json \
  --output result/deepflow_trace_report.json \
  --api-url http://127.0.0.1:20416/v1/query/ \
  --deepflow-app-url http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing \
  --count 200 \
  --max-iteration 6
```

## Local eBPF Collection

For local collection, prefer the full DeepFlow stack wrapper over pcap or
hand-converted datadump rows. PCAP can recover HTTP headers, request paths, and
TCP sequence numbers, but it cannot recover DeepFlow's process-side fields such
as `tap_side=c-p/s-p` or `syscall_trace_id_request/syscall_trace_id_response`.
Those fields are emitted by DeepFlow's eBPF path and are required for a faithful
DeepFlow tracing baseline.

The closest local path is:

```bash
OUT_DIR=result/deepflow_stack_bookinfo \
baseline/deepflow/deepflow_stack_capture.sh -- \
  python3 services/bookinfo/uniform_bookinfo_load.py \
    http://127.0.0.1:9080 \
    -c 20 \
    -R 100 \
    --count 200 \
    --book-count 100 \
    --mark-prefix df-stack \
    --json-out result/deepflow_stack_bookinfo/load_report.json
```

The wrapper starts the real DeepFlow v7.1 server stack, seeds one local
`host_device` resource so the normal-mode agent can register through DeepFlow's
standard path, applies the v7 agent-group YAML config through:

```text
/v1/agent-group-configuration/<agent-group-lcuuid>/yaml
```

It also writes the legacy `/v1/vtap-group-configuration/advanced/` config for
compatibility with older controllers. On v7.1, the new agent-group YAML API is
the one that is actually consumed by `deepflow-agent`.

The applied v7.1 config:

```yaml
inputs:
  proc:
    process_matcher:
    - match_regex: .*
      enabled_features:
      - proc.gprocess_info
  ebpf:
    socket:
      tunning:
        syscall_trace_id_disabled: false
      preprocess:
        out_of_order_reassembly_protocols: [HTTP, HTTP2]
        segmentation_reassembly_protocols: [HTTP, HTTP2]
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
```

The process matcher override is intentional. DeepFlow v7.1's default matcher
enables `ebpf.profile.on_cpu` for Java/Python/Node/deepflow processes; in the
local Docker path that caused continuous-profiler startup errors and agent
restarts. The baseline only needs socket eBPF and L7 trace reconstruction, so
profiling is disabled.

For single-benchmark Docker Compose runs, restrict DeepFlow's L7 collection at
the agent config layer with protocol port prefilters. For Hotel HTTP/1.1:

```bash
DEEPFLOW_L7_HTTP_PORTS=5000,8081-8089 \
DEEPFLOW_L7_HTTP2_PORTS=5000,8081-8089 \
OUT_DIR=result/deepflow_stack_hotel_http1 \
baseline/deepflow/deepflow_stack_capture.sh -- \
  ./scripts/run_hotel_http1_exp.sh deepflow
```

This keeps the agent running normally but prevents HTTP/HTTP2 traffic from
other benchmark ports from entering `l7_flow_log`. Do not use a complement
`kprobe.blacklist` for this: DeepFlow checks both sides of a connection, so
blacklisting non-Hotel ports can also drop Hotel flows whose client-side
ephemeral port falls in the blacklist.

After eBPF is ready, the query API is available at:

```text
http://127.0.0.1:20416/v1/query/
```

It also exposes DeepFlow app's original L7FlowTracing module at:

```text
http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing
```

On local Docker Compose Bookinfo there is no Kubernetes metadata, so
`pod_service_0/1` is empty even though DeepFlow captured the correct eBPF
fields. Pass a Docker IP service map to the evaluator; it fills missing service
names from DeepFlow's `auto_service_0/1` values:

```bash
python3 baseline/deepflow/evaluate_deepflow_trace.py \
  --load-report result/deepflow_stack_bookinfo/load_report.json \
  --output result/deepflow_stack_bookinfo/deepflow_trace_report.json \
  --api-url http://127.0.0.1:20416/v1/query/ \
  --deepflow-app-url http://127.0.0.1:20418/v1/stats/querier/L7FlowTracing \
  --service-map result/deepflow_stack_bookinfo/service_map.json \
  --count 200
```

The evaluator always asks DeepFlow app's `L7FlowTracing` module for the
reconstructed `_ids`; the local script only scores those returned rows against
the X-Mark ground truth.

## v7.1 Smoke Result

After switching the local stack to DeepFlow `v7.1` and writing the new
agent-group YAML config, the Hotel HTTP/1.1 smoke run:

```text
rps=100, connections=20, duration=5s
```

produced:

```text
Lineage      99.40% (497/500)
TraceWeaver  96.00% (480/500)
DeepFlow     85.00% (425/500)
```

DeepFlow captured the workload and `L7FlowTracing` returned results
(`query_rows=9916`, `anchor_marks_found=498`, `deepflow_success=498`). The
remaining loss was from span capture/pairing errors, not from a missing local
collector path.

For local Docker Compose Bookinfo, the service map can look like:

```json
{
  "172.17.0.5": {"service": "productpage", "namespace": "bookinfo"},
  "172.17.0.2": {"service": "details", "namespace": "bookinfo"},
  "172.17.0.4": {"service": "reviews", "namespace": "bookinfo"},
  "172.17.0.3": {"service": "ratings", "namespace": "bookinfo"}
}
```
