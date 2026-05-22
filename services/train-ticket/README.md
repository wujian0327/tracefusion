# TrainTicket Preserve Benchmark

Commands below are intended to be run from the repository root.

## Start services

Build the X-Mark propagation override images and start the trimmed TrainTicket
preserve stack:

```bash
services/train-ticket/overrides/xmark-propagation/build.sh

docker compose \
  -f services/train-ticket/docker-compose.yml \
  -f services/train-ticket/docker-compose.xmark.yml \
  up -d

docker compose \
  -f services/train-ticket/docker-compose.yml \
  -f services/train-ticket/docker-compose.xmark.yml \
  ps
```

Stop the stack when done:

```bash
docker compose \
  -f services/train-ticket/docker-compose.yml \
  -f services/train-ticket/docker-compose.xmark.yml \
  down
```

## Seed benchmark data

Seed the extra 20-station, 100-train preserve benchmark data. This creates
trips `D1345` through `D1444` and distributes them across 20 station pairs.

```bash
docker compose \
  -f services/train-ticket/docker-compose.yml \
  -f services/train-ticket/docker-compose.xmark.yml \
  exec -T ts-station-mongo \
  mongo --quiet < services/train-ticket/seed_extra_data.js
```

## Minikube deployment

The Kubernetes manifest is:

```bash
services/train-ticket/kube/train-ticket-xmark.yaml
```

Start Minikube with enough memory for the trimmed TrainTicket stack:

```bash
minikube start \
  --driver=docker \
  --container-runtime=containerd \
  --cpus=10 \
  --memory=16000 \
  --image-mirror-country=cn
```

The TrainTicket images are large and Docker Hub is often slow from WSL. If the
images already exist in the local Docker daemon, load them into Minikube before
applying the manifest. The manifest uses `imagePullPolicy: Never`, so pods use
these local images and do not try to pull from Docker Hub.

```bash
for IMAGE in \
  docker.io/library/mongo:4.4 \
  docker.io/codewisdom/ts-auth-service:0.2.0 \
  docker.io/codewisdom/ts-user-service:0.2.0 \
  docker.io/codewisdom/ts-verification-code-service:0.2.0 \
  docker.io/codewisdom/ts-route-service:0.2.0 \
  docker.io/codewisdom/ts-contacts-service:0.2.0 \
  docker.io/codewisdom/ts-order-service:0.2.0 \
  docker.io/codewisdom/ts-order-other-service:0.2.0 \
  docker.io/codewisdom/ts-config-service:0.2.0 \
  docker.io/codewisdom/ts-station-service:0.2.0 \
  docker.io/codewisdom/ts-train-service:0.2.0 \
  docker.io/codewisdom/ts-travel-service:0.2.0 \
  docker.io/codewisdom/ts-preserve-service:0.2.0 \
  docker.io/codewisdom/ts-basic-service:0.2.0 \
  docker.io/codewisdom/ts-ticketinfo-service:0.2.0 \
  docker.io/codewisdom/ts-price-service:0.2.0 \
  docker.io/codewisdom/ts-security-service:0.2.0 \
  docker.io/codewisdom/ts-seat-service:0.2.0
do
  minikube image load --daemon "$IMAGE"
done
```

Build the X-Mark propagation jar and create the ConfigMap used by the pods:

```bash
services/train-ticket/overrides/xmark-propagation/build.sh

kubectl create namespace train-ticket \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n train-ticket create configmap xmark-propagation-jar \
  --from-file=xmark-propagation.jar=services/train-ticket/overrides/xmark-propagation/build/xmark-propagation.jar \
  --dry-run=client -o yaml | kubectl apply -f -
```

Apply the TrainTicket manifest:

```bash
kubectl apply -f services/train-ticket/kube/train-ticket-xmark.yaml

kubectl -n train-ticket get pods -w
```

Wait for the services to roll out:

```bash
for DEPLOY in $(kubectl -n train-ticket get deploy -o name); do
  kubectl -n train-ticket rollout status "$DEPLOY" --timeout=180s
done
```

Seed the benchmark data inside the Kubernetes namespace:

```bash
kubectl -n train-ticket exec -i deploy/ts-station-mongo -- \
  mongo --quiet < services/train-ticket/seed_extra_data.js
```

Expose the three external endpoints used by the load generator. Port-forward is
usually the most predictable option on Minikube:

```bash
kubectl -n train-ticket port-forward svc/ts-preserve-service 14568:14568
kubectl -n train-ticket port-forward svc/ts-auth-service 12340:12340
kubectl -n train-ticket port-forward svc/ts-contacts-service 12347:12347
```

Alternatively, the manifest also exposes NodePorts:

```bash
MINIKUBE_IP=$(minikube ip)
echo "preserve: http://${MINIKUBE_IP}:31468"
echo "auth:     http://${MINIKUBE_IP}:31340"
echo "contacts: http://${MINIKUBE_IP}:31347"
```

Run the uniform preserve workload against port-forwarded services:

```bash
python3 services/train-ticket/uniform_train_ticket_load.py \
  http://127.0.0.1:14568 \
  -c 20 -R 1 -d 5s \
  --trip-ids D1345-D1444 \
  --trip-mode round-robin \
  --station-mode trip \
  --mark-prefix trainticket-kube-10rps \
  --json-out result/train_ticket/kube_10rps_5s/loadgen_report.json
```

Or run through NodePort:

```bash
MINIKUBE_IP=$(minikube ip)

python3 services/train-ticket/uniform_train_ticket_load.py \
  "http://${MINIKUBE_IP}:31468" \
  --auth-url "http://${MINIKUBE_IP}:31340/api/v1/users/login" \
  --contact-url "http://${MINIKUBE_IP}:31347/api/v1/contactservice/contacts/account" \
  -c 20 -R 10 -d 5s \
  --trip-ids D1345-D1444 \
  --trip-mode round-robin \
  --station-mode trip \
  --mark-prefix trainticket-kube-10rps \
  --json-out result/train_ticket/kube_10rps_5s/loadgen_report.json
```

For DeepFlow, the important labels are already present on pods and services:
`app=<service-name>` and `service=<service-name>`. After generating traffic,
check that DeepFlow sees flows in the `train-ticket` namespace, especially
edges from `ts-preserve-service` to `ts-security-service`,
`ts-contacts-service`, `ts-travel-service`, `ts-ticketinfo-service`,
`ts-seat-service`, `ts-order-service`, and `ts-user-service`.

## Fixed capture ports

Only capture the ports used by the trimmed preserve path. Run this snippet in
each shell that needs the variables.

```bash
TRAIN_TICKET_HTTP1_PORTS="14568,11188,12347,12346,12345,15681,18898,12031,12032,12342,15680,11178,14567,16579,15679,12340,15678"

TRAIN_TICKET_TCPDUMP_FILTER="tcp port 14568 or tcp port 11188 or tcp port 12347 or tcp port 12346 or tcp port 12345 or tcp port 15681 or tcp port 18898 or tcp port 12031 or tcp port 12032 or tcp port 12342 or tcp port 15680 or tcp port 11178 or tcp port 14567 or tcp port 16579 or tcp port 15679 or tcp port 12340 or tcp port 15678"
```

## Single run

Example: 10 RPS for 5 seconds.

Terminal 1: start packet capture.

```bash
OUT=result/train_ticket/manual_10rps_5s
mkdir -p "$OUT"

sudo tcpdump -i any -s 0 -U \
  -w "$OUT/traffic.pcap" \
  "$TRAIN_TICKET_TCPDUMP_FILTER"
```

Terminal 2: run uniformly paced preserve requests.

```bash
OUT=result/train_ticket/manual_10rps_5s

python3 services/train-ticket/uniform_train_ticket_load.py \
  http://127.0.0.1:14568 \
  -c 20 -R 10 -d 5s \
  --trip-ids D1345-D1444 \
  --trip-mode round-robin \
  --station-mode trip \
  --mark-prefix trainticket-10rps \
  --json-out "$OUT/loadgen_report.json"
```

Stop `tcpdump` in terminal 1 with `Ctrl-C`, then convert the pcap:

```bash
OUT=result/train_ticket/manual_10rps_5s

python3 src/pcap_to_cleaned.py \
  --pcap "$OUT/traffic.pcap" \
  --cleaned-out "$OUT/cleaned_data.csv" \
  --expected-trace-count 0 \
  --span-form rpc \
  --http1-ports "$TRAIN_TICKET_HTTP1_PORTS" \
  --http2-ports ""
```

Run lineage. For TrainTicket, use the service graph with slot/containment
fallback and the conservative per-edge gate. The preserve path has repeated
low-signal station and ticketinfo calls, so pure graph matching can shift those
calls to a neighboring request even at low RPS. The gate does not learn global
thresholds; it only disables fallback on edges whose slot profile overlaps
neighboring root requests.

```bash
OUT=result/train_ticket/manual_10rps_5s

LINEAGE_GRAPH_SLOT_FALLBACK=1 \
LINEAGE_GRAPH_CONTAINMENT_FALLBACK=1 \
LINEAGE_GRAPH_UNSUPERVISED_GATE=1 \
LINEAGE_GRAPH_SLOT_LOW_DIVERSITY_RATIO=0.3333333333333333 \
LINEAGE_GRAPH_SLOT_LOW_SIGNAL=0.7845594221512074 \
LINEAGE_GRAPH_SLOT_MAX_P95_MS=180 \
LINEAGE_GRAPH_SLOT_WEAK_SIGNAL_MAX_P95_MS=220 \
LINEAGE_GRAPH_SLOT_ROOT_REPEATED_MAX_P95_MS=180 \
LINEAGE_GRAPH_CONTAINMENT_LOW_DIVERSITY_RATIO=0.3333333333333333 \
LINEAGE_GRAPH_CONTAINMENT_MAX_OUTSIDE_MS=160 \
python3 src/lineage.py \
  --csv-path "$OUT/cleaned_data.csv" \
  --json-out "$OUT/lineage_report.json"
```

Optional: run the pure service-graph baseline. This leaves the adaptive
fallback path disabled and is useful only as an ablation.

```bash
OUT=result/train_ticket/manual_10rps_5s

python3 src/lineage.py \
  --csv-path "$OUT/cleaned_data.csv" \
  --json-out "$OUT/lineage_report_pure_graph.json"
```

On one local sweep, graph plus fallback and the conservative gate improved
`5 RPS` from `8.00%` to `100.00%`, matched pure graph at `10 RPS`
(`30.00%`), and fell back to pure graph behavior at `15 RPS` (`5.33%`).

## Interpreting RPS sweeps

TrainTicket results are sensitive to service warmup. A sweep started
immediately after `docker compose up` can show a misleading trend where
accuracy appears to improve as the configured RPS increases. In that case the
later points are not only higher-RPS points; they also run after the JVMs,
Mongo clients, HTTP connection pools, and service caches have warmed up.

This is especially visible with low connection counts. For example, with
`connections=2`, a configured `15` or `20` RPS run may be capped by request
latency and only reach about `9-11` actual requests/sec. The x-axis is then the
target RPS, not the effective RPS. Low-RPS points also have fewer traces, so
FullTraceAcc is noisy because a small number of shifted repeated calls can make
every full trace fail.

For comparable sweeps:

- Run a short uncollected warmup before each measured point.
- Check `actual_requests_sec`, `root_max_concurrency`, and latency in
  `loadgen_report.json`; do not interpret target RPS alone.
- Prefer repeating each point and reporting the median.
- If a service was restarted, seed the benchmark data again and verify one
  canary preserve request returns HTTP `200` with app status `1` before
  capturing packets.

## RPS sweep

This runs `1, 5, 10, 15, 20` RPS for 5 seconds each. Each RPS gets its own
pcap, cleaned CSV, load report, and lineage report.

```bash
BASE=result/train_ticket/rps_sweep_5s
mkdir -p "$BASE"

for RPS in 1 5 10 15 20; do
  OUT="$BASE/rps_${RPS}"
  mkdir -p "$OUT"

  sudo tcpdump -i any -s 0 -U \
    -w "$OUT/traffic.pcap" \
    "$TRAIN_TICKET_TCPDUMP_FILTER" \
    > "$OUT/tcpdump.log" 2>&1 &
  TCPDUMP_PID=$!

  sleep 1

  python3 services/train-ticket/uniform_train_ticket_load.py \
    http://127.0.0.1:14568 \
    -c 20 -R "$RPS" -d 5s \
    --trip-ids D1345-D1444 \
    --trip-mode round-robin \
    --station-mode trip \
    --mark-prefix "trainticket-sweep-${RPS}rps" \
    --json-out "$OUT/loadgen_report.json"

  sleep 3
  sudo kill -INT "$TCPDUMP_PID" || true
  wait "$TCPDUMP_PID" || true

  python3 src/pcap_to_cleaned.py \
    --pcap "$OUT/traffic.pcap" \
    --cleaned-out "$OUT/cleaned_data.csv" \
    --expected-trace-count 0 \
    --span-form rpc \
    --http1-ports "$TRAIN_TICKET_HTTP1_PORTS" \
    --http2-ports ""

  LINEAGE_GRAPH_SLOT_FALLBACK=1 \
  LINEAGE_GRAPH_CONTAINMENT_FALLBACK=1 \
  LINEAGE_GRAPH_UNSUPERVISED_GATE=1 \
  LINEAGE_GRAPH_SLOT_LOW_DIVERSITY_RATIO=0.3333333333333333 \
  LINEAGE_GRAPH_SLOT_LOW_SIGNAL=0.7845594221512074 \
  LINEAGE_GRAPH_SLOT_MAX_P95_MS=180 \
  LINEAGE_GRAPH_SLOT_WEAK_SIGNAL_MAX_P95_MS=220 \
  LINEAGE_GRAPH_SLOT_ROOT_REPEATED_MAX_P95_MS=180 \
  LINEAGE_GRAPH_CONTAINMENT_LOW_DIVERSITY_RATIO=0.3333333333333333 \
  LINEAGE_GRAPH_CONTAINMENT_MAX_OUTSIDE_MS=160 \
  python3 src/lineage.py \
    --csv-path "$OUT/cleaned_data.csv" \
    --json-out "$OUT/lineage_report.json"
done
```

Summarize the sweep:

```bash
python3 - <<'PY'
import csv
import json
import pathlib

base = pathlib.Path("result/train_ticket/rps_sweep_5s")
rows = []
for rps in [1, 5, 10, 15, 20]:
    out = base / f"rps_{rps}"
    load = json.load(open(out / "loadgen_report.json"))
    report = json.load(open(out / "lineage_report.json"))
    rows.append({
        "rps": rps,
        "ok_requests": load["ok_requests"],
        "target_requests": load["target_requests"],
        "actual_rps": round(load["actual_requests_sec"], 3),
        "latency_p50_ms": round(load["latency_ms"]["p50"], 3),
        "latency_p90_ms": round(load["latency_ms"]["p90"], 3),
        "latency_p99_ms": round(load["latency_ms"]["p99"], 3),
        "traces": report["root_trace_count"],
        "root_direct_accuracy_pct": round(report["root_direct_accuracy_pct"], 6),
        "span_accuracy_pct": round(report["edge_accuracy_pct"], 6),
        "full_trace_accuracy_pct": round(report["accuracy_pct"], 6),
    })

with open(base / "summary.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

for row in rows:
    print(row)
PY
```
