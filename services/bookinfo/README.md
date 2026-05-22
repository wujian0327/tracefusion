# Bookinfo X-Mark Workload

Local check:

```text
http://127.0.0.1:9080/productpage?id=42
```

Topology:

```text
-> bookinfo-productpage
    -> bookinfo-details
    -> bookinfo-reviews
        -> bookinfo-ratings
```

Docker Compose:

```bash
docker compose -f services/bookinfo/docker-compose.yml up --build
```

Kubernetes, for DeepFlow:

```bash
eval "$(minikube docker-env)"
docker build -t trace-fusion-bookinfo-details:extended services/bookinfo/overrides/details
docker build -t trace-fusion-bookinfo-ratings:extended services/bookinfo/overrides/ratings
docker build -t trace-fusion-bookinfo-reviews:extended services/bookinfo/overrides/reviews
docker build -t trace-fusion-bookinfo-productpage:extended services/bookinfo/overrides/productpage
eval "$(minikube docker-env -u)"

kubectl apply -f services/bookinfo/kube/bookinfo-xmark.yaml
kubectl -n bookinfo port-forward svc/productpage 9080:9080
```

Load test:

```bash
python3 uniform_bookinfo_load.py \
  http://127.0.0.1:9080 \
  -c 20 \
  -d 60s \
  -R 100 \
  --book-count 100 \
  --json-out ../../result/bookinfo_load_report.json
```

Each root request uses `/productpage?id=N`, so the service chain is:

```
productpage?id=N
  -> details/N
  -> reviews/N
      -> ratings/N
```

The load generator injects a unique marker header per root request:

```text
X-Mark: bookinfo-xmark-000001
```

Bookinfo forwards `X-Mark` through the microservice chain. The pcap/eBPF
cleaners map it to the cleaned CSV `trace_id`, so lineage and TraceWeaver can
use the same ground-truth request identity without relying on B3 headers.
