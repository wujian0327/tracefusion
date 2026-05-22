# Bookinfo Go/Gin X-Mark Workload

This is a Go/Gin version of the Bookinfo workload used for language/framework
comparison experiments. It keeps the same logical topology as the original
Bookinfo service:

```text
productpage
  -> details
  -> reviews
      -> ratings
```

Every service listens on port `9080` inside its container and forwards `X-Mark`
plus common trace-context headers. The Docker Compose root endpoint is
`http://127.0.0.1:9280`.

```bash
docker compose -f services/bookinfo-go/docker-compose.yml up --build

python3 services/bookinfo/uniform_bookinfo_load.py \
  http://127.0.0.1:9280 \
  -c 20 \
  -d 5s \
  -R 100 \
  --book-count 100 \
  --json-out result/bookinfo_go_load_report.json
```

For Minikube/DeepFlow:

```bash
eval "$(minikube docker-env)"
docker build -t trace-fusion-bookinfo-go:latest services/bookinfo-go
eval "$(minikube docker-env -u)"

kubectl apply -f services/bookinfo-go/kube/bookinfo-go-xmark.yaml
kubectl -n bookinfo-go port-forward svc/productpage 9280:9080
```
