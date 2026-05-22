# Bookinfo Rust/Axum X-Mark Workload

This is a Rust/Axum version of the Bookinfo workload used for
language/framework comparison experiments. It keeps the same logical topology
as the original Bookinfo service:

```text
productpage
  -> details
  -> reviews
      -> ratings
```

Every service listens on port `9080` inside its container and forwards `X-Mark`
plus common trace-context headers. The Docker Compose root endpoint is
`http://127.0.0.1:9480`.

```bash
cd services/bookinfo-rust
cargo build --release
cd ../..

docker compose -f services/bookinfo-rust/docker-compose.yml up --build

python3 services/bookinfo/uniform_bookinfo_load.py \
  http://127.0.0.1:9480 \
  -c 20 \
  -d 5s \
  -R 100 \
  --book-count 100 \
  --json-out result/bookinfo_rust_load_report.json
```

For Minikube/DeepFlow:

```bash
eval "$(minikube docker-env)"
docker build -t trace-fusion-bookinfo-rust:latest services/bookinfo-rust
eval "$(minikube docker-env -u)"

kubectl apply -f services/bookinfo-rust/kube/bookinfo-rust-xmark.yaml
kubectl -n bookinfo-rust port-forward svc/productpage 9480:9080
```
