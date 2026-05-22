# Bookinfo Java X-Mark Workload

This is a Java/Spring Boot version of the Bookinfo workload used for language
comparison experiments. It keeps the same logical topology as
`services/bookinfo`:

```text
productpage
  -> details
  -> reviews
      -> ratings
```

Every service listens on port `9080` inside its container and forwards `X-Mark`
plus the common trace-context headers. The external Docker Compose port for the
root service is `9180`, so the existing Bookinfo load generator can be reused:

```bash
docker compose -f services/bookinfo-java/docker-compose.yml up --build

python3 services/bookinfo/uniform_bookinfo_load.py \
  http://127.0.0.1:9180 \
  -c 20 \
  -d 5s \
  -R 100 \
  --book-count 100 \
  --json-out result/bookinfo_java_load_report.json
```

The same image is used for all four services. `SERVICE_ROLE` selects the active
role: `productpage`, `details`, `reviews`, or `ratings`.

For Minikube/DeepFlow:

```bash
eval "$(minikube docker-env)"
docker build -t trace-fusion-bookinfo-java:latest services/bookinfo-java
eval "$(minikube docker-env -u)"

kubectl apply -f services/bookinfo-java/kube/bookinfo-java-xmark.yaml
kubectl -n bookinfo-java port-forward svc/productpage 9180:9080
```
