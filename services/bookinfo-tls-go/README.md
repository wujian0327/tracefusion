# BookInfo TLS Go HTTP/1.1

Go HTTPS HTTP/1.1 BookInfo-style workload for TLS uprobe experiments.

This service is implemented independently from `services/bookinfo-http2` so the
HTTP/2 and TLS HTTP/1.1 experiments stay isolated. Each service listens on
container port `9080`; productpage is published on host port `9460`.

```bash
docker compose -f services/bookinfo-tls-go/docker-compose.yml up -d --build
python3 services/bookinfo/uniform_bookinfo_load.py https://127.0.0.1:9460 -R 20 -c 2 -d 2s
```

## Kubernetes

```bash
./scripts/start_bookinfo_tls_go_k8s.sh
kubectl -n bookinfo-tls-go port-forward svc/productpage 9460:9080
curl -k -H 'X-Mark: manual-check' 'https://127.0.0.1:9460/productpage?id=7'
```

If you are using Minikube with containerd, the script loads the local Docker
image into Minikube and the manifest uses `imagePullPolicy: Never` to avoid
accidental Docker Hub pulls.
