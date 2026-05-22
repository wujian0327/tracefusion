# BookInfo TLS OpenSSL

Python/Flask HTTPS version of the BookInfo-style service graph:

```text
productpage -> details
productpage -> reviews -> ratings
```

Each service runs HTTPS on container port `9080` using Python's `ssl` module
with an OpenSSL-generated self-signed certificate. This workload is intended for
TLS collector experiments: the cgroup network collector sees encrypted TLS
records, while a future `tls_uprobe` collector can attach around OpenSSL-backed
read/write boundaries.

Run:

```bash
docker compose -f services/bookinfo-tls-openssl/docker-compose.yml up --build
curl -k 'https://127.0.0.1:9440/productpage?id=7'
```

Host ports:

```text
9440 productpage
9441 details
9442 ratings
9443 reviews
```
