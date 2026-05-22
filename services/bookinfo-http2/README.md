# BookInfo HTTP/2 h2c

Small BookInfo-style service graph using Go and cleartext HTTP/2 (`h2c`):

```text
productpage -> details
productpage -> reviews -> ratings
```

Start:

```bash
docker compose -f services/bookinfo-http2/docker-compose.yml up -d --build
```

Smoke test:

```bash
curl --http2-prior-knowledge http://127.0.0.1:9450/productpage?id=7
```

Ports:

- `9450`: productpage
- `9451`: details
- `9452`: ratings
- `9453`: reviews

All internal service-to-service calls use h2c through `golang.org/x/net/http2`.
