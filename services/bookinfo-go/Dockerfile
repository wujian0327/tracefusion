FROM golang:1.21-alpine AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -ldflags="-s -w" -o /out/bookinfo-go ./cmd/bookinfo-go

FROM scratch
COPY --from=builder /out/bookinfo-go /bookinfo-go
ENV SERVER_PORT=9080
EXPOSE 9080
ENTRYPOINT ["/bookinfo-go"]
