FROM golang:1.21 AS builder

WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/bookinfo-tls-go ./main.go

FROM scratch

COPY --from=builder /out/bookinfo-tls-go /bookinfo-tls-go
EXPOSE 9080
ENTRYPOINT ["/bookinfo-tls-go"]
