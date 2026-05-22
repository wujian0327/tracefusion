FROM golang:1.24-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/bookinfo-http2 ./main.go

FROM scratch

COPY --from=builder /out/bookinfo-http2 /bookinfo-http2
EXPOSE 9080
ENTRYPOINT ["/bookinfo-http2"]
