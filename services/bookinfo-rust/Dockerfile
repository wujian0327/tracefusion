FROM trace-fusion-bookinfo-productpage:extended

WORKDIR /app
COPY target/release/bookinfo-rust /app/bookinfo-rust

ENV SERVER_PORT=9080
EXPOSE 9080

CMD ["/app/bookinfo-rust"]
