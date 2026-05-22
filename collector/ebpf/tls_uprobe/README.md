# TLS uprobe collector

Userspace eBPF collector for plaintext before/after TLS encryption. This is the
companion of `../cgroup_net`: cgroup capture sees encrypted HTTPS records, while
this collector hooks TLS library functions inside the target process and emits
decrypted buffers.

Currently supported symbols:

- `SSL_write`
- `SSL_read`
- `SSL_write_ex`
- `SSL_read_ex`
- `crypto/tls.(*Conn).Write` for Go 1.21+ on amd64

Go `crypto/tls.(*Conn).Read` is implemented behind `--go-capture-reads`, but it
uses a Go uretprobe and is intentionally off by default because it can break Go
runtime stack growth.

Build:

```bash
cargo build --release
```

Run against one process:

```bash
sudo -n ./target/release/tls_uprobe \
  --pid <PID> \
  --output /tmp/tls_plaintext.csv
```

When `--pid` is provided, the loader resolves `libssl.so` from
`/proc/<pid>/maps` and attaches only to that process. For a global attach,
provide `--libssl /path/to/libssl.so`.

Run against Go TLS processes:

```bash
sudo -n ./target/release/tls_uprobe \
  --go-pid <PID1>,<PID2> \
  --output /tmp/go_tls_plaintext.csv
```

When `--go-pid` is provided, the loader resolves the Go binary from
`/proc/<pid>/exe` and attaches only to that process. This default mode captures
Go TLS `Write` buffers, which include outbound client requests and server
responses.

Output format:

```csv
type,timestamp,direction,pid,tid,comm,function,ssl,requested_len,payload_len,captured_len,payload
```

`payload` is hex-encoded plaintext from the TLS library call. `WRITE` is data
being handed to the TLS library for encryption; `READ` is data returned by the
TLS library after decryption.
