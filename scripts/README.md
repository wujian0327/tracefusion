Experiment scripts
==================

Make sure DeepFlow is running before using the `deepflow` argument.

By default, the Bookinfo, Hotel HTTP/1.1, and TrainTicket experiment scripts
clean-rebuild their service stacks before running and wait 30 seconds for
services to settle. Use `SERVICE_START_WAIT_SECONDS=...` to change the wait.

Bookinfo
--------

```bash
CAPTURE_MODE=pcap \
OUT_DIR=result/bookinfo \
TARGET_URL=http://127.0.0.1:9080 \
CONNECTIONS_LIST="20 20 20 20" \
RATE_LIST="100 200 300 400" \
DURATION=3s \
EXPECTED_TRACE_COUNT=8 \
RUN_TOPOLOGY=0 \
./scripts/run_bookinfo_exp.sh deepflow
```

Set `CLEAN_BOOKINFO_STACK=0` to reuse existing Bookinfo containers.

Hotel HTTP/1.1
--------------

```bash
CAPTURE_MODE=pcap \
OUT_DIR=result/hotel_http1_exp \
TARGET_URL=http://127.0.0.1:5000 \
CONNECTIONS_LIST="50 50 50" \
RATE_LIST="800 1100 1400" \
DURATION=3s \
./scripts/run_hotel_http1_exp.sh deepflow
```

Set `CLEAN_HOTEL_STACK=0` and `RESTART_SERVICES_AT_START=0` to reuse existing
Hotel containers.

TrainTicket
-----------

```bash
CAPTURE_MODE=pcap \
OUT_DIR=result/train_ticket/exp \
TARGET_URL=http://127.0.0.1:14568 \
AUTH_URL=http://127.0.0.1:12340/api/v1/users/login \
CONTACT_URL=http://127.0.0.1:12347/api/v1/contactservice/contacts/account \
CONNECTIONS_LIST="2 2 2 2" \
RATE_LIST="5 10 15 20" \
DURATION=3s \
RUN_TRACEWEAVER=1 \
./scripts/run_trainticket_exp.sh deepflow
```

Set `CLEAN_TRAIN_TICKET_STACK=0` to reuse existing TrainTicket containers.

eBPF capture
------------

For HTTP/1.1-only cgroup eBPF capture, build the collector first:

```bash
(cd collector/ebpf/cgroup_net && cargo build -p cgroup --release)
```

Then switch any supported experiment script to eBPF:

```bash
CAPTURE_MODE=ebpf \
EBPF_COLLECTOR=collector/ebpf/cgroup_net/target/release/cgroup \
./scripts/run_hotel_http1_exp.sh
```

The collector writes `ebpf_output.bin`; `src/ebpf_to_cleaned.py` converts it to
the same `cleaned_data.csv` shape used by the pcap path.
