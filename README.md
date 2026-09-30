# Trace Fusion

Trace Fusion 是一个面向微服务调用链还原的实验项目。它把抓包、DeepFlow
eBPF 观测和负载生成时写入的 `X-Mark` ground truth 结合起来，比较三类链路还原方法：

- `TraceFusion`：本仓库的时序 + 数据血缘传播算法。
- `TraceWeaver`：基于时间关系的 baseline。
- `DeepFlow`：使用 DeepFlow 原始 L7FlowTracing 逻辑的 baseline。

当前实验覆盖三个 benchmark：

- Bookinfo
- Hotel Reservation HTTP/1.1
- TrainTicket

另外还有 Bookinfo 的多语言实现，用于比较 DeepFlow 对 Go/Java/Python/Rust 服务的采集和还原表现。

## Repository Layout

```text
src/
  tracefusion.py              TraceFusion 主算法入口
  pcap_to_cleaned.py          将 pcap 转成统一 CSV
  ebpf_to_cleaned.py          将 eBPF 输出转成统一 CSV
  topology.py                 从 cleaned CSV 推断服务拓扑
  plot/                       论文图表脚本

scripts/
  run_bookinfo_exp.sh         Bookinfo 一键实验脚本
  run_hotel_http1_exp.sh      Hotel HTTP/1.1 一键实验脚本
  run_trainticket_exp.sh      TrainTicket 一键实验脚本
  README.md                   三个脚本的启动命令

services/
  bookinfo/                   原始 Bookinfo workload 和 loader
  bookinfo-go/                Gin 版本 Bookinfo
  bookinfo-java/              Spring Boot 版本 Bookinfo
  bookinfo-python/            Flask 版本 Bookinfo
  bookinfo-rust/              Axum 版本 Bookinfo
  hotelReservation_http1.1/   Hotel HTTP/1.1 benchmark 和 loader
  train-ticket/               TrainTicket benchmark 和 loader

baseline/
  traceweaver/                TraceWeaver baseline
  deepflow/                   DeepFlow v7.1 local stack 和评测脚本

result/
  bookinfo/                   Bookinfo 画图数据
  hotel_http1/                Hotel HTTP/1.1 画图数据
  trainticket/                TrainTicket 画图数据
  bookinfo_go/                Go-Gin Bookinfo 画图数据
  bookinfo_java/              Java-Spring Bookinfo 画图数据
  bookinfo_python/            Python-Flask Bookinfo 画图数据
  bookinfo_rust/              Rust-Axum Bookinfo 画图数据
```

## Metrics

实验脚本会在每个 `summary.csv` 中输出以下核心指标：

- `FullTraceAcc`：一条 root trace 的 span 归属和父子顺序都正确才算正确。
- `TraceAssign`：trace 级别是否没有混入其他请求的 span。
- `SpanAcc`：单个 span 是否分到正确 trace。
- `Coverage`：算法是否给 ground-truth span 产出了预测。
- `ParentEdge F1`：预测父子边相对 ground truth 的 F1。

DeepFlow 评测会额外统计 span 采集缺失、span 配对错误和 wrong-mark span，方便区分“没采到”和“还原错”。

## Running Experiments

先启动 DeepFlow local stack。详细说明见 [baseline/deepflow/README.md](baseline/deepflow/README.md)。

典型用法是通过 DeepFlow wrapper 启动采集栈，再运行某个 benchmark 脚本：

```bash
OUT_DIR=result/deepflow_stack_hotel_http1 \
DEEPFLOW_L7_HTTP_PORTS=5000,8081-8089 \
DEEPFLOW_L7_HTTP2_PORTS=5000,8081-8089 \
baseline/deepflow/deepflow_stack_capture.sh -- \
  ./scripts/run_hotel_http1_exp.sh deepflow
```

三个实验脚本的直接启动示例在 [scripts/README.md](scripts/README.md)：

- Bookinfo: `./scripts/run_bookinfo_exp.sh deepflow`
- Hotel HTTP/1.1: `./scripts/run_hotel_http1_exp.sh deepflow`
- TrainTicket: `./scripts/run_trainticket_exp.sh deepflow`

默认情况下，三个脚本都会在实验开始前重建对应业务容器，并等待服务稳定：

- Bookinfo: `CLEAN_BOOKINFO_STACK=1`
- Hotel: `CLEAN_HOTEL_STACK=1`
- TrainTicket: `CLEAN_TRAIN_TICKET_STACK=1`
- 等待时间：`SERVICE_START_WAIT_SECONDS=30`

如果要复用已有容器，可以把对应 `CLEAN_*_STACK` 设为 `0`。

## Running TraceFusion Directly

TraceFusion 接收统一的 cleaned CSV；这个文件可以来自 pcap，也可以来自
cgroup eBPF：

```bash
python3 src/tracefusion.py \
  --csv-path result/bookinfo/conn_20_rps_400/cleaned_data.csv \
  --json-out result/bookinfo/conn_20_rps_400/tracefusion_report.json
```

常用拓扑模式：

```bash
python3 src/tracefusion.py \
  --csv-path cleaned_data.csv \
  --json-out tracefusion_report.json \
  --topology-mode service-graph
```

可选的拓扑模式包括：

- `service-tree`
- `edge-slot`
- `service-tree-edge`
- `service-graph`

TrainTicket 这种存在循环引用和复杂共享服务的场景，通常使用 `service-graph` 相关模式。

## Data Preparation

从 pcap 转成统一 CSV：

```bash
python3 src/pcap_to_cleaned.py \
  --pcap traffic.pcap \
  --cleaned-out cleaned_data.csv
```

从 cgroup eBPF HTTP/1.1 raw CSV 转成统一 CSV：

```bash
python3 src/ebpf_to_cleaned.py \
  --input ebpf_output.csv \
  --cleaned-out cleaned_data.csv \
  --span-form rpc
```

实验脚本可通过 `CAPTURE_MODE=pcap|ebpf` 选择采集方式；两种模式最终都会
生成同名的 `cleaned_data.csv`，后续 TraceFusion/TraceWeaver 使用方式一致。

生成服务拓扑图：

```bash
python3 src/topology.py \
  --csv-path cleaned_data.csv \
  --output topology.png
```

## Plotting

当前论文图表脚本集中在 `src/plot/`：

```bash
python3 src/plot/plot_bookinfo_rps_accuracy.py
python3 src/plot/plot_hotel_http1_accuracy.py
python3 src/plot/plot_trainticket_fulltraceacc.py
python3 src/plot/plot_bookinfo_language_fulltraceacc.py
```

默认读取这些目录：

- `result/bookinfo/summary.csv`
- `result/hotel_http1/summary.csv`
- `result/trainticket/summary.csv`
- `result/bookinfo_go/summary.csv`
- `result/bookinfo_java/summary.csv`
- `result/bookinfo_python/summary.csv`
- `result/bookinfo_rust/summary.csv`

输出的 PNG/PDF/CSV 会写回对应的 `result/...` 目录。

## Notes

- `X-Mark` 是实验 ground truth。loader 会为每个 root request 生成唯一 mark，并通过服务间调用传播。
- TraceFusion 评测时不会用 `trace_id` 做 span 配对；`trace_id` 只用于验证预测是否正确。
- DeepFlow local baseline 默认使用 `baseline/deepflow/deepflow-app-source` 中保留的 DeepFlow app tracing 代码，并从 DeepFlow Query API 批量读取 `l7_flow_log`，在本地调用原始 L7FlowTracing 逻辑。
- Hotel loader 已移动到 `services/hotelReservation_http1.1/uniform_hotel_load.py`，和 Bookinfo/TrainTicket 的 service-local loader 结构保持一致。

## Sensitive-data Provenance Benchmark

新增独立的敏感数据溯源实验台，包含基础传播、同值并发、重复读取和双来源干扰场景，
并提供隔离的字段来源真值、值/时间参考基线及来源/传播边评测。

```bash
python3 scripts/run_provenance_bench.py --requests 20 --concurrency 8
```

需要 Python 3.10+，默认模式不依赖第三方 Python 包。默认 boundary 模式用于插桩冒烟验证；
实际无侵入 HTTP 抓包使用 `--capture pcap`，需要 Linux、tcpdump、tshark 和抓包权限。
当前数据源是 SQLite 的 HTTP 查询网关，不代表原生数据库协议采集支持。
详细场景、数据格式、真值边界和运行命令见 [provenance benchmark README](services/provenance_bench/README.md)。

同一运行还会生成 `comparison/summary.json`，比较值/时间、请求参数、调用次数及两者结合四种基线。
约束基线的实验先验显式保存在 `constraint_profile.json`；已有结果可用
`python3 services/provenance_bench/compare_baselines.py --run-dir <运行目录>` 重评，无需重新采集。

用 `--suite stress` 检验读取后的额外处理和并行分支耗时不均，或用 `--suite all` 跑全部八个场景。
默认仍运行五个核心场景。每次比较额外输出两种时间排序的诊断；排序保留全部来源候选和传播边，
`summary.json` 的 `timing_rankings` 分别报告完整候选召回率、首选层召回率和错误唯一首选数。
时间排序依赖工作负载假设，分数不是概率，不能直接作为唯一归因。
