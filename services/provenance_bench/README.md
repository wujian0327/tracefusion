# Sensitive-data provenance benchmark (v1)

这是一个独立的受控实验台，用于研究“外部响应中的敏感值来自哪次读取、经过哪些字段传播”。
现有 TraceFusion、Bookinfo、Hotel、TrainTicket 的代码与运行方式不变。

**当前提供的是 benchmark + 值/时间候选基线，不是已经完成的新 TraceFusion 算法。**
所有数据是合成字符串，如 `SYNTH-PHONE-0017`；不使用真实个人信息。

## 快速运行

在仓库根目录运行，需要 Python 3.10+，没有额外 Python 依赖：

```bash
python3 scripts/run_provenance_bench.py --requests 20 --concurrency 8
```

`--requests` 是每个场景的请求数。默认共 5 个场景、100 次根请求、380 次 HTTP 交换。
默认输出到 `result/provenance_bench/<UTC时间>/`，终端打印绝对路径。
指定输出目录必须尚不存在，避免覆盖之前的实验。

```bash
python3 scripts/run_provenance_bench.py \
  --scenario same_value_concurrent --requests 100 --concurrency 16 \
  --seed 42 --max-delay-ms 25 --output result/provenance_case_01
```

`--port 18780` 控制监听端口。四个服务使用同一端口、不同的 loopback IP：
API `127.0.0.2`、Profile `.3`、另一路服务 Decoy `.4`、Store `.5`。
客户端出站绑定各自 IP，使外部抓包能识别调用方服务，不需要进程/线程真值。
启动前检查占用，结束或异常后清理本次启动的进程，不终止已有服务。
Linux 推荐；其他系统须支持这些 loopback 地址。

## 场景

| 场景 | 行为 | 检验目标 |
|---|---|---|
| `basic` | 串行 API → Profile → Store → 返回 | 确认来源与两条字段传播边 |
| `same_value_concurrent` | 并发查询 u17/u29，两条记录的 phone 相同 | 区分值相同与同一次数据读取 |
| `same_user_concurrent` | 并发查询同一用户 | 区分重复读取事件；必要时保留歧义 |
| `decoy_different` | API 并行调用两路，返回值不同，只采用一路 | 排除发生过调用但没有贡献出口字段的分支 |
| `decoy_same` | 两路返回相同值，API 内部随机采用一路 | 观测不可唯一判定时，保留多个候选 |

两路场景的实际选择只记录在 oracle，不放入 URL、header 或响应。`decoy` 是第二路服务的固定名字，
不意味着它总是不被采用。并发调度会影响随机序列消费顺序，固定 seed 不保证跨次运行逐事件相同。
`basic` 固定串行，其他场景使用 `--concurrency`。随机延迟在每个业务服务内部注入。

Store 使用真正的 SQLite 表和参数化 SELECT，通过 HTTP `/query` 暴露读取结果。
**这是 SQL 查询网关场景，不是原生 MySQL/PostgreSQL 协议采集验证。** 来源粒度是一次网关查询返回的
`phone` 字段；oracle 额外记录表/行/列。下一阶段可替换为网络数据库采集适配器。

## 观测与真值隔离

```text
<run>/
  observations/events.jsonl   算法输入：外部边界事件
  observations/queries.jsonl  算法输入：出口事件、敏感字段及其值
  oracle/{role}.jsonl         实际调用关系、字段赋值来源；仅评测读取
  oracle/boundary/            插桩边界记录；pcap 模式下仅作诊断
  oracle/fixture.sqlite      合成数据库
  predictions.jsonl          值/时间基线的候选来源和传播边
  report.json                整体、分场景指标及逐查询结果
  run.json                   配置、观测数量、采集完整性、完成/失败状态
  logs/                      服务与采集日志
  traffic.pcap               仅 pcap 模式生成
```

响应头 `X-Observation-ID` 是服务为**本次交换独立生成**的随机编号。它不在下游请求中传播，
不编码 root、parent、trace 或来源；用于将同一个已观测事件与 oracle 对齐。
导出的输入只把它作为 `event_id`，不把 header 当作 lineage token。
服务通过实际调用返回的编号记录真实父子关系，并在执行字段赋值时记录来源，
评测不使用时间启发式生成真值。

算法进程只接收 `observations` 两个文件，不接收 oracle 路径。文件分离不是 OS 级权限沙箱；
盲评时应把 observations 单独复制到隔离目录/机器运行算法，再把 predictions 交回评测端。
pcap 中的逐交换编号也不得作为跨请求关联特征。

## 两种采集模式

默认 `--capture boundary` 使用工作负载插桩记录的请求/响应边界。适合验证服务、schema、真值和评测，
**不能用它宣称无侵入采集或生产环境溯源性能**。与 oracle 共处的 boundary 记录经过白名单 schema 导出。

Linux 上可以使用实际 loopback 抓包：

```bash
# 安装 tcpdump、tshark，并确保当前运行身份有抓取 lo 的权限。
# 若用 sudo，确认其 python3 版本 >= 3.10。
sudo python3 scripts/run_provenance_bench.py \
  --capture pcap --requests 20 --concurrency 8 \
  --output result/provenance_pcap_01
```

pcap 模式由 tcpdump 捕获，tshark 重组明文 HTTP，再导出同一 schema。
归一化只读取 pcap，不读取 boundary 或 oracle。每个 TCP 连接只有一次 HTTP 请求，
通过 TCP stream 配对；不依赖 `X-Mark`/trace_id。请求与响应时间取 tshark 解码对应帧的时间，
与插桩模式时间边界并不完全相同。此解析器只支持本 benchmark 的小型 JSON HTTP/1.1 报文，
不承诺 TLS、HTTP/2、连接复用或任意生产流量支持。

抓包缺失时保留所有查询分母，`run.json` 报告 observed/expected exchanges 和 capture_complete；
不按真值筛掉不完整请求。完全无法解码、服务异常、缺失 oracle 路径会直接失败。
运行环境若没有抓包权限，请先完成 boundary 模式，再在有权限的服务器验证 pcap 模式。

## 接入自己的算法

基线只做响应值相等、调用方/被调用方一致和时间包含筛选，输出所有可达候选。
默认容差 5ms，可用独立 CLI 修改。它忽略部分请求语义，属于刻意简单的参考下界，
分数不代表现有 TraceFusion。一个查询输出如下：

```json
{
  "query_id": "basic:0",
  "sink": {"event_id": "sink-id", "location": "response", "field": "phone"},
  "status": "unique",
  "candidate_sources": [{"event_id": "store-id", "location": "response", "field": "phone"}],
  "edges": [
    {"from": {"event_id": "store-id", "location": "response", "field": "phone"},
     "to": {"event_id": "profile-id", "location": "response", "field": "phone"}},
    {"from": {"event_id": "profile-id", "location": "response", "field": "phone"},
     "to": {"event_id": "sink-id", "location": "response", "field": "phone"}}
  ]
}
```

同一查询可返回多个 candidate_sources；无法回答则 sources/edges 为空。
评测从候选数重新计算 unique/ambiguous/unknown，不信任提交的 status。
新算法暂时面向固定敏感字段 phone；其他字段和变换规则是后续扩展。

```bash
python3 services/provenance_bench/baseline.py \
  --observations result/provenance_case_01/observations/events.jsonl \
  --queries result/provenance_case_01/observations/queries.jsonl \
  --output result/provenance_case_01/alternative_predictions.jsonl --tolerance-ms 1

python3 services/provenance_bench/evaluate.py \
  --queries result/provenance_case_01/observations/queries.jsonl \
  --predictions result/provenance_case_01/alternative_predictions.jsonl \
  --oracle-dir result/provenance_case_01/oracle \
  --output result/provenance_case_01/alternative_report.json
```

## 指标解释

- `source_precision/recall`：候选读取事件/字段集合相对真实来源的微平均精确率/召回率。
- `edge_precision/recall`：候选传播边集合相对实际字段赋值边的微平均指标。
- `exact_graph_rate`：来源集合和边集合都完全正确的查询比例。
- `candidate_source_coverage`：候选集合覆盖全部真实来源的查询比例。
- `unique_answer_rate/accuracy`：唯一回答的比例，以及这些回答的准确率。
- `ambiguous_rate/unknown_rate`：多个候选/无来源候选的查询比例。分母为零的条件指标输出 null。

`decoy_same` 刻意包含无法从外部观测唯一识别的内部选择：多候选精确率和 exact_graph 低，
不自动意味着推断错误。应结合来源覆盖率、候选数量、错误唯一归因一起解读；
这些指标不是校准后的置信度，也尚不评估“所有观测等价路径”的集合正确性。
当前 oracle 描述本次响应采用的数据路径，不判断业务授权或是否违法泄露。

## 检查

```bash
python3 -m unittest discover -s services/provenance_bench -p 'test_*.py' -v
```

包含独立来源真值、错误唯一归因、同值多候选、缺失观测分母和 tshark JSON 解析合同检查。
仍需在实际服务器运行 pcap 模式验证 tcpdump/tshark 版本及权限。
