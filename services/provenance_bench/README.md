# Sensitive-data provenance benchmark (v1)

这是一个独立的受控实验台，用于研究“外部响应中的敏感值来自哪次读取、经过哪些字段传播”。
现有 TraceFusion、Bookinfo、Hotel、TrainTicket 的代码与运行方式不变。

**当前提供的是 benchmark + 值/时间候选基线 + 两层约束基线，不是已经完成的新 TraceFusion 算法。**
额外提供不裁剪候选的时间排序，用压力场景检验其假设是否可靠。
所有数据是合成字符串，如 `SYNTH-PHONE-0017`；不使用真实个人信息。

## 快速运行

在仓库根目录运行，需要 Python 3.10+，没有额外 Python 依赖：

```bash
python3 scripts/run_provenance_bench.py --requests 20 --concurrency 8
```

`--requests` 是每个场景的请求数。默认共 5 个场景、100 次根请求、380 次 HTTP 交换。
默认输出到 `result/provenance_bench/<UTC时间>/`，终端打印绝对路径。
指定输出目录必须尚不存在，避免覆盖之前的实验。

`--suite core`（默认）运行原来的五个场景；`--suite stress` 运行三个压力场景；
`--suite all` 运行全部八个场景。明确指定 `--scenario <名称>` 时优先运行该场景。
每场景 20 次请求时，stress 共 60 次根请求、260 次 HTTP 交换，all 共 160 次根请求、640 次交换。

```bash
python3 scripts/run_provenance_bench.py \
  --suite stress --requests 20 --concurrency 12 --seed 404 \
  --postprocess-ms 80 --branch-delay-ms 100
```

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
| `postprocess` | Profile 读取 Store 后，额外等待再返回 | 单下游调用不意味着读取后立即返回 |
| `decoy_unbalanced_different` | 不同值的两路调用，第二路额外等待后读取 | 检验并行分支耗时不均导致的时间排序偏差 |
| `decoy_unbalanced_same` | 相同值的两路调用，第二路额外等待后读取 | 同时检验时间偏差和内部选择歧义 |

两路场景的实际选择只记录在 oracle，不放入 URL、header 或响应。`decoy` 是第二路服务的固定名字，
不意味着它总是不被采用。并发调度会影响随机序列消费顺序，固定 seed 不保证跨次运行逐事件相同。
`basic` 固定串行，其他场景使用 `--concurrency`。随机延迟在每个业务服务内部注入。
三个压力场景由 `--suite stress` 选择（表中最后三行）。`postprocess` 的读取后等待均匀采样
自 `[0, --postprocess-ms]`（默认 80ms）；不均衡场景的第二路在读 Store 前等待
`[--branch-delay-ms / 2, --branch-delay-ms]`（默认 50–100ms）。原有随机延迟仍然生效。
这些等待模拟处理或调度延迟，不构成 CPU 负载或系统开销评测。注入的实际延迟仅记录在 oracle，
不作为推断输入；观测保留实际发生的请求路径和时间。

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

## 两层约束基线与四组对照

运行 `scripts/run_provenance_bench.py` 现在会自动额外生成 `comparison/`，
原来的 `predictions.jsonl` 和 `report.json` 仍属于值/时间基线。

```text
comparison/
  summary.json                 四种方法的整体/分场景指标与输入 SHA256
  value_time_predictions.jsonl 原始值/时间基线
  semantics_predictions.jsonl  只加入请求参数约束
  capacity_predictions.jsonl   只加入调用次数约束
  combined_predictions.jsonl   参数 + 调用次数约束
  *_report.json                独立 oracle 评测结果
  *_diagnostics.json           约束配置、调用候选及回退原因（约束方法）
  timing_*_predictions.jsonl   combined 完整候选 + 时间排序标注
  timing_*_diagnostics.json    排序方式、规模限制及未排序分量
  timing_*_report.json         保留候选指标和首选层诊断
```

已有完整运行目录可直接重评，无需重新启动服务或采集：

```bash
python3 services/provenance_bench/compare_baselines.py \
  --run-dir result/provenance_case_01
```

默认写入该目录的 `comparison/`，目标必须尚不存在；再次比较用
`--output-dir result/provenance_case_01/comparison_02`。
四种方法先分别在独立进程中生成预测，然后才调用评测器；预测器不接收 oracle 路径。
`summary.json` 的 `status` 应为 `complete`，算法比较使用相同的观察、查询和时间容差。

### 第一层：调用候选

`constraint_profile.json` 显式声明这个受控 workload 的先验：

- API→Profile、Profile→Store、Decoy→Store 保持请求 `user_id`。
- API→Decoy **不**要求相同 `user_id`，只在 `/case/decoy_` 路由发生。
- 每个选中的父操作在对应服务边上恰有一次子调用，每个子调用只属于一个父操作。
- 数据源角色为 Store，待溯源字段为响应 `phone`。

这些信息来自 benchmark 的设计，**不是从 oracle 学习，也不是声称能从外部观测自动获得的通用规律**。
业务中的重试、可选分支、批量调用、扇出及异步模型不一定满足这个 profile。

算法先按拓扑与时间容差构建二部候选图，再在声明透传的边上排除已知参数不一致的候选。
缺少参数视为未知，不直接排除。对时间图的每个连通分量检查一对一匹配：
每条边只有在至少一个完整可行匹配中出现，才被保留。没有按评分挑出唯一匹配，也不靠事件编号打破歧义。
实现逐边固定后检测匹配可行性，目的是正确验证方法，不是大规模优化求解器。

### 第二层：字段传播

从 sink 向下游遍历保留的调用候选，检查响应字段是否具有相同值，直到到达 Store 来源。
输出来源候选与传播边的**并集**，表示多种可能解释，不表示所有边同时成立，也不是概率或校准后的置信度。
`unique` 只表示在当前观测、profile 和参数下剩余一个来源，不能解读为无条件的因果证明。
这版仅支持标量 `phone` 的相同值传播，尚未实现字段变换或跨请求持久化溯源。

### 约束无解与规模限制

父子数量不相等、参数筛选后无完整匹配，或分量规模超过限制时，
该分量恢复到**时间筛选后的候选**，不强制匹配，也不保留导致无解的参数裁剪。
diagnostics 中分别记录 `unbalanced_counts`、`no_perfect_matching`、`component_limit`。
默认每分量最多 128 个子事件、4096 条参数筛选后的候选边；独立 CLI 可调整。

## 时间排序：可被压力场景否定的辅助假设

两种排序都使用 combined 的可行调用候选，并保留原来的 `candidate_sources`、`edges` 和 `status`。
只增加 `timing_ranking`；它不会把有歧义的回答改成唯一归因。排序器只读取观测、预测及约束诊断，
不读取 oracle。四个基线和两个排序均先生成预测，再独立评测。

- `all_return`：所有候选调用边都按父响应结束与子响应结束的间隔平方计成本。
- `single_child_return`：仅在 profile 声明父操作恰有一个下游调用时使用该成本；并行扇出父操作的成本为零。

在每个平衡、可匹配的调用分量中，用 Hungarian 算法求最小总成本。
某条边的评分是“强制选择它的最小总成本”减去“不强制的最小总成本”。
某个来源的评分是所有候选传播路径中边评分之和的最小值。分数越低越优先，但这是启发式，
不是概率、联合路径可行性的证明或经校准的置信度。相同最低分全部保留在首选层；事件编号仅用于展示排序。

单个下游调用也可能在读取结束后继续处理，因此 `single_child_return` 依然可能错误偏好其他请求的来源。
`postprocess` 专门检验这一点；两个不均衡分支场景检验扇出带来的偏差。
每个排序分量默认最多 24 个父/子事件；超过限制、约束回退或无法评分时，该分量的边评分全部为零，
不凭空加入排序偏好。独立 `timing_rank.py --max-component` 可调至最多 32，默认时间尺度为 5ms。

`comparison/summary.json` 新增 `timing_rankings`：

- `retained_candidates`：完整候选的来源及传播边指标，应与 combined 一致。
- `top_tier_source_recall`：真实来源落在首选层的比例。
- `unique_top_queries` / `correct_unique_top` / `wrong_unique_top`：首选层只有一个候选时的总数、正确数和错误数。
- `tied_top_queries`：最低分并列的查询数；不按编号强行挑一个。

后三类位于 `top_tier`，并有 `by_scenario` 明细。首选层指标只回答“假如只采用首选层会怎样”，
不表示已执行裁剪；重点检查错误唯一首选和来源召回损失。旧观测可直接重评时间排序，
新增压力场景则需要重新运行工作负载。

回退不会恢复未采集到的事件，也不能识别所有错误先验：例如父子恰好同时丢失时，
错误 profile 仍可能存在可行匹配。时间窗口本身也可能排除真实关系。
因此要同时检查来源召回率、错误唯一归因、采集完整性和 `fallback_components`。

只运行预测器（盲评时只提供 observations 与 profile）：

```bash
python3 services/provenance_bench/constrained.py \
  --observations result/provenance_case_01/observations/events.jsonl \
  --queries result/provenance_case_01/observations/queries.jsonl \
  --profile services/provenance_bench/constraint_profile.json \
  --output result/provenance_case_01/my_constrained_predictions.jsonl \
  --diagnostics result/provenance_case_01/my_constrained_diagnostics.json
```

使用 `--disable-semantics` 或 `--disable-capacity` 做消融，时间容差默认 5ms。
不要通过收紧窗口只追求少量候选：boundary 时间在发送后记录，真实子事件可能稍晚结束。

测试还包括所有 3×3 二部图与穷举匹配的比较、同值多解、参数先验无解、采集数量不平衡、
规模上限和输入顺序不影响来源选择。新增运行建议更换 seed 和并发度；参与算法设计的数据只作开发回归。
