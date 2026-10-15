# 中文期刊实验复核

旧实验默认行为保持不变；新入口是显式选择的盲推断配置。

## 当前发现

- 本次代码基于main提交2b0840a6048233a6cb81df548870b02f9fa7bc9c；仓库没有上传result原始结果。
- 默认服务图可利用首条真值trace确定子调用顺序。槽位回退模板也会读取首条真值trace；门控叫unsupervised不代表整个模板生成无真值。
- calibration-profile保存策略和阈值，不能单独证明测试槽位模板已与测试真值隔离。
- pcap/eBPF归一化会删除不完整trace。后续去除标签不能恢复已删除事件或纠正样本选择偏差。
- 旧默认ParentEdge F1参考边由真值trace分组后按因果时间规则推导，不是独立真实父子边。另行提供的真实调用日志可通过下述独立清单入口评测，不应混用两种真值来源。
- DeepFlow与TraceWeaver的输入、粒度及分母需逐配置核对。执行失败、协议不支持与成功运行后准确率0%需分开。
- TLS README说明Go读方向返回探针默认关闭，不能把协议表的勾选解释为完整采集验证。

## 新增入口

依赖Python 3.10+、NumPy、SciPy。三个步骤分开执行。输入必须是rpc粒度；默认标为previously-filtered，不假设它来自完整观测。

~~~bash
python3 scripts/paper_blind_eval.py prepare \
  --csv /path/to/cleaned_data.csv \
  --output result/paper_run_01

python3 scripts/paper_blind_eval.py infer \
  --observations result/paper_run_01/observations.csv \
  --predictions result/paper_run_01/full_predictions.json \
  --variant full

python3 scripts/paper_blind_eval.py evaluate \
  --observations result/paper_run_01/observations.csv \
  --oracle result/paper_run_01/oracle.json \
  --predictions result/paper_run_01/full_predictions.json \
  --output result/paper_run_01/full_metrics.json
~~~

prepare将trace_id、X-Mark、跨度标识与传播头隔离，拒绝残留已知真值标识的payload；自由文本须另行审计解析器。记录数与未配对RPC数写入manifest。

infer只接收观测文件，清除外部LINEAGE_*覆盖，冻结三种配置；引擎禁用真值调用排序、槽位模板、监督策略及相关回退，导出预测后停止，不计算准确率。schema仍需审计；这不是OS安全沙箱。

推断前后核对观测与引擎文件摘要；若执行期间发生变化则拒绝冻结结果。引擎先写临时文件，评测入口在补齐输入、版本与配置元数据后再发布预测；JSON写入采用临时文件替换，避免把中间输出当作最终结果。恢复批处理时，须核对prepare清单、当前观测与每个预测的摘要及配置，缺少元数据的文件隔离后重算，不手工补写来源字段。

盲评时应单独复制observations.csv至推断目录或机器，预测冻结后再交回评测端。普通流程实现进程和输入分离，不自动设置文件访问控制。

这些结果不能直接替换旧稿准确率：关闭真值回退改变了配置，必须重新运行。

## 分母与独立父子真值

若已知负载实际预期根请求总数，prepare可加--expected-traces该整数，数量来自真实load report，不能用配置RPS乘时长代替。

只有确认输入在过滤前导出时才设--capture-scope unfiltered。此标记是研究者声明，不能自动验证采集完整性。脚本无法识别或恢复历史上已被删除的RPC。

缺少独立父子真值时，只报告条件下的归属指标，FullTraceAcc和ParentEdge F1为null。未配对RPC也留在可用真值分母；预期但未采到的根请求计为失败。

完整结构评测须提供工作负载真实创建下游调用时记录的独立清单：

~~~json
{
  "complete_population": true,
  "events": [
    {
      "key": ["external:50000", "api:8080", "root-stream"],
      "trace_id": "request-ground-truth",
      "parent_key": null
    },
    {
      "key": ["api:50001", "backend:8080", "child-stream"],
      "trace_id": "request-ground-truth",
      "parent_key": ["external:50000", "api:8080", "root-stream"]
    }
  ]
}
~~~

这是格式示例，不是实际真值。必须包含全部预期请求及RPC，包括未采到事件。交换键需在采集与真值记录间对齐；不得用待评价的时间匹配规则生成parent_key。跨服务评测ID只能存在oracle，不进入观测。

evaluate加--parent-oracle /path/to/independent_population.json才启用结构指标；清单遗漏、重复键、不同trace父引用和总请求数冲突会拒绝计分。complete_population声明不能证明真值独立，须保留方法与日志。

### 已有独立日志的适配

若归档包含`independent-rpc-parent-ground-truth-v1`清单与保留评测HTTP头的CSV，可在预测生成后使用：

~~~bash
python3 scripts/paper_independent_oracle.py \
  --manifest /path/to/ground_truth_manifest.json \
  --capture-with-eval /path/to/cleaned_data_with_eval.csv \
  --output result/paper_run_01/independent_population.json

python3 scripts/paper_blind_eval.py evaluate \
  --observations result/paper_run_01/observations.csv \
  --oracle result/paper_run_01/oracle.json \
  --predictions result/paper_run_01/full_predictions.json \
  --parent-oracle result/paper_run_01/independent_population.json \
  --output result/paper_run_01/full_independent_metrics.json
~~~

适配只发生在评测端。它按请求头`X-TF-Eval-Span-Id`与独立清单中的span逐项精确对齐，同时核对父标识、observation标识及请求标签；不根据时间猜测父子关系，也不使用CSV中可能沿用旧定义的span_id列。重复标识、父引用环、缺失请求根和捕获身份冲突会报错。清单完整性仍取决于真实调用日志本身，须核对负载报告与原始JSONL。

未捕获但存在于独立清单的RPC保留为评测占位键，计入失败分母；只有响应而无请求身份时拒绝自动对齐。评测文件及保留评测头的CSV不能交给推断进程。prepare也会递归移除payload中的X-TF-Eval标识字段。

当前evaluate的SpanAcc/Coverage分母包含入口RPC；ParentEdge F1按全部非根真实父边计算。历史independent_metrics可能只统计内部RPC，比较前须统一单位与分母。DeepFlow若未导出可核验的父边，结构指标保持不适用。

## 消融与基线

同一observations.csv分别用--variant time-only、no-context、full，写入不同预测与指标文件。

- time-only：业务令牌与累计上下文权重为0。
- no-context：关闭累计祖先上下文，仅保留局部父子业务值；修订盲推断不使用兄弟顺序或兄弟响应证据。
- full：局部业务令牌加预测祖先累计上下文。

全部关闭读取测试真值的回退，no-context不代表完全没有上下文。不得把历史profile结果混入。

入口目前只导出TraceFusion预测，不自动运行或转换TraceWeaver/DeepFlow。后两者需适配为同一key/root_key/parent_key格式，用同一独立oracle计分；此项尚未完成。

## 最小补跑矩阵

1. 三个工作负载主要负载点至少3次独立重复，报告实际完成请求数、均值与标准差。
2. Bookinfo并发变化同时记录RPS、连接数、请求重叠与错误率。
3. 三种消融使用同一观测，避免改变负载或采集范围。
4. 同值并发、低令牌多样性、缺失观测；记录失败与未关联比例。
5. 保留多语言结论则固定同一业务行为与请求分布。
6. 开销覆盖采集、解析与引擎；CPU单位及核数归一化明确；延迟含无采集基准和P95/P99。
7. 保存原始抓包/事件、load report、配置、源码版本、日志和文件摘要。

## 检查

~~~bash
python3 -m unittest discover -s tests -v
~~~

回归检查是合成数据上的流程验证，不是三个基准的实际性能实验。

## 2026年10月15日初始化修复

盲推断已取消全局兄弟调用顺序和固定根层批次匹配，仅固定入口标签，根层与内部服务边统一选择可修正父候选。严格包含优先，原有界容差保留；上下文仅来自预测祖先，全部服务边迭代重扫，并记录收敛。历史非盲评路径保留兼容。

27项检查通过；12组抓包×3配置开发回归完成，完整方法四负载FullTraceAcc均值为100.00%、99.90%、99.70%、99.20%。仍有29个RPC错误，且400 RPS第3次下降0.6个百分点。完整与关闭累计项的逐RPC预测相同，不作累计项增益声明。详细版本、逐运行结果、剩余错误及当前/历史环境区别见[修复复核记录](bookinfo_blind_initialization_fix_20261015.md)。

当前不新增采集、不投稿。先审计剩余时间边界与同值歧义，冻结最终策略后再补同条件基线与开销；后续独立验证不能由这些已用于诊断的开发数据替代。
