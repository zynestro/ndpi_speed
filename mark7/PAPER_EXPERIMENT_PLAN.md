# mark5 / mark7 论文实验计划

## 1. 先澄清：如何理解当前 mark7

### 1.1 正确的心智模型

如果暂时不考虑 `Preprocess Time`，当前 `mark7` 可以抽象成：

```text
hardware RSS / 输入后端
  -> dispatch 阶段
      -> flow affinity lookup
      -> 首次出现 flow 的 worker 分配
      -> worker queue enqueue
  -> worker 阶段
      -> parse
      -> worker 私有 flow table
      -> nDPI detection
      -> protocol accounting
```

这个抽象对论文是有用的，因为受控实验主要考察调度策略，而不是磁盘 IO。

但当前代码的真实实现是：

```text
pcap preload / 软件模拟 RSS
  -> dispatcher shards
  -> worker queues
  -> worker nDPI processing
```

所以 preprocess 阶段不是真正的硬件 RSS。它当前做了：

- `pcap_next_ex()`；
- 链路层标准化；
- 报文解析；
- 双向归一化 flow key 构造；
- `flow_hash` 计算；
- `dispatcher_id = flow_hash % num_dispatchers`；
- 将包复制到 `dispatch_packet_t`。

如果后续实现 DPDK 路径，这些工作会发生变化：

- pcap IO 消失；
- 硬件 RSS 可以把包送到 RX queues；
- mbuf 指针替代 pcap 包缓冲区复制；
- 如果硬件 RSS 不能提供调度器所需的 canonical bidirectional key，软件仍然需要做足够的解析和 key 归一化。

### 1.2 flow 进入 dispatch 后发生什么

对于有合法 flow key 的包：

1. Preprocess 已经构造好了 canonical bidirectional `flow_key`。
2. Preprocess 已经计算好了 `flow_hash`。
3. Preprocess 分配 `dispatcher_id = flow_hash % num_dispatchers`。
4. Dispatcher 调用 `dispatch_lookup_or_assign()`。
5. Dispatch 在 shard-local affinity table 中查找该 flow。
6. 如果是已有 flow，dispatch 直接返回之前分配的 worker。
7. 如果是新 flow，dispatch 计算 cost bucket，并运行当前调度策略选择 worker。
8. Dispatcher 将包 enqueue 到目标 worker。
9. Worker 消费该包，并在自己的私有 nDPI 状态中处理它。

核心代码核实：

- preprocess 中 canonical flow key 和 hash：`mark7/src/reader.c:317-327`
- hash 到 dispatcher id：`mark7/src/reader.c:338-343`
- dispatch 调用时传入预计算 hash：`mark7/src/reader.c:456-462`
- affinity lookup 和首次 flow 分配：`mark7/src/dispatch.c:208-294`
- cost-aware worker 选择：`mark7/src/dispatch.c:75-113`
- worker 消费循环：`mark7/src/worker.c:384-409`

### 1.3 关键细节：双向 hash

“两个方向 hash 到同一个 flow”这个性质来自 canonical `flow_key`，不是普通 NIC RSS 自然保证的。

当前软件路径做的是：

```text
packet -> parsed 5-tuple -> canonical bidirectional flow_key -> flow_key_hash
```

因此 A->B 和 B->A 会映射到同一个 dispatch entry。若使用真实硬件 RSS，需要确认 NIC RSS 是否支持对称 RSS，以及它的 tuple 定义是否和我们的 flow affinity 要求一致。否则，DPDK 路径在 dispatch 前仍然需要软件 canonicalization。

## 2. Hash 成本与时间口径

### 2.1 当前 hash 时间

以一组代表性运行为例：

```text
Total Elapsed Time:              14.198593 s
Preprocess Time:                 12.863259 s
Preprocess hash:                  1.061632 s
Elapsed Time (No Preprocess):     1.335334 s
Dispatch flow->worker map:        1.185542 s
Dispatch enqueue:                 1.494571 s
```

当前 `Preprocess hash` 不是纯 hash 函数耗时，它包括：

- Ethernet/IP/TCP/UDP parse；
- canonical flow key 构造；
- flow hash；
- dst port 和 payload prefix 提取。

代码核实：

- 计时区域在 parse 之前开始：`mark7/src/reader.c:306`
- parse/key/hash/prefix 逻辑：`mark7/src/reader.c:317-327`
- 计时区域结束：`mark7/src/reader.c:333-336`

近似占比：

```text
Preprocess hash / Total Elapsed     = 1.061632 / 14.198593 ~= 7.5%
Preprocess hash / Preprocess        = 1.061632 / 12.863259 ~= 8.3%
Preprocess hash / No-Preprocess     = 1.061632 / 1.335334 ~= 79.5%
```

最后一个比例不能直接理解为“当前 dispatch 成本对比”，因为这部分 hash 工作被有意排除在 `Elapsed Time (No Preprocess)` 之外。它的意义是提醒我们：如果在线实现必须在 dispatch 前做完整软件 parse + canonical hash，这部分成本会非常重要。

按包计算，在 Monday trace 约 11.66M 包时：

```text
1.061632 s / 11.655M packets ~= 91 ns/packet
```

单包看起来不大，但总量上不可忽略。

### 2.2 当前吞吐的分母

当前 `mark7` 的吞吐计算是：

```text
effective_elapsed_sec = total_elapsed_sec - preprocess_sec
throughput_mpps       = total_packets / effective_elapsed_sec / 1e6
bandwidth_gbps        = total_bytes * 8 / effective_elapsed_sec / 1e9
```

代码核实：

- effective elapsed：`mark7/src/main.c:41-43`
- throughput 和 bandwidth：`mark7/src/main.c:85-87`
- 输出位置：`mark7/src/main.c:126-129`

因此当前 `Throughput` 不是 disk-to-result 的端到端吞吐，而是 pcap preload 之后的 offline replay effective throughput。

论文中需要明确写清楚：

> 除非特别说明，我们报告的是 dispatch-and-worker interval 上的 effective replay throughput，不包含 offline pcap preload 阶段。

如果论文也报告离线端到端吞吐，可以使用：

```text
end_to_end_mpps = total_packets / total_elapsed_sec / 1e6
```

两个数字都有效，但回答的是不同问题。

### 2.3 为什么 Dispatch(Read) 可能大于墙钟时间

`Dispatch(Read) Time` 是多个 dispatcher 线程内计时分项的总和：

```text
Dispatch(Read) = sum(dispatcher flow->worker + enqueue + other)
```

多个 dispatcher 并行运行，所以这个类似 CPU-time 的累计值可以大于真实墙钟 `Elapsed Time (No Preprocess)`。

代码核实：

- dispatcher 本地计时：`mark7/src/reader.c:433-435`
- 合并到 reader context：`mark7/src/reader.c:383-391`
- 最终 `read_time_ns`：`mark7/src/reader.c:107-109`

同理，`Process nDPI` 等 worker 子项是多个 worker 的累计值，而 `Process Time` 是所有 worker 中最大的 `processing_time_ns`。

代码核实：

- worker 最大 process time：`mark7/src/main.c:67-69`
- worker 子项累计：`mark7/src/main.c:73-82`

## 3. DPDK 与当前 pcap replay 的关系

### 3.1 哪个更快？

取决于比较边界。

如果看原始输入路径，DPDK 预期会明显快于当前 pcap 输入：

- DPDK 避免 `pcap_next_ex()`；
- DPDK 避免热路径上的磁盘/文件解析；
- DPDK 使用 burst 收包；
- DPDK 传递 mbuf 指针，而不是复制 pcap bytes。

但当前 `mark7` 的 effective throughput 排除了 pcap preload，只测量内存中的 dispatch + worker 阶段。因此这个数字可能高于真实 DPDK 端到端数字，因为它忽略了 NIC RX、mbuf 分配/回收、PCIe、内存放置、burst 调度和驱动开销。

### 3.2 推荐论文表述

用当前 pcap replay 做受控策略对比：

```text
Same trace, same workers, same cost table, same replay input.
Compare only scheduling policy behavior.
```

把 DPDK 单独作为系统验证：

```text
Real RX path, hardware queues/RSS, realistic packet ingress.
Compare Ours against DPDK RSS baseline.
```

不要把 pcap replay effective throughput 和 DPDK live-RX throughput 放在同一张图中当作同一种指标。如果必须同时出现，要明确标注：

- `offline replay effective throughput`；
- `DPDK live-RX end-to-end throughput`。

## 4. 论文结构评估

### 4.1 总体判断

论文可以清晰分成两部分：

1. `mark5`：measurement study 和 offline profiling 证据；
2. `mark7`：调度设计与 evaluation prototype。

目前 measurement 侧强于 evaluation 侧。

`mark5` 已经能支撑比较强的故事：

- protocol detection cost 存在显著差异；
- P/E 行为不同，但整体相对稳定；
- 首包可见特征可以用来构建 lookup table；
- 硬件计数器可以解释部分行为。

`mark7` 当前支持：

- 可运行的 cost-aware 调度原型；
- hash-only baseline；
- per-worker / P/E load observation；
- dispatch overhead observation。

但 `mark7` 还没有完全支撑 paper-grade evaluation matrix，因为它缺少 runtime policy baselines、结构化输出、重复实验，以及真实 tail latency 指标。

## 5. §II Measurement Study：审查与补充项

### 5.1 当前大纲的强项

当前 Measurement Study 的动机是成立的：

- 明确这是你的 measurement，而不是 background；
- 隔离 P/E 核与协议成本；
- 直接连接到 cost-aware scheduling 的设计需求；
- 自然解释为什么 offline cost modeling 是可行的。

### 5.2 建议 refinement

#### 当前 O1：协议成本差异显著

保留这个观察，但建议同时报告：

- flow-weighted distribution；
- protocol-weighted distribution。

原因是：如果某个 trace 被 ICMP 或某个大协议主导，flow-weighted mean 可能看起来过于稳定。protocol-weighted view 可以避免结论被热门协议过度支配。

推荐图：

- Figure 1(a)：per-protocol detection cost，P/E 并列；
- Figure 1(b)：detection cost CDF 或 violin plot；
- 可选：top-k protocols + others，增强可读性。

推荐统计：

- min / median / p90 / p99 protocol cost；
- max/min ratio；
- 跨 trace 的 Spearman correlation；
- 过滤后的 protocol 数量和 flow 数量。

#### 当前 O2：P/E speedup 近似稳定

这个观察很好，但措辞要谨慎。当前证据支持“在许多协议上相对稳定”，不一定支持“严格恒定”。

推荐指标：

- median E/P detection-time ratio；
- interquartile range；
- coefficient of variation；
- per-trace E/P speedup boxplot；
- IPC ratio 与 LLC miss ratio correlation。

推荐图：

- Figure 2(a)：按协议展示 E/P detection cost ratio；
- Figure 2(b)：IPC 和 LLC miss ratio summary 或 scatter。

#### 增加 O3：首包特征可用但不完美

这个观察对 bootstrapping problem 很重要：

```text
调度器需要在 nDPI 识别协议之前知道成本。
```

现有 mark5 数据已经有 first-packet signature 输出。论文应展示 lookup quality：

- coverage；
- purity；
- bucket accuracy；
- default bucket rate；
- 规则来源：port-only 还是 port+prefix。

这样 §II 到 §III 的过渡就不只是“我们测到了协议成本”，而是“我们可以在分类前估计成本”。

### 5.3 需要 dataset table

建议增加一张紧凑的数据集表：

```text
Trace | Packets | Bytes | Flows | Detected Flows | Top Protocols | Avg Packet Size
```

这张表用于回应 trace 代表性，并帮助审稿人理解协议分布偏斜。

## 6. §IV Evaluation：审查与补充项

### 6.1 当前大纲的强项

你提出的 baseline 表方向是对的：

```text
RSS | JSQ | Static Pool | Ours | Oracle
```

几个维度也合理：

- load-aware；
- cost-aware；
- core-aware；
- dynamic。

### 6.2 当前风险

当前实现直接支持的只有：

- hash-only target，可近似作为 RSS-like flow hash；
- cost-aware-jsw target，是早期 Ours prototype。

当前还没有实现：

- JSQ 作为一等策略；
- Static Pool；
- Oracle；
- 结构化 CSV/JSON 输出；
- 真实 p50/p99 latency。

所以在这些补齐之前，论文不宜声称已经完成完整 evaluation。

### 6.3 推荐 baseline 定义

#### RSS / Hash

策略：

```text
worker = flow_hash % num_workers
```

作用：

- 硬件 RSS-like flow affinity baseline；
- 不感知负载；
- 不感知成本；
- 不感知核类型。

当前实现：

- `ndpiBenchmarkMark7Hash`

需要改进：

- 暴露成 runtime `--policy rss`，而不是只通过编译 target 切换。

#### JSQ

策略：

```text
worker = argmin(queue_depth)
```

只在首次 flow assignment 时使用。已有 flow 保持 affinity。

作用：

- load-aware；
- 不 cost-aware；
- 不 core-aware。

需要实现：

- 增加基于 `queue_depth` 的 dispatch policy branch；
- 可选：使用 pending packets 或 estimated pending bytes。

#### Static Pool

策略示例：

```text
Easy    -> E-core pool
Middle  -> mixed pool 或 P/E weighted pool
Hard    -> P-core pool
within pool: round-robin 或 hash
```

作用：

- cost-aware；
- core-aware；
- 但不是动态 load-aware。

需要实现：

- bucket 到 core type 的映射；
- pool 内 worker 选择。

#### Ours

当前策略：

```text
score = pending_cost(worker) + cost_profile[core_type][bucket] + P_bias
worker = argmin(score)
```

作用：

- load-aware；
- cost-aware；
- core-aware；
- dynamic。

当前实现：

- `mark7/src/dispatch.c:75-113`

需要改进：

- 让策略在运行时可选；
- 调整或解释 `P_bias`；
- 输出 bucket 到 core type 的 placement 统计。

#### Oracle

策略选项：

1. Trace oracle：
   - 知道真实 flow protocol 或真实 measured flow cost；
   - 在调度前使用真实成本。

2. Offline scheduler oracle：
   - 看到整条 trace；
   - 可以做近似最优分配或 greedy list scheduling。

论文中推荐：

- 使用 trace oracle 作为 practical upper bound；
- 除非真的实现 optimizer，否则不要声称 global optimal。

需要实现：

- 生成 `flow_key -> true_cost` 或 `signature -> true_cost` 表；
- mark7 加载 oracle 表，并用真实 bucket/cost 做首次 flow assignment。

### 6.4 需要补充的指标

#### 已经有的指标

- throughput Mpps；
- bandwidth Gbps；
- cycles per packet；
- dispatch flow->worker time；
- dispatch enqueue time；
- process parse / flow / nDPI breakdown；
- per-worker packets/bytes/flows；
- P/E load summary。

#### 需要结构化，但不一定需要新 instrumentation

- CSV/JSON run summary；
- worker stats CSV；
- dispatch stats CSV；
- P/E placement summary；
- load imbalance metrics：
  - max/min worker packets；
  - max/min worker bytes；
  - coefficient of variation；
  - Gini coefficient；
  - max worker processing time / mean worker processing time。

#### 需要新 instrumentation

- p50/p99 per-packet sojourn latency；
- p50/p99 queue waiting time；
- p50/p99 dispatch decision time；
- sampled per-packet latency histogram。

因为 latency instrumentation 会影响吞吐，建议实现采样模式：

```text
--latency-sample-rate 1024
```

或 fixed-size reservoir sampling。

## 7. 当前距离论文设想还有多远

### 7.1 Measurement Study readiness

估计成熟度：高。

已有：

- mark5 profiling runs；
- P/E time 和 hardware summaries；
- protocol-level plots；
- lookup training outputs；
- first-packet signature summaries。

仍需补充：

- dataset table；
- cross-trace correlation numbers；
- speedup ratio CV/IQR；
- flow-cost CDF；
- lookup coverage/purity figure；
- 关于 trace skew 的谨慎表述。

### 7.2 Evaluation readiness

估计成熟度：中低。

已有：

- controlled replay platform；
- hash-only 对照 target；
- cost-aware prototype；
- dispatch optimization；
- detailed stdout stats。

仍需补充：

- runtime policy framework；
- JSQ baseline；
- Static Pool baseline；
- Oracle baseline；
- structured output；
- batch runner；
- plotting scripts；
- repeated runs with error bars；
- latency 或 queue waiting metric。

### 7.3 Design readiness

估计成熟度：中。

概念设计是自洽的：

```text
Offline profiling -> first-packet cost estimate -> dynamic heterogeneous scheduling
```

但实现上还要闭环：

```text
mark5 cost table -> mark7 policies -> structured evaluation -> paper figures
```

## 8. 推荐工程路线

### Phase 1：让 mark7 结果可直接画论文图

目标：

把 stdout 转成结构化实验输出。

实现：

- `--output-dir <dir>`；
- `run_summary.csv/json`；
- `worker_stats.csv`；
- `dispatch_stats.csv`；
- `core_type_summary.csv`；
- `policy_config.json`。

可能涉及文件：

- `mark7/src/main.c`；
- `mark7/include/ndpi_benchmark.h`；
- 可能新增 `mark7/src/result_writer.c`。

验收：

- 一次运行产生稳定的 machine-readable output；
- 现有 stdout 保留；
- batch scripts 不再依赖脆弱的正则解析。

### Phase 2：运行时 policy framework

目标：

把编译期策略切换替换为：

```text
--policy rss|jsq|static-pool|ours|oracle
```

实现：

- `dispatch_policy_t` enum；
- policy parser；
- dispatch context 保存 policy；
- dispatch assignment switch。

可能涉及文件：

- `mark7/src/main.c`；
- `mark7/src/dispatch.c`；
- `mark7/include/benchmark_internal.h`；
- `mark7/include/ndpi_benchmark.h`。

验收：

- 一个 binary 可以运行所有非 oracle 策略；
- `ndpiBenchmarkMark7Hash` 可以保留兼容，但不再是实验必须项。

### Phase 3：补齐 baseline

实现：

- RSS/hash；
- JSQ；
- Static Pool；
- Ours；
- Oracle-lite。

验收：

- 同一 trace 和同一 core list 可以跑所有 baseline；
- 输出记录 policy name 和 policy parameters。

### Phase 4：增加 latency 与 overhead 指标

实现：

- sampled queue waiting time；
- sampled dispatch decision time；
- histogram 计算 p50/p99；
- load imbalance metrics。

验收：

- throughput-only mode 低开销；
- latency mode 显式开启并有文档说明；
- p50/p99 可用于 Figure 4。

### Phase 5：batch runner 和 plotter

实现：

- `mark7/run_mark7_matrix.py`；
- `mark7/plot_mark7_results.py`。

实验矩阵：

```text
policies = rss, jsq, static-pool, ours, oracle
traces = Monday, 201706251400, seed_1500b, cap_traffic, selected normal traces
repeats = 5
core_sets = P-only, E-only, P+E
```

验收：

- 每个 batch 生成一个独立实验目录；
- 生成 CSV summary 和论文图。

## 9. 工程完成后推荐论文图

### Measurement figures

1. Protocol detection cost by protocol，P/E side-by-side。
2. E/P speedup ratio by protocol。
3. First-packet lookup quality：
   - coverage；
   - purity；
   - bucket confusion。
4. 可选：flow detection cost CDF。

### Evaluation figures

1. Overall throughput by policy。
2. p50/p99 queue 或 sojourn latency by policy。
3. Ablation：
   - RSS；
   - JSQ；
   - JSQ + cost；
   - JSQ + cost + core speed；
   - Ours + overload guard；
   - Oracle。
4. Robustness：
   - encrypted/unknown ratio；
   - short-flow vs long-flow mix；
   - trace-to-trace variation。
5. Micro-analysis：
   - P/E byte 和 flow share；
   - bucket placement by core type；
   - dispatch overhead ns/pkt。

## 10. 论文措辞建议

### 10.1 谨慎使用 “RSS”

当前 preprocess 是 RSS-like partitioning 的软件模拟。论文中建议写：

> In the offline replay, we pre-partition packets by a canonical flow hash to emulate the flow affinity provided by RSS. In the DPDK implementation, this stage can be mapped to hardware RX queues when symmetric RSS is available.

中文理解：

> 在离线 replay 中，我们用 canonical flow hash 预先划分包，以模拟 RSS 提供的 flow affinity。在 DPDK 实现中，当 symmetric RSS 可用时，这一阶段可以映射到硬件 RX queues。

### 10.2 谨慎说明吞吐

建议写：

> Unless otherwise stated, replay throughput excludes the offline pcap preload stage and measures the dispatch-and-worker interval.

中文理解：

> 除非特别说明，replay throughput 不包含 offline pcap preload 阶段，只测量 dispatch-and-worker interval。

如果报告端到端 pcap throughput，需要单独标注。

### 10.3 谨慎使用 “Oracle”

除非实现真正 optimizer，否则叫：

```text
Trace-informed oracle
```

或：

```text
Oracle cost estimator
```

不要叫 “optimal scheduler”。

### 10.4 谨慎描述 P/E speedup constancy

使用：

> approximately stable

而不是：

> constant

然后报告 median、IQR、CV。

## 11. 最终评估

论文方向是成立的：

```text
Measurement shows protocol and core heterogeneity.
First-packet features provide a usable cost prior.
Dynamic dispatch can use that prior to place flows on heterogeneous cores.
```

当前实现状态：

- `mark5`：接近可以支撑 Measurement Study；
- `mark7`：是很好的 prototype，但还不能直接支撑完整 Evaluation。

在提出强 evaluation claim 之前，至少需要补齐：

1. mark7 结构化输出；
2. runtime baseline policies；
3. repeated batch runs；
4. load-balance metrics；
5. 如果论文声称 latency benefit，需要 latency 或 queue-waiting metric。

完成这些之后，当前大纲可以支撑一个可信的 systems paper story。否则，§IV 应更保守地写成 prototype feasibility study，而不是 complete scheduler evaluation。
