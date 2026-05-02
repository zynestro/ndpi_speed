# mark7

`mark7` 是当前这条“离线 pcap 回放 + 模拟 RSS + 首包代价预测 + 异构核调度”实验线。

它的目标不是做真实网卡收发，而是先把下面这条链在离线模式里跑通并可重复对比：

`pcap preload -> simulated RSS to 8 E-core readers -> dispatch to 16 workers (8 P + 8 E) -> nDPI detection`

当前默认拓扑是：

- `8` 个 reader / dispatcher：`core 16-23`
- `16` 个 worker：`core 0,2,4,6,8,10,12,14,24-31`
  - `0,2,4,6,8,10,12,14` 视为每个 P 核选一个逻辑线程
  - `24-31` 视为 E 核

当前默认调度策略是：

- `cost-aware-jsw`

同时也保留了一个纯哈希 baseline：

- `hash-only`

当前调度成本已经拆成两层：

- `lookup_table.json`：只负责 `dst_port/payload_prefix -> Easy/Middle/Hard`
- `offline_costs/cost_profile.csv`：负责 `P/E x Easy/Middle/Hard` 六个离线 profiling 成本值

也就是说，调度时不再通过单一 `speed_factor` 推导 E 核成本，而是直接查当前 worker 核类型对应的 bucket cost。

## 1. 当前实现到底在做什么

`mark7` 现在不是在 `mark3` 上简单加一个端口表判断，而是把原来 `flow -> worker` 的软件 RSS 阶段，换成了一个真正的“调度层”。

这条数据路径分成三段：

1. 预处理阶段
   - 单个 reader controller 线程顺序扫描整个 pcap
   - 先把包标准化为 Ethernet 视图
   - 解析出双向 canonical flow key、原始 `dst_port`、前 2 字节 payload prefix
   - 按 flow key 哈希把包预分配到 8 个 dispatcher
   - 把包复制到内存中的 `dispatch_packet_t[]`
2. 分发阶段
   - 8 个 dispatcher 线程各自只处理自己的索引区间
   - 每个 dispatcher 对每个包做一次 `flow -> worker` 决策
   - 新流走首包调度，旧流直接命中 affinity
   - 然后把包放入目标 worker 队列
3. 处理阶段
   - worker 从自己的 ring/queue 里取包
   - 执行 `parse -> flow table -> ndpi_detection_process_packet`
   - 完成后把该包附带的预估代价 retire 掉

## 2. 当前用到的表

### 2.1 预处理包缓存表

预处理阶段不会直接把包发给 worker，而是先存成 `dispatch_packet_t[]`。

每个元素至少包含：

- `timestamp_us`
- `flow_key`
- `dispatcher_id`
- `dst_port`
- `payload_prefix[2]`
- `has_flow_key`
- `data`

作用是：

- 先把 pcap 全量拉入内存
- 再让多个 dispatcher 并发跑分发逻辑

### 2.2 dispatcher schedule 表

预处理完成后，会根据 `dispatcher_id` 再构建两张索引表：

- `dispatcher_offsets[d]`
- `dispatcher_indices[pos]`

这样每个 dispatcher 只遍历自己的 `[offset[d], offset[d+1])` 区间，不需要再次扫全量数组。

### 2.3 cost bucket lookup table

当前默认从这个 JSON 加载：

- `/home/zync/WORKSPACE/ndpi_speed/mark7/offline_costs/lookup_table.json`

它在内存里被加载成 `cost_table_t`，包含三类规则：

1. `default_bucket`
   - 当前默认是 `Middle`
2. `port_table`
   - `dst_port -> bucket`
3. `special_rules`
   - `(dst_port, payload_prefix)` -> bucket
   - 当前代码已经支持，但你现在这张表还是空的

当前 bucket 数值映射是：

- `Easy = 2 us`
- `Middle = 7 us`
- `Hard = 15 us`

实现上对应：

- `COST_EASY_X1000 = 2000`
- `COST_MIDDLE_X1000 = 7000`
- `COST_HARD_X1000 = 15000`

### 2.4 flow affinity table

这是 `mark7` 和 `mark3` 最大的行为差异之一。

当前 `mark7` 的调度层不再用 reader 侧的 quick hash 做 `flow -> worker` 粘性映射，而是用：

- `canonical bidirectional 5-tuple`

也就是说：

- `A:1234 -> B:443`
- `B:443 -> A:1234`

在调度层会被视为同一条会话，绑定到同一个 worker。

这张表由 `dispatch_context` 内部维护，是一个开放寻址哈希表，键是：

- `flow_key_t`

值是：

- `worker_id`

### 2.5 per-worker runtime state 表

每个 worker 还有一份 cache-line 对齐的运行态：

- `added_cost_x1000`
- `retired_cost_x1000`
- `queue_depth`
- `core_type`
- `core_id`
- `speed_factor_x1000`

它是 reader/dispatcher 做打分时唯一看的“负载视图”。

其中：

- P 核速度因子：`1.00`
- E 核速度因子：`0.56`

## 3. 新流是怎么调度的

当前新流首包的逻辑是：

1. 先根据包内容算 `canonical bidirectional flow key`
2. 用这个 key 查 affinity table
3. 如果命中，说明是旧流，直接用已有 `worker_id`
4. 如果未命中，说明是新流，开始做首包调度：
   - 用当前首包原始方向的 `dst_port` 查 bucket
   - 如有需要，再用 `(dst_port, payload_prefix)` 查 special rule
   - 得到 `Easy/Middle/Hard`
   - 把 bucket 转成数值代价
   - 遍历所有 worker 算 score
   - 选 score 最小的 worker
   - 把 `flow -> worker` 写回 affinity table
   - 同时把该流本次附带的预估代价累加到目标 worker 的 `added_cost_x1000`

这里有一个很重要的语义：

- `affinity key` 用双向 canonical key
- `cost lookup` 用首包原始方向的 `dst_port`

也就是说，如果一条双向会话最先出现的是“反方向包”，那这次分类查表就会按这个反方向包自己的 `dst_port` 来查，这和 flow affinity 是两件事。

## 4. 当前 score 公式

当前 `cost-aware-jsw` 的 score 是：

`score = pending + core_bucket_cost + optional_p_bias`

其中：

- `pending = added_cost_x1000 - retired_cost_x1000`
- `core_bucket_cost = cost_profile[core_type][bucket]`
- P 核额外加一个很小的偏置：
  - `DISPATCH_P_BIAS_X1000 = 10`

当前默认 `mark7/offline_costs/cost_profile.csv` 先用 P-core profiling 初始化，E-core 行暂时镜像 P-core 行：

- P 核：
  - `Easy = 2.262390 us`
  - `Middle = 7.626345 us`
  - `Hard = 17.278661 us`
- E 核：
  - `Easy = 2.262390 us`
  - `Middle = 7.626345 us`
  - `Hard = 17.278661 us`

后续跑出 E-core profiling 后，只需要替换 CSV 里的 `E,*` 三行。

## 5. 为什么现在 8 个 E worker 几乎没吃到量

这不是线程没起，也不是绑核失败，而是当前这版 score 逻辑的自然结果。

从你刚才那轮结果看，16 个 worker 里：

- `core 0-7` 基本各自拿到了约 `3 万` 条流
- `core 24-31` 只拿到了个位数到几十条流

当前原因主要有 4 个。

### 5.1 空载时 P/E 比分由离线成本表决定

这是最直接的原因。

旧版本用 `base_cost / speed_factor` 推导 E 核代价；现在改成直接查 `P/E x Easy/Middle/Hard` 六个离线值。也就是说同样一条 `Middle` 流：

- 放到 P 核：用 `P,Middle`
- 放到 E 核：用 `E,Middle`

当前默认 E 行还镜像 P 行，所以空载时 P/E 的 bucket cost 基本一样，只剩 P 核 `+10` 的小偏置会让同等条件下 E 核略占优。等你填入真实 E-core profiling 后，比例关系就由实测数据决定。

### 5.2 P 核数量本身就有 8 个

不是“1 个 P 对 8 个 E”，而是“8 个 P 和 8 个 E 一起竞争新流”。

当前 round-robin tie-break 会先把新流比较均匀地摊到 8 个 P 上，所以单个 P 的 pending 不会很快冲高。

结果就是：

- P 核之间先彼此吃掉大部分流
- E 核根本等不到“P 核 pending 高到不值得再放”的时刻

### 5.3 pending 用的是“估计代价”，不是实测代价

当前 `added_cost_x1000` 和 `retired_cost_x1000` 维护的是：

- 调度时估出来的 bucket 代价

不是：

- 实际 `ndpi_detection_process_packet()` 花掉的真实时间

这会带来两个效果：

1. 如果 bucket 粒度太粗，很多流在 P 核上看起来“并没有那么重”
2. P/E 的选择由离线 `core_bucket_cost` 决定，如果 E 表填得更高，E 核仍会在空载竞争中吃亏

于是 E 核很难靠“真实更空闲”翻盘。

### 5.4 flow affinity 会把首包决策锁死

一旦新流首包被分到某个 P worker，整条双向会话后续都不会迁移。

如果首包阶段 E 核几乎拿不到新流，那么整个运行过程中：

- E worker 就几乎没有机会靠后续包变热
- P worker 会持续吸收这条流的全部后续包

所以这是一个“首包偏向 P，后续越跑越偏”的闭环。

## 6. 当前结果应该怎么理解

现在的代码已经满足这些事情：

- 双向 flow affinity 是正确的
- lookup 表已经接进来了
- `8E reader -> 16 worker` 的骨架是通的
- 可以稳定跑同一个大 pcap 做重复实验
- `cost-aware` 和 `hash-only` 两个版本都能直接比较

但它还没有满足这件事：

- “让 8 个 E worker 真正稳定承担一部分 Easy/Middle 流”

换句话说，当前 `mark7` 已经是一个功能正确的实验平台，但还不是一个已经调优完成的异构调度器。

## 7. 当前吞吐是怎么测的

当前输出里的：

- `Throughput`
- `Bandwidth`

不是用线程时间相加算的，而是用 wall-clock 时间算的。

具体口径是：

1. `main` 在 reader 启动前记录 `wall_start_ns`
2. 等 reader 和所有 worker 全部 `join` 完
3. 记录 `wall_end_ns`
4. `Total Elapsed Time = wall_end_ns - wall_start_ns`
5. `Elapsed Time (No Preprocess) = Total Elapsed Time - Preprocess Time`
6. 最后：
   - `Throughput = total_packets / Elapsed Time (No Preprocess)`
   - `Bandwidth = total_bytes * 8 / Elapsed Time (No Preprocess)`

这意味着：

- `Dispatch(Read) Time` 可以大于 wall-clock，因为它是多个 dispatcher 的累计时间
- `Process Time` 是最慢 worker 的累计处理时间
- 真正拿来算吞吐的分母，是整轮实验的真实经过时间

## 8. hash-only baseline

当前这台机器上 `lscpu` 能看到：

- `0-15` 是 8 个 P-core 的 16 个逻辑 CPU
- `16-31` 是 16 个 E-core 逻辑 CPU

所以默认配置里故意没有使用 `1,3,5,...,15` 这些 P-core 的 SMT sibling，而是只取：

- `0,2,4,6,8,10,12,14`

这样可以更接近“每个 P 核一个执行线程”的实验口径。

当前 `mark7` 同时会生成两个目标：

- `ndpiBenchmarkMark7`
  - 默认 `cost-aware-jsw`
- `ndpiBenchmarkMark7Hash`
  - 纯哈希 baseline

`hash-only` 版本仍然使用相同的：

- 双向 canonical flow affinity key
- reader / worker 线程模型
- pcap preload 流程

只是新流分配时不看 bucket 和 worker runtime state，而是：

- `worker_id = hash(flow_key) % num_workers`

这样做的意义是：

- 你能在完全相同的执行骨架上，直接比较“调度机制本身”有没有带来收益

## 9. 典型运行方式

构建：

```bash
cmake -S mark7 -B mark7/build -DNDPI_PREFIX=$HOME/ndpi-install
cmake --build mark7/build -j
```

运行 `cost-aware`：

```bash
./mark7/build/ndpiBenchmarkMark7 \
  -i /home/zync/WORKSPACE/ndpi_speed/input/Monday-WorkingHours.pcap
```

运行 `hash-only`：

```bash
./mark7/build/ndpiBenchmarkMark7Hash \
  -i /home/zync/WORKSPACE/ndpi_speed/input/Monday-WorkingHours.pcap
```

静默模式：

```bash
./mark7/build/ndpiBenchmarkMark7 \
  -i /home/zync/WORKSPACE/ndpi_speed/input/Monday-WorkingHours.pcap \
  -q
```

## 10. 下一步更可能该改哪里

如果目标是“让 8 个 E worker 真正承担部分流量”，下一步更值得改的是调度公式，而不是再改线程骨架。

当前最值得实验的方向通常有这些：

1. 明显增大 P 核偏置
   - 现在的 `+10` 基本等于没有
2. 改 score 公式
   - 例如单独给 E 核一个更友好的 bucket 折扣
3. 让 `Easy` 流优先尝试 E 核
   - 不必让三类流统一竞争
4. 用更接近真实处理代价的运行时反馈
   - 不只依赖静态 bucket
5. 允许有限的“E 核保底流量”
   - 例如给 E worker 预留一部分新流配额

当前版本更像是：

- “功能正确、可实验、可比较”的第一版

而不是：

- “已经把 P/E 混合调度调到最好”的最终版
