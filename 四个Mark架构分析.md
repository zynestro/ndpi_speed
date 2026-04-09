# 四个 Mark 架构分析

## 1. 先给结论

这四个 `mark` 本质上是在回答同一个问题：

> 如何把 `PCAP -> 解析 -> flow 建状态 -> nDPI 检测 -> 汇总输出` 这条链路做得更快、也更容易分析瓶颈？

它们不是四套完全独立的业务，而是四种不同的执行模型：

- `mark1`：实验母体版。保留多种变体编译目标，用同一套主干代码测试不同 reader / RSS / fast path 策略。
- `mark2`：收敛后的基线多线程版。去掉构建层上的多变体暴露，保留最核心的 `reader -> worker` benchmark 主路径。
- `mark3`：把“读包/预处理”和“分发”拆成两层，并引入多 dispatcher 并发分发，重点研究前端分发阶段的扩展性。
- `mark4`：单线程直读对照版。没有 reader/worker 队列，没有 dispatcher，没有 RSS 映射，代码路径最短，适合作为准确性和低复杂度基线。

如果只看一句话区别：

- `mark1/mark2` 是“单 reader + 多 worker”的流式并行模型。
- `mark3` 是“预加载 + 多 dispatcher + 多 worker”的两段式并行模型。
- `mark4` 是“单线程一路跑到底”的串行模型。

---

## 2. 四个 Mark 的核心特性

### 2.1 mark1

核心特性：

- 主架构是 `1 reader + N worker`。
- reader 线程负责离线读取 PCAP、标准化报文、计算 flow hash、选择 worker、入队。
- worker 线程负责解析 L3/L4、查 flow table、推进 nDPI 检测状态。
- 同一套源码通过编译宏导出多个实验变体。

它最重要的意义不是“最稳定”，而是“最适合做实验矩阵”：

- `ndpiBenchmark`：默认基线。
- `ndpiBenchmarkClassified`：启用已识别流快速路径。
- `ndpiBenchmarkBatch`：启用 reader 侧批量提交入队。
- `ndpiBenchmarkMem`：把 PCAP 先载入内存再读。
- `ndpiBenchmarkSingleHash`：单哈希分流。
- `ndpiBenchmarkAggLB`：更激进的负载均衡。

一句话概括：

> `mark1` 是“多线程基线 + 多实验开关”的总试验台。

### 2.2 mark2

核心特性：

- 执行主路径与 `mark1` 基本同构。
- 仍然是 `pcap -> reader -> rss -> worker queue -> worker(parse/flow/ndpi)`。
- 但在构建层只保留一个目标：`ndpiBenchmarkMark2`。

它的作用更像：

- 把 `mark1` 里已经验证过的主路径收敛成单一 benchmark 版本。
- 降低实验宏与多目标带来的理解和维护成本。
- 让后续和 `mark3/mark4` 对比时，基线更清晰。

一句话概括：

> `mark2` 是“从 mark1 试验台里收敛出来的标准多线程基线版”。

### 2.3 mark3

核心特性：

- 不再是“读一包就立刻分发”。
- 引入了两个阶段：
  - 预处理阶段：先把 PCAP 全部扫描、标准化、算 hash、绑定到 dispatcher、缓存进 `dispatch_packet_t[]`。
  - 分发阶段：多个 dispatcher 线程并发处理自己负责的包索引，再把包分发给 worker。
- 运行期仍然保留 `flow -> worker` 粘性映射。
- 因为 dispatcher 是多线程并发访问共享 RSS 和队列，所以 `rss_table` 与 `packet_queue` 都做了并发增强。

它解决的是 `mark1/mark2` 的一个明显限制：

- 在 `mark1/mark2` 中，reader 始终是前端单点。
- 即使 worker 很多，读包、标准化、分发这段仍然是一个线程推进。
- `mark3` 试图把“分发层”本身做并行化，单独测它的瓶颈。

一句话概括：

> `mark3` 是“前端分发流水线并行化”的版本。

### 2.4 mark4

核心特性：

- 完全单线程。
- 没有 reader 线程，没有 worker 线程，没有队列，没有 RSS。
- 主循环直接做：`pcap_next_ex -> normalize -> parse -> flow_table -> ndpi_detection_process_packet`。
- 跑完后直接遍历 flow table，做分类统计、协议统计、CSV 输出。

它的优势不在扩展性，而在：

- 路径最短，行为最直接。
- 调试和验证最简单。
- 适合当“识别准确性/时延统计/输出格式”的基准版本。
- 适合作为 `mark1/2/3` 的对照组。

一句话概括：

> `mark4` 是“最纯粹、最容易解释的单线程基线”。

---

## 3. 四个 Mark 的主要区别

## 3.1 执行模型区别

| Mark | 执行模型 | 线程结构 | 重点优化方向 |
| --- | --- | --- | --- |
| `mark1` | 流式多线程 | 1 reader + N worker | 用编译变体快速测试不同策略 |
| `mark2` | 流式多线程 | 1 reader + N worker | 保留稳定主路径，作为标准基线 |
| `mark3` | 两段式并行 | 1 reader controller + D dispatcher + N worker | 优化前端分发阶段并分析 preprocess / dispatch |
| `mark4` | 单线程直读 | 仅 main 线程 | 降低复杂度，做准确对照和后处理输出 |

## 3.2 reader 路径区别

- `mark1`：reader 直接读 PCAP 并马上把包塞进 worker 队列。
- `mark2`：和 `mark1` 主路径一致，只是不再把多种变体作为构建目标暴露出来。
- `mark3`：reader 先预处理并缓存所有包，再让多个 dispatcher 并发进行第二次分发。
- `mark4`：没有独立 reader，主线程自己读取并自己处理。

## 3.3 分流 / 负载均衡区别

- `mark1/mark2`：核心是 `flow -> worker` 的软件 RSS；默认策略是 two-choice (`power-of-two choices`)，可按队列深度选更浅的 worker。
- `mark1`：额外暴露 `single-hash` 和 `aggressive LB` 两类实验目标，适合做 RSS 策略对比。
- `mark3`：有两层映射：
  - 预处理阶段 `flow -> dispatcher`
  - 运行阶段 `flow -> worker`
- `mark4`：没有 RSS，因为根本不需要跨线程分配。

## 3.4 队列模型区别

- `mark1/mark2`：默认假设一个 worker 队列只有一个 producer，就是 reader，所以队列实现偏向单生产者。
- `mark3`：一个 worker 队列可能被多个 dispatcher 同时投递，因此 `packet_queue_t` 增加了 `prod_lock` 做多生产者保护。
- `mark4`：无队列。

## 3.5 统计口径区别

- `mark1/mark2`：输出 `Read Time` 和 `Process Time`，其中 `Process Time` 取最慢 worker 的 wall time。
- `mark3`：额外把前端拆成 `Preprocess Time` 和 `Dispatch(Read) Time`，能更细分前端成本。
- `mark4`：更关注单线程总耗时、识别时延、协议/分类聚合以及 CSV 落盘。

## 3.6 工程定位区别

- `mark1`：研究型/实验型。
- `mark2`：稳定多线程基线型。
- `mark3`：并发架构演进型。
- `mark4`：验证/对照/结果输出型。

---

## 4. 各自代码组织架构是怎么组成的

## 4.1 mark1 代码组织

目录结构核心：

- `mark1/CMakeLists.txt`
- `mark1/include/ndpi_benchmark.h`
- `mark1/include/benchmark_internal.h`
- `mark1/src/main.c`
- `mark1/src/reader.c`
- `mark1/src/rss_table.c`
- `mark1/src/worker.c`
- `mark1/src/flow_table.c`
- `mark1/src/packet_parser.c`
- `mark1/src/benchmark_common.c`

模块职责：

- `include/ndpi_benchmark.h`
  - 统一定义核心数据结构。
  - 包括 `packet_queue_t`、`flow_key_t`、`bench_flow_t`、`worker_context_t` 等。
  - 这是整个多线程 benchmark 的公共协议头。

- `include/benchmark_internal.h`
  - 定义内部 glue 接口。
  - 让 `reader/rss/worker/parser/flow_table` 这些模块之间可以互相调用。
  - 这里能看到 `reader_context_t`，说明 `mark1` 的核心控制面围绕 reader 展开。

- `src/main.c`
  - 程序总控。
  - 解析参数、创建 worker、初始化 nDPI、启动 reader/worker 线程、join 线程、汇总统计。
  - 决定的是“生命周期”和“结果口径”。

- `src/reader.c`
  - 前端生产者。
  - 负责 `pcap_next_ex`、`normalize_to_ethernet`、`compute_flow_hash`、`rss_table_lookup_or_assign`、`packet_queue_push`。
  - 在 `NDPI_BENCHMARK_MEMREADER` 下还支持先把 PCAP 载入内存。
  - 在 `NDPI_BENCHMARK_BATCH` 下支持 batch commit 入队。

- `src/rss_table.c`
  - 维护 `flow -> worker` 粘性映射。
  - 默认用 `power-of-two choices` 选 worker。
  - 在不同宏下可以切单哈希和激进负载均衡策略。

- `src/worker.c`
  - 后端消费者。
  - 负责从队列取包、解析、构 flow key、查/建 flow、推进 nDPI 状态、统计首次识别。
  - 每个 worker 拥有独立的 nDPI module 和私有 flow table。

- `src/flow_table.c`
  - worker 私有流状态表。
  - 用开放寻址哈希表管理 `flow_key -> bench_flow_t`。
  - 这是 worker 热点路径之一。

- `src/packet_parser.c`
  - 报文标准化与解析。
  - 负责不同链路层统一成 Ethernet 视图，以及 IPv4/IPv6/TCP/UDP 解析。
  - 同时负责双向统一的 flow key 构造。

- `src/benchmark_common.c`
  - 放公共小工具。
  - 例如绑核、样本打印、字符串格式化等。

架构组合关系：

```text
main
 -> init workers / rss / ndpi
 -> start reader
 -> start workers

reader
 -> pcap read
 -> normalize
 -> hash + rss
 -> enqueue to worker queue

worker
 -> dequeue
 -> parse
 -> flow_table get/create
 -> ndpi_detection_process_packet
 -> protocol stats
```

mark1 的代码组织特点：

- 模块拆分完整。
- 主路径清楚。
- 通过宏把“实验变量”叠加在同一套代码骨架上。
- 非常适合做 benchmark 维度对比，但理解门槛也最高。

## 4.2 mark2 代码组织

目录结构几乎与 `mark1` 一致：

- `mark2/CMakeLists.txt`
- `mark2/include/ndpi_benchmark.h`
- `mark2/include/benchmark_internal.h`
- `mark2/src/main.c`
- `mark2/src/reader.c`
- `mark2/src/rss_table.c`
- `mark2/src/worker.c`
- `mark2/src/flow_table.c`
- `mark2/src/packet_parser.c`
- `mark2/src/benchmark_common.c`

从代码组织角度，`mark2` 可以理解成：

> `mark1` 去掉“面向实验矩阵的构建层复杂度”后的单目标收敛版。

模块职责基本不变：

- `main.c`：生命周期编排与结果汇总。
- `reader.c`：单 reader 读取与分发。
- `rss_table.c`：flow 粘性映射。
- `worker.c`：实际检测处理。
- `flow_table.c`：worker 私有流状态。
- `packet_parser.c`：链路层标准化、L3/L4 解析、flow key 构造。
- `benchmark_common.c`：公共工具。

和 `mark1` 最核心的组织区别不是源码拆分方式，而是“工程意图”：

- `mark1`：同一套主干承载多种变体目标。
- `mark2`：用同一套主干，只保留一个标准目标。

这意味着：

- 如果你要研究“这套 reader-worker 模型的标准实现”，看 `mark2` 更合适。
- 如果你要研究“同一模型下哪些微策略会影响性能”，看 `mark1` 更合适。

## 4.3 mark3 代码组织

目录结构：

- `mark3/CMakeLists.txt`
- `mark3/include/ndpi_benchmark.h`
- `mark3/include/benchmark_internal.h`
- `mark3/src/main.c`
- `mark3/src/reader.c`
- `mark3/src/rss_table.c`
- `mark3/src/worker.c`
- `mark3/src/flow_table.c`
- `mark3/src/packet_parser.c`
- `mark3/src/benchmark_common.c`

虽然文件数与 `mark2` 接近，但模块内部职责明显变化，尤其是 `reader.c`、`rss_table.c`、`ndpi_benchmark.h`。

### mark3 的关键结构变化 1：reader_context 变重了

在 `mark3/include/benchmark_internal.h` 里，`reader_context_t` 不只是“reader 的输入参数 + 计时器”，而是包含：

- `num_dispatchers`
- `dispatcher_cores`
- `packets`
- `packet_count`
- `dispatcher_offsets`
- `dispatcher_indices`
- `stats_lock`
- preprocess 与 dispatch 两套计时字段

这说明 `reader` 在 `mark3` 已经不只是读包线程，而是一个“控制器 + 预处理器 + dispatcher 管理者”。

### mark3 的关键结构变化 2：reader.c 成了核心模块

`mark3/src/reader.c` 是整个版本最重要的演进点，职责包含：

- `load_pcap_packets()`
  - 顺序读取 PCAP。
  - 标准化报文。
  - 计算 flow key。
  - 做 `flow -> dispatcher` 分配。
  - 把包缓存到 `dispatch_packet_t[]`。

- `build_dispatch_schedule()`
  - 根据 `dispatcher_id` 生成每个 dispatcher 的索引区间。
  - 本质上是在做一个按 dispatcher 分桶的 schedule。

- `dispatcher_thread_entry()`
  - dispatcher 线程只遍历属于自己的区间。
  - 再做 `flow -> worker` 分配。
  - 再把包投到 worker 队列。

- `merge_dispatcher_stats()`
  - 把多个 dispatcher 的统计汇总到 reader context。

一句话说，`reader.c` 在 `mark3` 里承担了“前端流水线”的主体实现。

### mark3 的关键结构变化 3：rss_table 变成线程安全双用途表

`mark3/src/rss_table.c` 里，RSS 表不再只是单 reader 用的轻量映射，而是：

- 内部带 `pthread_mutex_t lock`
- 提供两类接口：
  - `rss_table_lookup_or_assign()`：`flow -> worker`
  - `rss_table_lookup_or_assign_target()`：`flow -> dispatcher`

它的定位从“单层分流器”变成了“多阶段映射器”。

### mark3 的关键结构变化 4：queue 从单 producer 假设变为多 producer

在 `mark3/include/ndpi_benchmark.h` 里：

- `packet_queue_t` 新增 `pthread_mutex_t prod_lock`
- `packet_queue_push()` 会锁住 producer 路径
- `packet_queue_push_cached()` 在 mark3 里退化成直接调用 `packet_queue_push()`

根本原因是：

- 一个 worker 队列不再只被 reader 一个线程写入。
- 多个 dispatcher 都可能同时往同一 worker 队列塞包。

### mark3 其他模块职责

- `main.c`
  - 负责 worker 和 dispatcher 拓扑配置。
  - 输出时增加 `Preprocess Time` 和 `Dispatch(Read) Time`。

- `worker.c`
  - 和 `mark2` 接近。
  - worker 处理主路径并不是 mark3 的主要变化点。

- `flow_table.c`
  - 仍是 worker 私有状态表。

- `packet_parser.c`
  - 仍负责标准化和 flow key 构造。

架构组合关系：

```text
main
 -> start workers
 -> start reader controller

reader controller
 -> preload packets
 -> flow -> dispatcher mapping
 -> build dispatcher schedule
 -> start dispatchers

dispatcher
 -> iterate assigned packet indices
 -> flow -> worker mapping
 -> enqueue to worker queue

worker
 -> dequeue
 -> parse
 -> flow_table get/create
 -> ndpi_detection_process_packet
```

mark3 的组织本质：

- 模块数量看起来和 mark2 差不多。
- 但系统角色已经从“reader-worker 两级”升级成“reader controller-dispatcher-worker 三级”。
- 因而代码复杂度、并发同步复杂度、计时维度都明显增加。

## 4.4 mark4 代码组织

目录结构显著更轻：

- `mark4/CMakeLists.txt`
- `mark4/include/ndpi_benchmark.h`
- `mark4/include/benchmark_internal.h`
- `mark4/src/main.c`
- `mark4/src/packet_parser.c`
- `mark4/src/flow_table.c`

只有 3 个源码文件参与构建。

### mark4 的组织特点 1：main.c 吞掉了大量控制与汇总逻辑

`mark4/src/main.c` 不只是入口，它还承载了：

- 参数解析
- 绑核
- nDPI 初始化
- 单线程处理主循环
- per-flow 输出
- category 汇总
- proto+category 汇总
- CSV 写出
- 输出目录创建

也就是说，`mark4` 没有把控制逻辑再拆成 `reader.c`、`worker.c`、`benchmark_common.c` 之类的模块。

### mark4 的组织特点 2：只保留最必要的两个底层模块

- `packet_parser.c`
  - 统一链路层、解析 L3/L4、构造 flow key。
- `flow_table.c`
  - 保存单线程运行期间的全部 flow 状态。
  - 因为是单线程，所以不需要考虑 worker 私有、队列边界、RSS 迁移等问题。

### mark4 的组织特点 3：更强调“结果分析输出”

mark4 的一个很强的特点是后处理逻辑比较完整：

- `flow_table_foreach()` 遍历所有流。
- `aggregate_category_cb()` 做分类聚合。
- `aggregate_proto_cb()` 做协议+分类聚合。
- `write_proto_summary_csv()` 把结果落成 CSV。

这使得它不仅是 benchmark，也是一个“检测结果分析器”。

架构组合关系：

```text
main
 -> open pcap
 -> for each packet:
    -> normalize
    -> parse
    -> flow_table get/create
    -> ndpi_detection_process_packet
 -> flow_table_foreach
    -> print summary
    -> aggregate category/proto
    -> write csv
```

mark4 的组织本质：

- 文件更少。
- 控制流更直接。
- 更适合作为教学、验证、输出分析版本。
- 不适合拿来验证复杂并行架构收益，因为它根本没有并行分发层。

---

## 5. 从“为什么会有这四个版本”来理解它们

如果从演进路线看，这四个版本可以理解成下面这条链：

### 第一步：先把多线程流水线搭起来

这就是 `mark1`：

- 先建立 reader-worker 模型。
- 再用不同编译宏测试 reader 和 RSS 的不同变体。
- 这是探索阶段。

### 第二步：收敛出一个标准多线程基线

这就是 `mark2`：

- 保留主路径。
- 弱化多目标实验壳层。
- 让基线更干净，便于横向对比。

### 第三步：怀疑 reader 成了瓶颈，继续拆前端

这就是 `mark3`：

- 不满足于单 reader。
- 于是把前端拆成 preprocess + dispatch 两层。
- 再通过多个 dispatcher 并发投递，观察前端瓶颈是否缓解。

### 第四步：需要一个最朴素、最好解释的对照组

这就是 `mark4`：

- 不谈复杂并行。
- 先把识别流程完整跑通。
- 把统计与 CSV 输出做好。
- 方便校验协议识别结果和延迟统计逻辑。

---

## 6. 最值得记住的差异总结

如果你后面要继续读代码，我建议把它们记成下面四句话：

- `mark1`：多线程实验总盘，重点是“同一主干下切不同策略做 benchmark”。
- `mark2`：标准 reader-worker 基线，重点是“稳定、干净、易对照”。
- `mark3`：多 dispatcher 前端流水线，重点是“把分发层也并行化”。
- `mark4`：单线程对照与结果分析版，重点是“路径最短、输出最完整”。

再压缩成一个判断标准：

- 想研究实验变体：看 `mark1`
- 想研究标准多线程基线：看 `mark2`
- 想研究前端分发并行化：看 `mark3`
- 想研究单线程检测与结果输出：看 `mark4`

---

## 7. 本次分析对应的源码依据

主要依据这些目录和文件：

- `mark1/README.md`
- `mark1/CMakeLists.txt`
- `mark1/include/ndpi_benchmark.h`
- `mark1/include/benchmark_internal.h`
- `mark1/src/main.c`
- `mark1/src/reader.c`
- `mark1/src/rss_table.c`
- `mark1/src/worker.c`
- `mark1/src/flow_table.c`
- `mark1/src/packet_parser.c`
- `mark2/README.md`
- `mark2/CMakeLists.txt`
- `mark2/include/ndpi_benchmark.h`
- `mark2/include/benchmark_internal.h`
- `mark2/src/main.c`
- `mark2/src/reader.c`
- `mark2/src/rss_table.c`
- `mark2/src/worker.c`
- `mark3/README.md`
- `mark3/CMakeLists.txt`
- `mark3/include/ndpi_benchmark.h`
- `mark3/include/benchmark_internal.h`
- `mark3/src/main.c`
- `mark3/src/reader.c`
- `mark3/src/rss_table.c`
- `mark3/src/worker.c`
- `mark4/README.md`
- `mark4/CMakeLists.txt`
- `mark4/include/ndpi_benchmark.h`
- `mark4/include/benchmark_internal.h`
- `mark4/src/main.c`
- `mark4/src/packet_parser.c`
- `mark4/src/flow_table.c`

