# mark3 / mark4 代码运行全梳理

本文面向“讲解代码怎么跑起来”。重点是：入口、线程/数据路径、关键数据结构、关键实现点、两者差异。

## 1. 先给结论

- `mark3` 是“多 worker + 多 dispatcher + 软件 RSS + 队列解耦”的并发流水线。
- `mark4` 是“单线程直读 pcap + 直接做 flow/nDPI + 末尾统计聚合”的极简链路。
- 两者都依赖同一套核心：`parse_ethernet_frame -> flow_key_from_packet -> flow_table_get_or_create -> ndpi_detection_process_packet`。

---

## 2. 代码地图（你讲解时先展示这个）

### mark3

- 构建入口：`mark3/CMakeLists.txt`
- 程序入口与生命周期：`mark3/src/main.c:281`
- reader + dispatcher：`mark3/src/reader.c:343`
- worker 处理主路径：`mark3/src/worker.c:128`
- 软件 RSS：`mark3/src/rss_table.c:121`
- flow 状态表：`mark3/src/flow_table.c:173`
- 解析/流键：`mark3/src/packet_parser.c:171`, `mark3/src/packet_parser.c:297`
- 队列和核心结构定义：`mark3/include/ndpi_benchmark.h:40`, `mark3/include/benchmark_internal.h:26`

### mark4

- 构建入口：`mark4/CMakeLists.txt`
- 程序入口与主循环：`mark4/src/main.c:358`, `mark4/src/main.c:438`
- flow 状态表：`mark4/src/flow_table.c:183`
- 解析/流键：`mark4/src/packet_parser.c:231`, `mark4/src/packet_parser.c:357`
- 核心结构定义：`mark4/include/ndpi_benchmark.h:17`, `mark4/include/ndpi_benchmark.h:50`

---

## 2.1 最小可运行命令（从源码到跑起来）

### mark3

```bash
cd mark3
cmake -S . -B build -DNDPI_PREFIX=$HOME/ndpi-install
cmake --build build -j
./build/ndpiBenchmarkMark3 -i ../Monday-WorkingHours.pcap -n 4 -c 2,3,4,5 -d 0,1
```

### mark4

```bash
cd mark4
cmake -S . -B build -DNDPI_PREFIX=$HOME/ndpi-install
cmake --build build -j
./build/ndpiBenchmarkMark4 -i ../Monday-WorkingHours.pcap -q
```

---

## 3. mark3 是怎么跑起来的

## 3.1 启动阶段（main）

1. 解析参数：`mark3/src/main.c:198`
- `-i` pcap 文件
- `-n` worker 数量
- `-c` worker core 列表
- `-d` dispatcher core 列表

2. 初始化 nDPI 全局上下文：`mark3/src/main.c:289`

3. 创建每个 worker：`mark3/src/main.c:304`
- 分配队列 `packet_queue_create`：`mark3/src/main.c:310`
- 初始化每 worker 的 ndpi module + flow table：`mark3/src/main.c:335`, `mark3/src/worker.c:14`

4. 创建全局 flow->worker RSS 映射：`mark3/src/main.c:339`

5. 启动线程：
- 先起所有 worker：`mark3/src/main.c:358`
- 再起 reader 控制线程：`mark3/src/main.c:396`

6. 等待结束、汇总统计：`mark3/src/main.c:401`, `mark3/src/main.c:413`

## 3.2 reader 的两阶段设计（mark3 核心）

入口：`mark3/src/reader.c:343`

### 阶段 A：预处理（load + schedule）

在 `load_pcap_packets` 中逐包做：`mark3/src/reader.c:138`

1. `pcap_next_ex` 读取：`mark3/src/reader.c:168`
2. 链路层标准化到 Ethernet：`mark3/src/reader.c:193`
3. 快速 flow hash：`mark3/src/reader.c:210`
4. 先做 `flow->dispatcher` 的 RSS 分配：`mark3/src/reader.c:220`
5. 把包拷贝到预加载数组 `dispatch_packet_t`：`mark3/src/reader.c:230`

然后 `build_dispatch_schedule` 构建每个 dispatcher 的连续任务区间：`mark3/src/reader.c:78`
- `dispatcher_offsets[d]..offsets[d+1]` 是 dispatcher d 的包范围。

### 阶段 B：并发 dispatcher 分发

`reader_thread_entry` 会创建 `num_dispatchers` 个 dispatcher 线程：`mark3/src/reader.c:383`

每个 dispatcher 对自己的区间循环：`mark3/src/reader.c:291`

1. 用全局 RSS 表做 `flow->worker` 绑定：`mark3/src/reader.c:299`
2. 入对应 worker 队列：`mark3/src/reader.c:317`

最后 reader 给所有 worker 队列打 `finished`：`mark3/src/reader.c:406`

## 3.3 worker 单包处理链路

入口：`mark3/src/worker.c:306`

循环模型：`peek -> process -> consume`：`mark3/src/worker.c:312`

`worker_process_packet`（核心）：`mark3/src/worker.c:128`

1. 解析包：`parse_ethernet_frame`，失败则丢弃但计时：`mark3/src/worker.c:134`
2. 构造 canonical flow key：`mark3/src/worker.c:150`
3. flow table 查找/创建：`mark3/src/worker.c:183`
4. 新流初始化 nDPI flow：`mark3/src/worker.c:206`
5. 调 `ndpi_detection_process_packet` 做增量识别：`mark3/src/worker.c:242`
6. 首次识别成功（UNKNOWN->known）时计数：`mark3/src/worker.c:258`

可选分支（编译宏）：`NDPI_BENCHMARK_CLASSIFIED`，命中快路径可绕过重复 nDPI：`mark3/src/worker.c:157`

## 3.4 mark3 关键数据结构（讲解重点）

1. `packet_queue_t`（MPSC 环形队列）
- 定义：`mark3/include/ndpi_benchmark.h:53`
- 特点：
  - `head/tail` 原子计数
  - `prod_lock` 保护多生产者入队
  - `finished` 控制消费者退出

2. `reader_context_t`
- 定义：`mark3/include/benchmark_internal.h:26`
- 保存：worker 数组、dispatcher 映射数组、全套分段计时。

3. `dispatch_packet_t`
- 定义：`mark3/src/reader.c:5`
- 注意：`PREPROCESS_PACKET_SIZE=1400`（`mark3/src/reader.c:3`），预处理阶段会截断大包 `caplen` 到 1400。

4. `rss_table`
- 定义：`mark3/src/rss_table.c:18`
- 两个 API：
  - `lookup_or_assign_target`：预处理阶段做 flow->dispatcher：`mark3/src/rss_table.c:177`
  - `lookup_or_assign`：分发阶段做 flow->worker（P2C 选轻载队列）：`mark3/src/rss_table.c:121`, `mark3/src/rss_table.c:107`

5. `flow_table`
- 定义：`mark3/src/flow_table.c:17`
- 开放寻址 + tombstone + 线性探测：`mark3/src/flow_table.c:173`

6. `worker_context_t`
- 定义：`mark3/include/ndpi_benchmark.h:261`
- 重点字段：
  - `ndpi`：每 worker 独立
  - `flows`：每 worker 私有 flow 表
  - `queue`：输入队列
  - 分阶段 timing 和统计计数器

---

## 4. mark4 是怎么跑起来的

## 4.1 启动与初始化

入口：`mark4/src/main.c:358`

1. 解析参数：`mark4/src/main.c:77`
- `-i` pcap
- `-c` 可绑核
- `-o` 输出目录
- `-q` 静默 per-flow 输出

2. 创建输出目录（按时间戳）：`mark4/src/main.c:364`

3. 初始化 nDPI + flow table：`mark4/src/main.c:383`, `mark4/src/main.c:402`

4. 打开 pcap，进入单线程 while 主循环：`mark4/src/main.c:411`, `mark4/src/main.c:438`

## 4.2 单线程主循环

每包处理：

1. `pcap_next_ex`：`mark4/src/main.c:440`
2. `normalize_to_ethernet`：`mark4/src/main.c:455`
3. `parse_ethernet_frame`：`mark4/src/main.c:472`
4. `flow_key_from_packet + flow_table_get_or_create`：`mark4/src/main.c:483`, `mark4/src/main.c:488`
5. 新流时初始化 `ndpi_flow`：`mark4/src/main.c:498`
6. 调 `ndpi_detection_process_packet`：`mark4/src/main.c:532`
7. 首次识别时记录检测信息：
- 协议 ID：`mark4/src/main.c:544`
- category：`mark4/src/main.c:546`
- 检测时延：`mark4/src/main.c:549`

## 4.3 运行结束后的统计输出

- 总体包/流统计：`mark4/src/main.c:575`
- 可选 per-flow 明细：`mark4/src/main.c:589`
- 按 category 聚合：`mark4/src/main.c:597`
- 按 proto+category 聚合并排序：`mark4/src/main.c:621`
- 写 CSV：`mark4/src/main.c:656`

## 4.4 mark4 关键数据结构

1. `bench_flow_t`（比 mark3 多检测延迟字段）
- 定义：`mark4/include/ndpi_benchmark.h:50`
- 额外字段：
  - `first_seen_ns`
  - `detection_latency_ns`
  - `detection_packet_in_flow`
  - `detection_packet_global`
  - `detected_master_proto/app_proto/category`

2. `flow_table`
- 与 mark3 同类实现：`mark4/src/flow_table.c:23`
- 提供 `flow_table_foreach` 给末尾聚合：`mark4/src/flow_table.c:235`

3. `packet_parser`
- 比 mark3 多支持 `DLT_LINUX_SLL/SLL2`：`mark4/src/packet_parser.c:102`, `mark4/src/packet_parser.c:124`

---

## 5. mark3 vs mark4 实现差异（讲解时最关键）

1. 并发模型
- mark3：reader + dispatchers + workers（多线程）
- mark4：单线程

2. 数据通路
- mark3：`pcap -> preload数组 -> dispatcher -> worker队列 -> nDPI`
- mark4：`pcap -> parse/flow/nDPI`（一步到位）

3. 负载均衡
- mark3：软件 RSS + P2C（看队列深度）`mark3/src/rss_table.c:107`
- mark4：无调度层

4. 统计侧重点
- mark3：重 pipeline 各阶段细分 timing（preprocess/dispatch/process）
- mark4：重检测结果聚合与检测时延 CSV

5. 功能侧重点
- mark3：吞吐与并发扩展实验
- mark4：基线准确性 + 检测延迟分析

---

## 6. 你讲解时可直接用的“运行顺序脚本”

### mark3

1. `main` 建 worker / RSS / 线程。  
2. reader 先把 pcap 预处理成 `dispatch_packet_t[]` 并算好 dispatcher 任务区间。  
3. 多 dispatcher 并发把包投递到 worker 队列（flow 粘到同一 worker）。  
4. worker 做 parse -> flow 状态 -> nDPI 增量识别。  
5. reader 发 `finished`，worker 退出，主线程汇总 timing + 吞吐。

### mark4

1. `main` 初始化 nDPI + flow table。  
2. 单线程循环读包并直接 parse/flow/nDPI。  
3. 首次识别即记录检测时延与包序号。  
4. 结束后遍历 flow table 做 category/proto 聚合并输出 CSV。

---

## 7. 一个你讲的时候可以强调的设计点

- mark3 的“分流 key”与“真实 flow key”是两层：
  - 分流 key：`compute_flow_hash`（快）`mark3/src/packet_parser.c:342`
  - 真实 flow key：`flow_key_from_packet + flow_key_hash`（准）`mark3/src/packet_parser.c:297`, `mark3/src/flow_table.c:36`
- 这让调度阶段更轻，同时状态一致性仍由 worker 的 canonical flow key 保证。
