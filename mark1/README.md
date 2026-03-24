# mark1: 执行流程与代码对应（详细版）

## 1. 总体架构（代码真实执行模型）

`mark1` 的运行模型是：

1. `main` 线程做初始化与收尾
2. 1 个 `reader` 线程负责离线读 PCAP + 分流
3. `N` 个 `worker` 线程负责协议解析和 nDPI 检测

核心数据路径：

`pcap -> reader(normalize/hash/rss) -> worker queue -> worker(parse/flow/nDPI) -> 汇总`

关键文件与职责：

- `src/main.c`：生命周期编排、线程创建/join、最终指标汇总
- `src/reader.c`：读包、标准化、计算 flow key hash、选择 worker、入队
- `src/rss_table.c`：`flow -> worker` 粘性映射
- `src/worker.c`：单包处理主路径（parse -> flow -> nDPI -> proto 检查）
- `src/flow_table.c`：每个 worker 私有 `flow_key -> bench_flow_t`
- `src/packet_parser.c`：链路层标准化、L3/L4 解析、flow key 构造
- `src/benchmark_common.c`：线程绑核、样本打印、共享全局

## 2. 启动阶段（main）

对应代码：`src/main.c`

### 2.1 参数解析

- `parse_args()`
  - 解析 `-i/-n/-c/-r/-p/-q`
  - 构造 `benchmark_config_t`
  - `-c` 会填充 worker core list；未传时默认 `0..n-1`

### 2.2 初始化 nDPI 全局上下文

- `ndpi_global_init()`
  - 返回进程级 `g_ctx`
  - 后续每个 worker 的 ndpi module 都由它创建

### 2.3 创建 worker 上下文与队列

- `workers = calloc(...)`
- 为每个 worker 设置：
  - `worker_id/cpu_core/proto_file/g_ctx`
  - `queue = packet_queue_create(QUEUE_CAPACITY)`
  - （可选）`classified_table_create(...)`，由编译宏启用

### 2.4 初始化每个 worker 的 nDPI 模块

- `init_worker_ndpi(&workers[i])`（`src/worker.c`）
  - `ndpi_init_detection_module(g_ctx)`
  - `ndpi_set_config(..., "tcp_ack_payload_heuristic", "enable")`
  - 可选加载 `proto file`
  - `ndpi_finalize_initialization(...)`
  - `flow_table_create(16384)`

### 2.5 创建 reader 侧 RSS 表

- `rss = rss_table_create(RSS_TABLE_INIT_CAP)`
  - 保存 `flow -> worker` 粘性路由

### 2.6 启动线程与计时

- 先 `pthread_create(worker_thread_entry)`
- 后 `pthread_create(reader_thread_entry)`
- 记录 `rdtsc + get_time_ns` 作为总时钟

## 3. Reader 阶段（读包/分流/入队）

对应代码：`src/reader.c`

入口：

- `reader_thread_entry()`
  - 根据编译宏进入：
    - `reader_thread_stream()`（默认）
    - `reader_thread_mem()`（`NDPI_BENCHMARK_MEMREADER`）

### 3.1 通用计时初始化

- `reset_reader_timers(ctx)`
- 结束时 `finalize_reader_timers(ctx)`

### 3.2 流式读包主循环（默认）

函数：`reader_thread_stream()`

每轮循环执行：

1. `pcap_next_ex` 取包（统计 `pcap_read_ns`）
2. `normalize_to_ethernet(...)` 做链路层标准化
3. `compute_flow_hash(...)` 得到 `h1`
4. `h2 = rss_mix32(h1 ^ const)`，再拼接 `key`
5. `rss_table_lookup_or_assign(...)` 决定目标 worker
6. `packet_queue_push(...)` 入对应 worker 队列
7. 累加分项计时：
   - `hash_ns/rss_lookup_ns/enqueue_ns/read_other_ns`

### 3.3 MEM 版本（可选）

函数：`reader_thread_mem()`

额外步骤：

1. `read_file_to_memory()` 把 PCAP 全读内存
2. `fmemopen + pcap_fopen_offline` 从内存读包
3. 后续逻辑与 stream 版本一致

### 3.4 结束信号

- reader 结束后对每个 worker 调用 `packet_queue_finish()`
- worker 看到队列 finished 且耗尽后退出

## 4. RSS 映射阶段（flow -> worker）

对应代码：`src/rss_table.c`

关键函数：

- `rss_table_lookup_or_assign(...)`
  - 命中已有 key：返回原 worker（保持粘性）
  - 超过 `RSS_FLOW_TIMEOUT_MS` 可重选 worker
  - 未命中：按 `rss_select_worker(...)` 选 worker 并插入

- `rss_select_worker(...)`
  - 默认 `power-of-two choices`：候选 `w0/w1`，选队列更浅
  - 编译宏可切到单哈希或 aggressive LB

## 5. Worker 阶段（核心处理）

对应代码：`src/worker.c`

线程入口：

- `worker_thread_entry()`
  - `packet_queue_peek -> worker_process_packet -> packet_queue_consume`
  - 持续直到队列完成

单包主路径函数：

- `worker_process_packet(w, pkt)`

执行顺序：

1. `parse_ethernet_frame(...)`
2. `flow_key_from_packet(...)`
3. `flow_table_get_or_create(...)`
4. 新流初始化：
   - `ndpi_calloc(ndpi_flow_struct)`
   - `set_ndpi_flow_tuple(...)`
5. 更新流方向统计（c2s/s2c 包数字节）
6. 调 `ndpi_detection_process_packet(...)`
7. 首次命中协议时：
   - `ndpi_get_flow_appprotocol(...)`
   - `flow->protocol_counted = true`
   - `flows_with_protocol_total++`
   - `maybe_print_flow_sample(...)`

计时切片字段：

- parse、keybuild、flow_lookup、flow_init、ndpi_call、proto_check、other

## 6. Flow 状态阶段（worker 私有）

对应代码：`src/flow_table.c`

核心：

- `flow_table_get_or_create(...)`：开放寻址 + 线性探测
- `flow_key_hash(...)`：FNV-1a
- `flow_table_rehash(...)`：负载升高时扩容
- `flow_table_destroy(..., free_flow_cb, ...)`：释放时回调清理 ndpi flow

## 7. 汇总与输出阶段

对应代码：`src/main.c::print_benchmark_results(...)`

口径说明（代码逻辑）：

- 包数/字节/分项耗时：跨 worker 求和
- `Process Time`：取最慢 worker 的 wall time
- 输出：
  - Elapsed/Read/Process 分项
  - Throughput/Bandwidth/CPP
  - 协议命中流占比
  - 每 worker 统计与 scaling efficiency

## 8. mark1 的可执行变体（来自 CMake）

`mark1/CMakeLists.txt` 里实际构建多个目标：

- `ndpiBenchmark`：基线
- `ndpiBenchmarkClassified`：启用 `NDPI_BENCHMARK_CLASSIFIED`
- `ndpiBenchmarkBatch`：启用 `NDPI_BENCHMARK_BATCH`
- `ndpiBenchmarkMem`：启用 `NDPI_BENCHMARK_MEMREADER`

也就是：同一套代码，通过编译宏切不同执行路径。
