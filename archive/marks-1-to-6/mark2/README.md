# mark2: 执行流程与代码对应（详细版）

## 1. mark2 的定位

`mark2` 的代码执行模型与 `mark1` 主路径一致，但在构建层面只保留一个目标：

- 仅构建：`ndpiBenchmarkMark2`
- 不再在 CMake 中暴露 classified/batch/mem 等变体目标

因此它可以视为“单基线版本”。

## 2. 代码主干结构

- `src/main.c`：生命周期编排、线程启动与结果汇总
- `src/reader.c`：读包 -> 标准化 -> hash -> rss -> 入队
- `src/rss_table.c`：`flow -> worker` 粘性映射与重分配
- `src/worker.c`：单包处理（parse/flow/nDPI）
- `src/flow_table.c`：worker 私有流表
- `src/packet_parser.c`：包标准化与协议头解析
- `src/benchmark_common.c`：绑核与公共工具

## 3. main 执行阶段（按函数）

对应：`src/main.c`

### 阶段 A：参数解析

- `parse_args()`
  - 必填 `-i`
  - 解析 `-n/-c/-r/-p/-q`
  - 组装 `benchmark_config_t`

### 阶段 B：全局资源初始化

1. `ndpi_global_init()`
2. 分配 `worker_context_t[]`
3. 对每个 worker：
   - 创建 `packet_queue_create(...)`
   - `init_worker_ndpi(...)`（在 `src/worker.c`）
4. 创建 `rss_table_create(...)`

### 阶段 C：线程拉起

1. 先起全部 worker：`pthread_create(worker_thread_entry)`
2. 再起 reader：`pthread_create(reader_thread_entry)`
3. 使用 `rdtsc` + `get_time_ns` 记录运行总时长

### 阶段 D：收尾

1. `pthread_join(reader)`
2. `pthread_join(all workers)`
3. `print_benchmark_results(...)`
4. 释放 `rss/workers/g_ctx/core_list`

## 4. reader 执行阶段

对应：`src/reader.c`

入口：`reader_thread_entry()`

- 默认进 `reader_thread_stream()`
- 若定义 `NDPI_BENCHMARK_MEMREADER` 才进 `reader_thread_mem()`

基线（mark2 默认）是 stream 路径。

### stream 主循环细节

函数：`reader_thread_stream()`

每个包：

1. `pcap_next_ex()` 取包
2. `normalize_to_ethernet(...)`
3. `compute_flow_hash(...)` 计算 `h1`
4. `h2 = rss_mix32(...)`，拼 `flow key`
5. `rss_table_lookup_or_assign(...)` 选 worker
6. `packet_queue_push(...)` 投递到 worker 队列

结束时：

- 对每个 worker 调 `packet_queue_finish(...)` 作为结束信号
- `finalize_reader_timers(...)`

## 5. RSS 映射逻辑

对应：`src/rss_table.c`

关键函数：

- `rss_table_lookup_or_assign(...)`
  - 命中：返回历史 worker，保持流粘性
  - 超时（`RSS_FLOW_TIMEOUT_MS`）可重选 worker
  - 未命中：调用 `rss_select_worker(...)` 分配

- `rss_select_worker(...)`
  - 默认 `power-of-two choices`
  - 候选 `w0 = h1 % N`, `w1 = h2 % N`
  - 选队列更浅的一边

## 6. worker 执行阶段（核心）

对应：`src/worker.c`

入口：`worker_thread_entry()`

- 循环 `packet_queue_peek -> worker_process_packet -> packet_queue_consume`

单包主函数：`worker_process_packet()`

按顺序：

1. `parse_ethernet_frame(...)`
2. `flow_key_from_packet(...)`
3. `flow_table_get_or_create(...)`
4. 新流时：
   - `ndpi_calloc(ndpi_flow_struct)`
   - `set_ndpi_flow_tuple(...)`
5. 更新 c2s/s2c 统计和 `last_seen_ms`
6. `ndpi_detection_process_packet(...)`
7. `ndpi_get_flow_appprotocol(...)` 检查首次命中并计数

## 7. flow_table 阶段

对应：`src/flow_table.c`

- `flow_table_get_or_create(...)` 是热点路径
- 开放寻址 + 线性探测
- `flow_table_rehash(...)` 扩容
- `flow_table_destroy(..., free_flow_cb, ...)` 释放 nDPI flow

## 8. 输出指标对应

对应：`src/main.c::print_benchmark_results()`

输出分层：

1. Read 路径：
   - `pcap_next_ex/hash/rss_lookup/enqueue/other`
2. Process 路径：
   - `parse/flowkey_lookup/flow_init/flow/ndpi_call/proto_check/other`
3. 全局：
   - Throughput/Bandwidth/CPP
   - 检测命中流占比
   - 每 worker 统计

特别口径：

- `Process Time` 取最慢 worker（wall 主导）
- 其余分项多为跨 worker 求和
