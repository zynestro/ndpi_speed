# mark3: 执行流程与代码对应（详细版）

## 1. mark3 与 mark2 的关键差异

`mark3` 的核心变化不是 worker 处理逻辑，而是“读包与分发”前移成两段：

1. **预处理阶段（单线程 reader 控制器）**
   - 整个 PCAP 先读入内存结构 `dispatch_packet_t[]`
   - 先建立 `flow -> dispatcher` 粘性映射
   - 再生成每个 dispatcher 的索引区间（schedule）

2. **运行阶段（多 dispatcher 并发）**
   - 每个 dispatcher 只遍历自己的索引区间
   - 再通过共享 `flow -> worker` 映射把包投递到 worker 队列

worker 侧的 `parse/flow/nDPI` 主路径基本沿用 mark2。

## 2. 关键文件

- `src/main.c`：参数、线程编排、计时汇总
- `src/reader.c`：预处理 + dispatcher 线程逻辑（mark3 重点）
- `src/rss_table.c`：线程安全的 RSS 表（含锁），支持两类映射
- `src/worker.c`：worker 包处理主路径
- `src/flow_table.c`：worker 私有流表

## 3. main 生命周期（代码顺序）

对应：`src/main.c`

### 3.1 参数解析

- `parse_args()`
  - worker 参数：`-n/-c`
  - dispatcher 参数：`-d`
  - 输入与选项：`-i/-p/-q`
  - `-d` 通过 `parse_dispatcher_core_list()` 解析为 dispatcher core 数组

### 3.2 初始化

1. `ndpi_global_init()`
2. 分配并初始化 `worker_context_t[]`
3. 每个 worker：
   - `packet_queue_create(...)`
   - `init_worker_ndpi(...)`
4. 创建共享 `rss_table_create(...)`（用于运行期 `flow -> worker`）

### 3.3 启动线程

1. 启动所有 worker：`worker_thread_entry`
2. 启动 reader 控制线程：`reader_thread_entry`
3. 计时：`rdtsc + get_time_ns`

### 3.4 结束与汇总

1. `pthread_join(reader)`
2. `pthread_join(all workers)`
3. `print_benchmark_results(...)`
   - 输出 `Preprocess` 与 `Dispatch(Read)` 两段耗时
4. 回收 `rss/workers/g_ctx/core_list/dispatcher_core_list`

## 4. reader 控制线程（mark3 核心）

对应：`src/reader.c::reader_thread_entry()`

它不是直接逐包入队，而是：

### 阶段 A：预处理加载

函数：`load_pcap_packets(ctx, &packets, &count)`

每包流程：

1. `pcap_next_ex` 取包
2. `normalize_to_ethernet`
3. `compute_flow_hash` 得到 `flow_key`
4. `rss_table_lookup_or_assign_target(...)`
   - 在 `dispatcher_map` 上做 `flow -> dispatcher` 粘性分配
5. `append_packet(...)`
   - 复制到 `dispatch_packet_t[]`
   - 保存 `flow_key/dispatcher_id/timestamp/data`

### 阶段 B：构建调度索引

函数：`build_dispatch_schedule(...)`

输出两组关键数组：

- `dispatcher_offsets[d]`
- `dispatcher_indices[pos]`

使得每个 dispatcher 可以只处理属于自己的连续索引区间。

### 阶段 C：启动多个 dispatcher 线程

为每个 dispatcher 创建 `dispatcher_thread_entry(...)`。

### 阶段 D：结束处理

1. join 所有 dispatcher
2. 对每个 worker `packet_queue_finish(...)`
3. `cleanup_preloaded_packets(...)`
4. `finalize_reader_timers(...)`

## 5. dispatcher 线程执行路径

对应：`src/reader.c::dispatcher_thread_entry()`

每个 dispatcher 只遍历 `[offset[d], offset[d+1])`：

1. 根据 `dispatcher_indices[pos]` 取真实包
2. 用共享 RSS 表做 `flow -> worker`：
   - `rss_table_lookup_or_assign(ctx->rss, ctx, flow_key, ts_ms)`
3. `packet_queue_push(...)` 投递到目标 worker 队列
4. 累加本 dispatcher 的 `rss_lookup/enqueue/other`
5. 调 `merge_dispatcher_stats(...)` 汇总到 reader context（带锁）

## 6. RSS 表在 mark3 的双层用途

对应：`src/rss_table.c`

### 6.1 `flow -> dispatcher`（预处理阶段）

- 函数：`rss_table_lookup_or_assign_target(...)`
- 选择策略：`rss_select_worker_random(...)`
- 用独立 `dispatcher_map` 表

### 6.2 `flow -> worker`（运行阶段）

- 函数：`rss_table_lookup_or_assign(...)`
- 选择策略：`rss_select_worker_p2c(...)`（两候选队列深度）
- 使用共享 `ctx->rss`

### 6.3 线程安全

- `struct rss_table` 内部有 `pthread_mutex_t lock`
- `lookup_or_assign*` 全程持锁
- 因为 mark3 有多个 dispatcher 并发访问同一映射表

## 7. worker 处理路径

对应：`src/worker.c`

入口与 mark2 一致：

- `worker_thread_entry()`：
  - `peek -> worker_process_packet -> consume`

`worker_process_packet()` 仍是：

1. `parse_ethernet_frame`
2. `flow_key_from_packet`
3. `flow_table_get_or_create`
4. 新流初始化 `ndpi_flow`
5. `ndpi_detection_process_packet`
6. `ndpi_get_flow_appprotocol` 首次命中计数

## 8. 结果输出口径（main）

对应：`src/main.c::print_benchmark_results()`

mark3 特有输出分层：

1. `Preprocess Time`
   - pcap_read / normalize / hash / flow->dispatcher map / packet_store / schedule_build
2. `Dispatch(Read) Time`
   - flow->worker map / enqueue / other
3. `Process Time`（最慢 worker）
4. `Elapsed Time (No Preprocess)`
   - 用于更接近运行期吞吐

## 9. 线程模型总结

`main`
-> `reader_controller`（做预处理 + 拉起 dispatchers）
-> `dispatchers[0..D-1]`（分发）
-> `workers[0..N-1]`（处理）

这是 mark3 相对 mark2 的本质结构变化。
