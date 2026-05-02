# mark7 代码运行流程交付验收文档

## 1. 文档目的

本文档用于验收当前 `mark7` benchmark 的端到端运行流程，重点确认：

- 程序如何从命令行配置启动；
- pcap 如何预处理为内存包；
- dispatcher 如何把 flow 粘性分配到 worker；
- worker 如何维护私有 flow 状态并调用 nDPI；
- 优化后的 dispatch / enqueue 路径是否符合当前设计；
- 最终输出的时间、吞吐、P/E 核分布统计分别来自哪里。

本文档中的每个阶段都包含“核心代码核实点”，用于代码审查时快速定位实现。

## 2. 当前交付范围

### 2.1 交付目标

`mark7` 是一个离线 pcap 回放 benchmark：

1. 读取 pcap 文件；
2. 预处理为固定上限的内存包；
3. 按 flow hash 将包分配给 dispatcher；
4. dispatcher 按 cost-aware JSW 策略选择 worker；
5. worker 私有执行 parse / flow table / nDPI；
6. 汇总 preprocess / dispatch / process / per-worker / P/E 核统计。

### 2.2 构建目标

当前 CMake 生成两个可执行文件：

- `ndpiBenchmarkMark7`：默认 cost-aware-jsw 策略；
- `ndpiBenchmarkMark7Hash`：`MARK7_DISPATCH_HASH_ONLY=1` 的 hash-only 对照策略。

核心代码核实：

- 构建源文件列表：`mark7/CMakeLists.txt:43-60`
- 默认优化构建：`mark7/CMakeLists.txt:15-19`
- mark7 热路径编译开关：`mark7/CMakeLists.txt:70-74`
- 两个 target：`mark7/CMakeLists.txt:88-97`

验收点：

- `cmake --build mark7/build -j` 能同时构建两个 target；
- Release 模式使用 `-O3`；
- `NDPI_BENCHMARK_BATCH=1`、`QUEUE_PACKET_USE_REF=1` 已启用，说明当前交付版使用批量入队和队列引用传包。

## 3. 运行主流程总览

当前运行主线：

```text
main()
  -> parse_args()
  -> ndpi_global_init()
  -> cost_table_load()
  -> cost_profile_load_csv()
  -> alloc_worker_runtime_states()
  -> create worker_context_t + packet_queue_t
  -> init_worker_ndpi()
  -> dispatch_context_create()
  -> pthread_create(worker_thread_entry)
  -> pthread_create(reader_thread_entry)
      -> load_pcap_packets()
      -> build_dispatch_schedule()
      -> pthread_create(dispatcher_thread_entry)
          -> dispatch_lookup_or_assign()
          -> packet_queue_push_batch()
      -> packet_queue_finish()
  -> pthread_join(reader)
  -> pthread_join(workers)
  -> print_benchmark_results()
  -> print_dispatch_summary()
  -> cleanup
```

核心代码核实：

- benchmark 主入口：`mark7/src/main.c:523-760`
- worker 线程启动：`mark7/src/main.c:653-658`
- reader 线程启动与 join：`mark7/src/main.c:697-705`
- reader 主控流程：`mark7/src/reader.c:528-614`
- dispatcher 线程入口：`mark7/src/reader.c:415-526`
- worker 线程入口：`mark7/src/worker.c:384-409`

验收点：

- worker 先启动，等待队列数据；
- reader 再启动，负责预处理和启动 dispatcher；
- reader 完成所有 dispatcher 后标记 worker 队列结束；
- main 等 reader 和所有 worker 都退出后再释放预加载包，保证 `QUEUE_PACKET_USE_REF=1` 的指针生命周期正确。

## 4. 阶段 0：参数解析与默认拓扑

### 4.1 行为说明

程序从命令行读取：

- `-i`：pcap 文件；
- `-n`：worker 数量；
- `-c`：worker core list；
- `-d`：dispatcher core list；
- `-m`：lookup table；
- `-C`：cost profile；
- `-p`：协议配置；
- `-q`：静默模式。

默认拓扑：

- worker 数量：16；
- dispatcher 数量：8；
- worker core：`0,2,4,6,8,10,12,14,24,25,26,27,28,29,30,31`；
- dispatcher core：`16-23`。

### 4.2 核心代码核实

- 默认常量：`mark7/src/main.c:13-19`
- 策略名称宏：`mark7/src/main.c:21-25`
- 参数解析入口：`mark7/src/main.c:421-520`
- 默认 worker core list：`mark7/src/main.c:358-370`
- dispatcher 默认 core list：`mark7/src/main.c:511-518`

### 4.3 验收点

- 不传 `-c` 且 `-n=16` 时，worker 自动使用 8 个 P 核 + 8 个 E 核；
- 不传 `-d` 时，dispatcher 自动使用 core 16-23；
- `MARK7_DISPATCH_HASH_ONLY` target 输出策略名为 `hash-only`，否则为 `cost-aware-jsw`。

## 5. 阶段 1：全局 nDPI、cost table、runtime state 初始化

### 5.1 行为说明

主线程先初始化 nDPI 全局上下文，再加载调度使用的 lookup table 与 P/E cost profile。随后为每个 worker 创建运行态 `worker_runtime_state_t`，记录 core id、core type、pending cost、queue depth 等调度观察字段。

### 5.2 核心代码核实

- nDPI 全局初始化：`mark7/src/main.c:533-539`
- lookup table 加载：`mark7/src/main.c:541-547`
- cost profile 加载：`mark7/src/main.c:549-556`
- worker runtime state 分配：`mark7/src/main.c:372-389`
- core type 判定：`mark7/src/dispatch.c:46-53`
- runtime state 字段定义：`mark7/include/ndpi_benchmark.h:409-419`

### 5.3 验收点

- `core_id < 16` 被判定为 P 核，否则为 E 核；
- 每个 worker 的 `added_cost_x1000`、`retired_cost_x1000`、`queue_depth` 初始化为 0；
- cost-aware 调度使用 cost profile 中 P/E + bucket 的成本值。

## 6. 阶段 2：worker 上下文、队列、nDPI 私有实例创建

### 6.1 行为说明

每个 worker 拥有：

- 独立 `worker_context_t`；
- 独立 `packet_queue_t`；
- 独立 nDPI detection module；
- 独立 worker 私有 flow table。

这样 worker 处理路径不共享 nDPI flow 状态，避免 nDPI 热路径锁竞争。

### 6.2 核心代码核实

- worker 数组创建：`mark7/src/main.c:573-580`
- worker 字段填充：`mark7/src/main.c:581-586`
- worker 队列创建：`mark7/src/main.c:588-600`
- worker nDPI 初始化调用：`mark7/src/main.c:618-620`
- `init_worker_ndpi()`：`mark7/src/worker.c:70-93`
- 队列结构定义：`mark7/include/ndpi_benchmark.h:56-77`
- 队列创建：`mark7/include/ndpi_benchmark.h:112-130`

### 6.3 验收点

- 每个 worker 都有独立 `ndpi`；
- 每个 worker 都有独立 `flows`；
- 每个 worker 队列容量是 `QUEUE_CAPACITY`，当前为 4096；
- 当前 mark7 队列使用 reference 模式：`queue_packet_t.data` 指向预加载包数据，不再在 enqueue 阶段复制 payload。

## 7. 阶段 3：dispatch context 创建与当前优化结构

### 7.1 行为说明

当前 dispatch 表已经从“全局单表”改为“按 dispatcher 分片”：

- `dispatch_context_t` 持有 `dispatch_shard_t *shards`；
- shard 数量等于 dispatcher 数量；
- 预处理阶段已经按 `flow_hash % num_dispatchers` 固定 dispatcher；
- 因此同一 flow 只会进入一个 dispatcher / shard；
- dispatcher 热路径不再需要全局 dispatch mutex。

### 7.2 核心代码核实

- main 创建 dispatch context：`mark7/src/main.c:623-625`
- dispatch context 结构：`mark7/src/dispatch.c:27-37`
- shard 结构：`mark7/src/dispatch.c:16-25`
- shard 分配与初始化：`mark7/src/dispatch.c:162-196`
- lookup 中按 shard_id 取 shard：`mark7/src/dispatch.c:208-220`
- 热路径无 mutex 注释与实现：`mark7/src/dispatch.c:221-227`

### 7.3 验收点

- `num_shards == num_dispatchers`；
- 同一 flow 的所有包在预处理阶段被路由到同一个 dispatcher；
- dispatch lookup 使用预处理保存的 `flow_hash`，不在 dispatch 阶段重复计算 hash；
- 统计汇总通过 `dispatch_get_stats()` 聚合所有 shard。

## 8. 阶段 4：worker 与 reader 线程启动

### 8.1 行为说明

主线程先启动所有 worker。worker 启动后阻塞在自己的队列上。随后主线程创建 reader 线程，reader 负责预处理、启动 dispatcher、等待 dispatcher 完成、最后通知 worker 结束。

### 8.2 核心代码核实

- worker 线程创建：`mark7/src/main.c:653-658`
- reader context 初始化：`mark7/src/main.c:660-685`
- wall time / cycles 开始计时：`mark7/src/main.c:689-695`
- reader 线程创建：`mark7/src/main.c:697-700`
- reader join 与 worker join：`mark7/src/main.c:702-707`

### 8.3 验收点

- worker 线程先于 reader 线程启动；
- `reader_ctx` 中保存 workers、dispatcher cores、dispatch context、计时字段；
- wall clock 总时间从 reader 启动前开始，到 reader + worker 全部 join 后结束。

## 9. 阶段 5：预处理 pcap 到内存包

### 9.1 行为说明

reader 先执行完整预处理：

1. 打开离线 pcap；
2. `pcap_next_ex()` 顺序读取包；
3. 规范化为 Ethernet；
4. 解析 L3/L4；
5. 生成 canonical flow key；
6. 计算 `flow_hash`；
7. 保存 `dst_port` 和 payload prefix；
8. 计算 `dispatcher_id = flow_hash % num_dispatchers`；
9. 复制最多 1400 字节到 `dispatch_packet_t.data`；
10. 累加 preprocess 细项时间。

### 9.2 核心代码核实

- 预处理入口：`mark7/src/reader.c:230-380`
- `pcap_open_offline()`：`mark7/src/reader.c:238-243`
- `pcap_next_ex()` 计时：`mark7/src/reader.c:262-266`
- 标准化调用：`mark7/src/reader.c:288-295`
- parse / flow key / hash：`mark7/src/reader.c:306-336`
- dispatcher id 计算：`mark7/src/reader.c:338-347`
- packet store：`mark7/src/reader.c:349-364`
- `dispatch_packet_t` 字段：`mark7/src/reader.c:21-34`
- `append_packet()`：`mark7/src/reader.c:128-168`
- Ethernet 标准化实现：`mark7/src/packet_parser.c:28-120`
- Ethernet parse 实现：`mark7/src/packet_parser.c:204-260`

### 9.3 验收点

- 每个可解析包在预处理阶段保存 `flow_key`、`flow_hash`、`dispatcher_id`；
- `PREPROCESS_PACKET_SIZE` 当前为 1400；
- `caplen` 被裁剪到最多 1400，但 `wirelen` 保留原始线长，用于最终带宽统计；
- `Preprocess hash` 包含 parse、flow key、hash、payload prefix 提取；
- `Preprocess packet_store` 包含写入 `dispatch_packet_t` 和数据复制。

## 10. 阶段 6：构建 dispatcher 调度计划

### 10.1 行为说明

预处理完成后，reader 根据每个包的 `dispatcher_id` 构建调度计划：

- `dispatcher_offsets[d]` 表示 dispatcher d 在索引数组中的起点；
- `dispatcher_indices[pos]` 保存原始 packet 数组下标；
- dispatcher 后续只遍历属于自己的 `[start, end)` 区间。

### 10.2 核心代码核实

- `build_dispatch_schedule()`：`mark7/src/reader.c:170-228`
- counts 统计：`mark7/src/reader.c:173-183`
- offsets 构建：`mark7/src/reader.c:185-193`
- indices 填充：`mark7/src/reader.c:195-220`
- reader 中调用：`mark7/src/reader.c:559-576`

### 10.3 验收点

- 所有 packet 都被分配到合法 dispatcher；
- `dispatcher_offsets[num_dispatchers] == packet_count`；
- 后续 dispatcher 不再扫描全量包，只扫描自己的索引区间；
- `Preprocess schedule_build` 对应该阶段耗时。

## 11. 阶段 7：dispatcher 并发分发

### 11.1 行为说明

reader 创建多个 dispatcher 线程。每个 dispatcher：

1. 绑定到指定 core；
2. 读取自己的 packet index 范围；
3. 对每个包执行 `flow -> worker`；
4. 将包加入目标 worker 的本地 batch；
5. batch 满或线程结束时批量写入 worker queue；
6. 汇总本 dispatcher 的 dispatch 时间统计。

### 11.2 核心代码核实

- dispatcher 创建：`mark7/src/reader.c:578-600`
- dispatcher join：`mark7/src/reader.c:602-604`
- dispatcher 入口：`mark7/src/reader.c:415-526`
- dispatcher 绑核：`mark7/src/reader.c:424-426`
- dispatcher 范围：`mark7/src/reader.c:437-449`
- flow->worker 调用：`mark7/src/reader.c:452-467`
- batch item 填充：`mark7/src/reader.c:473-487`
- 末尾 flush：`mark7/src/reader.c:515-521`
- dispatch 统计合并：`mark7/src/reader.c:383-391`

### 11.3 验收点

- `Dispatch flow->worker map` 来自 dispatcher 中 `dispatch_lookup_or_assign()` 的累计线程内耗时；
- `Dispatch enqueue` 来自 batch 填充、batch flush、queue push 的累计线程内耗时；
- `Dispatch(Read) Time` 是多 dispatcher 线程内时间求和，不等于真实墙钟；
- dispatcher 完成后 reader 才会 `packet_queue_finish()`。

## 12. 阶段 8：flow -> worker cost-aware 调度

### 12.1 行为说明

`dispatch_lookup_or_assign()` 保证同一 flow 粘到同一 worker：

- 先在 shard 表中用 `key_hash` 做开放寻址查找；
- 命中已有 flow：直接返回旧 worker；
- 新 flow：根据 dst port / payload prefix 查 cost bucket；
- cost-aware 模式下扫描 worker，选择 `pending + core_cost + P_bias` 最小者；
- hash-only 模式下直接 `key_hash % num_workers`；
- 新 flow 写入 dispatch affinity 表。

### 12.2 核心代码核实

- lookup 函数签名：`mark7/src/dispatch.c:208-214`
- shard 选择：`mark7/src/dispatch.c:219-220`
- rehash 判断：`mark7/src/dispatch.c:229-231`
- 开放寻址查找：`mark7/src/dispatch.c:233-292`
- 新 flow cost bucket：`mark7/src/dispatch.c:240-247`
- hash-only 分支：`mark7/src/dispatch.c:251-252`
- cost-aware 分支：`mark7/src/dispatch.c:253-254`
- 新 flow 写表与统计：`mark7/src/dispatch.c:257-277`
- 已有 flow 命中：`mark7/src/dispatch.c:281-288`
- cost-aware worker 选择：`mark7/src/dispatch.c:75-113`
- queue depth / pending cost 读取：`mark7/src/dispatch.c:82-96`

### 12.3 验收点

- 已有 flow 不会重新选择 worker；
- 新 flow 才进入 cost-aware 决策；
- `added_cost_x1000` 在新 flow 分配时增加；
- `retired_cost_x1000` 在 worker 消费对应 packet 后增加；
- P/E 差异主要来自 `cost_profile_value_x1000()`，而不是硬编码吞吐。

## 13. 阶段 9：worker queue 与 batch enqueue

### 13.1 行为说明

当前交付版启用：

- `NDPI_BENCHMARK_BATCH=1`；
- `QUEUE_PACKET_USE_REF=1`；
- `QUEUE_PACKET_DATA_SIZE=2048`。

dispatcher 不再每包复制 payload 到 queue slot，而是把 `dispatch_packet_t.data` 指针放进 queue。预加载包内存会在 worker 全部 drain 后释放。

### 13.2 核心代码核实

- 编译开关：`mark7/CMakeLists.txt:70-74`
- `queue_packet_t` 引用模式字段：`mark7/include/ndpi_benchmark.h:56-66`
- `packet_queue_push_batch()`：`mark7/include/ndpi_benchmark.h:180-221`
- queue `head` 发布：`mark7/include/ndpi_benchmark.h:218-219`
- worker `peek`：`mark7/include/ndpi_benchmark.h:224-233`
- worker `consume`：`mark7/include/ndpi_benchmark.h:236-239`
- queue finish：`mark7/include/ndpi_benchmark.h:248-250`
- 预加载包延迟清理：`mark7/src/main.c:702-707`
- reader 不在成功路径清理预加载包：`mark7/src/reader.c:606-613`

### 13.3 验收点

- enqueue 阶段不再二次复制 packet bytes；
- worker 消费期间 `pkt->data` 指针仍有效；
- main 在 reader 与所有 worker join 后调用 `reader_context_cleanup()`；
- `queue_depth` 在 batch flush 成功后按 batch count 增加，在 worker 消费每包后减少。

## 14. 阶段 10：worker 消费与 nDPI 处理

### 14.1 行为说明

worker 线程循环从自己的队列取包：

1. `packet_queue_peek()` 等待数据；
2. `worker_process_packet()` 做 parse；
3. 构造 canonical flow key；
4. 在 worker 私有 flow table 查找或创建 flow；
5. 新 flow 初始化 nDPI flow state；
6. 更新方向、包数、字节、last_seen；
7. 调用 `ndpi_detection_process_packet()`；
8. 检查 UNKNOWN -> KNOWN 的协议识别边沿；
9. 更新 worker 统计；
10. consume queue slot。

### 14.2 核心代码核实

- worker 线程循环：`mark7/src/worker.c:384-409`
- queue peek：`mark7/include/ndpi_benchmark.h:224-233`
- worker 单包入口：`mark7/src/worker.c:184-379`
- parse：`mark7/src/worker.c:193-206`
- flow key：`mark7/src/worker.c:208-220`
- flow lookup/create：`mark7/src/worker.c:244-258`
- 新 flow 初始化：`mark7/src/worker.c:260-283`
- 方向和流量统计：`mark7/src/worker.c:286-303`
- nDPI 调用：`mark7/src/worker.c:312-324`
- 协议边沿检查：`mark7/src/worker.c:332-352`
- worker 包/字节统计：`mark7/src/worker.c:354-359`
- queue depth retire：`mark7/src/worker.c:397-404`
- queue consume：`mark7/src/worker.c:405`

### 14.3 验收点

- worker flow table 是私有的，不跨 worker 共享；
- 同一 flow 因 dispatch affinity 会进入同一 worker；
- worker 统计中的 `bytes_processed` 使用 `wirelen`，所以带宽按线长统计；
- `Process Time` 取所有 worker 中最大的 `processing_time_ns`，代表并行处理阶段关键路径。

## 15. 阶段 11：线程结束与资源释放

### 15.1 行为说明

dispatcher 全部完成后，reader 给所有 worker queue 设置 finished。worker 在队列空且 finished 后退出。main 等待 reader 和所有 worker 完成，然后释放预加载包、dispatch context、worker、cost table 和 nDPI global context。

### 15.2 核心代码核实

- dispatcher join：`mark7/src/reader.c:602-604`
- queue finish：`mark7/src/reader.c:606-609`
- reader finalize timers：`mark7/src/reader.c:611-612`
- main join：`mark7/src/main.c:702-707`
- reader 预加载包清理：`mark7/src/reader.c:123-126`
- 最终资源释放：`mark7/src/main.c:748-757`
- worker cleanup：`mark7/src/worker.c:98-122`

### 15.3 验收点

- 不会出现 worker 永久等待；
- reference queue 模式下不会提前释放预加载包；
- reader 失败路径会主动 finish worker queue，避免死锁；
- 所有主要资源有对应 destroy/free。

## 16. 阶段 12：结果统计与验收输出

### 16.1 行为说明

最终输出分为几类：

1. wall-clock 总耗时；
2. preprocess 细分；
3. dispatch 多线程累计耗时；
4. worker process 细分；
5. 总包数、字节、吞吐；
6. 协议识别校验；
7. per-worker 统计；
8. per-worker load details；
9. P/E core type summary；
10. dispatch summary。

### 16.2 核心代码核实

- `print_benchmark_results()`：`mark7/src/main.c:27-286`
- wall time 输出：`mark7/src/main.c:94-103`
- dispatch 输出：`mark7/src/main.c:104-107`
- process 输出：`mark7/src/main.c:108-117`
- total packets / bytes / throughput：`mark7/src/main.c:124-129`
- 协议识别校验：`mark7/src/main.c:131-140`
- per-worker 原始统计：`mark7/src/main.c:158-202`
- per-worker load details：`mark7/src/main.c:204-233`
- P/E summary：`mark7/src/main.c:235-260`
- imbalance hints：`mark7/src/main.c:262-278`
- dispatch summary：`mark7/src/main.c:392-419`
- main 调用统计输出：`mark7/src/main.c:732-746`

### 16.3 验收点

- `Total Elapsed Time` 是真实墙钟；
- `Elapsed Time (No Preprocess) = Total Elapsed Time - Preprocess Time`；
- `Dispatch(Read) Time` 是多个 dispatcher 的线程内耗时求和，可能大于真实墙钟；
- `Process parse / flow / nDPI` 是所有 worker 分项累计，可能大于 `Process Time`；
- `Process Time` 是 worker 最大处理时间，不是所有 worker 求和；
- `AvgB/Pkt = bytes_processed / packets_processed`，用于解释 PPS 和 Gbps 不一致；
- `Pkts/Flow` 用于判断 heavy flow 是否造成单 worker 高 PPS / 高 Gbps。

## 17. 当前性能优化验收点

### 17.1 已交付优化

当前代码已经交付以下 dispatch 加速手段：

1. dispatcher/shard 分片，避免旧版全局 dispatch 表锁瓶颈；
2. 复用预处理阶段 `flow_hash`，避免 dispatch 阶段重复 hash；
3. batch enqueue，降低 worker queue lock 次数；
4. queue reference mode，避免 enqueue 阶段二次复制 packet bytes；
5. 成功路径延迟释放预加载包，保证 reference queue 指针生命周期。

### 17.2 核心代码核实

- shard dispatch：`mark7/src/dispatch.c:16-37`
- lookup 传入 `key_hash`：`mark7/include/benchmark_internal.h:160-166`
- reader 调用传入 `pkt->flow_hash`：`mark7/src/reader.c:456-462`
- batch enqueue：`mark7/src/reader.c:428-430`、`mark7/src/reader.c:473-487`
- batch flush：`mark7/src/reader.c:515-521`
- queue reference mode：`mark7/CMakeLists.txt:70-74`
- 延迟清理：`mark7/src/main.c:702-707`

### 17.3 验收点

使用同一个大 pcap 对比旧版输出，预期：

- `Dispatch flow->worker map` 显著下降；
- `Dispatch enqueue` 显著下降；
- `Elapsed Time (No Preprocess)` 下降；
- E 核不再长期接近 0 flow，除非 cost profile 或流量分布明确导致偏 P；
- `Per-Worker Load Details` 能解释 PPS/Gbps 不均衡来自平均包长或 heavy flow。

## 18. 交付验收命令

建议验收命令：

```bash
cmake --build mark7/build -j
./mark7/build/ndpiBenchmarkMark7 -i mark1/test.pcap -q
./mark7/build/ndpiBenchmarkMark7Hash -i mark1/test.pcap -q
./mark7/build/ndpiBenchmarkMark7 -i input/Monday-WorkingHours.pcap -q
```

验收输出重点检查：

- `Total Packets` 是否符合输入 pcap 预期；
- `Flows with detected protocol` 是否非 0；
- `Dispatch Summary` 中 `New flow assignments + Existing flow hits` 是否约等于可解析包数；
- `Per-Worker Load Details` 中 `Pkt% / Byte% / AvgB/Pkt / Pkts/Flow` 是否能解释 per-worker Mpps/Gbps；
- `Core-Type Load Summary` 中 P/E 分布是否符合 cost-aware 策略预期。

## 19. 已知边界

1. 当前 `PREPROCESS_PACKET_SIZE=1400`，超出部分不会传给 worker/nDPI；这会降低内存与 enqueue 成本，但对依赖深 payload 的协议可能影响识别。
2. 当前 `core_type_from_core_id()` 仍假设 `core_id < 16` 为 P 核，否则 E 核；换机器或换拓扑时需要显式确认。
3. cost-aware 只在新 flow 首次分配时决策；已有 flow 后续包保持 affinity，不会重新平衡。
4. `Dispatch(Read) Time` 与 `Process nDPI` 等多线程累计时间不能直接和 wall-clock 相加。
5. 队列仍是每 worker 一个 MPSC queue，batch 降低了锁频率，但没有完全消除多 dispatcher 命中同一 worker 时的 queue lock 竞争。

## 20. 验收结论

当前 `mark7` 的交付状态满足以下条件：

- 运行流程完整：配置、初始化、预处理、调度、worker 处理、统计、释放均有明确路径；
- dispatch 热路径已完成第一轮优化；
- 输出已经具备定位 per-worker/P/E 分布的统计字段；
- 每个关键阶段均有对应代码核实点，可用于后续复审和性能回归定位。
