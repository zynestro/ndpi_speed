# mark7 代码结构与运行流程教程

这份文档按“先看整体，再看一次运行的时间顺序”的方式解释 `mark7`。读完之后，你应该能知道：

- 每个源码文件负责什么；
- 程序启动后先初始化什么、再启动哪些线程；
- 一个 pcap 包从磁盘读出后，如何进入 dispatcher、如何被调度到 worker；
- worker 如何维护 flow 状态并调用 nDPI；
- 当前异构核调度的 score 是怎么进入流程的。

## 1. mark7 在做什么

`mark7` 是一个离线 pcap benchmark，不是真实网卡收包程序。它把 pcap 文件预加载到内存，然后模拟一条多线程处理流水线：

```text
pcap file
  -> reader controller 预处理
  -> dispatch_packet_t[] 内存包缓存
  -> 多个 dispatcher 并发分发
  -> flow -> worker 调度层
  -> 每个 worker 的 queue
  -> worker parse / flow table / nDPI detection
  -> 汇总吞吐、时间、flow、调度统计
```

默认拓扑是：

```text
8 个 dispatcher: core 16-23
16 个 worker:    core 0,2,4,6,8,10,12,14,24,25,26,27,28,29,30,31
```

当前会构建两个可执行文件：

```text
ndpiBenchmarkMark7      cost-aware-jsw 调度策略
ndpiBenchmarkMark7Hash  hash-only baseline
```

它们使用同一套源码，只是 `ndpiBenchmarkMark7Hash` 编译时打开了 `MARK7_DISPATCH_HASH_ONLY`。

## 2. 文件地图

### 2.1 构建文件

`CMakeLists.txt`

- 定义工程、C 标准、编译选项；
- 查找 nDPI、libpcap、pthread；
- 把所有 `.c` 文件打进两个目标：
  - `ndpiBenchmarkMark7`
  - `ndpiBenchmarkMark7Hash`
- `ndpiBenchmarkMark7Hash` 额外定义 `MARK7_DISPATCH_HASH_ONLY=1`。

### 2.2 公共头文件

`include/ndpi_benchmark.h`

这是最重要的公共数据结构头文件，里面定义了：

- `packet_queue_t`：dispatcher 到 worker 的环形队列；
- `parsed_packet_t`：解析后的 L3/L4 视图；
- `flow_key_t`：双向 canonical flow key；
- `bench_flow_t`：worker 私有 flow 状态；
- `cost_bucket_t`：`Easy / Middle / Hard`；
- `worker_runtime_state_t`：调度层观察 worker 负载用的运行态；
- `worker_context_t`：每个 worker 的上下文；
- `benchmark_config_t`：命令行解析后的全局配置。

其中当前 cost 数值是：

```c
COST_EASY_X1000   = 2000
COST_MIDDLE_X1000 = 7000
COST_HARD_X1000   = 15000
```

当前离线成本表在：

```text
mark7/offline_costs/cost_profile.csv
```

它维护六个值：

```text
P/E x Easy/Middle/Hard
```

也就是 `P_COST_EASY`、`P_COST_MIDDLE`、`P_COST_HARD`、`E_COST_EASY`、`E_COST_MIDDLE`、`E_COST_HARD`。lookup JSON 只负责把 flow 分成 bucket，真正的 P/E bucket cost 由这个 CSV 提供。

`include/benchmark_internal.h`

这是各 `.c` 文件之间共享的内部接口，主要放：

- `reader_context_t`；
- `dispatch_context_t` 的前向声明；
- parser、flow table、cost table、dispatch、worker、reader 的函数声明；
- 调度相关常量，例如 `DISPATCH_TABLE_INIT_CAP`、`DISPATCH_P_BIAS_X1000`。

注意：有些源码注释里还写着 `mark3`，这是历史继承注释；当前目录里的代码实际是 `mark7`。

### 2.3 入口与总体控制

`src/main.c`

职责：

- 解析命令行参数；
- 准备默认 worker core list 和 dispatcher core list；
- 初始化 nDPI global context；
- 加载 lookup cost table；
- 创建 worker runtime state；
- 创建 worker、queue、worker 私有 nDPI module；
- 创建 dispatch context；
- 启动 worker 线程；
- 启动 reader controller 线程；
- 等待所有线程结束；
- 汇总输出 benchmark 结果和 dispatch summary；
- 释放资源。

你可以把 `main.c` 理解成“总导演”。

### 2.4 pcap 预处理与 dispatcher

`src/reader.c`

职责：

- 打开 pcap；
- 顺序读取每个包；
- 标准化链路层为 Ethernet 视图；
- 解析出 flow key、原始方向 `dst_port`、payload prefix；
- 先按 `flow_hash % num_dispatchers` 给包分配 dispatcher；
- 把包复制到 `dispatch_packet_t[]`；
- 构建 dispatcher 调度计划；
- 启动多个 dispatcher 线程；
- dispatcher 对包做 `flow -> worker` 查询并入队；
- 所有 dispatcher 完成后，通知 worker 队列结束。

`reader.c` 其实包含两层角色：

```text
reader controller:
  负责 pcap 预加载、构建 dispatcher schedule、启动 dispatcher

dispatcher thread:
  负责消费自己那一份预加载包，做 flow->worker 分配并 push 到 worker queue
```

### 2.5 flow 到 worker 的调度层

`src/dispatch.c`

职责：

- 维护调度层的 `flow_key -> worker_id` affinity table；
- 对新 flow 查 cost bucket；
- 用当前策略选 worker；
- 更新每个 worker 的估计 pending cost；
- 统计每个 bucket 和每个 worker 被分配了多少新 flow。

当前 `cost-aware-jsw` 的核心逻辑是：

```text
新 flow:
  bucket = cost_table_lookup_bucket(dst_port, payload_prefix)
  遍历所有 worker:
    pending = added_cost_x1000 - retired_cost_x1000
    core_cost = cost_profile[worker.core_type][bucket]
    score = pending + core_cost
    如果是 P 核，再加 DISPATCH_P_BIAS_X1000
  选择 score 最低的 worker
  写入 flow affinity table
  added_cost_x1000 += core_cost

旧 flow:
  直接返回 affinity table 中已有 worker
```

`hash-only` 版本会跳过 score：

```text
worker_id = flow_key_hash % num_workers
```

### 2.6 cost lookup 表

`src/cost_table.c`

职责：

- 读取 lookup table JSON；
- 解析 `default_bucket`；
- 解析 `port_table`；
- 解析 `special_rules`；
- 提供 `cost_table_lookup_bucket()`。

查表顺序当前是：

```text
1. 如果 dst_port 在 port_table 中，直接返回该 bucket
2. 否则遍历 special_rules，按 payload prefix 匹配
3. 如果都没有命中，返回 Hard
```

这点很重要：当前代码最后 miss 返回 `Hard`。

### 2.7 报文解析与 flow key

`src/packet_parser.c`

职责：

- `normalize_to_ethernet()`：把不同链路层视图统一成 Ethernet；
- `parse_ethernet_frame()`：解析 Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP；
- `flow_key_from_packet()`：生成双向 canonical flow key；
- `endpoint_equal()`：判断当前包方向；
- `compute_flow_hash()`：提供一个快速 hash，用于 fallback 或历史 RSS 逻辑。

最关键的是 `flow_key_from_packet()`。它会把：

```text
A:1234 -> B:443
B:443  -> A:1234
```

规范化成同一个 `flow_key_t`。这样双向包会进入同一个 flow 状态和同一个 worker。

### 2.8 worker 线程

`src/worker.c`

职责：

- 初始化每个 worker 的 nDPI detection module；
- 创建 worker 私有 flow table；
- 从自己的 queue 中取包；
- 对每个包执行：
  - parse；
  - build flow key；
  - flow lookup/create；
  - 更新方向、包数、字节数；
  - 调用 `ndpi_detection_process_packet()`；
  - 首次识别出协议时计数；
  - 更新耗时统计；
  - retire 调度层给该包附带的估计 cost。

worker 是真正执行 nDPI 的地方。

### 2.9 worker 私有 flow table

`src/flow_table.c`

职责：

- 给每个 worker 提供私有 `flow_key -> bench_flow_t*` 哈希表；
- 采用开放寻址；
- 支持 `get_or_create`；
- 支持删除和 tombstone；
- 销毁时释放每条 flow 的 nDPI flow state。

这个表不跨 worker 共享。调度层把一个 flow 粘到某个 worker 后，该 worker 内部才会维护该 flow 的真实 nDPI 状态。

### 2.10 软件 RSS 表

`src/rss_table.c`

职责：

- 提供历史版本的 `flow -> target` 稳定映射工具；
- 现在 `mark7` 预处理分 dispatcher 主要直接用 `flow_hash % num_dispatchers`；
- `rss_table.c` 仍然保留在构建中，方便兼容和扩展其它策略。

### 2.11 公共工具

`src/benchmark_common.c`

职责：

- `set_thread_affinity()`：线程绑核；
- `maybe_print_flow_sample()`：打印前几条识别成功的 flow 样本；
- 全局 quiet/sample 状态。

## 3. 核心数据结构关系

### 3.1 配置对象

`benchmark_config_t`

```text
pcap_file
num_workers
core_list
num_dispatchers
dispatcher_core_list
quiet_mode
proto_file
lookup_file
```

它来自命令行参数，后续 `main()` 都围绕它展开。

### 3.2 worker_context_t

每个 worker 一个：

```text
worker_id
cpu_core
ndpi detection module
worker 私有 flow_table
packet_queue_t
worker_runtime_state_t
各种处理时间和计数
pthread_t
```

worker 的核心原则是：每个 worker 自己维护自己的 nDPI module 和 flow table，不共享热路径状态。

### 3.3 worker_runtime_state_t

这是调度层观察 worker 的轻量状态：

```text
added_cost_x1000
retired_cost_x1000
queue_depth
core_type
core_id
speed_factor_x1000
```

dispatcher 在选 worker 时会读它；worker 消费包后会更新它。

### 3.4 dispatch_context_t

`dispatch.c` 内部私有结构：

```text
flow affinity slots
cost_table
workers
num_workers
rr_cursor
dispatch_stats
mutex lock
```

它是 `mark7` 调度层的核心状态，负责保证同一个 flow 后续继续回到同一个 worker。

### 3.5 dispatch_packet_t

`reader.c` 内部私有结构，代表预处理后的包缓存项：

```text
timestamp_us
flow_key
fallback_hash
dispatcher_id
caplen / wirelen
dst_port
payload_prefix
payload_prefix_len
has_flow_key
data[1400]
```

注意：预加载缓存只保留前 `1400` 字节。这样减少内存和复制成本，但对需要更深 payload 的协议可能有影响。

## 4. 一次运行的完整时间线

下面按一次执行命令后的时间顺序讲。

示例命令：

```bash
./mark7/build/ndpiBenchmarkMark7 \
  -i input/Monday-WorkingHours.pcap \
  -q
```

### 阶段 0：进程启动和参数解析

入口是 `main()`。

`parse_args()` 做这些事：

1. 读取 `-i` pcap 路径；
2. 读取 `-n` worker 数；
3. 读取 `-c` worker core list；
4. 读取 `-d` dispatcher core list；
5. 读取 `-m` lookup table JSON；
6. 读取 `-p` nDPI protocol config；
7. 读取 `-q` quiet mode。

如果没有传 `-c`：

- 当 `num_workers == 16` 时，使用默认异构 worker core list；
- 否则使用 `0..num_workers-1`。

这意味着：如果你运行 `-n 8` 但不传 `-c`，默认 worker 会是 `0-7`，不再是 `24-31` 这些 E 核。

### 阶段 1：初始化 nDPI global context

`main()` 调用：

```text
ndpi_global_init()
```

这个 global context 会传给每个 worker，用于初始化每个 worker 自己的 detection module。

### 阶段 2：加载 cost lookup table

`main()` 调用：

```text
cost_table_load(&cost_table, cfg.lookup_file)
```

`cost_table_load()` 会打开 JSON 文件，填充：

```text
default_bucket
port_bucket[65536]
port_present[65536]
special_rules[]
```

后面新 flow 调度时会通过 `dst_port + payload_prefix` 查这个表。

### 阶段 3：创建 worker runtime state

`alloc_worker_runtime_states()` 根据 worker core list 初始化每个 worker 的运行态：

```text
core_id
core_type
added_cost_x1000 = 0
retired_cost_x1000 = 0
queue_depth = 0
```

`core_type_from_core_id()` 当前规则很简单：

```text
core_id < 16 -> P
core_id >= 16 -> E
```

调度时不再用 `speed_factor` 推导 P/E 代价，而是用 `cost_profile.csv` 中的 P/E bucket cost。

### 阶段 4：创建 worker_context_t 和 queue

`main()` 分配 `worker_context_t workers[num_workers]`。

对每个 worker：

1. 设置 `worker_id`；
2. 设置绑定 CPU `cpu_core`；
3. 设置 nDPI global context；
4. 设置 runtime state；
5. 创建 `packet_queue_t`。

这个 queue 是 dispatcher 到 worker 的唯一数据通道。

### 阶段 5：初始化每个 worker 的 nDPI module

`main()` 对每个 worker 调用：

```text
init_worker_ndpi(&workers[i])
```

里面做：

1. `ndpi_init_detection_module(worker->g_ctx)`；
2. 启用 `tcp_ack_payload_heuristic`；
3. 如果有 `-p`，加载协议配置文件；
4. `ndpi_finalize_initialization()`；
5. 创建 worker 私有 flow table。

这一步之后，每个 worker 都有自己的 nDPI module。

### 阶段 6：创建 dispatch context

`main()` 调用：

```text
dispatch_context_create(&cost_table, workers, num_workers)
```

这会创建调度层的 affinity table。这个 table 保存：

```text
flow_key -> worker_id
```

它与 worker 内部的 flow table 不同：

- dispatch affinity table 决定一条 flow 去哪个 worker；
- worker flow table 保存这条 flow 的 nDPI 状态。

### 阶段 7：启动所有 worker 线程

`main()` 先启动 worker：

```text
pthread_create(worker_thread_entry, &workers[i])
```

每个 worker 启动后：

1. 调用 `set_thread_affinity(w->cpu_core)` 绑核；
2. 进入 `packet_queue_peek()`；
3. 如果队列为空，就等待；
4. 等 dispatcher 后面 push 包进来。

### 阶段 8：启动 reader controller 线程

`main()` 创建 reader controller：

```text
pthread_create(reader_thread_entry, &reader_ctx)
```

然后 `main()` 自己等待：

```text
pthread_join(reader)
pthread_join(all workers)
```

真正的 pcap 读取和 dispatcher 启动都发生在 reader controller 线程里。

## 5. reader controller 内部流程

`reader_thread_entry()` 是 reader controller 的入口。

它按这个顺序执行：

```text
reset timers
load_pcap_packets()
build_dispatch_schedule()
create dispatcher threads
join dispatcher threads
finish all worker queues
cleanup preloaded packets
finalize timers
```

### 5.1 load_pcap_packets()

这是预处理阶段。

对 pcap 中每个包，执行：

1. `pcap_next_ex()` 读取一个包；
2. 检查长度；
3. `normalize_to_ethernet()` 统一成 Ethernet；
4. `parse_ethernet_frame()` 解析 L3/L4；
5. 如果解析成功：
   - `flow_key_from_packet()` 生成双向 flow key；
   - `flow_key_hash()` 生成 hash；
   - 记录原始方向 `dst_port`；
   - 复制最多 4 字节 payload prefix；
6. 如果解析失败：
   - 用 `compute_flow_hash()` 做 fallback hash；
7. 计算 dispatcher：
   - `dispatcher_id = rss_hash % num_dispatchers`；
8. 调用 `append_packet()` 把包写入 `dispatch_packet_t[]`。

预处理后，内存里会有一个连续数组：

```text
packets[0..packet_count-1]
```

### 5.2 build_dispatch_schedule()

预处理数组里每个包都有 `dispatcher_id`，但它们在数组中不是按 dispatcher 连续排列的。

所以这里构建两个表：

```text
dispatcher_offsets[d]
dispatcher_indices[pos]
```

含义是：

```text
dispatcher d 处理:
  pos in [dispatcher_offsets[d], dispatcher_offsets[d+1])
  packet index = dispatcher_indices[pos]
```

这样每个 dispatcher 线程只需要扫自己的索引区间。

### 5.3 启动 dispatcher 线程

reader controller 根据 `num_dispatchers` 启动多个 dispatcher。

每个 dispatcher 参数包括：

```text
ctx
dispatcher_id
cpu_core
```

dispatcher 启动后也会尝试绑核。

## 6. dispatcher 每包流程

dispatcher 入口是 `dispatcher_thread_entry()`。

它只处理自己那段 schedule：

```text
for pos in my range:
  idx = dispatcher_indices[pos]
  pkt = packets[idx]
  worker_id = dispatch_lookup_or_assign(...)
  packet_queue_push(worker[worker_id].queue, pkt)
  worker[worker_id].runtime.queue_depth++
```

### 6.1 可解析包

如果 `pkt->has_flow_key == true`，dispatcher 调用：

```text
dispatch_lookup_or_assign(
  ctx->dispatch,
  &pkt->flow_key,
  pkt->dst_port,
  pkt->payload_prefix,
  pkt->payload_prefix_len
)
```

调度层返回：

```text
worker_id
retire_cost_x1000
is_new_flow
```

`retire_cost_x1000` 会一起放进 worker queue。worker 处理完这个包后，会把它加到 `retired_cost_x1000`。

### 6.2 不可解析包

如果没有 flow key，就走 fallback：

```text
worker_id = fallback_hash % num_workers
```

这种包不会进入 cost-aware flow affinity table。

## 7. dispatch_lookup_or_assign() 的细节

这是 `mark7` 调度机制的核心。

### 7.1 先查 affinity table

调度层用双向 canonical `flow_key_t` 做 key。

如果命中：

```text
return existing worker_id
retire_cost_x1000 = 0
is_new_flow = false
```

也就是说，旧 flow 不再重新打分。

### 7.2 新 flow 查 cost bucket

如果 table 中没有这条 flow：

```text
bucket = cost_table_lookup_bucket(dst_port, payload_prefix)
```

bucket 会映射到当前 worker 核类型上的离线 cost：

```text
P + Easy   -> P,Easy 行的 cost_us
P + Middle -> P,Middle 行的 cost_us
P + Hard   -> P,Hard 行的 cost_us
E + Easy   -> E,Easy 行的 cost_us
E + Middle -> E,Middle 行的 cost_us
E + Hard   -> E,Hard 行的 cost_us
```

### 7.3 cost-aware-jsw 选 worker

普通 `ndpiBenchmarkMark7` 调用：

```text
choose_cost_jsw_worker()
```

它遍历所有 worker，计算：

```text
pending = added_cost_x1000 - retired_cost_x1000
core_cost = cost_profile[core_type][bucket]
score = pending + core_cost
if P-core:
  score += DISPATCH_P_BIAS_X1000
```

当前 `DISPATCH_P_BIAS_X1000 = 10`。

当前默认 `cost_profile.csv` 用 P-core profiling 初始化，E-core 行暂时镜像 P-core 行：

```text
P,Easy   = 2.262390 us
P,Middle = 7.626345 us
P,Hard   = 17.278661 us
E,Easy   = 2.262390 us
E,Middle = 7.626345 us
E,Hard   = 17.278661 us
```

你跑完 E-core profiling 后，把 `E,*` 三行替换成真实值即可。

### 7.4 写入 affinity table

选出 worker 后：

```text
flow_key -> worker_id
```

会写入 dispatch table。

同时：

```text
worker[worker_id].runtime.added_cost_x1000 += retire_cost_x1000
stats.worker_flow_counts[worker_id]++
stats.bucket_flow_counts[bucket]++
```

后续同 flow 的包都会直接走这个 worker。

### 7.5 hash-only baseline

如果编译的是 `ndpiBenchmarkMark7Hash`：

```text
worker_id = flow_key_hash % num_workers
```

它仍然写 affinity table，只是新 flow 的第一次分配不用 cost score。

## 8. worker 每包处理流程

worker 入口是 `worker_thread_entry()`。

它循环：

```text
while packet_queue_peek(queue, &pkt):
  worker_process_packet(w, pkt)
  retired_cost_x1000 += pkt->retire_cost_x1000
  queue_depth--
  packet_queue_consume(queue)
```

队列被 reader 标记 finished 且已经消费空后，worker 线程退出。

### 8.1 worker_process_packet()

这是真正热路径。

对每个包：

1. `parse_ethernet_frame()` 解析；
2. `flow_key_from_packet()` 构造双向 flow key；
3. `flow_key_hash()` 计算 flow table hash；
4. 在 worker 私有 flow table 中 `get_or_create`；
5. 如果是新 flow：
   - 记录首包方向；
   - 创建 `ndpi_flow_struct`；
   - 填充 nDPI 需要的五元组；
6. 根据当前包源 endpoint 判断方向：
   - 与首包 client 相同就是 `dir=0`；
   - 否则 `dir=1`；
7. 更新 c2s/s2c 包数和字节数；
8. 调用：
   - `ndpi_detection_process_packet()`；
9. 调用：
   - `ndpi_get_flow_appprotocol()`；
10. 如果第一次从 UNKNOWN 变为已识别：
    - `flows_with_protocol_total++`；
    - 可选打印 flow sample；
11. 更新各种时间统计。

### 8.2 nDPI 状态在哪里

nDPI 的每流状态放在：

```text
bench_flow_t.ndpi_flow
```

而 `bench_flow_t` 放在 worker 私有 `flow_table` 中。

所以 flow 必须稳定到同一个 worker，否则不同 worker 会各有一份不完整的 nDPI 状态。这就是为什么 `dispatch.c` 需要 flow affinity table。

## 9. 线程结束流程

dispatcher 全部跑完后，reader controller 调用：

```text
packet_queue_finish(worker[i].queue)
```

worker 的 `packet_queue_peek()` 逻辑是：

```text
如果队列有包:
  返回包
如果队列空但 finished=false:
  等待
如果队列空且 finished=true:
  返回 false，线程退出
```

因此不会提前退出：所有已经入队的包都会被 drain 完。

## 10. 结果汇总流程

`main()` 等 reader 和所有 worker 结束后，调用：

```text
print_benchmark_results(...)
print_dispatch_summary(...)
```

### 10.1 print_benchmark_results()

输出：

- 总 elapsed time；
- preprocess time；
- dispatch time；
- process time；
- process 内部分项：
  - parse；
  - flowkey lookup；
  - flow init；
  - flow；
  - nDPI call；
  - proto check；
  - other；
- per-core process time；
- total packets；
- total bytes；
- throughput；
- bandwidth；
- cycles per packet；
- per-worker stats。

吞吐的分母是：

```text
elapsed_no_preprocess = total_wall_time - preprocess_time
```

也就是说预加载 pcap 的时间被单独扣掉。

### 10.2 print_dispatch_summary()

输出：

- 新 flow 分配数；
- 旧 flow 命中数；
- Easy/Middle/Hard bucket 分布；
- 每个 worker 被分到的新 flow 数；
- 每个 worker 当前 pending cost；
- 每个 worker 当前 queue depth。

这部分是观察调度是否真的把 flow 分到 E 核的关键。

## 11. 一包到底经历了什么

用最短路径串起来就是：

```text
pcap_next_ex()
  -> normalize_to_ethernet()
  -> parse_ethernet_frame()
  -> flow_key_from_packet()
  -> dispatcher_id = flow_hash % num_dispatchers
  -> append_packet() 存进 dispatch_packet_t[]
  -> build_dispatch_schedule()
  -> dispatcher_thread_entry()
  -> dispatch_lookup_or_assign()
       -> old flow: affinity table 命中
       -> new flow: cost lookup + score 选 worker + 写 affinity
  -> packet_queue_push(worker queue)
  -> worker_thread_entry()
  -> worker_process_packet()
       -> parse_ethernet_frame()
       -> flow_key_from_packet()
       -> worker 私有 flow_table get_or_create
       -> ndpi_detection_process_packet()
       -> ndpi_get_flow_appprotocol()
  -> retire_cost_x1000
  -> queue consume
```

## 12. 两张 flow 表不要混淆

`mark7` 里有两类“flow 表”，名字很容易混。

### 12.1 dispatch affinity table

位置：`dispatch.c`

用途：

```text
flow_key -> worker_id
```

它回答的问题是：

```text
这条 flow 应该交给哪个 worker？
```

它不保存 nDPI 状态。

### 12.2 worker flow_table

位置：`flow_table.c`

用途：

```text
flow_key -> bench_flow_t*
```

它回答的问题是：

```text
这个 worker 内部，这条 flow 的 nDPI 状态在哪里？
```

它保存 nDPI per-flow state。

## 13. 当前调度机制为什么会影响 E 核流量

当前分配到 P/E 的关键点是 `choose_cost_jsw_worker()`。

现在调度不再依赖 speed factor，而是依赖 `cost_profile.csv` 中的六个离线成本值。E 核是否能吃到流，主要取决于：

- `rr_cursor` 从哪里开始遍历；
- 各 worker 的 `pending`；
- 各 worker 的 `queue_depth`；
- P 核额外 `+10` 偏置；
- `P/E x Easy/Middle/Hard` 六个离线成本值；
- 新 flow 首包一旦绑定后，后续不会迁移。

如果运行后 E 核仍然吃不到量，下一步更可能要看：

- `rr_cursor` 的推进方式；
- `pending` retire 太快导致负载视图不明显；
- 是否要按 bucket 强制 Easy 优先 E；
- 是否要设置 E 核保底比例；
- 是否要用真实处理时间反馈替代静态 cost。

## 14. 常用运行方式

构建：

```bash
cmake -S mark7 -B mark7/build -DNDPI_PREFIX=$HOME/ndpi-install
cmake --build mark7/build -j
```

运行 cost-aware：

```bash
./mark7/build/ndpiBenchmarkMark7 \
  -i input/Monday-WorkingHours.pcap
```

运行 hash-only baseline：

```bash
./mark7/build/ndpiBenchmarkMark7Hash \
  -i input/Monday-WorkingHours.pcap
```

显式指定 worker / dispatcher core：

```bash
./mark7/build/ndpiBenchmarkMark7 \
  -i input/Monday-WorkingHours.pcap \
  -c 0,2,4,6,8,10,12,14,24,25,26,27,28,29,30,31 \
  -d 16,17,18,19,20,21,22,23
```

指定 lookup table：

```bash
./mark7/build/ndpiBenchmarkMark7 \
  -i input/Monday-WorkingHours.pcap \
  -m mark7/offline_costs/lookup_table.json
```

指定离线 P/E bucket cost 表：

```bash
./mark7/build/ndpiBenchmarkMark7 \
  -i input/Monday-WorkingHours.pcap \
  -C mark7/offline_costs/cost_profile.csv
```

## 15. 阅读源码建议顺序

如果你第一次完整读这套代码，建议按这个顺序：

1. `include/ndpi_benchmark.h`
2. `include/benchmark_internal.h`
3. `src/main.c`
4. `src/reader.c`
5. `src/dispatch.c`
6. `src/worker.c`
7. `src/packet_parser.c`
8. `src/flow_table.c`
9. `src/cost_table.c`
10. `src/benchmark_common.c`
11. `src/rss_table.c`

这样看最顺：先理解数据结构，再理解线程和数据流，最后补工具和历史兼容模块。
