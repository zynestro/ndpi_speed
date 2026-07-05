# mark9 代码级工作流详解

## 架构总览：三阶段流水线

mark9 是一个**多线程离线 pcap 重放**的 nDPI 协议识别 benchmark。整个工作流分为 3 个阶段、3 种线程角色：

```
pcap 文件 (硬盘)
    │
    ▼
┌──────────────────────────────────────┐
│  Phase 1: Preprocess (Reader 线程)    │
│  读盘 → 链路层标准化 → 解析 → Hash     │
│  → 分配 dispatcher → 缓存到内存数组    │
└──────────────┬───────────────────────┘
               │ dispatch_packet_t 数组
               ▼
┌──────────────────────────────────────┐
│  Phase 2: Dispatch (N× Dispatcher)    │
│  Flow→Worker 绑定 → 成本估算          │
│  → 入队到对应 Worker 的 ring buffer    │
└──────────────┬───────────────────────┘
               │ N 个 packet_queue_t
               ▼
┌──────────────────────────────────────┐
│  Phase 3: Process (N× Worker)         │
│  出队 → 解析 → Flow Table → nDPI 识别  │
│  → 统计汇总                            │
└──────────────────────────────────────┘
```

核心思想：**把 I/O、分发、识别三层解耦，便于独立测量和优化各级开销**。

---

## Phase 1: Preprocess（Reader 线程）

入口：`reader_thread_entry()` → `load_pcap_packets()`

### 1.1 打开 pcap 文件

```c
// reader.c:239
pcap_t *handle = pcap_open_offline(ctx->pcap_file, errbuf);
```

使用 libpcap 的**离线模式**打开硬盘上的 pcap 文件。与在线模式 (`pcap_open_live`) 不同，离线模式不需要网卡、不经过内核协议栈、不受 BPF 过滤影响。

### 1.2 逐包读取 + 标准化

```c
// reader.c:263
int rc = pcap_next_ex(handle, &header, &data);
```

`pcap_next_ex` 逐包读取。每包经历 5 个子步骤：

#### Step 1: 读取 (`pcap_read_ns`)
libpcap 从文件读取原始 pcap record（包头 + 数据）。

#### Step 2: 链路层标准化 (`normalize_ns`)

```c
// packet_parser.c:28
bool ok = normalize_to_ethernet(linktype, data, pkt_caplen, pkt_wirelen,
                                &pkt_data, &pkt_caplen, &pkt_wirelen,
                                scratch, sizeof(scratch));
```

**为什么要标准化？** pcap 文件可能来自不同链路层：Ethernet (DLT_EN10MB)、BSD Loopback (DLT_NULL)、Raw IP 等。标准化函数把它们统一为 **Ethernet 视图**：
- 已是 Ethernet → 原样返回
- Loopback/NULL → 补一个伪 Ethernet 头（14 字节，ethertype 填 IPv4/IPv6）
- 不支持的类型 → 跳过该包

这样后续所有解析代码只需处理一种链路层格式，大幅减少分支。

#### Step 3: 快速包解析 (`hash_ns`)

```c
// reader.c:317
parse_result_t parsed = parse_ethernet_frame(pkt_data, pkt_caplen, &pp);
```

从 Ethernet 帧中提取 L3/L4 关键字段到 `parsed_packet_t`：

```
Ethernet 帧
  ├── dst_mac, src_mac, ethertype
  ├── IPv4/IPv6 头
  │     ├── src_ip[16], dst_ip[16]
  │     ├── ip_version (4 or 6)
  │     ├── l3 指针, l3_len（nDPI 处理时从此开始）
  │     └── l4_proto (TCP/UDP)
  ├── TCP/UDP 头
  │     ├── src_port, dst_port
  │     └── payload 指针, payload_len（前 4 字节用于 prefix 查找）
```

然后构造 **双向 canonical flow key**：

```c
// packet_parser.c
flow_key_from_packet(&pp, &flow_key, &src_ep, &dst_ep);
```

`flow_key_t` 的巧妙设计——**保证双向流量归并到同一个 key**：

```c
typedef struct {
  uint8_t  ip_version;     // 4 or 6
  uint8_t  l4_proto;       // TCP/UDP
  uint16_t port_a;         // min(src_port, dst_port)
  uint16_t port_b;         // max(src_port, dst_port)
  uint8_t  addr_a[16];     // lexicographically smaller IP
  uint8_t  addr_b[16];     // lexicographically larger IP
} flow_key_t;
```

A→B 和 B→A 的包经过 `min/max` 排序后产生**完全相同的 key**，保证同一个 TCP/UDP 连接的双向包映射到同一个 flow 状态。

然后对 key 做 **FNV-1a 哈希**：

```c
flow_hash = flow_key_hash(&flow_key);   // 64-bit FNV-1a
```

对于解析失败的包（非 IP 或截断），使用 `compute_flow_hash()` 对原始字节做 fallback 哈希——保证每个包至少有一个可用于 RSS 分片的哈希值。

#### Step 4: 分配 Dispatcher (`preprocess_dispatch_rss_ns`)

```c
// reader.c:341
dispatcher_id = (uint32_t)(rss_hash % ctx->num_dispatchers);
```

#### Step 5: 存储到预加载数组 (`preprocess_store_ns`)

```c
// reader.c:350
append_packet(&packets, &count, &cap, pkt_data, pkt_caplen, ...);
```

关键设计点：**每个包的数据被截断到 1400 字节**（`PREPROCESS_PACKET_SIZE`）：

```c
// reader.c:146
uint16_t stored_caplen = (caplen > PREPROCESS_PACKET_SIZE)
                             ? (uint16_t)PREPROCESS_PACKET_SIZE
                             : caplen;
```

这是内存与精度的 tradeoff——1400 字节覆盖了绝大多数协议识别所需的头部载荷，同时大幅降低了预加载数组的内存占用。

`dispatch_packet_t` 结构体：

```c
typedef struct {
  uint64_t timestamp_us;        // pcap 时间戳
  flow_key_t flow_key;          // 双向 flow key
  uint64_t flow_hash;           // FNV-1a hash
  uint64_t fallback_hash;       // 解析失败时的备用 hash
  uint32_t dispatcher_id;       // RSS 分配的 dispatcher
  uint16_t caplen;              // 实际存储长度 (≤ 1400)
  uint16_t wirelen;             // 线长
  uint16_t dst_port;            // 目标端口
  uint8_t  payload_prefix[4];   // payload 前 4 字节
  uint8_t  payload_prefix_len;
  bool     has_flow_key;        // 解析是否成功
  uint8_t  data[PREPROCESS_PACKET_SIZE];  // 包数据（截断）
} dispatch_packet_t;
```

### 1.3 构建 Dispatcher 调度计划

```c
// reader.c:170
build_dispatch_schedule(ctx, packets, packet_count);
```

所有包读完后，按 `dispatcher_id` 分组统计，构建**偏移量数组 + 索引数组**：

```
dispatcher_offsets[0..N]:  每个 dispatcher 的包在 indices 中的起止位置
dispatcher_indices[0..M]:  包在 packets 数组中的下标（按 dispatcher 分组排列）
```

这样每个 dispatcher 线程可以**独立、无锁地**遍历自己的包区间，且同 dispatcher 的包在内存中聚合（cache friendly）。

---

## Phase 2: Dispatch（N 个 Dispatcher 线程）

入口：`dispatcher_thread_entry()`

每个 dispatcher 处理自己的 `[start, end)` 区间：

```c
// reader.c:461
size_t idx = ctx->dispatcher_indices[pos];
const dispatch_packet_t *pkt = &packets[idx];
```

### 2.1 Flow → Worker 绑定

核心调用：`dispatch_lookup_or_assign()` （`dispatch.c:344`）

```
dispatch_lookup_or_assign(ctx, shard_id, &flow_key, flow_hash,
                          dst_port, payload_prefix, payload_prefix_len)
```

这是一个 **sharded open-addressing hash table**，存储 `flow_key → worker_id` 映射：

```
┌─────────────────────────────────────────────────┐
│              dispatch_context                     │
│  ┌──────────┐ ┌──────────┐      ┌──────────┐    │
│  │ Shard 0  │ │ Shard 1  │ ...  │ Shard N  │    │
│  │ (hashtab)│ │ (hashtab)│      │ (hashtab)│    │
│  └──────────┘ └──────────┘      └──────────┘    │
└─────────────────────────────────────────────────┘
```

**关键设计**：每个 dispatcher 线程**独占**一个 shard（预处理阶段 RSS 到 dispatcher_id 时就确定了 shard），因此 shard 级别的操作无需加锁。

查找逻辑（`dispatch.c:373-438`）：
- **命中**（same hash + same key）→ 返回已绑定的 `worker_id`（flow 粘性）
- **未命中**→ 执行成本估算 + 选择 worker：

### 2.2 成本估算

```c
// dispatch.c:384-396
if (ctx->proto_lookup_table) {
    // mark9 v2: port → proto_hint (O(1) 数组查找)
    lookup_result_t lr = proto_lookup(ctx->proto_lookup_table,
                                      dst_port, payload_prefix, payload_prefix_len);
    bucket = lr.bucket;
} else {
    // mark7 v1 fallback: port → bucket (Easy/Middle/Hard)
    bucket = cost_table_lookup_bucket(ctx->cost_table,
                                      dst_port, payload_prefix, payload_prefix_len);
}
```

mark9 v2 的 `proto_lookup()` （`ndpi_benchmark.h:618-656`）：

```
Step 1: port_rules[dst_port] 直接命中 (O(1))
     ↓ 未命中
Step 2: 遍历 prefix_rules 匹配 payload 前缀（仅 ambiguous ports）
     ↓ 未命中
Step 3: 返回 PROTO_HINT_UNKNOWN + 默认 bucket
```

### 2.3 Worker 选择策略

```c
// dispatch.c:206
worker_id = choose_policy_worker(ctx, shard, key_hash, bucket, &retire_cost);
```

支持 5 种策略（`dispatch_policy_t`）：

| 策略 | 算法 |
|---|---|
| `RSS` | `hash % num_workers` — 静态哈希 |
| `JSQ` | Join-Shortest-Queue — 选队列最短的 worker |
| `STATIC_POOL` | Easy 流 → E-core，Hard 流 → P-core |
| `OURS` | Cost-aware Join-Shortest-Work — 基于 `pending_cost + new_cost` 选最轻 worker |
| `ORACLE` | 查 ground-truth cost table，做最优调度 |

### 2.4 入队

```c
// reader.c:496 (batch 模式)
packet_queue_push_batch(ctx->workers[worker_id].queue, batches[worker_id], count);
```

Dispatcher 把包推入对应 worker 的 `packet_queue_t` —— 一个**多生产者单消费者**的环形缓冲区（容量 `QUEUE_CAPACITY = 4096`）：

```
packet_queue_t
┌──────────────────────────────────────────────────┐
│ buffer[4096]  (ring buffer, power-of-2)           │
│ head (_Atomic uint32_t, 单调递增的写指针)           │
│ tail (_Atomic uint32_t, 单调递增的读指针)           │
│ finished (_Atomic bool, 生产者结束后置 true)        │
│ prod_lock (pthread_mutex, 多 dispatcher 写保护)    │
└──────────────────────────────────────────────────┘
```

入队时 `memcpy` 包数据到 `queue_packet_t.storage[65535]`，保证 worker 拿到的数据在队列生命周期内有效。

批量模式（`DISPATCH_ENQUEUE_BATCH=32`）：累积 32 个包才推一次，减少锁竞争。

---

## Phase 3: Process（N 个 Worker 线程）

入口：`worker_thread_entry()`

```c
// worker.c:408-433
while (packet_queue_peek(w->queue, &pkt)) {
    worker_process_packet(w, pkt);
    // 更新 retired_cost 和 queue_depth
    packet_queue_consume(w->queue);
}
```

每个 worker 有**独立的**：
- `ndpi_detection_module` — 避免 nDPI 内部状态的锁竞争
- `flow_table` — 开放寻址哈希表，存 `bench_flow_t`
- （可选）`classified_table` — 已识别流的缓存快路径

### worker_process_packet 的 6 步主线

#### Step 1: 解析 (`parse_time_ns`)

```c
parse_ethernet_frame(pkt->data, pkt->caplen, &pp);
```

与预处理阶段相同的解析——取出 IP 版本、协议号、端口、IP 地址、L3 指针和 payload 指针。

（注意：这一步在 preprocess 和 process 阶段都被调用了——preprocess 阶段是为了提取 flow_key 做 hash，process 阶段是为了给 nDPI 提供 `pp.l3` 和 `pp.l3_len` 的起点。）

#### Step 2: 构造 Flow Key + Hash (`keybuild_time_ns`)

```c
flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);
uint64_t h = flow_key_hash(&key);
```

#### Step 3: 查找/创建 Flow 状态 (`flow_lookup_time_ns`)

```c
bench_flow_t *flow = flow_table_get_or_create(w->flows, &key, h, &is_new);
```

`flow_table` 是**开放寻址 + 线性探测**的哈希表（`flow_table.c`）：
- 负载因子 > 0.7 → 自动扩容 rehash
- Tombstone 机制（`SLOT_DELETED`）保持探测链正确
- 新流插入时优先复用 tombstone 槽位

`bench_flow_t` 结构：

```c
typedef struct {
  flow_key_t key;                    // 双向 canonical key
  endpoint_t client;                 // 首包 src（定义"正向"）
  endpoint_t server;                 // 首包 dst
  struct ndpi_flow_struct *ndpi_flow; // nDPI 每流状态机
  uint64_t last_seen_ms;
  uint64_t c2s_packets, s2c_packets;
  uint64_t c2s_bytes, s2c_bytes;
  uint64_t seen_packets;
  bool     protocol_counted;          // 首次识别后置 true
  uint64_t first_enqueue_time_ns;     // 用于计算识别延迟
} bench_flow_t;
```

#### Step 4: 方向判断 + 更新统计

```c
uint8_t dir = endpoint_equal(&src_ep, &flow->client) ? 0 : 1;
```

**约定**：流首包的方向被定义为"正向"（client→server）。后续包通过 `endpoint_equal` 与 client 比较判定方向。这个 `dir` 传给 nDPI 的 `in_pkt_dir`，影响协议识别的内部逻辑（某些协议依赖方向特征）。

#### Step 5: nDPI 增量识别 (`ndpi_call_time_ns`)

```c
struct ndpi_flow_input_info in = {0};
in.in_pkt_dir = dir;
in.seen_flow_beginning = (flow->seen_packets == 0);

ndpi_detection_process_packet(w->ndpi, flow->ndpi_flow,
                              pp.l3, pp.l3_len, ts_ms, &in);
```

**关键**：nDPI 是**增量识别**——每包 `ndpi_detection_process_packet` 推进内部状态机，但不保证每包都有最终结论。可能第 1 包还是 UNKNOWN，第 3 个包才识别出 HTTP。因此不能每包都 +1 识别计数。

#### Step 6: 识别边沿检测 (`proto_check_time_ns`)

```c
if (!flow->protocol_counted) {
    uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
    if (app != NDPI_PROTOCOL_UNKNOWN) {
        flow->protocol_counted = true;
        w->flows_with_protocol_total++;
        worker_record_flow_detect_latency(w, detect_now_ns - first_ns);
    }
}
```

只在 **UNKNOWN → KNOWN** 的边沿触发一次计数，记录识别延迟。

---

## 完整生命周期总结

```
main()
  │
  ├── [1/4] 初始化
  │     ├── ndpi_global_init()         ← 全局只读元数据
  │     ├── cost_table_load()          ← v1 port→bucket 查找表
  │     ├── proto_lookup_table_load()  ← v2 port→proto_hint 查找表 (mark9 新增)
  │     ├── cost_profile_load_csv()    ← {Easy,Middle,Hard} × {P,E}-core 成本
  │     └── oracle_cost_table_load()   ← ground-truth cost（仅 ORACLE 策略）
  │
  ├── [2/4] 创建 Worker
  │     ├── 每个 worker: packet_queue_create() + init_worker_ndpi()
  │     │     └── ndpi_init_detection_module()  ← 独立 nDPI 实例
  │     │     └── flow_table_create(16384)      ← 私有 flow 状态表
  │     └── dispatch_context_create()  ← 共享的 flow→worker 映射表
  │
  ├── [3/4] 启动三阶段流水线
  │     ├── pthread_create(所有 worker)     ← worker 阻塞等包
  │     ├── pthread_create(reader)          ← reader 开始工作
  │     │     ├── load_pcap_packets()       ← 预加载所有包到内存
  │     │     ├── build_dispatch_schedule() ← 按 dispatcher 分组
  │     │     ├── 启动所有 dispatcher 线程
  │     │     ├── pthread_join(所有 dispatcher)
  │     │     └── packet_queue_finish(所有 queue) ← 通知 worker 退出
  │     ├── pthread_join(reader)
  │     └── pthread_join(所有 worker)
  │
  └── [4/4] 汇总输出
        ├── print_benchmark_results()  ← 分项计时 + 吞吐统计
        ├── print_dispatch_summary()   ← dispatch 策略统计
        └── write_structured_results() ← JSON 结构化输出
```

---

## 与"正常从网卡进来的 pcap"的区别

| 维度 | mark9（离线 pcap 文件） | 生产环境（在线网卡） |
|---|---|---|
| **包源** | `pcap_open_offline()` + `pcap_next_ex()` 从文件系统读 | `pcap_open_live()` / AF_PACKET / DPDK / AF_XDP 从网卡 RX ring 读 |
| **数据路径** | 磁盘 → libpcap buffer → `dispatch_packet_t` → ring buffer → worker | NIC → DMA → kernel sk_buff → (或 DPDK 用户态零拷贝) → 应用 |
| **时间节奏** | **全速回放**，无真实时间间隔。10 秒的抓包可能 0.5 秒跑完 | **实时到达**，包按线速到达，有真实的 inter-packet gap |
| **预加载** | **先全部读到内存**（`load_pcap_packets`），再分发处理。可预先知道总包数和 flow 分布 | **无法预加载**，必须边收边处理。不知道何时结束，也不知道总包数 |
| **包截断** | 预加载时截断到 **1400 字节**，节省内存 | 通常处理完整包（或由网卡硬件做截断） |
| **调度计划** | 预处理后 **预先构建 dispatcher 调度**（`build_dispatch_schedule`），按 dispatcher 重排索引 | 无法预知，必须**实时决策**，每包到达时立即决定去向 |
| **批处理** | Dispatcher 可以 **批量入队**（32 包一批），摊销锁开销 | 也可以批量，但延迟敏感场景不能攒太多 |
| **丢包** | **零丢包**——pcap 文件包含所有包 | **可能丢包**——网卡 ring 满、内核 socket buffer 满、应用处理跟不上 |
| **时间戳** | 使用 pcap 文件中的**历史时间戳**（可能是几天前的） | 使用**当前实时时间** |
| **线程分工** | Reader + Dispatcher × N + Worker × M，三层分离用于**benchmark 各阶段独立测量** | 通常只有收包线程 + 处理线程，或 DPDK run-to-completion 模型 |
| **Flow 粘性** | 通过 **dispatch shard hash table** 维持：同一 flow 的后续包查表得到同一个 worker_id | 通常用 **RSS hash**（网卡硬件做 Toeplitz hash）保证同 flow 到同 queue |
| **结束条件** | 所有包分发完毕 → `packet_queue_finish()` → worker drain 队列后退出 | **永不结束**，持续运行 |
| **内存模型** | 预加载阶段分配大量连续内存（19M 包 × 1400 字节结构的数组），峰值内存高 | 只需 ring buffer + flow table，内存稳态 |
| **可复现性** | **完全可复现**——同一个 pcap 每次运行结果一致 | 流量模式变化，不可复现 |

### 最核心的三个区别

1. **"预加载 vs 流式"**：mark9 为了精确测量，选择先把整个 pcap 读到内存再分发。生产系统不可能这样做——必须边收边处理。这导致了截然不同的内存和调度策略。

2. **"全速 vs 实时"**：mark9 以 CPU 能处理的最快速度回放，不存在真实的时间流逝。这意味着队列积压、worker 负载等行为与真实环境不同——真实的 10Gbps 流量有自然的 pacing，而离线回放可能在短时间内灌入大量包。

3. **"分阶段测量 vs 持续运行"**：mark9 的三阶段设计（preprocess → dispatch → process）是为了**独立测量每层开销**，这是 benchmark 的需求。生产系统的收包和处理是交织的，无法干净地分离。

> **一句话总结**：mark9 是一个**批处理式、离线、全速回放**的 benchmark 框架，用于评估 dispatch 策略和 nDPI 性能。它把真实网卡场景的"连续流"改成了"分批预处理 + 并发分发 + 独立处理"的三段式，代价是需要大量预加载内存且无法模拟真实的实时到达模式。
