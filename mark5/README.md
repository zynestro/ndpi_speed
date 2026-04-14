# mark4：当前运行时会测量什么，涉及哪些函数

## 1. mark4 的定位

`mark4` 是单线程直读版本，不走 `reader + worker queue`，也没有 dispatcher。

它的主路径就是：

`pcap_next_ex -> normalize_to_ethernet -> parse_ethernet_frame -> flow_table_get_or_create -> ndpi_detection_process_packet -> 汇总输出 -> CSV`

对应源码：

- `mark4/src/main.c`
- `mark4/src/packet_parser.c`
- `mark4/src/flow_table.c`

## 2. 当前运行时实际测量的内容

mark4 当前真正统计、输出的内容主要分 4 类。

### 2.1 全局包级统计

在主循环里维护这些计数器：

- `total_packets`
  - 成功从 `pcap_next_ex()` 读到的包数
- `total_bytes`
  - 所有读到的包的原始 `hdr->len` 累加
- `parse_ok_packets`
  - 成功通过 `parse_ethernet_frame()` 的包数
- `parse_fail_packets`
  - 标准化成功，但 L3/L4 解析失败的包数
- `normalize_fail_packets`
  - `normalize_to_ethernet()` 失败的包数

这些值最后打印为：

- `Total packets`
- `Total bytes`
- `Parse-ok packets`
- `Parse-fail packets`
- `Normalize-fail packets`

### 2.2 全局流级统计

主循环中还会统计：

- `flows_created`
  - 新流数量，也就是 `flow_table_get_or_create()` 返回 `is_new=true` 的次数
- `flows_detected`
  - 至少被 nDPI 首次识别成功一次的流数量

最终打印为：

- `Total flows`
- `Detected flows`

这里的“Detected”定义是：

- 对某条流调用 `ndpi_detection_process_packet()` 后
- 再通过 `ndpi_get_flow_appprotocol()` 读到的协议不再是 `NDPI_PROTOCOL_UNKNOWN`
- 并且该流此前还没被计数过

### 2.3 时间开销统计

mark4 当前会统计 3 类时间：

- `Elapsed`
  - 整次运行的墙钟时间
- `pcap_read`
  - 只包住 `pcap_next_ex()` 的累计耗时
- `process`
  - 每个包从标准化、解析、建流/查流到 nDPI 识别这段累计耗时

注意：

- `process` 不包含最后的汇总打印和 CSV 写盘
- `Elapsed` 包含全部阶段，所以通常会大于 `pcap_read + process`

### 2.4 每条已识别流的阶段性处理统计

对于每条首次识别成功的流，mark4 当前会记录的不是“首包到识别成功的墙钟延迟”，而是按识别前后拆分的累计处理时间和包位次：

- `detecting_time_ns_total`
  - 该 flow 在“首次识别成功之前”累计处理了多少纳秒
- `post_time_ns_total`
  - 该 flow 在“首次识别成功之后”累计处理了多少纳秒
- `detecting_packet_samples_ns`
  - 识别前每个包的处理耗时样本，用于后续计算 p50/p99
- `post_packet_samples_ns`
  - 识别后每个包的处理耗时样本，用于后续计算 p50/p99
- `detection_packet_in_flow`
  - 这条流的第几个包被识别出来
- `detection_packet_global`
  - 从整份 PCAP 的全局进度看，是在第几个包时识别出来
- `detected_master_proto`
  - nDPI master protocol
- `detected_app_proto`
  - nDPI app protocol
- `detected_category`
  - nDPI category

这些数据会进入：

- 控制台 `Per-flow Detection Details`
- 控制台 `Category Summary`
- 控制台 `Proto+Category Summary`
- `proto_category_summary.csv`

## 3. 它没有单独测量什么

为了避免误解，这几个点当前 **没有被单独拆出来统计**：

- 没有单独统计 `normalize_to_ethernet()` 自己的耗时
- 没有单独统计 `parse_ethernet_frame()` 自己的耗时
- 没有单独统计 `flow_table_get_or_create()` 的耗时
- 没有单独统计 `ndpi_detection_process_packet()` 的耗时
- 没有输出 PPS / Gbps / 每流平均包数
- 没有输出未识别流的协议分布
- 没有把 EOF 后的聚合打印、`qsort()`、CSV 落盘时间单独计入 `process`

所以它更像是一个：

- 单线程端到端基线 benchmark
- 外加“协议识别前后处理成本”观测器

## 4. 运行时会经过哪些关键函数

下面按实际执行顺序列出。

### 4.1 启动与初始化

对应 `mark4/src/main.c`

- `parse_args()`
- `make_timestamp()`
- `mkdir_p()`
- `set_thread_affinity()`，仅当传了 `-c`
- `ndpi_global_init()`
- `ndpi_init_detection_module()`
- `ndpi_set_config()`
- `ndpi_load_protocols_file()`，仅当传了 `-p`
- `ndpi_finalize_initialization()`
- `flow_table_create()`
- `pcap_open_offline()`
- `pcap_datalink()`

### 4.2 每个包的热路径函数

对应 `mark4/src/main.c`、`mark4/src/packet_parser.c`、`mark4/src/flow_table.c`

每个包都会经过这些关键函数：

1. `pcap_next_ex()`
2. `normalize_to_ethernet()`
3. `parse_ethernet_frame()`
4. `flow_key_from_packet()`
5. `flow_key_hash()`
6. `flow_table_get_or_create()`
7. 新流时额外执行：
   - `ndpi_calloc()`
   - `set_ndpi_flow_tuple()`
8. `endpoint_equal()`
9. `ndpi_detection_process_packet()`
10. 若尚未识别成功，则继续检查：
   - `ndpi_get_flow_appprotocol()`
   - `ndpi_get_flow_masterprotocol()`
   - `ndpi_get_flow_category()`

### 4.3 `packet_parser.c` 内部会走到的函数

- `normalize_to_ethernet()`
  - 支持 `DLT_EN10MB`
  - 支持 `DLT_NULL / DLT_LOOP`
  - 支持 `DLT_RAW`
  - 支持 `DLT_LINUX_SLL`
  - 支持 `DLT_LINUX_SLL2`
- `parse_ethernet_frame()`
  - 解析 Ethernet / VLAN / QinQ
  - 解析 IPv4
  - 解析 IPv6
  - 提取 TCP / UDP 端口
- `parse_ipv6_find_l4()`
  - 处理 IPv6 扩展头定位
- `flow_key_from_packet()`
  - 生成双向 canonical flow key
- `endpoint_equal()`
  - 判断当前包方向

### 4.4 `flow_table.c` 内部会走到的函数

- `flow_table_create()`
- `flow_table_get_or_create()`
- `flow_key_hash()`
- `fnv1a64()`
- `flow_table_rehash()`，当负载升高时触发
- `flow_table_foreach()`，结束后做汇总时使用
- `flow_table_destroy()`

说明：

- `flow_table_delete()` 和 `compute_flow_hash()` 当前 `mark4` 主流程没有用到

## 5. 运行结束后会输出什么

### 5.1 控制台总览

固定会输出：

- `Total packets`
- `Total bytes`
- `Parse-ok packets`
- `Parse-fail packets`
- `Normalize-fail packets`
- `Total flows`
- `Detected flows`
- `Elapsed | pcap_read | process`

### 5.2 Per-flow 明细

只有未开启 `-q` 时才输出：

- `flow_table_foreach(..., print_flow_cb, ...)`

每条流会显示：

- `client/server endpoint`
- `proto`
- `category`
- `flow_detecting`
- `flow_post`
- `flow_total`
- `detect_pkt(flow)`
- `detect_pkt(global)`

### 5.3 Category Summary

通过：

- `flow_table_foreach(..., aggregate_category_cb, ...)`

按 `category` 聚合输出：

- `flows`
- `avg_flow_detecting`
- `avg_flow_post`
- `avg_flow_total`
- `avg_detect_pkt(flow)`
- `avg_detect_pkt(global)`

### 5.4 Proto+Category Summary

通过：

- `flow_table_foreach(..., aggregate_proto_cb, ...)`
- `qsort(..., proto_stat_cmp_desc)`

按 `(master_proto, app_proto, category)` 聚合输出：

- `flows`
- `avg_flow_detecting`
- `avg_flow_post`
- `avg_flow_total`
- `detecting_pkt_p50`
- `detecting_pkt_p99`
- `post_pkt_p50`
- `post_pkt_p99`
- `avg_detect_pkt(flow)`
- `avg_detect_pkt(global)`

### 5.5 CSV 文件

输出文件：

- `output/<timestamp>/proto_category_summary.csv`

写文件函数：

- `write_proto_summary_csv()`

CSV 列如下：

- `proto_name`
- `master_proto`
- `app_proto`
- `category_name`
- `category_id`
- `flows`
- `avg_flow_detecting_ms`
- `avg_flow_post_ms`
- `avg_flow_total_ms`
- `detecting_pkt_p50_us`
- `detecting_pkt_p99_us`
- `post_pkt_p50_us`
- `post_pkt_p99_us`
- `avg_detect_pkt_flow`
- `avg_detect_pkt_global`

## 6. 一句总结

当前 mark4 跑起来，本质上测的是：

- 单线程从 PCAP 读包到 nDPI 首次识别成功的端到端处理过程
- 全局包/流统计
- 每条已识别流在“识别前”和“识别后”分别累计花了多少处理时间，以及第几个包识别成功
- 按 category、proto+category 的识别结果聚合

如果你后面想把 README 再补成“带源码行号的版本”，我也可以继续帮你把每一项后面直接标到具体行号。
