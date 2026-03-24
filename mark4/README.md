# mark4: 执行流程与代码对应（详细版）

## 1. mark4 的定位

`mark4` 是单线程直读版本，去掉了 `reader + worker queue`（以及 mark3 的 dispatcher 层）。

执行链路就是一条主循环：

`pcap_next_ex -> normalize -> parse -> flow_table -> ndpi -> 统计/汇总 -> CSV`

构建目标只包含：

- `src/main.c`
- `src/packet_parser.c`
- `src/flow_table.c`

## 2. 启动阶段（main）

对应：`src/main.c`

### 2.1 参数解析

- `parse_args()`
  - 必选：`-i <pcap>`
  - 可选：`-c/-p/-o/-q`
  - `-o` 为输出根目录（默认 `output`）

### 2.2 输出目录准备

- `make_timestamp()` 生成 `YYYYMMDD_HHMMSS`
- `mkdir_p()` 创建 `output/<timestamp>/`
- 目标 CSV 路径：`proto_category_summary.csv`

### 2.3 初始化 nDPI 与 flow table

1. `ndpi_global_init()`
2. `ndpi_init_detection_module(g_ctx)`
3. `ndpi_set_config(... tcp_ack_payload_heuristic ...)`
4. 可选 `ndpi_load_protocols_file(...)`
5. `ndpi_finalize_initialization(...)`
6. `flow_table_create(16384)`

### 2.4 打开 PCAP

- `pcap_open_offline(...)`
- 获取 `linktype = pcap_datalink(pc)`

## 3. 单线程主循环（核心）

对应：`src/main.c` 的 `while (1)` 循环

每个包执行：

1. `pcap_next_ex` 读包
2. `normalize_to_ethernet(...)`
3. `parse_ethernet_frame(...)`
4. `flow_key_from_packet(...)`
5. `flow_table_get_or_create(...)`
6. 若新流：
   - 初始化 `bench_flow_t`
   - 分配 `flow->ndpi_flow = ndpi_calloc(...)`
   - `set_ndpi_flow_tuple(...)`
7. 更新流向统计（c2s/s2c 包数字节）
8. 调 `ndpi_detection_process_packet(...)`
9. 若该流首次识别成功：
   - `ndpi_get_flow_appprotocol(...)`
   - 记录：
     - `detected_app_proto/master_proto/category`
     - `detection_packet_in_flow`
     - `detection_packet_global`
     - `detection_latency_ns`

主循环同时累计：

- `total_packets/total_bytes`
- `parse_ok/parse_fail/normalize_fail`
- `flows_created/flows_detected`
- `pcap_read_ns/process_ns`

## 4. 流表与解析模块职责

### 4.1 `src/packet_parser.c`

- `normalize_to_ethernet`：
  - 统一 DLT 差异（EN10MB/NULL/LOOP/RAW）
- `parse_ethernet_frame`：
  - 解析 IPv4/IPv6 + TCP/UDP
- `flow_key_from_packet`：
  - 构造双向规范化 flow key

### 4.2 `src/flow_table.c`

- `flow_table_get_or_create`：开放寻址哈希表热路径
- `flow_key_hash`：FNV-1a
- `flow_table_foreach`：后处理聚合遍历

## 5. 后处理与输出阶段

主循环结束后（`main.c`）：

### 5.1 总览输出

- 总包数/总字节/解析失败
- 总流数/识别流占比
- `Elapsed | pcap_read | process`

### 5.2 逐流明细（非 `-q`）

- `flow_table_foreach(..., print_flow_cb, ...)`
- 每条流打印：
  - client/server endpoint
  - proto/category
  - detect_latency
  - detect_pkt(flow/global)

### 5.3 分类汇总

- `flow_table_foreach(..., aggregate_category_cb, ...)`
- 输出 `Category Summary`

### 5.4 协议+分类汇总

- `flow_table_foreach(..., aggregate_proto_cb, ...)`
- `qsort(proto_ctx.items, ..., proto_stat_cmp_desc)`
- 输出 `Proto+Category Summary`

### 5.5 CSV 落盘

- `write_proto_summary_csv(csv_path, ndpi, proto_stats, count)`
- 字段：
  - `proto_name/master_proto/app_proto`
  - `category_name/category_id`
  - `flows`
  - `avg_detect_latency_ms`
  - `avg_detect_pkt_flow`
  - `avg_detect_pkt_global`

## 6. 资源回收阶段

按顺序：

1. `pcap_close(pc)`
2. `flow_table_destroy(..., free_flow_cb, ...)`
3. `ndpi_exit_detection_module(ndpi)`
4. `ndpi_global_deinit(g_ctx)`

## 7. 运行示例

```bash
./mark4/build/ndpiBenchmarkMark4 -i /path/to/xx.pcap -q
```

输出目录示例：

- `output/20260323_224756/proto_category_summary.csv`

## 8. 输出结果怎么看（重点）

### 8.1 先看控制台总览

运行结束会先给一组总览指标：

- `Total packets / Total bytes`：PCAP 中总包量与总字节。
- `Parse-ok / Parse-fail / Normalize-fail`：
  - `Normalize-fail` 高：通常是链路层类型不支持或包截断。
  - `Parse-fail` 高：说明已标准化但 L3/L4 解析失败。
- `Total flows`：成功建流数量。
- `Detected flows`：至少识别出一次协议的流数量与占比。
- `Elapsed | pcap_read | process`：
  - `pcap_read` 偏高：I/O 或 pcap 读取开销大。
  - `process` 偏高：解析/flow_table/nDPI 计算开销大。

### 8.2 CSV 每一列含义（`proto_category_summary.csv`）

每一行代表一个分组：`(proto_name, master_proto, app_proto, category_name)`。

- `proto_name`：协议名（如 `DNS`、`HTTP_Connect.Github`）。
- `master_proto/app_proto`：nDPI 主协议 ID / 应用协议 ID。
- `category_name/category_id`：nDPI 分类名与分类 ID。
- `flows`：该分组下的流数量（不是包数量）。
- `avg_detect_latency_ms`：该分组流从首包到“首次识别成功”的平均时延（毫秒）。
- `avg_detect_pkt_flow`：平均每条流在第几包被识别（值越小越快）。
- `avg_detect_pkt_global`：在全局处理进度中，平均到第几包时识别（更偏时间位置，不是单流难度）。

### 8.3 “横坐标分别是啥？”

这个 CSV 本身是“汇总表”，没有天然横坐标；你画图时自己定义：

- 看协议分布：`x = proto_name`，`y = flows`
- 看识别速度（时延）：`x = proto_name`，`y = avg_detect_latency_ms`
- 看识别速度（包数）：`x = proto_name`，`y = avg_detect_pkt_flow`
- 若协议太多，建议只画 `flows` Top-N（如前 10 或前 15）

控制台中的 `Category Summary` / `Proto+Category Summary` 也是分组统计，不是时间序列图，因此也没有固定横坐标。

### 8.4 结合你这份样例怎么解读

你贴的结果可以读出这些关键信息：

- `DNS` 流最多（`7099`），且 `avg_detect_pkt_flow = 1.0`，说明 DNS 基本首包即识别。
- `HTTP`（Web）`873` 流、`avg_detect_pkt_flow ≈ 4.82`，识别通常需要前几包。
- `MySQL` `252` 流、`avg_detect_pkt_flow = 7.0`，比 DNS/HTTP 更靠后识别。
- `HTTP_Connect.*`（Microsoft365/Github/Azure）存在，说明抓包里确实有较多 TLS 隧道/代理场景。
- `SSH` 只有 `15` 流，符合你脚本里 SSH 生成次数较少的设置。
- 同一个 `proto_name` 可出现在不同 `category`（例如 `HTTP_Connect` 同时在 `ArtifIntelligence` 和 `Web`），这是 nDPI 在不同流特征下的正常分类结果。
