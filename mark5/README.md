# mark5

`mark5` 是在 `mark4` 单线程直读骨架上继续演进出来的 profiling 版本，核心目标是把：

- 首包签名
- 识别前的处理成本
- 协议级平均画像

统一落成可直接做分析和调度建模的 CSV。

当前实现采用“共享主逻辑 + 两个可执行文件”的方式：

- `ndpiBenchmarkMark5Time`
  - 只测时间相关成本
- `ndpiBenchmarkMark5Hardware`
  - 只测硬件计数器

这样做的原因是：时间测量和 PMU 测量的探针开销、解释口径都不一样，拆开跑更干净，也更适合后面做论文分析。

## 1. 主流程

两个可执行文件共享同一套主路径：

`pcap_next_ex -> normalize_to_ethernet -> parse_ethernet_frame -> flow_table_get_or_create -> ndpi_detection_process_packet -> per-flow accumulate -> per-protocol aggregate -> CSV`

执行时：

1. 逐包读取 pcap
2. 标准化链路层为 Ethernet 视图
3. 解析 IP/TCP/UDP 和 payload 前缀
4. 用 canonical flow key 查/建流表
5. 调用 nDPI 推进识别
6. 按“识别前 / 识别后”拆分累计指标
7. 结束后输出逐流表和按协议聚合表

## 2. 输出目录

默认输出根目录是仓库级：

`ndpi_speed/output`

每次运行会新建一个时间戳子目录：

`output/<timestamp>/`

时间模式输出：

- `time_flow_profile.csv`
- `time_protocol_summary.csv`

硬件模式输出：

- `hardware_flow_profile.csv`
- `hardware_protocol_summary.csv`

## 3. 两个可执行文件

### 3.1 时间模式

构建目标：

- `mark5/build/ndpiBenchmarkMark5Time`

作用：

- 统计每条流在“首次识别成功前”的总时间
- 拆出 `detection-only` 时间
- 拆出 `flow-table` 时间
- 用减法得到 `other` 时间
- 记录前 20 包逐包时间样本

### 3.2 硬件模式

构建目标：

- `mark5/build/ndpiBenchmarkMark5Hardware`

作用：

- 用 `perf_event_open` 打开两组 PMU 事件
- 每包前后各读一次 group，得到增量
- 累加识别前的：
  - instructions
  - cycles
  - LLC misses
  - LLC references
  - branch misses
- 记录前 20 包逐包硬件样本

当前事件配置：

- work group:
  - `instructions`
  - `cpu cycles`
- bottleneck group:
  - `llc misses`
  - `llc references`
  - `branch misses`

事件全程使用：

- `exclude_kernel = 1`
- `exclude_hv = 1`

### 3.3 硬件模式的权限要求

硬件模式依赖 Linux perf 权限。

如果系统的：

- `/proc/sys/kernel/perf_event_paranoid`

设置过高（例如 `4`），普通用户会收到：

- `perf_event_open(...) failed: Permission denied`

这种情况下需要：

- 降低 `perf_event_paranoid`
- 或者给进程 `CAP_PERFMON`
- 或者以有权限的用户运行

## 4. 时间模式 CSV 含义

### 4.1 `time_flow_profile.csv`

每条流一行。

核心字段：

- `flow_id`
  - 导出顺序号
- `protocol_detected`
  - 该流是否最终被 nDPI 识别
- `ip_version`
- `l4_proto`
- `server_port`
- `prefix_4`
  - 首包 payload 前 4 字节十六进制
- `detect_pkt_in_flow`
  - 第几个包识别成功
- `protocol`
  - 最终协议名
- `detecting_total_ms`
  - 识别前整段累计处理时间
- `detecting_detection_only_ms`
  - 识别前 `ndpi_detection_process_packet()` 累计时间
- `detecting_flow_table_ms`
  - 识别前 `flow_table_get_or_create()` 累计时间
- `detecting_other_ms`
  - `detecting_total - detection_only - flow_table`
- `detecting_detection_ratio`
  - `detection_only / total`
- `detecting_flow_table_ratio`
  - `flow_table / total`
- `detecting_other_ratio`
  - `other / total`
- `detecting_bytes`
  - 到首次识别成功前累计看到的字节数
- `packets_in_flow`
- `bytes_in_flow`

此外还会展开前 20 包逐包样本：

- `pkt01_total_ns`
- `pkt01_detection_ns`
- `pkt01_flow_table_ns`
- `pkt01_other_ns`
- ...
- `pkt20_*`

### 4.2 `time_protocol_summary.csv`

按协议聚合，给出每种协议的平均值。

核心字段：

- `flows`
- `avg_detect_pkt_in_flow`
- `avg_detecting_bytes`
- `avg_detecting_total_ms`
- `avg_detecting_detection_only_ms`
- `avg_detecting_flow_table_ms`
- `avg_detecting_other_ms`
- `avg_detecting_detection_ratio`
- `avg_detecting_flow_table_ratio`
- `avg_detecting_other_ratio`

这张表适合看“协议平均识别成本长什么样”。

## 5. 硬件模式 CSV 含义

### 5.1 `hardware_flow_profile.csv`

每条流一行。

核心字段：

- `detecting_instructions`
  - 识别前累计 retired instructions
- `detecting_cycles`
  - 识别前累计 CPU cycles
- `detecting_ipc`
  - `instructions / cycles`
- `detecting_llc_misses`
- `detecting_llc_refs`
- `detecting_llc_miss_ratio`
  - `llc_misses / llc_refs`
- `detecting_branch_misses`
- `detecting_branch_miss_per_kinst`
  - 每千条识别前指令对应多少 branch miss
- `detecting_bytes`
- `detect_pkt_in_flow`

还会展开前 20 包逐包样本：

- `pkt01_instr`
- `pkt01_cycles`
- `pkt01_llc_misses`
- `pkt01_llc_refs`
- `pkt01_branch_misses`
- ...
- `pkt20_*`

### 5.2 `hardware_protocol_summary.csv`

按协议聚合，给出每种协议识别前硬件画像平均值。

核心字段：

- `avg_detecting_instructions`
- `avg_detecting_cycles`
- `avg_detecting_ipc`
- `avg_detecting_llc_misses`
- `avg_detecting_llc_refs`
- `avg_detecting_llc_miss_ratio`
- `avg_detecting_branch_misses`
- `avg_detecting_branch_miss_per_kinst`

这张表适合回答：

- 哪些协议“本身工作量大”
- 哪些协议“主要卡在 cache”
- 哪些协议“分支路径更复杂”

## 6. 构建与运行

配置：

```bash
cmake -S mark5 -B mark5/build -DNDPI_PREFIX=$HOME/ndpi-install
```

编译：

```bash
cmake --build mark5/build --target ndpiBenchmarkMark5Time
cmake --build mark5/build --target ndpiBenchmarkMark5Hardware
```

运行时间模式：

```bash
./mark5/build/ndpiBenchmarkMark5Time -i input/Monday-WorkingHours.pcap -q
```

运行硬件模式：

```bash
./mark5/build/ndpiBenchmarkMark5Hardware -i input/Monday-WorkingHours.pcap -q
```

## 7. 实现思路总结

这个版本最核心的设计是：

- 共享同一套单线程 pcap 处理主循环
- 共享同一套 flow 状态与协议判定逻辑
- 只在“计量逻辑”和“CSV 输出”上通过编译期开关分叉

这样做的好处是：

- 时间版和硬件版的流定义完全一致
- 输出字段可以自然对齐
- 不需要维护两份容易漂移的主循环代码
- 后续新增指标时，只改对应模式的计量块即可
