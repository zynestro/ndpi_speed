# Mark8：闭环 EWMA 自适应调度

## 相比 Mark7 的变化

Mark8 新增调度策略 `DISPATCH_POLICY_ADAPTIVE`，通过 worker 的 EWMA（指数加权移动平均）反馈实现闭环代价估计。

### 与 mark7 `DISPATCH_POLICY_OURS`（静态开环）的主要区别：

| 维度（Aspect） | mark7 (ours) | mark8 (adaptive) |
|--------|-------------|------------------|
| 代价模型（Cost model） | 静态 3-bucket 表 | 逐协议连续值，EWMA 更新 |
| 反馈（Feedback） | 无（开环） | Worker 将实际检测代价写入 ring |
| 冷启动（Cold start） | 始终使用静态表 | 累积 >= 8 个样本前回退到静态表 |
| 核能力（Core capability） | 编译期常量 | 运行时标定的速度比 |

### 修改的文件（相对于 mark7 副本）：

- `include/ndpi_benchmark.h` — 新增 `adaptive_cost_entry_t`、`adaptive_cost_table_t`、
  `cost_feedback_entry_t`、`cost_feedback_ring_t` 结构体；新增 `DISPATCH_POLICY_ADAPTIVE`
  枚举值；在 `worker_context_t` 中新增 `feedback_ring` 字段
- `include/benchmark_internal.h` — 新增 `dispatch_context_set_adaptive()` 和
  `dispatch_get_adaptive_table()` 声明
- `src/dispatch.c` — 在 `dispatch_context` 中新增 adaptive 字段；新增
  `adaptive_drain_feedback()`、`choose_adaptive_worker()` 函数；在
  `choose_policy_worker()` 中新增 `DISPATCH_POLICY_ADAPTIVE` 分支；在策略名/解析中
  新增 "adaptive"；新增 `dispatch_context_set_adaptive()` 和
  `dispatch_get_adaptive_table()`
- `src/worker.c` — 在协议检测边缘（`!flow->protocol_counted` 代码块内）新增
  feedback ring 写入
- `src/main.c` — 新增 adaptive table + feedback ring 的分配/初始化；新增 adaptive
  代价表摘要输出；更新 usage/banner 为 mark8；新增 adaptive 资源清理
- `CMakeLists.txt` — 目标重命名为 `ndpiBenchmarkMark8`

### 设计决策：

- 每个 worker 一个 SPSC 无锁 ring（worker 与 dispatcher 之间无竞争）
- 反馈在协议确认时按流触发（非逐包）
- 每 256 次 dispatch 执行一次 drain（均摊开销）
- 定点 EWMA：alpha = 13/256 ≈ 0.05
- Ring 满则丢弃（worker 永不阻塞）
- 所有现有策略保留且完全可用

## 构建方法

```bash
cd /path/to/mark8
mkdir -p build && cd build
cmake -DNDPI_PREFIX=$HOME/ndpi-install -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

带调试符号构建：
```bash
cmake -DNDPI_PREFIX=$HOME/ndpi-install -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

## 运行方法

### 静态代价感知（mark7 逻辑，用作基线对比）：
```bash
./ndpiBenchmarkMark8 -P ours -i trace.pcap -o results_static/
```

### 自适应 EWMA（mark8 新增）：
```bash
./ndpiBenchmarkMark8 -P adaptive -i trace.pcap -o results_adaptive/
```

### 其他策略（均从 mark7 保留）：
```bash
./ndpiBenchmarkMark8 -P rss -i trace.pcap -o results_rss/
./ndpiBenchmarkMark8 -P jsq -i trace.pcap -o results_jsq/
./ndpiBenchmarkMark8 -P oracle -O oracle_costs.csv -i trace.pcap -o results_oracle/
```

### 漂移实验（两个 trace 拼接）：
```bash
cat trace_A.pcap trace_B.pcap > trace_drift.pcap
./ndpiBenchmarkMark8 -P ours     -i trace_drift.pcap -o results_drift_static/
./ndpiBenchmarkMark8 -P adaptive -i trace_drift.pcap -o results_drift_adaptive/
```

### 完整参数列表：
```
  -i <file>    待处理的 PCAP 文件（必需）
  -n <num>     Worker 线程数（默认：16）
  -c <list>    Worker 核心列表
  -d <list>    Dispatcher 核心列表
  -m <file>    查找表 JSON
  -C <file>    离线 P/E bucket 代价 CSV
  -P <policy>  rss|jsq|static|ours|oracle|adaptive（默认：ours）
  -O <file>    Oracle 流代价 CSV
  -o <dir>     结构化结果输出目录
  -p <file>    协议配置文件
  -q           静默模式
```

## 已知问题 / 限制

### macOS 与 Linux 差异：

1. **线程亲和性**（`set_thread_affinity`）使用 Linux 特有的 `sched_setaffinity`。
   在 macOS 上为空操作或编译错误（取决于实现方式）。
   不影响正确性，仅影响性能测量精度。

2. **`posix_memalign`** 在 macOS 上可用，但 `aligned_alloc` 可能更优。
   当前代码使用 `posix_memalign`，两个平台均支持。

3. **`CLOCK_MONOTONIC_RAW`** 为 Linux 特有。在 macOS 上可能需要回退到
   `CLOCK_MONOTONIC` 或 `mach_absolute_time`。

4. **核心类型映射**（`core_id < 16 => P-core`）针对 i9-14900 平台硬编码。
   macOS Mx 芯片拓扑不同。

5. **`_GNU_SOURCE`** 宏定义为部分 Linux 特有 API 所需。

### Adaptive 策略限制：

- 流创建时协议未知。在 adaptive table 累积足够样本前，dispatcher 回退到
  静态 bucket 代价。
- EWMA alpha 固定为 0.05。快速漂移检测（alpha=0.30）已定义但尚未自动触发
  （未来：检测方差突增时切换）。
- Adaptive table 按 nDPI 协议 ID 索引（最大 256）。ID >= 256 的协议无法
  受益于自适应代价修正。
- 速度比运行时标定初始化为 1.8x，但尚未根据观测到的 P/E 代价比自动更新
  （未来增强）。
