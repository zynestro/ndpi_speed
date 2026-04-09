# scripts 目录说明

`scripts/` 按用途分成 `setup`、`data`、`benchmarks`、`analysis`、`legacy` 几类。下面按目录说明每个脚本现在的实际功能、典型输入输出，以及适合什么时候用。

## 目录总览

### `setup/`

用于跑 benchmark 前做机器环境准备，尽量降低频率波动、绑核干扰和 SMT 影响。

### `data/`

用于准备 PCAP 输入数据，包括合成流量和抓取一小段真实流量。

### `benchmarks/`

用于批量运行各代 `mark` 版本的 benchmark，并把结果落成 CSV / PNG。

### `analysis/`

用于对 benchmark 结果做复盘、画图、聚合统计，或者做 CPU 单线程能力测试。

### `legacy/`

保留一些早期手写命令或旧入口，主要作参考，不建议作为主流程使用。

## setup

### `setup/prepare_benchmark_env.sh`

用途：
- 在 Ubuntu/Linux 上把机器切到更稳定的 benchmark 状态。
- 尝试切换到 `performance` 电源策略。
- 可选关闭 SMT/超线程。
- 粗略识别 P-core / E-core，并给出建议绑核方案。
- 可选生成 `scripts/setup/benchmark_env.sh` 供后续 `source` 使用。

主要参数：
- `--disable-smt`：关闭 SMT。
- `--write-env-file`：写出环境变量文件。

输出：
- 控制台打印当前 CPU 拓扑、governor、SMT 状态、估计的 P/E 核列表。
- 可选生成 `scripts/setup/benchmark_env.sh`。

适用场景：
- 在正式扫 benchmark 前先把环境固定住。
- 在混合架构 CPU 上快速估计哪些逻辑核更适合 reader / worker。

## data

### `data/generate_1500b_pcap.py`

用途：
- 生成较大的合成 PCAP，给 nDPI benchmark 做吞吐测试。
- 流量里混合了 HTTP、HTTPS、DNS、SSH、MySQL 等协议。
- 支持按目标文件大小持续写出，而不是只按固定流数生成。

主要参数：
- `-o/--output`：输出文件路径。
- `--output-dir`：输出目录。
- `--flows`：流数量。
- `--pkts-per-flow`：每条流的包数。
- `--payload-size`：最大载荷大小。
- `--target-mb` / `--target-bytes`：目标 PCAP 大小。
- `--size-profile`：`mtu` / `mixed` / `small`。
- `--plaintext-only`：只生成明文类协议。

输出：
- 默认输出到 `input/seed_150b.pcap`。

适用场景：
- 需要一个可控、可重复生成的大体量测试 PCAP。
- 不方便抓真实流量，但又想让输入比纯随机包更像真实协议。

### `data/cap-pcap.sh`

用途：
- 用 `tcpdump` 抓一段小规模真实流量，同时主动发起 DNS、HTTP、HTTPS、SSH 等请求。
- 目标是快速凑一份“带协议混合度”的 PCAP，适合 nDPI 识别测试。

主要参数和环境变量：
- `OUTPUT`：输出 PCAP 路径。
- `IFACE`：抓包网卡。
- `CAPTURE_SEC`：最长抓包时长。
- `MAX_PKTS`：最大包数。
- `SNAPLEN`：抓包截断长度。
- `PROFILE`：`encrypted_heavy` 或 `balanced`。

输出：
- 默认输出到 `input/cap_traffic_fast.pcap`。
- 如果系统有 `capinfos`，还会打印基础统计信息。

适用场景：
- 想快速做一份含 DNS/HTTP/TLS/SSH 的真实抓包样本。
- 想让 TLS/SSH 协议占比更高时，可以用默认的 `encrypted_heavy`。

## benchmarks

### `benchmarks/mark0/benchmark_sweep_mark0.py`

用途：
- 面向较早期 `mark0` 二进制的自动化扫描脚本。
- 同时 sweep `worker` 数量和 `loops` 次数。
- 从程序输出中解析 `Bandwidth`、`Throughput`、`Cycles per packet`、`Elapsed Time` 等指标。

输出：
- 多张折线图。
- 一张 2x2 综合对比图。
- CSV 结果文件。

适用场景：
- 复现早期 `mark0` 的 worker / loops 扫描实验。

说明：
- 这是老版本 benchmark 用的脚本，和后面的 `mark1/2/3/4` 工作流已经不完全一致。

### `benchmarks/mark1/benchmark_sweep_mark1.py`

用途：
- `mark1` 的主扫描脚本。
- 默认 reader 固定绑核到 `0`，worker 绑到 `1..N`。
- 不使用 `loops`，直接按 `workers` 扫描。
- 会解析比较完整的 `read` / `process` 时间拆分，以及每核 process time。

主要输出：
- `benchmark_results_<timestamp>.csv`
- dashboard PNG
- 多种折线图

适用场景：
- 跑标准的 `mark1` worker 数量扩展实验。
- 想看 `read_time_sec`、`process_time_sec` 以及更细的处理阶段拆分。

### `benchmarks/mark1/benchmark_sweep_mark1_singlecore.py`

用途：
- `mark1` 单 worker 逐核扫描脚本。
- reader 默认固定在 `31`，每次只起一个 worker。
- 用来比较“worker 放在哪个逻辑核上更快”。

主要参数：
- `--reader-core`：reader 所在核心。
- `--worker-cores`：要遍历的 worker 核列表。

输出：
- `output/<timestamp>-singlecore/benchmark_results_<timestamp>.csv`
- `output/<timestamp>-singlecore/benchmark_dashboard_<timestamp>.png`

适用场景：
- 排查某些核心慢、NUMA/调度异常、P/E 核混用等问题。

### `benchmarks/mark1/run_mark1_sweep_all_10g.sh`

用途：
- `mark1` 扫描脚本的 shell 包装器。
- 默认对 `input/seed_10G.pcap` 跑 sweep。
- 目前只启用了 `ndpiBenchmark`，其他变体留在脚本里注释掉了。

输出：
- 实际输出由 `benchmark_sweep_mark1.py` 决定，通常在 `output/` 下生成时间戳目录。

适用场景：
- 想一条命令跑完整套 `mark1` 10G 输入扫描。

### `benchmarks/mark2/benchmark_sweep_mark2.py`

用途：
- `mark2` 的扫描脚本。
- 支持两种模式：
- `worker_count`：扫描 worker 数量，执行形态是 `-n K -c 1..K -r 0`
- `worker_core`：固定单 worker，扫描 worker 核编号，执行形态是 `-n 1 -c C -r 0`

输出：
- CSV 结果
- 2x2 dashboard
- 按模式不同绘制 worker 数量或 worker core 的时间分布图

适用场景：
- 比较 `mark2` 在扩线程和单核落点两种维度上的表现。

### `benchmarks/mark3/benchmark_sweep_mark3.py`

用途：
- `mark3` 的主扫描脚本。
- 用户不直接输入 `-n`，脚本会根据 `worker_set` 长度自动推导 worker 数。
- 支持同时 sweep `worker_sets` 和 `reader_sets`。
- 支持两种任务组合模式：
- `paired`：第 `i` 个 worker set 对第 `i` 个 reader set
- `cross`：worker set 与 reader set 做笛卡尔积

配置能力：
- 可以直接在命令行传集合字符串，例如 `2,3,4;6,7`
- 也可以从 JSON / YAML 配置文件读取
- 仓库里的 `benchmarks/mark3/sweep3.yaml` 是一个示例配置

输出：
- `output/<timestamp>/benchmark_results_<timestamp>.csv`
- `output/run.log`
- dashboard PNG

CSV 里会包含：
- `worker_set`
- `reader_set`
- `status`
- preprocess / dispatch / process 各阶段时间
- throughput / bandwidth / cycles
- flow 统计

适用场景：
- 测 `mark3` 在不同 reader / worker 核组合下的差异。
- 做“绑核布局”实验，而不是只看 worker 数量。

### `benchmarks/mark3/sweep3.yaml`

用途：
- `benchmark_sweep_mark3.py` 的配置样例文件。

适用场景：
- 不想把复杂的 `worker_sets` / `reader_sets` 都写在命令行里时，用配置文件管理实验参数。

## analysis/cpu

### `analysis/cpu/core_hash_boxplot_32.py`

用途：
- 做单线程 SHA256 算力测试。
- 每次把进程绑到一个逻辑核上，重复多轮，比较每个核心的单线程吞吐。
- 根据每核平均值粗分成 `big_like` / `little_like` 两组。

输出：
- `raw_per_run.csv`
- `summary_per_cpu.csv`
- `boxplot_per_cpu.png`

适用场景：
- 先从纯 CPU 算力层面判断核心快慢分布。
- 粗看机器是否存在明显的大小核差异。

### `analysis/cpu/wsl_vcpu_singlethread_bench.py`

用途：
- 面向 Linux / WSL 的单线程 vCPU 分布测试。
- 原理同样是逐 vCPU 绑核跑 SHA256，但更偏“虚拟 CPU 一致性”排查。
- 会根据中位数间隙做一个简单的快/慢组切分提示。

输出：
- `output/wsl_vcpu_bench/per_vcpu_singlethread.csv`
- `output/wsl_vcpu_bench/per_vcpu_singlethread.png`

适用场景：
- 想看 WSL 或虚拟化环境里，不同 vCPU 的单线程性能是否均匀。

## analysis/plots

### `analysis/plots/merge_proto_category_summary.py`

用途：
- 对 `mark4` 的 `proto_category_summary.csv` 做两轮合并。
- 第一轮先按 `proto_name` 合并，把同名协议但不同 `category` 的项加权合并。
- 第二轮再按点号前缀合并，例如把 `TLS.Google`、`TLS.twitter` 合并到 `TLS`。

当前合并规则：
- `flows` 直接求和
- 平均值和 p50/p99 类字段都按 `flows` 加权平均
- `master_proto`、`app_proto`、`category_name`、`category_id` 目前保留“占比最大”的代表值

输出：
- 默认在原 CSV 同目录生成 `proto_category_summary_merged.csv`

适用场景：
- 想把 `mark4` 识别出的细粒度子协议先收敛成主协议统计。

说明：
- 这个脚本是新的协议聚合工具，不负责画图。
- 如果后续希望彻底去掉 `category/app_proto` 代表列，还可以继续改。

### `analysis/plots/plot_mark4_proto_summary.py`

用途：
- 面向 `mark4/proto_category_summary.csv` 的通用汇总看板。
- 关注的是 `proto+category` 层面的“谁最多、谁最贵、category 分布如何”。

会生成的内容：
- Top `proto+category` 按流数的横向条形图
- `avg_flow_detecting_ms` vs `avg_flow_post_ms` 散点图
- Top `avg_flow_total_ms` 条形图
- Category 维度的堆叠条形图
- 另外还会写一份按 category 加权汇总的 CSV

输出：
- `mark4_proto_dashboard.png`
- `mark4_category_summary.csv`

适用场景：
- 想快速浏览 `mark4` 当前协议和业务分类分布。
- 想找出高流量、高总耗时的 `proto+category` 组合。

### `analysis/plots/plot_mark4_protocol_profiling.py`

用途：
- 也是读取 `mark4/proto_category_summary.csv`，但目标不是普通 dashboard，而是“协议复杂度 profiling”。
- 它会根据 `avg_detect_pkt_flow` 和 `detecting_pkt_p50_us` 把协议分成 `Easy / Medium / Hard` 三类。

会生成的内容：
- 协议复杂度散点图
- per-flow detection cost Top20
- 不同复杂度桶的 p50 / p99 对比图
- 流量占比 vs detection cost 占比双饼图

输出：
- 一个 PDF 图文件，默认 `protocol_profiling_analysis.pdf`

适用场景：
- 想分析“哪些协议检测复杂、为什么复杂、复杂协议占了多少成本”。

说明：
- 这个脚本对 CSV 格式更宽容，能处理列名前后带空格、文件前面有杂行的情况。
- 如果安装了 `adjustText`，标签避让效果会更好。

### `analysis/plots/plot_0306_main_time_compare.py`

用途：
- 对一组固定的历史实验目录做比较图。
- 默认比较：
- `20260306_095830-mark`
- `20260306_100137-classified`
- `20260306_100436-batch`

会生成的内容：
- 3x2 dashboard，比较不同实现变体在 `read_pcap`、`enqueue`、`parse`、`flow`、`ndpi`、`other` 等时间项上的变化
- 一份“按原始行拼接”的 CSV
- 一份“长表形式”的 metric CSV

适用场景：
- 专门复盘 2026-03-06 那组主时间分解实验。

说明：
- 这是一个强绑定历史目录名的分析脚本，不是通用画图器。

### `analysis/plots/plot_process_time_variants.py`

用途：
- 比较几种实现变体的 `process_time_sec` 随 worker 数量变化的曲线。
- 默认比较 `mark / classified / batch / mem` 四类目录。

输出：
- `process_time_vs_workers_variants.png`

适用场景：
- 只想看不同实现版本在 `process_time_sec` 上的整体趋势差异。

说明：
- 同样依赖固定目录名，是面向特定历史结果集的快捷脚本。

### `analysis/plots/plot_mark3_core_diff.py`

用途：
- 从 `mark3` 的 `benchmark_results_*.csv` 里提取每个 worker core 的时间项差异。
- 以“相对中位数的偏差（毫秒）”画热力图。
- 只保留那些变化范围超过阈值的指标。

主要参数：
- `--min-range-ms`：过滤低波动指标的阈值，默认 `80 ms`

输出：
- 一张 heatmap PNG

适用场景：
- 想看某些 worker core 是否在特定时间项上显著偏慢或偏快。
- 适合找“某个核心拖后腿”的模式。

### `analysis/plots/replot_mark3_dashboard_from_csv.py`

用途：
- 不重新跑 benchmark，只基于已有的 `mark3 benchmark_results_*.csv` 重新画 dashboard。
- 适合 CSV 已经有了，但想调整展示方式或补图。

输出：
- 默认为同目录下的 `benchmark_dashboard_<ts>_replot_custom.png`

适用场景：
- benchmark 已完成，只想重画图，不想重新执行实验。

说明：
- 这个版本相对主 `mark3` dashboard 做了些裁剪，例如去掉部分总时间项，强调 reader / process breakdown。

### `analysis/plots/plot_proto_bucket_compare-legacy.py`

用途：
- 一个旧版协议桶对比图脚本。
- 按人工定义的 `Easy / Mid / Hard` 协议列表画两张柱状图。

依赖字段：
- `avg_detect_latency_ms`
- `avg_detect_pkt_flow`

输出：
- `proto_bucket_perf_compare.png`

适用场景：
- 只在旧 CSV 字段格式还存在时可用。

说明：
- 这是 legacy 脚本，和现在的 `mark4` CSV 字段不完全兼容。
- 当前仓库里更推荐用 `plot_mark4_protocol_profiling.py` 替代。

## legacy

### `legacy/run.sh`

用途：
- 收集了几条早期的手写 benchmark 命令。

适用场景：
- 作为命令样例参考。

说明：
- 不属于结构化自动化脚本，不建议作为正式实验入口。

## 实际使用建议

如果你的目标是“完整跑一轮实验并做分析”，通常可以按这个顺序：

1. 先运行 `setup/prepare_benchmark_env.sh` 固定实验环境。
2. 用 `data/generate_1500b_pcap.py` 或 `data/cap-pcap.sh` 准备输入 PCAP。
3. 选择对应版本的 benchmark 脚本：
- `mark1` 用 `benchmarks/mark1/`
- `mark2` 用 `benchmarks/mark2/`
- `mark3` 用 `benchmarks/mark3/`
4. 跑完以后去 `analysis/plots/` 或 `analysis/cpu/` 做复盘和画图。

如果你的目标是“分析 mark4 的协议识别结果”，常用组合是：

1. 先看 `plot_mark4_proto_summary.py` 做总览。
2. 再看 `plot_mark4_protocol_profiling.py` 分析复杂度结构。
3. 如果想先把子协议合并到主协议，再跑 `merge_proto_category_summary.py`。

## 备注

- `scripts/__pycache__/` 下的 `.pyc` 文件是 Python 编译缓存，不是源脚本，不需要单独维护说明。
- 部分分析脚本绑定了固定历史输出目录，它们更像“专题复盘工具”，不是通用框架。
- `plot_proto_bucket_compare-legacy.py` 是旧字段时代留下的脚本，后续如果继续使用新 `mark4` CSV，优先考虑更新或替换它。
