# ndpi_speed

在异构多核（Intel i9-14900，8 P-core + 16 E-core）上跑软件 DPI（nDPI）的调度研究。

**核心想法**：不同协议的 nDPI 检测代价差异很大（约 18×），所以调度器如果能预知"这条流大概要花多久"，就能把流分派到最划算的核上；流识别完成后再用实测代价反过来修正预测。最终目标是**在满足 p99 time-to-verdict SLO 的前提下最大化可持续吞吐**。

---

## 这个仓库怎么读

| 你想做什么 | 看哪里 |
|-----------|--------|
| 快速了解仓库里都有什么、每个目录是什么 | **[REPO_INVENTORY.md](REPO_INVENTORY.md)** ← 先看这个 |
| 了解项目当前进展和瓶颈 | `docs/0905进展.md` |
| 了解下一步计划（mark10） | `docs/0906改进prompt.md` |
| 了解论文故事和实验设计 | `docs/progress_presentation.md` |
| 查某次实验输出的来源 | `docs/EXPERIMENT_LOG.md` + `scripts/classify_output.py` |
| 了解早期 mark1~4 的架构 | `archive/marks-1-to-6/四个Mark架构分析.md` |

---

## 目录结构

```
ndpi_speed/
├── docs/           说明性文档（进展、计划、实验日志）
├── mark5/          ⭐ 数据生产者：协议检测代价 profiling
├── mark7/          ⭐ 当前 baseline：5 种可切换调度策略
├── mark8/          闭环 EWMA 反馈（代码骨架可复用）
├── mark9/          协议级查表 v2 + 训练脚本
├── scripts/        环境配置、流量生成、批量实验、绘图
├── evaluation/     调度实验结果（globecom/ = GLOBECOM 论文图数据；i9/ = 10 月 i9 复测）
├── input/          PCAP traces（62 GB，见下）
├── output/mark5/   原始 profiling 数据（74 GB）
├── archive/        封存内容（marks-1-to-6/ = 已停用的 mark1~4、mark6 及其脚本）
└── REPO_INVENTORY.md
```

---

## 演进主线

三个阶段，不是九个独立项目：

### 阶段 A：并行化探索（mark1 ~ mark3）

研究"怎么把 `pcap → 解析 → 建流表 → nDPI 检测` 跑快"。

- **mark1**：实验母体版，一套源码编出 6 个变体（基线 / Classified / Batch / Mem / SingleHash / AggLB）
- **mark2**：收敛成单一基线（源码与 mark1 完全相同）
- **mark3**：拆出独立 dispatcher 层，研究前端分发阶段的扩展性

### 阶段 B：代价测量（mark4 ~ mark5）

不搞调度了，改成**单线程 profiler**，把每种协议的检测代价精确测出来。

- **mark4**：单线程直读对照版，得到"干净"的端到端耗时
- **mark5**：⭐ **唯一的数据生产者**。`ndpiBenchmarkMark5Time`（计时）+ `ndpiBenchmarkMark5Hardware`（PMU：instructions / cycles / LLC miss / branch miss）
  - 产出 `output/mark5/` 的 74 GB 原始数据
  - 其 Python 脚本（`train_port_prefix_lookup.py` 等）训练出 mark6~9 用的全部离线代价表

### 阶段 C：代价感知调度（mark6 ~ mark9）

- **mark6**：第一个代价感知调度器（首包 bucket 代价预测 + cost-aware dispatch）
- **mark7**：⭐ **当前 baseline**。加运行时策略框架（RSS / JSQ / STATIC_POOL / ORACLE / OURS）+ per-flow 延迟记录 + 结构化输出
- **mark8**：加闭环 EWMA 反馈（`adaptive_cost_table` + SPSC feedback ring）
- **mark9**：加协议级查表 v2（`proto_lookup_table` JSON）

---

## ⚠️ 动手之前必读：代码现状与文档宣称的落差

`REPO_INVENTORY.md` §4 有完整证据。这里只列结论，**避免被 README 误导**：

| 文档宣称 | 代码现状 |
|---------|---------|
| "P/E 加速比 ≈ 1.8×" | **代码里没有这个模型**。`SPEED_FACTOR_P_X1000` 和 `SPEED_FACTOR_E_X1000` 都是 `1000`（即 1.0×）。核类型判定是硬编码 `core_id < 16` |
| "mark8 已有闭环实现" | mark8 的 adaptive 分支传哨兵值，**每次都 fallback 到静态表**，闭环从不生效 |
| "mark9 改为 protocol-level continuous cost" | `proto_hint` 算出后被 `(void)` 丢弃（带 TODO）；v2 表的 bucket **恒为 Middle**；训练出的 `proto_cost_prior.csv` 在 C 代码里从未被消费 |
| "mark8 + mark9 待合并" | 字面属实——**mark9 把 mark8 的整套 adaptive 子系统删掉了**（`adaptive` 出现次数 mark7=0 / mark8=72 / mark9=2） |
| mark6 与 mark7 的 5 份文档 | 逐行 diff 后**只有 `mark6`→`mark7` 字符串替换**，零实质更新 |

另外：**mark7 的真实评测结果不在 `output/` 下**（被 `.gitignore` 排除了），而在 `evaluation/globecom/`（原 `archive/globecom-evaluation/`，2026-11-17 移出）。

---

## 构建与运行

依赖 nDPI，默认路径 `$HOME/ndpi-install`（可用 `-DNDPI_PREFIX=` 覆盖）：

```bash
cd mark9 && mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j8
./ndpiBenchmarkMark9 -i <trace.pcap> -n <num_workers> -P <policy>
```

`-P` 可选：`rss` / `jsq` / `static_pool` / `oracle` / `ours`（mark8 另有 `adaptive`）。

**构建状态**：mark5、mark7、mark9 均有可用 `build/`。mark8 此前因 `src/main.c` 中的中文弯引号导致语法错误而无法编译，已于 2026-09-18 修复，现在可以正常构建。

---

## 数据资产

| 路径 | 大小 | 说明 |
|------|------|------|
| `output/mark5/time/` | 49 GB | 108 个 run 的计时 profile。论文 Measurement 章节的原始证据 |
| `output/mark5/hardware/` | 25 GB | 83 个 run 的 PMU 计数器数据（全部 2026-04-17） |
| `input/` | 62 GB | ⚠️ 主力 trace 在 `input/` **顶层**（`normal_1..13.pcap` 等），`input/normal-pcaps/` 是**空的** |
| `evaluation/globecom/` | 15 MB | ⭐ **全仓唯一的 mark7 实测结果集**：`final/figure3~7_*.csv` 是论文图的数据源 |

体积大是正常的（单个 `time_flow_profile.csv` 就有 7 GB），不是垃圾。

---

## 已停用的版本

`mark1` ~ `mark4` 属于并行化探索期，与当前研究问题无关；`mark6` 已被 mark7 完全包含。这五个目录连同它们专用的 `scripts/benchmarks/`、`scripts/legacy/` 已于 2026-11-17 移到 `archive/marks-1-to-6/`，**不再维护**，保留源码仅为追溯。mark4 的测量已被 mark5 完全取代。

（源码全部在 git 历史中可恢复，另有 `archive/ndpi-speed-0625/` 一份 mark1~mark7 的源码快照。）

---

## 下一步

`docs/0906改进prompt.md` 规划了新系统 `mark10-risk-aware`，把论文故事从"weighted JSW + EWMA 负载均衡"升级为**"成本是逐步揭示的，而非已知的"——面向 p99 尾延迟的风险感知调度**。

⚠️ 该文件目前**被截断**（停在 117 行一个未写完的列表项），且**引用了 macOS 路径**（`/Users/wanghao137/...`）。用之前需要先补齐。

`REPO_INVENTORY.md` §7 有完整的好坏分析，其中最关键的问题：文档一边要求"不修改 nDPI 检测逻辑 + 优先复用 PCAP replay"，一边要求"检测中 CPU-time accounting"——nDPI 的 `ndpi_detection_process_packet()` 是黑盒调用，不碰它拿不到检测中途的时间。**这个矛盾需要在开工前解决。**
