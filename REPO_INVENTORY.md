# ndpi_speed 目录盘点报告

> 生成时间：2026-09-18
> 盘点范围：`/home/zync/WORKSPACE/ndpi_speed` 全部内容（191 GB，不含 .git）
> 方法：逐目录清点 + 源码 diff + git 历史核对。所有"代码事实"均已在源码中验证，并与 README 宣称逐条对照。

---

## 0. 三句话结论

1. **没有"0905 之后的新文件夹"。** 目录里最新的 *文件夹* 是 `mark9`（2026-07-06）。9 月 5 日 / 9 月 6 日只新增了两个 markdown 文件（`0905进展.md`、`0906改进prompt.md`），没有对应的新代码目录。你记忆里的"几个新文件夹"应该是 7 月建的 `mark8` / `mark9`。
2. **mark5 不能删。** 你说"mark5 之前的都可以不要"——这个判断是对的，`mark1`~`mark4` 确实可以删（建议删）。但 **mark5 必须留**：它是唯一的数据生产者，`output/mark5/` 那 74 GB 原始 profile 数据全靠它产生，mark6~mark9 的离线代价表也全部由 mark5 的 Python 训练脚本产出。
3. **文档宣称与代码现状有明显落差，这是本次盘点最重要的发现。** README / 进展文档说"mark8 已有闭环 EWMA 实现""P/E 加速比 1.8×"，但代码里 **mark8 根本编译不过**、adaptive 逻辑是死代码、**P/E 速度因子被硬编码成 1.0×1.0**、**mark9 把 mark8 的整条反馈闭环删掉了**。详见 §4。

---

## 1. 项目主线：这堆 mark 到底在做什么

一句话：**在异构多核（Intel i9-14900，8 P-core + 16 E-core）上跑软件 DPI（nDPI），利用"不同协议的检测代价差很多"这个事实，把每条流分派到"最划算"的核上，并在流识别完成后用实测代价反过来修正预测。**

代码演进实际上是三个阶段：

| 阶段 | 版本 | 在做什么 |
|------|------|---------|
| **A. 并行化探索** | mark1 ~ mark3 | 怎么把 `pcap → 解析 → 建流表 → nDPI 检测` 这条链路跑快。reader/worker 模型、软件 RSS、多 dispatcher。 |
| **B. 代价测量** | mark4 ~ mark5 | 不搞调度了，改成**单线程 profiler**，把每种协议的检测代价精确测出来（时间 + 硬件计数器）。产出离线代价表。 |
| **C. 代价感知调度** | mark6 ~ mark9 | 回到多线程，加入"预估代价 → 加权调度"和"在线反馈修正"。这才是论文的主体。 |

---

## 2. 逐 mark 说明

### 阶段 A：并行化探索（可删）

| | mark1 | mark2 | mark3 |
|---|---|---|---|
| **目标** | 实验母体版，一套源码编出 6 个变体 | 收敛成单一基线 | 拆出独立 dispatcher 层 |
| **架构** | 1 reader + N worker，RSS 哈希粘性映射 | 同上（源码与 mark1 完全相同） | 预加载整包 → 多 dispatcher → 多 worker |
| **调度** | power-of-two choices | 同 mark1 | flow→dispatcher 随机，flow→worker P2C |
| **输出** | 仅 console | 仅 console | console（Preprocess / Dispatch / Process 三段耗时） |
| **代价模型** | 无 | 无 | 无 |
| **P/E 建模** | 无 | 无 | 无 |
| **可运行** | ✅ `build/` 里 7 个二进制 | ✅ | ✅ |

**mark1 的 6 个变体**：`ndpiBenchmark`（基线）/ `Classified`（已识别流快速路径）/ `Batch`（批量入队）/ `Mem`（pcap 先入内存）/ `SingleHash` / `AggLB`（激进负载均衡）。

### 阶段 B：代价测量

| | mark4 | mark5 |
|---|---|---|
| **目标** | 单线程直读对照版 —— 去掉全部线程，得到"干净"的端到端耗时 | 在 mark4 骨架上做 **profiling**：首包特征 + 检测代价 + 硬件计数器 |
| **架构** | 纯单线程，`main.c` / `packet_parser.c` / `flow_table.c` 三个文件 | 同 mark4 |
| **输出** | `output/<ts>/proto_category_summary.csv`（协议分类汇总） | `time_flow_profile.csv`、`time_protocol_summary.csv`、`hardware_flow_profile.csv`、`hardware_protocol_summary.csv` |
| **双二进制** | 无 | `ndpiBenchmarkMark5Time`（计时）/ `ndpiBenchmarkMark5Hardware`（PMU：instructions / cycles / LLC miss / branch miss） |
| **P/E** | 无 | C 代码里无调度，但 `run_mark5_batch.sh` 把核 0 钉成 P、核 19 钉成 E，做 P/E 对比 |
| **可运行** | ✅ | ✅（含一个残留的 `ndpiBenchmarkMark5Prefix4` 二进制，CMake 目标已删除） |

**mark5 的 Python 脚本（离线代价表的真正来源）**：

| 脚本 | 作用 |
|------|------|
| `train_lookup.py` | 从 mark5 CSV 训练 cost bucket 查表（协议 → Easy/Middle/Hard） |
| `train_port_prefix_lookup.py` | **核心**：per-protocol 平均耗时 W → 对 `log(W)` 做 k-means(k=3) → 学高纯度 dst_port 规则 + 歧义端口的 `prefix_1/2/4` 规则 |
| `plot_protocol_profiles.py` | P/E 对比，输出 2 CSV + 7 图（时间分量 / LLC / IPC / branch / scatter / cross-core ratio） |
| `plot_time_only_figure1.py` | 论文 Figure 1（P/E 检测代价对比） |
| `plot_protocol_manifest.py` | 批量编排器，读 `manifest.json` 跑上面这些 |
| `plot_detecting_time.py` | `detecting_cost_ms` 的 Easy/Middle/Hard 三色图 |
| `plot_protocol_numberline.py` | 1D 数轴分布图 |
| `merge_protocol_csv.py` | 协议 CSV 二级归并（`TLS.Google → TLS`） |

### 阶段 C：代价感知调度

| | mark6 | mark7 | mark8 | mark9 |
|---|---|---|---|---|
| **目标** | 第一个代价感知调度器 | 加运行时策略框架 | 加闭环 EWMA 反馈 | 加 protocol-level 连续代价查表 |
| **二进制** | `Mark6` + `Mark6Hash`（编译宏二选一） | 单二进制 + `-P` 策略参数 | 无 build/ | `ndpiBenchmarkMark9` |
| **策略** | 编译期 hash-only / cost-aware-jsw | 运行期 5 种：RSS / JSQ / STATIC_POOL / ORACLE / OURS | 多一个 ADAPTIVE | 同 mark7（**ADAPTIVE 已删**） |
| **新文件** | `cost_table.c`、`dispatch.c` | `oracle_table.c` | — | — |
| **新增能力** | 首包 bucket 代价预测、cost-aware dispatch | per-flow 检测延迟记录（p50/p99）、结构化输出 `run_summary.csv` / `latency_summary.csv` / `worker_stats.csv` / `dispatch_stats.csv` / `policy_config.json` | adaptive_cost_table + SPSC feedback ring + EWMA | `proto_lookup_table`（v2 JSON）、`-L` 参数 |
| **能否编译** | ✅ `build/` 有二进制 | ✅ `build/` 有二进制 | ❌ **不能**（见 §4.2） | ✅ `build/` 有二进制（2026-07-06 01:49） |

**mark6 → mark7 → mark8 → mark9 的真实代码差异**（`diff -rq` 实测）：

- `mark6 → mark7`：改 `dispatch.c`、`main.c`、`reader.c`、`worker.c`，新增 `oracle_table.c`
- `mark7 → mark8`：改 `dispatch.c`、`main.c`、`worker.c`
- `mark8 → mark9`：改 `cost_table.c`、`dispatch.c`、`main.c`、`worker.c`
- `benchmark_common.c`、`flow_table.c`、`packet_parser.c`、`rss_table.c` **四个 mark 全程字节相同**

**关键**：`mark8 → mark9` 的 diff 方向说明 **mark9 不是从 mark8 长出来的**。mark9 更接近"mark7 + v2 查表"，并且**主动删除了 mark8 的整套 adaptive 子系统**（详见 §4.3）。

---

## 3. 数据资产盘点

全仓 191 GB，其中 **190 GB 是数据，代码只有 1 GB 左右**。

### 3.1 `output/` — 74 GB

| 子目录 | 大小 | 内容 | 价值判断 |
|--------|------|------|---------|
| `mark5/time/` | **49 GB** | 108 个 run 目录，239 文件，2026-04-12 ~ 05-03 | ⭐ **核心资产**。论文 Measurement 章节的原始证据 |
| `mark5/hardware/` | **25 GB** | 83 个 run，PMU 计数器数据，全部 04-17 一天 | ⭐ 论文 Figure 2（P/E 加速比与微架构行为关联）的唯一来源 |
| `mark5/batch/` | 35 MB | 6 个批量运行 + `plots/` | 有用，保留 |
| `mark5/plots/` | 5.7 MB | 5 个绘图输出 + PNG | 有用，保留 |
| `legacy/` | 27 MB | mark1~mark4 早期输出，407 文件（210 PNG / 155 CSV） | 可归档或删 |
| `mark4/` | 352 KB | 6 个 `proto_category_summary.csv` | **已被 mark5 完全取代**，可删 |
| `mark9/` | 12 KB | `proto_cost_prior.csv` + `proto_lookup_table.json` | ⭐ 真数据（非占位），如 ICMP 均值 1.97 µs / 1580 万条流，TLS 20.16 µs / 17674 条流 |
| `_test/` | 3.8 MB | 冒烟测试输出 | 可删 |

按文件类型：552 CSV、319 PNG、63 JSON、6 log。**这些 CSV 单个就 7 GB**（`time_flow_profile.csv` = 7,119,409,894 字节），所以体积大是正常的，不是垃圾。

### 3.2 `input/` — 52 GB

⚠️ **`input/normal-pcaps/` 是空目录**。真正的 trace 全在 `input/` 顶层：

| 文件 | 大小 | 用途 |
|------|------|------|
| `normal_1.pcap` ~ `normal_13.pcap` | 各 1.06~1.26 GB，共 14.6 GB | **实验主力 trace**，2026-04-09 |
| `Monday-WorkingHours.pcap` | 10.8 GB | 经典公开 trace |
| `seed_10G.pcap` | 10.7 GB | 合成流量（Mar 06） |
| `归档.zip` | 11.8 GB | 压缩归档 |
| `201706251400.pcap` | 6.2 GB | 公开 trace |
| `cap_traffic.pcap` + `cap_traffic_fast.pcap` | 911 MB + 3.1 MB | tcpdump 抓的 |
| `seed_1500b.pcap` | 160 MB | 合成 |

（仓库根目录还散着一个 `Monday-WorkingHours.pcap`，只有 110 KB，是截断的残片，可删。）

### 3.3 `archive/` — 66 GB（**其中 ~66 GB 是纯冗余**）

| 子目录 | 大小 | 内容 | 判断 |
|--------|------|------|------|
| `ndpi-speed-0503/` | **66 GB** | 5 月 3 日的整仓快照 | ❌ **几乎 100% 冗余**：其中 `input/`(52 GB) 与顶层 `input/` 逐字节相同；`output/`(14 GB) 是 `output/mark5/time/` 中 24 个目录的完全副本（连 7.1 GB 的单文件都对得上） |
| `output-temp/` | 286 MB | mark5 临时输出 | ❌ 其中 `20260411_180000-Mdpcap-lookup`(115 MB) 与 `output/mark5/` 下的副本字节相同 |
| `ndpi-speed-0625/` | 83 MB | 6 月 25 日的**纯源码**快照（mark1~mark7） | ✅ 有用：是 mark1~mark7 的第二份源码备份，且轻量。**但没有 mark8/mark9** |
| `globecom-evaluation/` | 15 MB | ⭐ **GLOBECOM 论文的完整评测结果** | ⭐ **不该待在 archive 里**（见 §6） |
| `mark0/` | 16 MB | 最早的探索版（含 15 MB test.pcap） | 可删 |
| `docs_mark3_mark4/` | 16 KB | mark3/4 代码走读文档 | 可删（内容已被 `四个Mark架构分析.md` 覆盖） |
| `mark-1/`、`ssh_detector/` | 64 KB + 16 KB | 更早的独立小工具 | 可删 |

`archive/globecom-evaluation/` 内部结构：
- `mark7/` (12 MB) — 真实的 mark7 批量运行结果，`batch_20260503_*` 共 11 个
- `final/` (136 KB) — **论文图的数据源**：`figure3_throughput.csv`、`figure4_latency.csv`、`figure5_robustness.csv`、`figure6_overload.csv`、`figure7_workload.csv`、`all_runs.csv`、`all_worker_stats.csv`
- `plots/` (416 KB) — figure4~7 的 PDF + PNG
- `mark5/` (1.4 MB) — 对应的 mark5 输入数据

> **这是全仓唯一存在的 mark7 实测结果集。** `output/` 下没有任何 mark7 输出（`.gitignore` 把 `evaluation/` 排除了）。

### 3.4 冗余汇总

| 项 | 可回收 |
|----|-------|
| `archive/ndpi-speed-0503/`（input + output 双份） | ~66 GB |
| `archive/output-temp/` 中重复的那个 run | ~0.1 GB |
| **合计** | **≈ 66 GB** |

删掉之后仓库从 191 GB → 约 125 GB。

---

## 4. ⚠️ 代码现实 vs 文档宣称（本次最重要的发现）

这一节的每一条都已用 grep / diff 在源码里核实过。**如果下一步要基于这些代码做新系统，这些是必须先知道的坑。**

### 4.1 P/E 速度差异根本没建模 —— 论文核心卖点之一在代码里不存在

```
mark9/include/ndpi_benchmark.h:418:  #define SPEED_FACTOR_P_X1000 1000U
mark9/include/ndpi_benchmark.h:419:  #define SPEED_FACTOR_E_X1000 1000U
```

两个宏**都是 1000**，即 P 核 = E 核 = 1.0×。`core_speed_factor_x1000()`（`mark9/src/dispatch.c:53`）返回的就是这两个常量，所以调度公式里的 `/speed_i` 项恒等于除以 1。

- 核类型判定是硬编码阈值：`core_id < 16 → P`，否则 `E`（`dispatch.c:49-51`），没有做任何拓扑探测。
- mark8 里加了个 `speed_ratio_x1000` 初始化为 1800（`main.c:917`），注释写着"runtime calibrated"——**但全仓搜不到任何更新它的代码**，是个死变量。
- 唯一真实体现 P/E 差异的地方是 `cost_profile.csv` 里 P/E 两行不同的实测代价（Easy 2.26 / Middle 7.63 / Hard 17.28 µs，P 核）。
- 唯一让 P 核显得"更贵"的是 `DISPATCH_P_BIAS_X1000 = 10`（`benchmark_internal.h:32`）——一个人为偏置，不是速度模型。

**含义**：0905 文档说的"P/E speed ratio ≈ 1.8 需要重新标定"，实际情况比这更糟——**代码里压根没有速度比这个概念**，1.8 只存在于论文故事和 PPT 里。

### 4.2 mark8 编译不过

`mark8/src/main.c` 第 1104~1127 行用了**中文弯引号当字符串定界符**：

```c
1104:    printf(“\nAdaptive Cost Table Summary:\n”);
1105:    printf(“  %-6s  %-12s  %-12s  %-10s  %-10s\n”,
1106:           “Proto”, “P_cost_x1000”, ...);
1118:      printf(“  %-6u  %-12u  ...\n”, p, cp, ce, sp, se);
1127:    printf(“  Speed Ratio (E/P): %.3f\n”, (double)ratio / 1000.0);
```

`“` 和 `”` 不是合法的 C 字符串定界符，这是语法错误。其它文件里的弯引号都在中文注释里（无害），**只有 main.c 这 5 行是真错误**。

这解释了为什么 `mark8/` 是全仓唯一**没有 `build/` 目录**的 mark。也就是说：**mark8 从未被编译过，更从未被运行过。**

而 `progress_presentation.md` 里 mark8 的状态写的是 "✅ 代码已写, 待Linux测试"——"代码已写"这个说法具有误导性。

> **✅ 已修复（2026-09-18）**：`mark8/src/main.c` 的 6 处弯引号定界符已替换为 ASCII 引号（文件内剩余弯引号均在中文注释里，无害）。已实测 `cmake + make` 通过，产出 `mark8/build/ndpiBenchmarkMark8`（88 KB），**零 error**。
>
> 注意：这只解决了**编译**问题。§4.4 说的 adaptive 死代码问题仍然存在——mark8 现在能跑，但跑的还是静态表。

### 4.3 mark9 把 mark8 的闭环删掉了

grep `adaptive` 的结果：

| | mark7 | mark8 | mark9 |
|---|---|---|---|
| 出现次数 | 0 | **72** | **2**（都是一句注释和一句 TODO） |

mark9 剩的两处是：
```
mark9/include/ndpi_benchmark.h:604:  /* Backward compat: retain bucket fallback for pre-ADAPTIVE_MIN_SAMPLES */
mark9/src/dispatch.c:397:      (void)proto_hint; /* TODO: pass to choose_adaptive_worker in mark8+9 merge */
```

mark9 删除的内容包括：`DISPATCH_POLICY_ADAPTIVE` 枚举值、adaptive 策略解析、`adaptive_drain_feedback()`、`choose_adaptive_worker()`、`cost_feedback_ring_t` 定义、worker 侧的 feedback 写入。

**所以 mark8 + mark9 不是一个累进的序列，而是两条分岔。** 0905 文档里说的"mark8+mark9 合并"这个任务，字面上是对的——它们确实需要合并，因为**mark9 是 mark8 的一个子集加了一个新查表**。

### 4.4 即使在 mark8 里，adaptive 调度也是死代码

`choose_policy_worker()` 在 `DISPATCH_POLICY_ADAPTIVE` 分支里，把 `ADAPTIVE_MAX_PROTOCOLS` 当作哨兵值传给 `choose_adaptive_worker()`，导致每次都走静态 bucket fallback。也就是说**就算 mark8 能编译、能跑，它跑的也还是静态表，不是闭环**。

mark8 里写得对的部分（可以作为重建的基础）：
- SPSC ring：`cost_feedback_ring_t`，`head`/`tail` 原子变量，1024 项
- worker 在协议确认后写入：`actual_cost = (detect_now_ns - first_ns + 500) / 1000` µs
- dispatcher 每 256 次调度 drain 一次：`if ((ctx->dispatch_counter & 0xFF) == 0) adaptive_drain_feedback(ctx)`
- EWMA 定点实现：`updated = ((256-alpha)*old + alpha*actual)/256`，`ADAPTIVE_ALPHA_NORMAL = 13`（≈0.05），`ADAPTIVE_MIN_SAMPLES = 8`

**这套 ring + EWMA 的骨架是 mark8 唯一真正有价值的遗产**，重建 mark10 时应该从这里抄，而不是从 mark9 抄。

### 4.5 mark9 的 v2 协议级查表目前是退化的

```c
// mark9/src/dispatch.c:380-397
uint16_t proto_hint = PROTO_HINT_UNKNOWN;
if (ctx->proto_lookup_table) {
  lookup_result_t lr = proto_lookup(ctx->proto_lookup_table, dst_port, payload_prefix, payload_prefix_len);
  proto_hint = lr.proto_hint;
  bucket = lr.bucket;
} else { bucket = cost_table_lookup_bucket(...); }
(void)proto_hint;  /* TODO: pass to choose_adaptive_worker in mark8+9 merge */
```

两个问题：

1. **`proto_hint` 算出来了但被丢弃**（`(void)` + TODO）。mark9 号称的"port/prefix → proto_hint → protocol-level continuous cost"这条链**断在最后一步**——proto_hint 从未参与任何调度决策。
2. **v2 表的 bucket 恒为 Middle**：`cost_table.c:583` 默认值是 `COST_BUCKET_MIDDLE`，且 `cost_table.c:683` 把每个命中端口的 fallback bucket 都设成 Middle。所以 v2 查表**永远只输出 Middle 一个档位**，比 mark7 的静态 3 桶表信息量还少。
3. v2 JSON 里的 `proto_cost_prior` 字段**被解析后丢掉**，只有 `port_rules` / `prefix_rules` 被真正消费。

**含义**：`train_proto_lookup_v2.py` 训练出的连续代价先验（`proto_cost_prior.csv`），在 C 代码里**完全没被用到**。0905 文档说"mark9 改为 port/prefix → proto_hint → protocol-level continuous cost"，实际只完成了前半段的**表生成**，后半段的**消费**没做。

### 4.6 mark6 / mark7 的文档是机械改名产物

`mark6/README.md` 与 `mark7/README.md`、`CODE_WALKTHROUGH.md`、`PAPER_EXPERIMENT_PLAN.md`、`MARK6_DELIVERY_ACCEPTANCE.md`、`DISPATCH_BOTTLENECK_NOTES.md` 逐行 diff 后：**每一行差异都只是 `mark6` → `mark7` 字符串替换**，没有任何实质内容增删。

也就是说 mark7 新增的运行时策略框架、`oracle_table.c`、结构化输出、per-flow 延迟记录，**README 里一个字都没写**。读 mark7 的 README 学不到 mark7。

### 4.7 其它小问题

- `mark9/scripts/.claude/` 里有一个 starship 提示符相关的权限配置，和项目完全无关，是误创建的残留。
- mark9 的 v2 训练脚本 `train_proto_lookup_v2.py`（13 KB）在 `mark9/scripts/`，但 mark7/mark8 的脚本（`build_oracle_cost_table.py`、`run_mark7_eval.py` 等 4 个）与 mark6 的**完全相同**，也是复制品。
- CMake 默认 `NDPI_PREFIX=$HOME/ndpi-install`，本机确实存在（`/home/zync/ndpi-install`，含 `libndpi.so.5.1.0`），源码在 `~/WORKSPACE/nDPI-dev`。构建链是通的。

---

## 5. `scripts/` 盘点（524 KB）

`scripts/README.md`（14.5 KB，4 月 9 日）写得很详细，但它描述的 `analysis/` 目录结构**和实际磁盘布局对不上**。

| 子目录 | 内容 | 状态 |
|--------|------|------|
| `setup/prepare_benchmark_env.sh` | 固定 CPU governor / SMT / 拓扑 | ✅ 当前 |
| `data/generate_1500b_pcap.py`、`cap-pcap.sh` | 合成 / 抓取 trace | ✅ 当前 |
| `benchmarks/mark1/`、`mark2/`、`mark3/` | 各版本的 sweep 脚本 + 绘图 | ⚠️ 对应 mark 已停用 |
| `benchmarks/mark0/` | 最早的 sweep | ❌ 过期 |
| `cpu/core_hash_boxplot_32.py`、`wsl_vcpu_singlethread_bench.py` | 核哈希分布 / WSL vCPU 均匀性 | ⚠️ 少见 |
| `protos/merge_proto_category_summary.py` | mark4 协议 CSV 归并 | ✅ 当前 |
| `classify_output.py` | **最新**（7 月 5 日），指纹识别 output 目录并追加到 `EXPERIMENT_LOG.md` | ✅ 当前，推荐保留 |
| `legacy/` | 8 个早期脚本 | ❌ README 自己标注 "reference only" |

两个不一致：README 说有 `analysis/plots/`，实际绘图脚本散落在 `legacy/` 和 `benchmarks/mark2|mark3/`；`legacy/plot_profiling.py` 和 `legacy/summarize_proto_reliability.py` 存在但 README 没收录。

---

## 6. 文档清单

| 文件 | 日期 | 内容 | 判断 |
|------|------|------|------|
| `progress_presentation.md` | 07-06 | 项目进展汇报（修订版），架构图 + 算法伪代码 + 论文大纲 + 实验设计 | ⚠️ **部分内容与代码不符**（见 §4），但作为"论文故事"的设计稿仍然有用 |
| `0905进展.md` | 09-05 | 9 月的冷静复盘：研究定位收窄、mark7 是唯一有评测资产的版本、DPDK 未完成、residual-work 未实现 | ⭐ **最诚实、最准确的一份**，结论基本被代码验证（除 §4.3 的 mark8 判断过于乐观） |
| `0906改进prompt.md` | 09-06 | 给下一个编码 agent 的 prompt，要求另起 `mark10-risk-aware` | ⚠️ **文件被截断**，且路径是 Mac 的（见 §7） |
| `四个Mark架构分析.md` | 03-30 | mark1~mark4 的架构对比分析 | 📦 阶段性成果，随 mark1~4 一起归档 |
| `output/EXPERIMENT_LOG.md` | 07-05 | 实验输出日志：时间线、指纹规则、目录结构 | ⭐ **有用**，配合 `classify_output.py` 使用 |
| `scripts/README.md` | 04-09 | 脚本说明 | ⚠️ 与实际布局部分不符 |

---

## 7. `0906改进prompt.md` 分析

这份文件的内容是：一份交给下一个编码 agent 的指令，要求它**不要去改 mark7/8/9，而是另起一个 `mark10-risk-aware` 系统**。

### 7.1 写得好的地方

1. **故事线的升级方向是对的。** 它把论文从"weighted JSW + EWMA 负载均衡"改写成：
   > *Cost Is Revealed, Not Known: Risk-Aware Flow Scheduling for Predictable Software DPI on Hybrid Cores*

   核心问题改成"检测成本隐藏 + 首包预测有误差 + 检测过程逐步揭示 + P/E 能力不同，如何满足 p99 time-to-verdict SLO 的同时最大化可持续吞吐"。**这正面回应了 0905 文档自己指出的最大风险**："目前最危险的版本是：离线表 → weighted JSW → EWMA 更新……算法新颖性偏弱"。把科学对象从"预测代价"换成"隐藏且逐步揭示的工作量的风险感知估计"，确实是唯一能把新颖性做出来的方向。

2. **风险公式很具体，可证伪：**
   $$risk(f,c) = P\left(\frac{backlog_c + cost_f}{speed_c} > remaining\_deadline\right)$$
   并给出第一版的降级实现（quantile-aware dispatch：安全 worker 里选预计完成时间最短的，E 核都不安全才用 P 核保险容量）。**"P 核是对冲不确定性的保险资源，不是重流专用核"**——这个重新定义比原来的 P/E 分工说法有说服力得多，是个真正的概念贡献。

3. **十条研究边界非常清醒**，尤其是：
   - #3「不把旧实验数字当事实。18x、1.8x、旧 throughput、旧 p99 等**全部必须重新测量**」
   - #8「如果实验结果否定当前故事，**必须记录并提出修改，而不是强行制造支持性结果**」
   - #9「所有结果必须保留原始日志、配置、**失败运行和异常说明**」

   这三条正好堵住了 LLM agent 做科研时最典型的失败模式（编造支持性结果、只报告成功的 run）。**这是整份文档里最有价值的部分。**

4. **先审计后编码。** 第三节要求"先不要写新算法代码"，先产出 `MARK_INVENTORY.md`，并给了 **15 个逐 mark 的核查问题 + 10 个全局实验环境问题**（含"是否存在把 PCAP replay 时间误当成真实网络到达时间的问题""是否存在旧结果、美化数据、缺少重复运行或数据泄漏"）。这是很好的工程习惯。

5. 指标选择正确：主指标是「满足 p99 TTV SLO 时的最大可持续吞吐」，而不是裸吞吐。

### 7.2 不好的地方

1. **文件是截断的。** 第 117 行就是结尾，停在"当前最可信的 baseline；"这个列表项上，`MARK_INVENTORY.md` 该包含什么还没列完。**这份 prompt 不能直接拿去用**——需要先补齐（或者找到原始完整版）。

2. **路径是别的机器的。** 第三节让 agent 扫描：
   ```
   /Users/wanghao137/WORKSPACE/ndpi-speed-0625/
   /Users/wanghao137/WORKSPACE/_Markdown/1000.P.Projects/ndpi-speed/
   ```
   这是 macOS 路径，本机（Linux, `/home/zync/...`）不存在。文档里补了一句"如果路径不存在，请自行寻找"作为兜底，但这说明**整份文档是从另一台机器复制过来的**，其它隐含假设可能也带着旧环境。

3. **⚠️ 最大的技术风险：它规定的研究边界和它要的机制互相矛盾。** 文档同时要求：
   - 贡献 2：「**不修改 nDPI 检测逻辑**」，构建调度系统
   - 边界 #5：「第一阶段优先在现有 PCAP replay / reader-worker 框架中完成」
   - 但 System 贡献又要「**检测中 CPU-time accounting**」和「检测过程**逐步揭示**真实成本」

   **在既不碰 nDPI、又只用 PCAP replay 的前提下，你拿不到"检测中途的 CPU 时间"**。nDPI 的 `ndpi_detection_process_packet()` 是个黑盒调用，不暴露回调。要做到"逐步揭示"，只有三条路：① 改 nDPI 加 hook；② 在包级别切分 `process_packet` 的返回值来近似；③ 用 mark5 那种外部计时。**文档没有意识到这个矛盾，也没指定走哪条路。** 这是 mark10 能不能做成的真正关卡，比算法新不新颖更关键。

4. **deadline / SLO 语义在 replay 环境里是虚假的。** 风险公式依赖 `remaining_deadline`，也就是需要每流有真实的到达时间和排队延迟。但现在的框架是 PCAP replay——包是"尽快灌进去"的，没有真实到达时间。文档在审计清单里问了这个问题（一.9），**但没有把它当成设计约束**，而它直接决定了 risk 公式能不能测。

5. **对现有代码基础过于乐观。** 文档让 agent 把 mark7/8/9 当作"已有原型和实验资产"复用。但实际（见 §4）：
   - mark8 编译不过、adaptive 是死代码 → 没有"闭环雏形"可复用，只有 ring+EWMA 的骨架可抄
   - 代码里 P/E 速度因子是 1.0× → "P/E 能力建模"要从零做
   - mark9 删了反馈环、proto_hint 被丢弃、v2 表恒为 Middle → "protocol-level continuous cost"要从零做
   - residual-work 只有 `added_cost - retired_cost`，且 0905 自己承认这不是真正的剩余工作

   **文档没有一条要求 agent 去核实 README 与代码的一致性。** 强烈建议在审计阶段加一条：*"对每个 mark，把 README 的每一条能力宣称与代码逐条对照，标注 已实现 / 部分实现 / 仅文档"。* 本次盘点已经证明 README 的宣称可靠度很低。

6. **没有验收标准。** 文档只详细规定了第一阶段（审计）。后面系统阶段、评测阶段要做到什么程度、什么算"完成"、每阶段的交付物是什么，全部没写。也没有时间预算。作为一个交给 agent 的长任务，缺少里程碑定义会导致它无限期地做审计或过早开始写代码。

7. **量化先验的参数没定。** `feature bucket → {p50, p90, p99, sample_count, confidence}` 里的 `confidence` 怎么算、`sample_count` 多少才算够、冷启动怎么办——都没写。而这些恰好是 mark8 已经趟过一次的地方（`ADAPTIVE_MIN_SAMPLES = 8`）。

8. **没定义基线公平性。** 说了要比 RSS / JSQ / 静态代价 / adaptive / Oracle，但没说怎么保证比较公平（同样的 CPU 预算？同样的核分配？Oracle 会不会泄漏？）。

### 7.3 总评

**方向对，边界的自觉程度罕见地高，但这份文件还不能用。** 

一句话：*它把一个工程性选题正确地升级成了一个有科学问题的选题，并且正确地预判了 agent 会说谎的方式；但它对现有代码资产的乐观程度是错的，而且它要的核心机制（检测中途的时间记账）和它设的边界（不改 nDPI、只跑 replay）直接冲突。*

**建议的修补**（如果要用这份 prompt）：
1. 补齐被截断的 `MARK_INVENTORY.md` 要求清单
2. 把所有 `/Users/wanghao137/...` 换成 `/home/zync/WORKSPACE/...`
3. 在第二节边界里插入一条：**"必须在审计阶段核实 README 与代码的一致性，逐条标注 已实现 / 部分实现 / 仅文档"**
4. 把"检测中 CPU-time accounting"和"不修改 nDPI"的矛盾显式写出来，并明确选路（我推荐路线 ②：先用量化的包级近似，因为它不需要改 nDPI，且能被审计）
5. 明确 replay 环境下 TTV / deadline 的定义——要么承认它是"逻辑时间"，要么先给 replay 加上基于 pcap 时间戳的虚拟时钟
6. 给每个阶段写验收标准

---

## 8. 回答"mark5 之前的能不能删"

**能删，而且建议删。** 具体判断：

| 目标 | 建议 | 理由 |
|------|------|------|
| `mark1/` `mark2/` `mark3/` | ❌ **删** | 并行化探索期产物，与当前研究问题无关。三个 mark 的源码全部在 git 历史里（HEAD 中均有 `markN/src/*.c`），另有 `archive/ndpi-speed-0625/mark1..mark3` 第二份备份。mark2 源码与 mark1 完全相同，mark3 只多一个 dispatcher 层 |
| `mark4/` | ❌ **删**（或与 mark5 一起留） | 单线程对照版，已经被 mark5 完全取代（mark5 就是 mark4 骨架 + profiling）。`output/mark4/` 的 6 个 CSV 也同样被取代 |
| `mark5/` | ✅ **必须留** | ⭐ 唯一的数据生产者。`output/mark5/` 74 GB 原始数据靠它产生；mark6~9 的离线代价表全部来自它的 Python 训练脚本。**删了之后所有实验数据都变成不可复现的孤儿** |
| `mark6/` | ⚠️ 可留可删 | 已被 mark7 完全覆盖（mark7 = mark6 + 策略框架 + oracle + 结构化输出）。1.6 MB，很小，建议留作"mark7 从哪来"的参照，或整体归档 |
| `mark7/` | ✅ **必须留** | 唯一有完整评测结果集的版本（结果在 `archive/globecom-evaluation/`）。5 种可切换策略 + 结构化输出是当前最可信的 baseline |
| `mark8/` | ✅ **留** | 编译不过，但 ring + EWMA 的代码骨架是重建闭环时唯一可抄的东西。删了就只剩 README 的空话 |
| `mark9/` | ✅ **留** | v2 查表 + `train_proto_lookup_v2.py` + 已训练出的 `proto_lookup_table.json`（真数据） |

**所以你的直觉是对的，只是边界要挪一格：删 `mark1`~`mark4`，留 `mark5` 起步。**

---

## 9. 建议的重新组织方案

### 9.1 目标结构

```
ndpi_speed/
├── README.md                    # ⭐ 新建：项目总览 + 这个仓库怎么读
├── REPO_INVENTORY.md            # 本文件
├── docs/                        # ⭐ 新建：所有说明性文档集中
│   ├── 0905进展.md
│   ├── 0906改进prompt.md
│   ├── progress_presentation.md
│   └── EXPERIMENT_LOG.md        # 从 output/ 移上来
├── src/                         # ⭐ 或者保留 "markX" 平铺但加区分
│   ├── mark5/                   # 数据生产者（profiling）
│   ├── mark7/                   # 当前 baseline
│   ├── mark8/                   # 闭环骨架（编译不过，待修）
│   ├── mark9/                   # v2 查表
│   └── mark10-risk-aware/       # 下一步
├── results/                     # ⭐ 新建：评测结果（从 archive 里救出来）
│   ├── globecom/                # archive/globecom-evaluation/ 整体移入
│   └── mark5-profile/           # output/mark5 保持原样（74G，不动）
├── data/                        # input/ 改名
├── scripts/
├── archive/                     # 只留真正需要"封存"的
│   ├── marks-1-to-4/            # mark1~4 + 四个Mark架构分析.md
│   ├── legacy-output/           # output/legacy
│   └── source-snapshot-0625/    # ndpi-speed-0625（纯源码，83M）
└── （删除 ndpi-speed-0503/ 66G、output-temp/、mark0/、mark-1/、ssh_detector/）
```

### 9.2 分步执行建议

**第 0 步（无风险）—— ✅ 已执行 2026-09-18：**
- ✅ 新建 `README.md` 导航页，含项目主线、mark 表、构建说明、"代码 vs 文档"落差速查表
- ✅ `0905进展.md`、`0906改进prompt.md`、`progress_presentation.md`、`EXPERIMENT_LOG.md` 已移入 `docs/`
- ✅ 删除 `mark9/scripts/.claude/`（无关残留）、根目录 110 KB 的 `Monday-WorkingHours.pcap`（截断残片）

**第 1 步（回收空间）—— ✅ 已执行 2026-09-18：**
- ✅ 删除 `archive/ndpi-speed-0503/` → 回收 **65 GB**（删前最后核对：`input/` 两边均 20 个文件、55,198,189,508 字节完全一致）
- ✅ 删除 `archive/output-temp/`（286 MB）—— 其中 3 个目录在 `output/mark5/` 里有对应物，是同一批 4/17 运行的**更早版本**（非字节相同，最终版日期更新）
- ✅ 删除 `archive/mark0/`、`archive/mark-1/`、`archive/ssh_detector/`
- ⬜ `archive/docs_mark3_mark4/`（16 KB）**未删**（内容已被 `四个Mark架构分析.md` 覆盖，留着无害）

> **实测结果：仓库 191 GB → 126 GB。**

**第 2 步（未执行，需确认）：**
- ⬜ 删除 `mark1/` ~ `mark4/`（已确认 git 可恢复 + 0625 快照有备份）
- ⬜ **把 `archive/globecom-evaluation/` 移到 `results/globecom/`** —— 这是全仓唯一的 mark7 实测结果，放在 archive 里很容易在某次清理中误删
- ⬜ 删除 `output/mark4/`、`output/_test/`、`output/legacy/` → 回收 30 MB（相对 74 GB 微不足道，主要是减少干扰）

**第 3 步（建议但非必须）：**
- ✅ mark8 弯引号已修复，`cmake + make` 实测通过
- ⬜ 在 `docs/` 下写一份 `CODE_VS_DOCS.md`，把 §4 的六条落差固化下来，避免下一个 agent 又被 README 误导（目前该内容在 `README.md` 和本文件 §4 里）

### 9.3 不做的事

- **不动 `output/mark5/` 和 `input/`** —— 74 GB + 52 GB 的原始数据是论文证据，体积大是正常的，碰它有风险没收益
- **不删 `mark8/`** —— 虽然编译不过，但那 72 处 adaptive 代码是重建闭环的唯一参考
- **不重命名 mark 目录** —— 虽然 `src/mark5/` 结构更漂亮，但 mark 编号在本项目里已经是事实上的版本号，跨文档引用很多（0905、0906、git log、脚本路径全在用），改名的收益不抵风险

---

## 10. 如果只记三件事

1. **mark5 不能删**，它是所有数据的老家。mark1~4 可以删。
2. **代码比文档落后很多**：mark8 从未编译过、P/E 速度比在代码里是 1.0×、mark9 删了反馈闭环、proto_hint 被丢弃。0906 prompt 里"复用现有资产"这个前提基本不成立。
3. **0906 的方向是对的，但那份文件被截断了，路径是 Mac 的，而且"不改 nDPI"和"检测中途 CPU 记账"这两个要求直接冲突。** 用之前必须先解决这个冲突。
