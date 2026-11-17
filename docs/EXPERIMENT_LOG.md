# 实验输出日志

> 2026-11-17：`output/mark4/`、`output/legacy/`、`output/_test/` 已删除（被 mark5 数据取代）。下文对这三个目录的描述仅作历史记录。

> 自动/手工维护。新跑实验后请更新本文档末尾的"新增记录"区域。

## 项目演进时间线

| 时间 | Mark | 二进制 | 说明 |
|------|------|--------|------|
| 2026-01-31 ~ 02-08 | mark0/mark1 | `ndpiBenchmark` 等 6 变体 | 最早探索，reader-worker 模型 + 编译变体实验 |
| 2026-02-27 ~ 03-06 | mark1 | 六变体 | 正式变体对比（mark/classified/batch/Mem/singlehash/AggLB） |
| 2026-03-09 ~ 03-13 | mark2 / mark3 | `ndpiBenchmarkMark2` / `ndpiBenchmarkMark3` | 收敛基线 + preprocess/dispatcher 并行化实验 |
| 2026-03-23 ~ 04-09 | mark3 / mark4 | `ndpiBenchmarkMark3` / `ndpiBenchmarkMark4` | 大量 mark3/mark4 对照实验 |
| 2026-04-10 ~ 04-11 | **mark4** | `ndpiBenchmarkMark4` | 单线程批量运行 → `output/mark4/` |
| 2026-04-11 晚 | **mark5** | `ndpiBenchmarkMark5` | 首次 lookup 训练实验 → `output/mark5/time/20260411_180000-Mdpcap-lookup/` |
| 2026-04-15 ~ 04-17 | **mark5** | `ndpiBenchmarkMark5` | 密集 time + hardware profiling → `output/mark5/time/` + `output/mark5/hardware/` |
| 2026-04-24 ~ 04-27 | **mark5** | `ndpiBenchmarkMark5` | port+prefix lookup 增强 → `output/mark5/time/` |
| 2026-05-01 ~ 05-03 | **mark5** | `ndpiBenchmarkMark5` | 批量 profiling 收尾 → `output/mark5/time/` |
| 2026-05 之后 | mark7 | `ndpiBenchmarkMark7` | evaluation 框架（输出在 `evaluation/mark7/`，不在这里） |

---

## 指纹规则 — 如何识别输出来自哪个 Mark

| 特征文件 | → Mark | → 二进制 |
|----------|--------|----------|
| `proto_category_summary.csv` | mark4 | `ndpiBenchmarkMark4` |
| `time_flow_profile.csv` + `time_protocol_summary.csv` (无 `hardware_flow_profile.csv`) | mark5 (time) | `ndpiBenchmarkMark5` |
| `hardware_flow_profile.csv` 或 `hardware_protocol_summary.csv` | mark5 (hardware) | `ndpiBenchmarkMark5` |
| `flow_profile.csv` + `first_packet_signature_summary.csv` + `lookup/` | mark5 (early/lookup) | `ndpiBenchmarkMark5` |
| `batch.log` + `manifest.json` | mark5 (batch) | `run_mark5_batch.sh` |
| `plot_summary.json` | mark5 (plots) | mark5 绘图脚本 |
| `run_summary.csv` + `policy_config.json` + `worker_stats.csv` | mark7 | `ndpiBenchmarkMark7` |

---

## 目录结构

```
output/
├── mark4/                    # ndpiBenchmarkMark4 — 单线程对照版 (6 runs)
│   ├── 20260410_234655/
│   ├── 20260411_100321/
│   ├── 20260411_105506/
│   ├── 20260411_143044/
│   ├── 20260411_145547/
│   └── 20260411_150933/
│
├── mark5/
│   ├── time/                 # ndpiBenchmarkMark5 — 时间 profiling (99 runs)
│   ├── hardware/             # ndpiBenchmarkMark5 — 硬件计数器 profiling (69 runs)
│   ├── batch/                # run_mark5_batch.sh — 批量实验 (6 runs)
│   └── plots/                # mark5 绘图脚本输出 (5 runs)
│
├── legacy/                   # mark0~mark4 早期输出归档 (不变)
│   ├── timeline/             # 2026-01-31 ~ 04-09 全部历史实验
│   ├── core_hash_boxplot/
│   ├── flow-demo-output/
│   ├── logs.md               # 手写实验日志
│   └── ...
│
├── _test/                    # 测试/冒烟输出
│   ├── plots_smoke_test/     # mark5 绘图冒烟测试
│   └── test_manifest_plots/  # mark5 manifest 批量绘图测试
│
├── test_manifest.json
└── EXPERIMENT_LOG.md         # 本文件
```

---

## mark4 (ndpiBenchmarkMark4) — 6 个输出

**二进制**: `ndpiBenchmarkMark4`
**关键输出**: `proto_category_summary.csv`（协议分类汇总）
**日期范围**: 2026-04-10 ~ 2026-04-11

| 文件夹 | 日期 | 内容摘要 |
|--------|------|----------|
| `20260410_234655` | 04-10 深夜 | proto_category_summary.csv |
| `20260411_100321` | 04-11 上午 | proto_category_summary.csv |
| `20260411_105506` | 04-11 上午 | proto_category_summary.csv |
| `20260411_143044` | 04-11 下午 | proto_category_summary.csv |
| `20260411_145547` | 04-11 下午 | proto_category_summary.csv |
| `20260411_150933` | 04-11 下午 | proto_category_summary.csv |

共 6 次运行，输入 pcap 不同（正常的批量测试）。

---

## mark5 (ndpiBenchmarkMark5)

### time/ — 时间 profiling (99 个输出)

**二进制**: `ndpiBenchmarkMark5`
**关键输出**: `time_flow_profile.csv`, `time_protocol_summary.csv`
**日期范围**: 2026-04-11 ~ 2026-05-03

| 日期段 | 数量 | 代表性文件夹 | 说明 |
|--------|------|-------------|------|
| 2026-04-11 | 1 | `20260411_180000-Mdpcap-lookup` | 首次 mark5 lookup 训练实验，含 `lookup/`, `first_packet_signature_summary.csv`, `flow_profile.csv` |
| 2026-04-15 | 6 | `20260415_005559` ~ `20260415_230437` | 早期 time profiling |
| 2026-04-16 | 8 | `20260416_202624` ~ `20260416_224153` | 密集 time profiling |
| 2026-04-17 | 18 | `20260417_011207` ~ `20260417_122049` | 大规模批量，含 `021113-Mdpcap`（Mdpcap 输入） |
| 2026-04-24 | 1 | `20260424_232908` | port+prefix lookup 训练 (含 `lookup_port_prefix/`) |
| 2026-04-27 | 2 | `20260427_114830`, `20260427_115710` | port+prefix lookup 训练 |
| 2026-05-01 | 1 | `20260501_224006` | （1 个空目录 `20260501_223350` — 失败/中断） |
| 2026-05-02 | 25 | `20260502_033624` ~ `20260502_034217` | 密集批量，约 20 个连续运行 |
| 2026-05-03 | 37 | `20260503_041815` + `20260503_132131` ~ `20260503_132725` | 最后一批约 36 个 |

### hardware/ — 硬件计数器 profiling (69 个输出)

**二进制**: `ndpiBenchmarkMark5`
**关键输出**: `hardware_flow_profile.csv`, `hardware_protocol_summary.csv`，部分同时含 `time_flow_profile.csv`
**日期范围**: 2026-04-17

| 日期段 | 数量 | 说明 |
|--------|------|------|
| 2026-04-17 | 69 | `20260417_012601` ~ `20260417_021434`，与 time profiling 交替运行 |

这批 hardware profiling 测量了 per-protocol 的硬件计数器（branch misses, LLC misses, IPC 等），用于论文 Figure 2（P/E speedup 与硬件行为关联分析）。

### batch/ — 批量实验运行 (6 个)

**脚本**: `mark5/run_mark5_batch.sh`
**关键输出**: `batch.log`, `manifest.json`, `runs.tsv`, `figure1_time/`, `plots/`

| 文件夹 | 日期 | 说明 |
|--------|------|------|
| `batch_20260417_011207` | 04-17 | 批量运行 |
| `batch_20260417_015808` | 04-17 | 批量运行 |
| `batch_20260417_015829-overall` | 04-17 | overall 汇总批量，含 `plots/` 和 `run_mark5_batch.snapshot.sh` |
| `batch_20260501_223350` | 05-01 | 批量运行（日志少） |
| `batch_20260502_033601` | 05-02 | 批量运行（日志少） |
| `batch_20260502_033624` | 05-02 | 批量运行，含 `figure1_time/` |

### plots/ — 绘图输出 (5 个)

**脚本**: mark5 Python 绘图脚本（`plot_protocol_profiles.py`, `plot_detecting_time.py` 等）
**关键输出**: `plot_summary.json`, 各种 PNG

| 文件夹 | 日期 | 说明 |
|--------|------|------|
| `plots_20260416_224257` | 04-16 晚 | 协议 profile 绘图 |
| `plots_20260416_230355` | 04-16 晚 | 协议 profile 绘图 |
| `plots_20260416_231003` | 04-16 晚 | 协议 profile 绘图 |
| `plots_20260417_001221` | 04-17 凌晨 | 协议 profile 绘图 |
| `plots_20260417_125332` | 04-17 下午 | 协议 profile 绘图 |

---

## legacy/ — 早期输出归档

**来源**: mark0, mark1, mark2, mark3, mark4
**日期范围**: 2026-01-31 ~ 2026-04-09

| 子目录/文件 | 说明 |
|------------|------|
| `timeline/` | **全部历史实验原始输出**（60+ runs），按时间戳命名。涵盖 mark0~mark4 完整演进 |
| `logs.md` | 手工维护的实验日志，记录每次运行的内容和观察 |
| `protocol_profiling_analysis.pdf` | 协议分析综合报告 |
| `core_hash_boxplot/` | flow hash 分布分析 |
| `flow-demo-output/` | flow 演示输出 |
| `mark4_normal_pcaps_merged_*` | mark4 的合并 pcap 输出 |
| `merged_pcaps_*` | 合并 pcap 输出 |
| `run.log` | 某次运行的日志 |

`timeline/` 中的文件夹命名直观反映了实验阶段：
- `20260131_*` ~ `20260208_*`：mark0, mark1
- `20260227_*-mark`, `*-classified`, `*-batch`, `*-Mem`, `*-singlehash`, `*-AggLB`：mark1 六变体
- `20260305_*`, `20260306_*`：mark1 单变体深入
- `20260309_*-singlecore`, `20260312_*-singlecore`：mark2 单核实验
- `20260313_*-pre`：mark3 preprocess 实验
- `20260323_*`, `20260324_*`：mark3 分发实验
- `20260407_*`, `20260409_*`：mark4 大量批量运行（30+ runs）

---

## _test/ — 测试和验证输出

| 文件夹 | 说明 |
|--------|------|
| `plots_smoke_test/` | mark5 绘图脚本冒烟测试：验证所有 plot 类型能正常生成 |
| `test_manifest_plots/` | mark5 manifest 批量绘图流程测试：验证 `plot_protocol_manifest.py` pipeline |

---

## 如何添加新实验记录

### 方法 1：运行分类脚本（推荐）

```bash
python3 scripts/classify_output.py --update-log
```

自动扫描 `output/` 下新出现的文件夹，指纹识别 → 追加到本文档。

### 方法 2：手动添加

在下方"新增记录"区域按格式追加。

### 格式模板

```markdown
| `folder_name/` | YYYY-MM-DD | markX | `binary_name` | 关键内容摘要 |
```

---

## 新增记录

<!-- 新实验记录请追加到此行下方 -->

| 文件夹 | 日期 | Mark | 二进制 | 内容摘要 |
|--------|------|------|--------|----------|
| | | | | |
