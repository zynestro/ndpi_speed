# mark7 至强（Xeon）迁移跑测文档

> 目标：把 i9-14900K 上的 mark7 调度器 benchmark 原样搬到至强机器上，两边用**同一份代码、同一个 nDPI、同一个合成 trace、同一组参数**各跑一遍，比较速度。
> trace 不再用 Monday-WorkingHours.pcap（太大），改用 `generate_1500b_pcap.py` 生成的 **10 GB 大包合成 trace**。
> 写于 2026-10-19。§8 是给隔壁机器 Claude Code 的 prompt。

---

## 0. 交付物

隔壁机器会拿到这些：

```
ndpi_speed/
├── mark7/                              调度器 benchmark 源码（不含 build/）
│   ├── CMakeLists.txt
│   ├── include/  src/
│   ├── offline_costs/                  lookup_table.json + cost_profile.csv
│   └── scripts/run_mark7_eval.py       批量跑测
│       scripts/prepare_figure_csvs.py  汇总
├── scripts/data/generate_1500b_pcap.py 合成 trace 生成器
└── docs/XEON_迁移跑测文档.md           本文档
nDPI-dev.tgz                            nDPI 源码（5.1.0 dev 快照，必须用同一份）
```

在 i9 上打包：

```bash
cd ~/WORKSPACE/ndpi_speed
tar czf ~/mark7_xeon_bundle.tgz --exclude build --exclude __pycache__ \
  mark7 scripts/data/generate_1500b_pcap.py docs/XEON_迁移跑测文档.md
tar czf ~/nDPI-dev.tgz -C ~/WORKSPACE --exclude .git nDPI-dev
```

> **nDPI 一定要带过去。** 本机 nDPI 是 `5.1.0` 的 dev 快照（CHANGELOG 最新一节是 5.0，版本号已经升到 5.1.0），不是正式发布版。从 GitHub 拉一个别的 commit，协议识别结果和耗时都可能不一样，两边就不可比了。

---

## 1. mark7 代码逻辑

### 1.1 一句话

离线 pcap 重放 benchmark：先把整个 pcap 读进内存，再由多个 dispatcher 线程按调度策略把**每条流**分配给某个 worker，worker 跑 nDPI 协议识别。对比不同策略下的吞吐和"流识别延迟"。

### 1.2 三阶段流水线

```
pcap ──► [Reader 线程] ──► 内存包数组 ──► [8 × Dispatcher] ──► 16 个 SPSC 队列 ──► [16 × Worker]
          预加载(不计时)                    流→worker 决策                          nDPI 识别
```

| 阶段 | 代码 | 做什么 |
|---|---|---|
| ① 预加载 | `reader.c: load_pcap_packets()` | `pcap_next_ex` 逐包读 → 链路层统一成 Ethernet → 解析 5 元组 → 构造双向一致的 flow key（小 IP/端口在前）→ FNV-1a 哈希 → `hash % 8` 决定这个包归哪个 dispatcher（相当于网卡 RSS）→ 包截断到 1400B 存进内存数组。**这一段不计入吞吐。** |
| ② 分发 | `reader.c: dispatcher_thread_entry()` → `dispatch.c: dispatch_lookup_or_assign()` | 每个 dispatcher 只处理分给自己的包。查 flow→worker 映射表：**老流**直接沿用已绑定的 worker；**新流**才调用调度策略选 worker，然后把绑定写进表。包批量写入 worker 的无锁 ring（容量 4096）。 |
| ③ 处理 | `worker.c: worker_process_packet()` | 出队 → 解析 → 查/建 flow 表 → `ndpi_detection_process_packet()`。识别出协议后：记录**识别延迟** = 识别完成时刻 − 该流第一个包入队时刻；把这条流放进 classified 缓存，后续包走快速路径，不再调 nDPI。 |

线程绑核：worker 和 dispatcher 各自用 `pthread_setaffinity_np` 绑到 `-c` / `-d` 指定的核（`benchmark_common.c`）。reader 主线程不绑核。

### 1.3 调度策略（`dispatch.c: choose_policy_worker()`）

只在**新流的第一个包**到达时做决策：

| `-P` | 选 worker 的规则 |
|---|---|
| `rss` | `flow_hash % num_workers`，静态哈希 |
| `jsq` | 当前队列深度最小的 worker |
| `static` | 先查代价 bucket：Easy → 只在 "E 核" worker 里哈希；Middle/Hard → 只在 "P 核" worker 里哈希 |
| `ours` | 代价感知 JSW：对每个 worker 算 `score = pending_cost + cost(该核类型, bucket) + (P核 ? 10 : 0)`，选最小 |
| `oracle` | 同 ours，但代价用每条流的真实测量值（需要 `-O`，合成 trace 没有，**本次不跑**） |

**代价从哪来**（`cost_table.c: cost_table_lookup_bucket()`）：用新流第一个包的 `dst_port` + 前 1~4 字节 payload 查 `offline_costs/lookup_table.json`，得到 Easy / Middle / Hard 三档之一；查不到就是 Hard。再查 `offline_costs/cost_profile.csv` 得到这一档在 P/E 核上的预估耗时（µs）：

```
core_type,bucket,cost_us
P,Easy,2.26    P,Middle,7.63    P,Hard,17.28
E,Easy,4.12    E,Middle,13.58   E,Hard,31.04
```

**pending_cost**：给某个 worker 分配新流时，`added_cost += 预估代价`；worker 处理到这条流的第一个包时，`retired_cost += 同一个值`。两者之差就是"已分配、还没开始处理"的预估工作量。

### 1.4 ⚠️ P/E 核类型是按核编号硬编码的

```c
// mark7/src/dispatch.c:49
return (core_id < 16U) ? CORE_TYPE_P : CORE_TYPE_E;
```

这是按 i9-14900K 写死的（逻辑核 0-15 = P 核，16-31 = E 核）。**至强上所有核都一样，但程序照样把编号 ≥16 的核当成 E 核**，于是：
- `ours` 会认为这些核慢约 1.8 倍（用 E 行代价），少给它们分流；
- `static` 会把 Easy 流全塞给编号 ≥16 的核。

不改代码，靠选核和代价表来控制这个变量（§5）。

### 1.5 输出（`-o <dir>`）

| 文件 | 关键字段 |
|---|---|
| `run_summary.csv` | `throughput_pps`（= 总包数 / replay 时间，replay 时间不含预加载）、`bandwidth_gbps`、`detect_latency_p50_ms` / `p99_ms`、`total_packets`、`total_flows`、`detected_flows` |
| `worker_stats.csv` | 每个 worker 的核号、核类型、包数、流数、`processing_time_ns`、`busy_ratio` |
| `dispatch_stats.csv` | 各 bucket 的新流数等 |
| `latency_summary.csv`、`policy_config.json` | 延迟分位数、本次配置 |

### 1.6 其它要知道的

- 默认 lookup / cost 路径写死为 `/home/zync/WORKSPACE/ndpi_speed/mark7/offline_costs/...`（`main.c:15-16`）。**别的机器上必须显式传 `-m` / `-C`**（`run_mark7_eval.py` 对应 `--lookup` / `--cost-profile`）。
- `PROCESS_TIME_CORE_SLOTS = 32`：核号 ≥32 的 worker 不会出现在 stdout 的 "Per-Core Process Time" 那一行。只影响这一行打印，CSV 不受影响。

---

## 2. 合成 trace

### 2.1 生成器做了什么

`scripts/data/generate_1500b_pcap.py`（依赖 scapy）：按权重随机生成 5 种协议的流，HTTP 30% / HTTPS 40% / DNS 10% / SSH 10% / MySQL 10%。
- TCP 流 = 3 次握手 + 20 轮请求/响应 + 2 个 FIN，共 45 包；UDP（DNS）流 = 20 轮请求/响应，共 40 包。
- `--size-profile mtu`：payload 在 1200~1400B 之间随机，即"大包"。
- `--seed 1` 固定随机数，时间戳也是确定的 → **同一个 Python + scapy 版本下，两次生成逐字节相同**（已在 i9 上验证）。
- 写够 `--target-mb` 就停。

### 2.2 生成命令（两边完全一样）

```bash
cd ndpi_speed
mkdir -p input
python3 scripts/data/generate_1500b_pcap.py \
  --size-profile mtu --payload-size 1400 --target-mb 10240 --seed 1 \
  --output-dir input -o input/syn_mtu_10G.pcap
```

单线程，i9 上实测 **58.5 分钟**（3511 s，≈3 MB/s）。

### 2.3 一致性校验

先跑一个 50 MB 的样本（17 秒），和 i9 的 sha256 对比；对上了再生成 10 GB：

```bash
python3 scripts/data/generate_1500b_pcap.py --size-profile mtu --payload-size 1400 \
  --target-mb 50 --seed 1 --output-dir /tmp -o /tmp/t50.pcap
sha256sum /tmp/t50.pcap
```

| 文件 | i9 上的值 |
|---|---|
| 生成环境 | Python 3.13.12，scapy 2.6.1 |
| `t50.pcap` sha256 | `058220f2064fb5ab9986d9fd7e0613448f656faab811d11b230330f0e1bba1a8`（42,965 包，965 流） |
| `syn_mtu_10G.pcap` sha256 | `f70f7db744ce2415de0f0b044155c98d7cb43d615def50df382b73e0af34d031`（10,878,055,779 字节） |
| mark7 读出的 `total_packets` / `total_flows` / `detected_flows` | 8,789,665 / 197,546 / 197,546 |

sha256 对不上，多半是 scapy 版本不同：`pip install scapy==2.6.1` 后重新生成。实在对不上，就把 i9 的 10 GB 文件直接拷过去（`rsync`），**不要两边用不同的 trace 比速度**。

---

## 3. 环境准备

### 3.1 依赖

```bash
sudo apt install -y build-essential cmake autoconf automake libtool pkg-config \
  libpcap-dev libjson-c-dev numactl python3-pip
pip install scapy==2.6.1 pandas
```

### 3.2 编译 nDPI（装到 `~/ndpi-install`）

```bash
mkdir -p ~/WORKSPACE && tar xzf nDPI-dev.tgz -C ~/WORKSPACE
cd ~/WORKSPACE/nDPI-dev
make distclean 2>/dev/null || true      # 清掉 i9 带来的编译产物
./autogen.sh && ./configure --prefix=$HOME/ndpi-install
make -j"$(nproc)" && make install
grep Version ~/ndpi-install/lib/pkgconfig/libndpi.pc     # 应为 5.1.0
```

### 3.3 编译 mark7

```bash
cd ndpi_speed
cmake -S mark7 -B mark7/build -DCMAKE_BUILD_TYPE=Release -DNDPI_PREFIX=$HOME/ndpi-install
cmake --build mark7/build -j
```

### 3.4 稳定频率

i9 上是用 `powerprofilesctl set performance` 设的（EPP=performance），governor 仍显示 `powersave`，这在 intel_pstate 下是正常的。至强上有 `powerprofilesctl` 就用它，没有就直接写 governor：

```bash
powerprofilesctl set performance 2>/dev/null || \
  for f in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do echo performance | sudo tee $f >/dev/null; done
# turbo：两边要么都关，要么都开，并记录下来
cat /sys/devices/system/cpu/intel_pstate/no_turbo
```

跑测期间机器上不要有其它负载，生成 pcap 的进程也要等它跑完。

---

## 4. 选核

一共 24 个线程（16 worker + 8 dispatcher），要**各占一个物理核**，并且都在**同一个 NUMA 节点**上。

i9 上用的：

```
WORKER_CORES=0,2,4,6,8,10,12,14,24,25,26,27,28,29,30,31   # 8 个 P 核(各取一个超线程) + 8 个 E 核
DISPATCHER_CORES=16,17,18,19,20,21,22,23                  # E 核
```

至强的超线程编号和 i9 不一样（通常 `0..N-1` 是各物理核的第一个线程，`N..2N-1` 才是兄弟线程，多路机器还会按 socket 交错），**先看清楚**：

```bash
lscpu -e=CPU,CORE,SOCKET,NODE,MAXMHZ
numactl -H
```

然后用这个脚本自动选：在 NODE 0 上，每个物理核取第一个逻辑 CPU；worker 选 8 个编号 <16 的 + 8 个编号 ≥16 的（让代码里的 "P/E 标签" 比例和 i9 一样是 8+8），dispatcher 再取 8 个编号 ≥16 的：

```bash
eval "$(python3 - <<'EOF'
import subprocess
rows = [l.split(",") for l in subprocess.check_output(
    ["lscpu", "-p=CPU,CORE,NODE"], text=True).splitlines() if not l.startswith("#")]
seen, cpus = set(), []
for cpu, core, node in rows:
    if node != "0" or core in seen:
        continue
    seen.add(core); cpus.append(int(cpu))
low  = [c for c in cpus if c < 16][:8]
high = [c for c in cpus if c >= 16]
assert len(low) == 8 and len(high) >= 16, f"node0 物理核不够: low={low} high={len(high)}"
print("export WORKER_CORES=" + ",".join(map(str, low + high[:8])))
print("export DISPATCHER_CORES=" + ",".join(map(str, high[8:16])))
EOF
)"
echo "$WORKER_CORES"; echo "$DISPATCHER_CORES"
```

断言失败（node0 不足 24 个物理核）时，把实际情况记下来，dispatcher 可以退而用兄弟超线程，结果里注明。

### 4.1 冒烟测试

```bash
numactl --cpunodebind=0 --membind=0 \
  mark7/build/ndpiBenchmarkMark7 -i /tmp/t50.pcap -P ours \
  -n 16 -c "$WORKER_CORES" -d "$DISPATCHER_CORES" \
  -m mark7/offline_costs/lookup_table.json -C mark7/offline_costs/cost_profile.csv \
  -o /tmp/smoke -q | tail -20
cat /tmp/smoke/run_summary.csv
```

检查：stderr 里没有 `pthread_setaffinity_np ... failed`；`total_packets=42965`、`total_flows=965`、`detected_flows=965`（和 i9 一致）。

---

## 5. 跑测矩阵

| 组 | 代价表 | 策略 | 目的 |
|---|---|---|---|
| **A 照搬** | 原版 `cost_profile.csv`（E 行 ≈ 1.8× P 行） | rss, jsq, static, ours | 和 i9 一模一样的配置，直接比速度 |
| **B 同构** | `cost_profile_homog.csv`（E 行 = P 行） | ours | 至强是同构的，看"告诉调度器核都一样"之后 ours 怎么变 |

（rss / jsq / static 的决策不读代价值，B 组跑它们和 A 组一样，所以 B 只跑 ours。）

所有命令在 `ndpi_speed/` 目录下执行：

```bash
PCAP=input/syn_mtu_10G.pcap
NUMA="numactl --cpunodebind=0 --membind=0"     # i9 上置空：NUMA=""
COMMON="--pcap $PCAP --worker-cores $WORKER_CORES --dispatcher-cores $DISPATCHER_CORES \
  --lookup mark7/offline_costs/lookup_table.json --repeats 5 --tag overall"

# A 组
$NUMA python3 mark7/scripts/run_mark7_eval.py $COMMON \
  --cost-profile mark7/offline_costs/cost_profile.csv \
  --policy rss --policy jsq --policy static --policy ours \
  --workload-label A --eval-root evaluation/A

# B 组
cat > mark7/offline_costs/cost_profile_homog.csv <<'EOF'
core_type,bucket,cost_us
P,Easy,2.262390
P,Middle,7.626345
P,Hard,17.278661
E,Easy,2.262390
E,Middle,7.626345
E,Hard,17.278661
EOF
$NUMA python3 mark7/scripts/run_mark7_eval.py $COMMON \
  --cost-profile mark7/offline_costs/cost_profile_homog.csv \
  --policy ours \
  --workload-label B --eval-root evaluation/B
```

每个 run 都会把原始输出写到 `evaluation/<组>/batch_<时间戳>/raw/<run_id>/`；任何一次 run 失败，脚本会直接报错退出。

单次 run 大部分时间花在预加载 10 GB pcap 上。内存需求约 `包数 × 1.5 KB`，10 GB trace 大约 12 GB，NUMA 节点上空闲内存最好 ≥ 24 GB。

---

## 6. 汇总

```bash
for g in A B; do
  b=$(ls -d evaluation/$g/batch_* | tail -1)
  python3 mark7/scripts/prepare_figure_csvs.py --batch-dir $b
  echo "== $g"; cat $b/derived/figure3_throughput.csv $b/derived/figure4_latency.csv
done

# 每个 run 的明细（看重复间波动）
python3 - <<'EOF'
import glob, json, pandas as pd
rows = []
for d in glob.glob("evaluation/*/batch_*/raw/*"):
    s = pd.read_csv(f"{d}/run_summary.csv").iloc[0]
    m = json.load(open(f"{d}/run_meta.json"))
    rows.append(dict(group=m["workload_label"], policy=m["policy"], rep=m["repeat"],
                     Mpps=s.throughput_pps/1e6, Gbps=s.bandwidth_gbps, replay_s=s.replay_sec,
                     p50=s.detect_latency_p50_ms, p99=s.detect_latency_p99_ms,
                     pkts=s.total_packets, flows=s.total_flows, detected=s.detected_flows))
df = pd.DataFrame(rows).sort_values(["group","policy","rep"])
print(df.to_string(index=False))
print(df.groupby(["group","policy"])[["Mpps","Gbps","p50","p99"]].agg(["mean","std"]).round(3))
EOF
```

同时把机器信息存一份：

```bash
{ date; hostname; uname -r; lscpu; numactl -H; free -g;
  cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null;
  cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor;
  gcc --version | head -1; grep Version ~/ndpi-install/lib/pkgconfig/libndpi.pc;
  python3 -c "import scapy;print('scapy',scapy.__version__)"
  sha256sum input/syn_mtu_10G.pcap
  echo "WORKER_CORES=$WORKER_CORES"; echo "DISPATCHER_CORES=$DISPATCHER_CORES";
} > evaluation/machine.txt
```

---

## 7. i9 基准结果与对比

### 7.1 i9-14900K 实测（同一 trace、同一命令）

环境：i9-14900K，32 逻辑核，单 NUMA，62 GB；gcc 13.3.0；nDPI 5.1.0；performance 策略，turbo 开。

跑测时间 2026-10-20，`powerprofilesctl`=performance、EPP=performance（governor 显示 `powersave` 是 intel_pstate 的正常表现），turbo 开（`no_turbo=0`）。
核：`WORKER_CORES=0,2,4,6,8,10,12,14,24,25,26,27,28,29,30,31`，`DISPATCHER_CORES=16,17,18,19,20,21,22,23`。
25 次 run 共 4.6 分钟，每次约 11 s，其中 replay 只有 0.6~0.8 s，其余是预加载。
所有 run 的 `total_packets / total_flows / detected_flows` 都是 **8,789,665 / 197,546 / 197,546**。

5 次重复的均值 ± 标准差：

| 组 | policy | Mpps | Gbps | replay (s) | p50 (ms) | p99 (ms) | worker 负载 CV（rep1） |
|---|---|---|---|---|---|---|---|
| A | rss    | 12.50 ± 0.22 | 122.2 ± 2.1 | 0.703 | 1.42 ± 0.13 | 5.76 ± 0.59 | 0.262 |
| A | jsq    | 14.78 ± 0.12 | 144.5 ± 1.2 | 0.595 | 2.07 ± 0.03 | 4.78 ± 0.32 | 0.018 |
| A | static | 11.32 ± 0.11 | 110.6 ± 1.1 | 0.777 | 2.07 ± 0.00 | 3.14 ± 0.11 | 0.836 |
| A | ours   | 14.69 ± 0.18 | 143.5 ± 1.8 | 0.598 | 2.05 ± 0.01 | 3.73 ± 0.25 | 0.017 |
| B | ours   | 14.80 ± 0.11 | 144.7 ± 1.1 | 0.594 | 2.02 ± 0.01 | 4.51 ± 0.28 | 0.016 |

i9 上能看到的现象（给至强对照用）：
- **jsq ≈ ours > rss > static**。jsq/ours 比 rss 快约 18%。
- rss：流按哈希均分，P/E 各拿一半流，但 E 核 busy 0.60、P 核 0.36，E 核成了瓶颈。
- static：合成 trace 里查表得到 Easy 的流只占约 10%，所以 E 核 worker 几乎闲着（busy 0.06），全部压在 8 个 "P" worker 上，最慢。
- ours 和 jsq 吞吐差不多，ours 的 p99 更低（3.73 vs 4.78 ms）。
- B 组（同构代价表）吞吐和 A 组 ours 在噪声范围内，p99 偏高（4.51 vs 3.73 ms）。
- replay 不到 1 秒，单次 run 的吞吐会有 1~2% 的波动，比较时用 5 次的均值。

### 7.2 对比表（隔壁填）

| 指标 | i9 | 至强 | 至强 / i9 |
|---|---|---|---|
| A rss Mpps | 12.50 | | |
| A jsq Mpps | 14.78 | | |
| A static Mpps | 11.32 | | |
| A ours Mpps | 14.69 | | |
| A ours p50 / p99 (ms) | 2.05 / 3.73 | | |
| B ours Mpps | 14.80 | | |
| B ours p50 / p99 (ms) | 2.02 / 4.51 | | |

### 7.3 怎么看

1. **先核对正确性**：两边 `total_packets`、`total_flows`、`detected_flows` 必须完全一致。不一致说明 trace 或 nDPI 不同，性能数字没法比。
2. **绝对速度**：至强单核频率通常比 i9 P 核（5.7~6.0 GHz）低，但缓存和内存带宽更大。主要看 rss 基线的 Mpps 差多少。
3. **策略间差异在两台机器上是否一致**：比如 i9 上 ours 相对 rss 快/慢多少，至强上是不是同一个方向。
4. **A vs B**：同构硬件上，ours 用错误的 P/E 代价（A）和正确的同构代价（B）谁更好。
5. 合成 trace 只有 5 种协议、流结构完全规整，nDPI 很快就能识别，代价差异比真实流量小得多。所以这里测的主要是**流水线本身的吞吐**，不代表真实流量下 ours 的收益。

---

## 8. 给隔壁机器 Claude Code 的 prompt

把 `mark7_xeon_bundle.tgz`、`nDPI-dev.tgz` 放到至强机器的 `~/WORKSPACE/` 下，在 `~/WORKSPACE` 里启动 Claude Code，粘贴下面这段：

```text
我在做一个跨机器的性能复现实验。另一台机器（i9-14900K）上已经跑完了，现在要在这台至强机器上做一模一样的复现，然后对比速度。

材料都在 ~/WORKSPACE 下：
- mark7_xeon_bundle.tgz：解压到 ~/WORKSPACE/ndpi_speed/，里面有 mark7/（nDPI 调度器 benchmark 源码）、scripts/data/generate_1500b_pcap.py（合成 pcap 生成器）、docs/XEON_迁移跑测文档.md（跑测文档）
- nDPI-dev.tgz：nDPI 5.1.0 dev 源码，必须用这一份，不要从网上下别的版本

请严格按 docs/XEON_迁移跑测文档.md 执行，先通读全文，尤其是 §1.4（P/E 核类型按核编号硬编码）和 §4（选核）。步骤：
1. 解压，装依赖，编译 nDPI 到 ~/ndpi-install，编译 mark7（§3）。
2. 生成 50 MB 样本，核对 sha256 是否和文档 §2.3 里 i9 的值一致；一致再生成 10 GB trace（大约 1 小时，放后台跑），生成完再核对 10 GB 文件的 sha256。任何一个对不上就停下来告诉我，并报告 python 和 scapy 版本。
3. 用 lscpu -e / numactl -H 看清楚拓扑，按 §4 选核，跑 §4.1 冒烟测试，核对包数和流数。
4. 设置 performance governor，确认 turbo 状态（和 i9 一样开着），跑 §5 的 A、B 两组，每组 5 次重复。
5. 按 §6 汇总，填 §7.2 的对比表，按 §7.3 的几点给出结论。

要求：
- 不要修改 mark7 的源码和生成器代码；文档以外的参数改动（比如 NUMA 节点、核数不够时的退路）先问我。
- 跑测期间不要在这台机器上并行做别的重负载任务（包括编译、生成 pcap）。
- 任何一次 run 失败，或者 total_packets / total_flows / detected_flows 和 i9 对不上，先停下来报告，不要继续往下跑。
- 最后把 evaluation/ 目录和 evaluation/machine.txt 打包成 ~/xeon_results.tgz，并给我一段简短的结论：两台机器各策略的 Mpps、p50/p99、比值，以及 A/B 两组的差别。
```

---

## 9. 常见问题

| 现象 | 处理 |
|---|---|
| cmake 报 `nDPI not found` | 没传 `-DNDPI_PREFIX=$HOME/ndpi-install`，或 nDPI 没 `make install` |
| `failed to open lookup table` / `failed to open cost profile` | §1.6，默认路径写死了，显式传 `--lookup` / `--cost-profile` |
| `pthread_setaffinity_np(core=N) failed` | 核号不存在，或不在 `numactl --cpunodebind` 指定的节点里 |
| `worker core list must contain exactly N cores` | 手动跑时 `-n` 和 `-c` 的个数不一致 |
| 进程被 OOM kill | 内存不够，见 §5 末尾 |
| 重复间吞吐波动大 | 关掉其它负载、固定频率；必要时 `--repeats` 加到 10 |
| 生成器报 `scapy is required` | `pip install scapy==2.6.1` |
