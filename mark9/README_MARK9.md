# mark9：逐协议连续代价查找表

## 相比 mark7 的变化

mark7 将首包 port/prefix 规则映射到 3 个粗粒度 bucket（Easy/Middle/Hard）。
mark9 将查找输出从 **bucket** 升级为 **proto_hint**（nDPI 协议 ID），
实现逐协议连续代价估计，自然对接 EWMA adaptive cost table。

### 主要区别

| 维度（Dimension） | mark7 | mark9 |
|-----------|-------|-------|
| 查找输出（Lookup output） | bucket (Easy/Mid/Hard) | proto_hint（协议 ID） |
| 代价粒度（Cost granularity） | 3 个值 | 67+ 连续值 |
| 歧义端口（Ambiguous ports） | 回退到 default_bucket | prefix 消歧 → proto_hint |
| Adaptive table 兼容性 | 无（adaptive 按 proto 索引） | 天然兼容（输出即 proto_hint） |
| 纯度阈值（Purity threshold） | 0.95 | 0.90（EWMA 修正误差） |
| 运行时开销（Runtime overhead） | O(1) 数组 | O(1) 数组（相同） |

### 相比 mark7 修改的文件

- `include/ndpi_benchmark.h` — 新增 `port_proto_rule_t`、`prefix_proto_rule_t`、`proto_lookup_table_t`、`lookup_result_t`，内联函数 `proto_lookup()`
- `include/benchmark_internal.h` — 新增 `proto_lookup_table_load()`、`proto_lookup_table_destroy()` 声明；更新 `dispatch_context_create()` 签名
- `src/cost_table.c` — 新增 `proto_lookup_table_load()`（v2 JSON 解析器）、`proto_lookup_table_destroy()`；保留 `cost_table_load()` 不变以向后兼容
- `src/dispatch.c` — `dispatch_context` 现持有 `proto_lookup_table` 指针；`dispatch_lookup_or_assign()` 在 v2 表可用时使用 `proto_lookup()`
- `src/main.c` — 新增 `-L` 参数用于 v2 proto 查找表；加载并传递给 dispatch context；更新 banner/usage
- `CMakeLists.txt` — 目标重命名为 `ndpiBenchmarkMark9`

### 新增文件

- `scripts/train_proto_lookup_v2.py` — 训练脚本：读取 mark5 CSV，输出 v2 JSON + prior CSV
- `offline_costs/proto_lookup_table_example.json` — v2 格式示例
- `offline_costs/proto_cost_prior_example.csv` — 逐协议代价先验示例

---

## 训练流水线

```bash
# 步骤 1：运行 mark5 profiling 获取逐流 CSV
# （假设 mark5 输出已存在）

# 步骤 2：训练 v2 查找表
cd mark9/scripts
python3 train_proto_lookup_v2.py \
    --flow-csv /path/to/mark5/output/time_flow_profile.csv \
    --output-dir ../offline_costs/ \
    --purity 0.90 \
    --min-support 5

python3 train_proto_lookup_v2.py \
    --flow-csv /home/zync/WORKSPACE/ndpi_speed/output/mark5/20260417_011726/time_flow_profile.csv \
    --output-dir /home/zync/WORKSPACE/ndpi_speed/output/mark9/ \
    --purity 0.90 \
    --min-support 5

# 输出：
#   offline_costs/proto_lookup_table.json  （v2 格式）
#   offline_costs/proto_cost_prior.csv     （逐协议代价先验）
```

---

## 构建与运行说明

```bash
# 构建
mkdir -p build && cd build
cmake -DNDPI_PREFIX=$HOME/ndpi-install ..
make -j$(nproc)

# 仅使用 v1 运行（向后兼容，与 mark7 相同）
./ndpiBenchmarkMark9 -i input.pcap -m ../offline_costs/lookup_table.json

# 使用 v2 proto 查找表运行（mark9 模式）
./ndpiBenchmarkMark9 -i input.pcap \
    -m ../offline_costs/lookup_table.json \
    -L ../offline_costs/proto_lookup_table.json \
    -P ours

# 完整参数
./ndpiBenchmarkMark9 -i input.pcap \
    -n 16 \
    -c 0,2,4,6,8,10,12,14,24,25,26,27,28,29,30,31 \
    -d 16,17,18,19,20,21,22,23 \
    -m ../offline_costs/lookup_table.json \
    -L ../offline_costs/proto_lookup_table.json \
    -C ../offline_costs/cost_profile.csv \
    -P ours \
    -o results/
```

### 新增命令行参数

| 参数（Flag） | 说明（Description） |
|------|-------------|
| `-L <file>` | v2 proto 查找表 JSON 路径。未指定时仅使用 v1 bucket 表。 |

---

## V2 JSON 格式规范

```json
{
  "version": 2,
  "description": "mark9 proto-level lookup table",
  "purity_threshold": 0.90,
  "min_support": 5,
  "port_rules": {
    "<port>": {
      "proto_hint": "<nDPI_protocol_name>",
      "purity": <float 0-1>,
      "support": <int flow_count>
    }
  },
  "prefix_rules": {
    "<port>": {
      "<prefix_hex>": {
        "proto_hint": "<nDPI_protocol_name>",
        "prefix_len": <int 1-4>,
        "purity": <float 0-1>
      }
    }
  },
  "proto_cost_prior": {
    "<protocol_name>": <float mean_cost_us>
  },
  "default_proto_hint": "UNKNOWN"
}
```

### 字段语义

- `version`：必须为 `2`（v2 格式）
- `port_rules`：端口 → 协议的直接映射。键为端口号字符串。
  - `proto_hint`：nDPI 协议名（加载时通过 `ndpi_get_protocol_id_by_name()` 解析为 ID）
  - `purity`：该端口上属于此协议的流比例
  - `support`：该端口的总流数
- `prefix_rules`：用于 port_rules 未覆盖的歧义端口。
  - 键：端口字符串 → 子键：十六进制 prefix 字符串 → 规则对象
  - `prefix_len`：待匹配的载荷字节数（1、2 或 4）
- `proto_cost_prior`：逐协议平均检测代价（微秒），用于初始化 adaptive_cost_table
- `default_proto_hint`：无法解析的流的哨兵值

---

## 向后兼容说明

1. **v1 JSON 仍可使用**：`-m` 参数加载 mark7 的 `lookup_table.json`（v1 格式，含 `port_table`/`special_rules`/`default_bucket`）。此路径始终有效。

2. **v2 为增量添加**：`-L` 参数可选。指定后，dispatch 路径优先尝试 v2 proto 查找。若 proto_hint 解析成功则使用；否则回退到 v1 bucket 查找。

3. **现有 dispatch 策略无破坏性变更**：RSS、JSQ、static-pool 继续使用 bucket 调度。proto_hint 当前用于 OURS 策略路径，将与 adaptive_cost_table（mark8 合并）集成。

4. **`cost_table_load()` 未修改**：原始 v1 加载代码原样保留。mark7 配置无需修改即可运行。

5. **协议解析**：v2 JSON 中的协议名在加载时使用临时 nDPI 检测模块解析为 nDPI ID。若名称无法解析（如未知协议），该规则被静默跳过。
