# mark2: nDPI Streaming Benchmark (Single Baseline Version)

`mark2` 是对 `mark1` 的“单基线重构版”：
- 只保留一个可执行版本：`ndpiBenchmarkMark2`
- 不包含 `classified/batch/mem/singlehash/agglb` 这些变体目标
- 线程模型与流程保持一致：`reader -> hash/rss -> worker -> flow table -> nDPI`

## 目录结构

- `include/ndpi_benchmark.h`
  统一声明类型、队列、计时字段与函数接口
- `include/benchmark_internal.h`
  reader/worker/main 的内部共享接口
- `src/main.c`
  参数解析、线程生命周期、结果汇总与打印
- `src/reader.c`
  reader 线程：读取/分流/入队 + 读路径计时
- `src/worker.c`
  worker 线程：解析/查流/识别 + 处理路径计时
- `src/packet_parser.c`
  链路层标准化、L3/L4 解析、flow key 构造、快速 hash
- `src/flow_table.c`
  worker 私有 flow 状态表
- `src/rss_table.c`
  reader 侧 flow->worker 粘性映射表
- `src/benchmark_common.c`
  共享工具和样本打印逻辑

## 构建

```bash
cmake -S mark2 -B mark2/build
cmake --build mark2/build -j4
```

如果 nDPI 不在默认路径 `$HOME/ndpi-install`：

```bash
cmake -S mark2 -B mark2/build -DNDPI_PREFIX=/path/to/ndpi-install
```

## 运行

```bash
./mark2/build/ndpiBenchmarkMark2 -i /path/to/xx.pcap -n 4 -c 1,2,3,4 -r 0
```

参数：
- `-i` 输入 pcap（必选）
- `-n` worker 数
- `-c` worker 绑核列表
- `-r` reader 绑核
- `-p` 协议配置文件（可选）
- `-q` quiet 模式

## 计时口径（重点）

mark2 的计时以纳秒为内部单位，统一使用 `CLOCK_MONOTONIC_RAW`。

### Read 路径
- `Read pcap_next_ex`: 取包调用时间
- `Read hash`: 分流 hash 计算
- `Read rss_lookup`: RSS 映射查找/分配
- `Read enqueue`: 入队时间（包含队列压力带来的等待）
- `Read other`: 其余 reader 开销（包含 normalize + 循环边界开销）

### Process 路径
- `Process parse`: 报文解析
- `Process flowkey_lookup`: flowkey 构造 + flow 查找/创建
- `Process flow_init`: 新流初始化
- `Process flow`: flow 阶段聚合
- `Process nDPI call`: nDPI 检测函数调用
- `Process proto_check`: 协议命中检查/统计
- `Process nDPI`: nDPI 阶段聚合
- `Process classified_fastpath`: 预留字段（mark2 基线通常为 0）
- `Process other`: 其余处理开销

说明：
- `Process Time` 口径仍是“最慢 worker”的处理时长（wall 主导）
- 分项阶段为可加总统计，用于定位瓶颈

