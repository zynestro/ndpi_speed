# mark1: nDPI Streaming Benchmark

这个目录是一个离线 PCAP 吞吐测试工具，核心目标是模拟线上流式处理：
- 一个 reader 线程读包
- 按流哈希分发给多个 worker
- worker 维护自己的 flow table 并调用 nDPI 做协议识别

## 代码结构

- `src/main.c`
  - 参数解析、线程创建、主流程控制、结果汇总输出
- `src/reader.c`
  - reader 线程逻辑（普通流式读取 / 内存预读两种模式）
- `src/rss_table.c`
  - reader 使用的 `flow -> worker` 映射表（RSS table）
- `src/worker.c`
  - worker 生命周期、单包处理、调用 nDPI
- `src/flow_table.c`
  - worker 私有流表（可选 classified table）
- `src/packet_parser.c`
  - 链路层标准化、IPv4/IPv6 解析、流键构造、分流 hash
- `src/benchmark_common.c`
  - 全局状态、样例打印、线程绑核
- `src/benchmark_internal.h`
  - 内部跨模块接口与共享类型

## 运行流程

1. `main.c` 初始化 nDPI 全局上下文，创建 workers、queues、rss table。
2. 启动多个 worker 线程（每个 worker 有自己的 flow table）。
3. 启动 reader 线程。
4. reader 每读到一个包：
   - 做链路层标准化（`normalize_to_ethernet`）
   - 计算分流哈希（`compute_flow_hash`）
   - 查 `rss_table` 决定投递到哪个 worker
5. worker 取包后：
   - 解析 L2/L3/L4
   - 查找或创建 flow（worker 私有 `flow_table`）
   - 调用 nDPI 处理并更新统计
6. 所有包处理完后，主线程 join 所有线程并打印性能结果。

## flow_table 和 rss_table 的关系

- `rss_table`：进程级共享（主要由 reader 线程操作），负责决定流分配到哪个 worker。
- `flow_table`：每个 worker 私有，负责维护该 worker 内流状态与 nDPI flow state。

可以理解为：
- `rss_table` 解决“发给谁”
- `flow_table` 解决“在这个 worker 里怎么持续跟踪这个流”

## 依赖

- CMake >= 3.10
- libpcap
- pthread
- nDPI（默认路径：`$HOME/ndpi-install`）

如果 nDPI 不在默认目录，配置时传：

```bash
cmake -S mark1 -B mark1/build -DNDPI_PREFIX=/your/ndpi/install
```

## 构建

```bash
cmake -S mark1 -B mark1/build
cmake --build mark1/build -j4
```

构建后会生成 4 个可执行文件：
- `mark1/build/ndpiBenchmark`：基础版
- `mark1/build/ndpiBenchmarkClassified`：分类后将流固定在 classified table
- `mark1/build/ndpiBenchmarkBatch`：reader 端批量入队
- `mark1/build/ndpiBenchmarkMem`：先把 pcap 读入内存再处理

## 运行

最常用命令：

```bash
./mark1/build/ndpiBenchmark -i /path/to/xx.pcap -n 4 -c 1,2,3,4 -r 0
```

参数说明：
- `-i <file>`：PCAP 文件路径（必填）
- `-n <num>`：worker 线程数
- `-c <list>`：worker 绑核列表（逗号分隔）
- `-r <core>`：reader 线程绑核
- `-p <file>`：可选协议配置文件
- `-q`：安静模式
- `-h`：帮助

上面这条命令的意思是：
- 用 `xx.pcap` 做输入
- 启动 4 个 worker
- worker 分别绑到 CPU 1/2/3/4
- reader 绑到 CPU 0

## 其它变体运行示例

```bash
./mark1/build/ndpiBenchmarkClassified -i /path/to/xx.pcap -n 4 -c 1,2,3,4 -r 0
./mark1/build/ndpiBenchmarkBatch      -i /path/to/xx.pcap -n 4 -c 1,2,3,4 -r 0
./mark1/build/ndpiBenchmarkMem        -i /path/to/xx.pcap -n 4 -c 1,2,3,4 -r 0
```

## 输出结果包含

- 总耗时、读包耗时、处理耗时
- 吞吐（Mpps）与带宽（Gbps）
- cycles per packet
- 协议识别命中率（flows with detected protocol）
- 多 worker 下的每核统计
