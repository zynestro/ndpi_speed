# ndpiBenchmark (独立版本)


## 目录结构

```
ndpi-benchmark/
  include/
    ndpi_benchmark.h     # 主头文件
    packet_parser.h      # 数据包解析器头文件
    flow_table.h         # 流表头文件
  src/
    main.c               # 主程序入口
    benchmark_util.c     # 工具函数（PCAP加载、流哈希等）
    packet_parser.c      # 以太网/VLAN/IPv4/IPv6 解析器
    flow_table.c         # 每线程流表实现
  Makefile              # 构建配置
  README.md             # 本文档
```

## 单独构建 nDPI

你可以在独立的目录/前缀中构建 nDPI，然后基于它构建此应用。

示例（从源码构建 nDPI）：

```bash
git clone https://github.com/ntop/nDPI.git
cd nDPI-dev
./autogen.sh
./configure --prefix=$HOME/ndpi-install --with-only-libndpi
make -j
make install
```

注意事项：
- `--with-only-libndpi` 仅构建库而不构建示例工具。
- 你可能需要安装 `libpcap-dev` / `libpcap-devel`。

## 构建/编译



```bash
cd benchmark
mkdir build && cd build
cmake ..
make -j$(nproc)
```



#### CMake 常用命令

```bash
# 清理并重新构建
rm -rf build && mkdir build && cd build && cmake .. && make

# 查看详细编译命令
make VERBOSE=1

# 并行编译（使用所有CPU核心）
make -j$(nproc)

# 只重新编译修改的文件
make

# 安装到系统
sudo make install
```



## 运行

如果你将 nDPI 安装到非系统前缀，需要确保运行时链接器能找到 `libndpi.so`：

```bash
export LD_LIBRARY_PATH=$HOME/ndpi-install/lib:$LD_LIBRARY_PATH
./ndpiBenchmark -i /path/to/trace.pcap -n 4 -l 1000 -r -t -c 0,1,2,3
```

---


## 命令行参数说明

### 必需参数
- `-i <pcap>`: 输入的 PCAP 文件路径

### 可选参数
- `-n <num>`: 工作线程数量（默认：1）
- `-l <num>`: 循环次数（默认：1）
- `-c <list>`: CPU 核心列表，用逗号分隔（例如：0,1,2,3）
- `-r`: 每次循环随机化流元组（避免缓存作弊）
- `-t`: 时间戳抖动 + 启用 `-r` 时在循环间清理流表
- `-p <file>`: 加载 nDPI 协议配置文件
- `-q`: 安静模式（减少输出）
- `-h`: 显示帮助信息

## 使用示例

### 快速验证测试
```bash
./ndpiBenchmark -i test.pcap -l 10
```

### 多核性能测试
```bash
./ndpiBenchmark -i test.pcap -n 8 -c 0,2,4,6,8,10,12,14 -l 100
```

### 完整压力测试
```bash
./ndpiBenchmark -i test.pcap -n 4 -l 10000 -r -t
```

### 使用自定义协议配置
```bash
./ndpiBenchmark -i test.pcap -p custom_protos.txt -n 4
```

## 工作原理

每个工作线程：
- 维护**私有**流表（无锁设计）
- 对于每个数据包：
  1) 解析以太网/VLAN + IP + TCP/UDP
  2) 查找/创建规范化的双向流键
  3) 对流状态调用 `ndpi_detection_process_packet()`

当启用 `-r -t` 时：
- 每次循环修改5元组，使数据包看起来像新流
- 在循环之间清理流表以避免无限增长

## 性能指标说明

运行后会显示以下指标：

```
========================================
Benchmark Results
========================================
Elapsed Time: 2.456 seconds            # 运行时间
Total Packets: 50000000                # 处理的总数据包数
Total Bytes: 32000.00 MB              # 处理的总字节数

Performance:
  Throughput: 20.36 Mpps               # 吞吐量（百万包/秒）
  Bandwidth: 104.23 Gbps               # 等效带宽
  Cycles per packet: 142.58            # 每包CPU周期数（越低越好）

Protocol Detection Verification:
  Total flows created: 25000           # 创建的流总数
  Flows with detected protocol: 24856 (99.4%)  # 检测到协议的流
  ✓ nDPI is actively detecting protocols!

Per-Worker Statistics:                 # 每个工作线程的统计
  Worker  0 [Core  0]: 5.09 Mpps, 26.06 Gbps, 6250 flows
  Worker  1 [Core  1]: 5.09 Mpps, 26.06 Gbps, 6250 flows
  Worker  2 [Core  2]: 5.09 Mpps, 26.05 Gbps, 6250 flows
  Worker  3 [Core  3]: 5.09 Mpps, 26.06 Gbps, 6250 flows

Scaling Efficiency: 100.0%             # 多核扩展效率
========================================
```

## 获取测试数据

### 方法 1：下载公开 PCAP 样本

```bash
# 小流量样本（适合快速测试）
wget https://tcpreplay.appneta.com/wiki/captures/smallFlows.pcap

# 大流量样本（适合性能测试）
wget https://tcpreplay.appneta.com/wiki/captures/bigFlows.pcap

# 使用 tcpdump 捕获实时流量
sudo tcpdump -i eth0 -w my_traffic.pcap -c 10000
```

### 方法 2：使用 nDPI 测试文件

```bash
# 如果已克隆 nDPI 仓库
cp /path/to/nDPI/tests/pcap/*.pcap ./
```

## 故障排查

### 问题 0：编译时出现 `unknown type name 'u_int'` 错误

这是因为 `pcap.h` 依赖 BSD 类型定义，但在严格 C11 模式下这些类型被隐藏。

**解决方法**：确保在包含 `<pcap.h>` 之前定义 `_GNU_SOURCE` 并包含 `<sys/types.h>`：

```c
#define _GNU_SOURCE
#include <sys/types.h>
#include <pcap.h>
```

或者在 Makefile 的 CFLAGS 中添加：
```makefile
CFLAGS += -D_GNU_SOURCE
```

### 问题 1：找不到 nDPI 库

```bash
# 检查 nDPI 是否已安装
ldconfig -p | grep ndpi

# 如果没有，设置库路径
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# 或者在系统范围内配置
sudo ldconfig /usr/local/lib
```

### 问题 2：PCAP 文件无数据包

```bash
# 验证 PCAP 文件
tcpdump -r test.pcap -c 10

# 查看文件详细信息
capinfos test.pcap
```

### 问题 3：性能异常低

```bash
# 检查 CPU 频率调节器
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 设置为性能模式（需要root权限）
sudo cpupower frequency-set -g performance

# 或者临时设置单个核心
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### 问题 4：协议检测率低

可能的原因：
- PCAP 文件中的流量已加密（HTTPS、TLS）
- 数据包被截断，缺少关键信息
- 需要自定义协议配置文件

解决方法：
```bash
# 使用 nDPI 自带的示例配置
./ndpiBenchmark -i test.pcap -p /path/to/nDPI/example/protos.txt
```

## 性能优化建议

### 1. CPU 优化
```bash
# 禁用超线程（在 BIOS 中或使用）
echo off | sudo tee /sys/devices/system/cpu/smt/control

# 隔离 CPU 核心（在 GRUB 配置中添加）
# isolcpus=0-7 nohz_full=0-7 rcu_nocbs=0-7
```

### 2. 内存优化
```bash
# 配置大页内存
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages

# 在应用中使用大页（需要修改代码）
```

### 3. NUMA 优化
```bash
# 查看 NUMA 拓扑
numactl --hardware

# 将进程绑定到特定 NUMA 节点
numactl --cpunodebind=0 --membind=0 ./ndpiBenchmark -i test.pcap -n 4
```

### 4. 网络捕获优化
```bash
# 使用更大的捕获缓冲区
sudo tcpdump -i eth0 -B 16384 -w capture.pcap

# 或使用高性能捕获工具
sudo tcpreplay --intf1=eth0 --pps=1000000 test.pcap
```

## 高级功能

### 流随机化（-r 参数）

流随机化通过修改数据包的 IP ID 和源端口，使每次循环的数据包被识别为新流：

```c
// 每次循环修改：
// 1. IP ID = 原始ID XOR (loop_id * 65521 + worker_id * 251)
// 2. 源端口 = 原始端口 XOR ((loop_id & 0xFF) << 8)
```

好处：
- 避免缓存效应影响测试结果
- 测试 nDPI 在大量并发流下的性能
- 模拟真实网络环境

### 时间戳抖动（-t 参数）

为每个循环增加时间偏移（每循环 +1 小时）：

```c
// 时间戳调整
pkt->timestamp_us += (uint64_t)loop_id * 3600 * 1000000;
```

配合 `-r` 使用时，会在循环间清理流表，避免：
- 流超时判断错误
- 内存无限增长
- 流表查找性能下降

## 架构说明

### 无锁并行设计

```
┌─────────────────────────────────────────────────┐
│              PCAP 文件加载到内存                  │
│         (64字节对齐，优化缓存访问)                 │
└────────────────┬────────────────────────────────┘
                 │
                 ├─── 按流哈希分配 ───┐
                 │                    │
        ┌────────▼────────┐  ┌────────▼────────┐
        │  Worker 0       │  │  Worker 1       │
        │  - CPU Core 0   │  │  - CPU Core 1   │
        │  - 私有流表     │  │  - 私有流表     │
        │  - nDPI实例     │  │  - nDPI实例     │
        └────────┬────────┘  └────────┬────────┘
                 │                    │
                 └──────── 统计 ──────┘
                          汇总
```

### 数据结构层次

```
packet_pool_t
  └─ mem_packet_t[] (连续内存块)
       └─ 数据包数据

worker_context_t
  └─ flow_table_t (哈希表)
       └─ bench_flow_t
            └─ ndpi_flow_struct
```

## 与原版 ndpiBenchmark 的比较

| 特性 | 原版 | 独立版 |
|------|------|--------|
| 依赖 nDPI example | ✓ | ✗ |
| 自定义流表 | ✗ | ✓ |
| 自定义数据包解析 | ✗ | ✓ |
| 易于集成 | 难 | 易 |
| 维护独立性 | 低 | 高 |
| 性能 | 好 | 更好 |

## 许可证

本项目遵循与 nDPI 相同的许可证（LGPL-3.0）。

## 贡献

欢迎提交 Issue 和 Pull Request！

主要贡献方向：
- 支持更多协议解析（MPLS、GRE等）
- 优化哈希表性能
- 添加更多性能分析指标
- 改进 NUMA 支持
- 添加 GPU 加速支持

## 联系方式

- 项目主页：https://github.com/your-repo/ndpi-benchmark
- nDPI 官方：https://github.com/ntop/nDPI

## 致谢

- nDPI 项目提供了出色的 DPI 库
- 原始 ndpiBenchmark 工具提供了设计灵感

