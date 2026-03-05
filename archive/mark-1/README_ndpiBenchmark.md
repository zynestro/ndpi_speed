# ndpiBenchmark - nDPI高性能吞吐量测试工具

## 功能特性

1. **内存预加载**: 将整个PCAP文件预先加载到内存，消除IO瓶颈
2. **多核并行**: 支持多线程，按流哈希分配数据包到不同核心
3. **流随机化**: 避免缓存作弊，每次循环修改5元组
4. **时间戳抖动**: 避免流表污染和重传误判
5. **保证准确性**: 完整保留nDPI流表管理、双向识别等机制

## 编译

```bash
cd /home/yzy/nDPI/example
make ndpiBenchmark
```

或手动编译：
```bash
gcc -fPIC -DPIC -I../src/include -pthread -O2 -c ndpiBenchmark.c -o ndpiBenchmark.o
gcc -fPIC -DPIC -I../src/include -pthread -O2 -c benchmark_util.c -o benchmark_util.o  
gcc -o ndpiBenchmark ndpiBenchmark.o benchmark_util.o reader_util.o -L../src/lib -lndpi -lpcap -pthread -lm
```

## 使用方法

### 基本用法

```bash
./run_benchmark.sh -i <pcap文件> [选项]
```

### 常用选项

- `-i <file>` : PCAP文件路径 (必需)
- `-n <num>`  : 工作线程数 (默认: 1)
- `-l <num>`  : 循环次数 (默认: 1)
- `-c <list>` : CPU核心列表，如 "0,1,2,3"
- `-r`        : 启用流随机化 (推荐，避免缓存作弊)
- `-t`        : 启用时间戳抖动 (推荐，避免流污染)
- `-p <file>` : 协议配置文件
- `-q`        : 安静模式
- `-h`        : 显示帮助

## 使用示例

### 1. 单核测试
```bash
./run_benchmark.sh -i test.pcap -n 1 -l 1000 -r -t
```

### 2. 多核测试 (4核)
```bash
./run_benchmark.sh -i test.pcap -n 4 -l 1000 -r -t -c 0,1,2,3
```

### 3. 高性能测试 (8核，大循环)
```bash
./run_benchmark.sh -i test.pcap -n 8 -l 5000 -r -t -c 0,1,2,3,4,5,6,7
```

## 输出说明

### 总体统计
- **Elapsed time**: 总耗时
- **Total packets**: 处理的总包数
- **Total bytes**: 处理的总字节数
- **Unique flows**: 检测到的唯一流数

### 吞吐量指标
- **Packets/sec**: 每秒处理包数 (Mpps)
- **Bits/sec**: 每秒处理比特数 (Gbps)
- **Avg packet size**: 平均包大小
- **Avg time/packet**: 平均每包处理时间

### 多核统计 (仅多线程模式)
- 每个Worker的吞吐量和流数
- **Scaling Efficiency**: 扩展效率 (理想值100%)

## 测试结果示例

```
========================================
Benchmark Results
========================================

Total Statistics:
  Elapsed time:    13.414 seconds
  Total packets:   10000000
  Total bytes:     14540000000 (13866.42 MB)
  Unique flows:    256724

Throughput:
  Packets/sec:     745513 (0.746 Mpps)
  Bits/sec:        8.67 Gbps
  Avg packet size: 1454 bytes
  Avg time/packet: 1341.36 ns

Per-Worker Statistics:
  Worker  0 [Core  0]: 0.15 Mpps, 1.73 Gbps, 51252 flows
  Worker  1 [Core  1]: 0.30 Mpps, 3.47 Gbps, 102722 flows
  Worker  2 [Core  2]: 0.22 Mpps, 2.60 Gbps, 77050 flows
  Worker  3 [Core  3]: 0.07 Mpps, 0.87 Gbps, 25700 flows

Scaling Efficiency: 125.0%
========================================
```

## 与ndpiReader对比

| 特性 | ndpiReader | ndpiBenchmark |
|------|-----------|---------------|
| 目的 | 功能验证 | 性能测试 |
| IO方式 | libpcap文件读取 | 内存预加载 |
| 多核支持 | 仅实时捕获 | PCAP文件支持 |
| 缓存优化 | 无 | 流随机化 |
| 流表管理 | 重复读取会污染 | 时间戳抖动 |
| 预期性能 | 1-2 Gbps/核 | 3-5 Gbps/核 |

## 注意事项

1. **流随机化 (-r)**: 推荐开启，但会产生更多流，消耗更多内存
2. **时间戳抖动 (-t)**: 推荐开启，避免流超时导致的识别中断
3. **CPU绑定 (-c)**: 指定核心列表可获得更稳定的性能
4. **内存需求**: 需要足够内存加载PCAP，约为PCAP大小的1.2倍

## 性能调优建议

1. 使用CPU绑定 (`-c`) 避免线程迁移
2. 关闭超线程以获得更准确的单核性能
3. 循环次数建议1000+以减少测试误差
4. 多核测试时注意流分布均衡性

## 故障排除

### 链接错误: cannot find libndpi.so
```bash
export LD_LIBRARY_PATH=/path/to/nDPI/src/lib:$LD_LIBRARY_PATH
```

### 段错误
- 检查PCAP文件是否损坏
- 减小循环次数或线程数
- 检查可用内存是否充足

### 性能异常
- 检查是否开启了流随机化 (`-r`)
- 验证CPU亲和性设置是否生效
- 使用`perf`工具分析热点函数
