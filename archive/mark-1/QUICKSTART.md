# ndpiBenchmark 快速上手指南

## 一、快速开始 (3步)

### 1. 编译
```bash
cd /home/yzy/nDPI/example
make clean && make ndpiBenchmark
```

### 2. 运行单核测试
```bash
./run_benchmark.sh -i /home/yzy/dataset/ndpi_test/seed_1500b.pcap -n 1 -l 1000 -r -t
```

### 3. 运行多核测试
```bash
./run_benchmark.sh -i /home/yzy/dataset/ndpi_test/seed_1500b.pcap -n 4 -l 1000 -r -t -c 0,1,2,3
```

## 二、常用命令

### 基础测试
```bash
# 最简单的测试 (1核, 10循环)
./run_benchmark.sh -i test.pcap -n 1 -l 10

# 标准测试 (1核, 1000循环, 启用优化)
./run_benchmark.sh -i test.pcap -n 1 -l 1000 -r -t

# 高性能测试 (4核, 5000循环)
./run_benchmark.sh -i test.pcap -n 4 -l 5000 -r -t -c 0,1,2,3
```

### 综合测试
```bash
# 自动测试所有配置 (1核/2核/4核/8核)
./comprehensive_benchmark.sh test.pcap

# 查看结果
cat benchmark_results/benchmark_*.txt.summary
```

### 对比测试
```bash
# 对比 ndpiReader vs ndpiBenchmark
./compare_tools.sh test.pcap
```

## 三、参数说明

### 必需参数
- `-i <file>` : PCAP文件路径

### 性能参数
- `-n <num>` : 线程数 (1-64, 默认1)
- `-l <num>` : 循环次数 (建议≥1000)
- `-c <list>` : CPU核心绑定 (如 "0,1,2,3")

### 优化开关
- `-r` : **流随机化** (推荐开启)
- `-t` : **时间戳抖动** (推荐开启)

### 其他
- `-p <file>` : 协议配置文件
- `-q` : 安静模式
- `-h` : 帮助信息

## 四、输出解读

### 关键指标
```
Throughput:
  Packets/sec:     471075 (0.471 Mpps)  ← 每秒处理包数
  Bits/sec:        5.48 Gbps             ← 吞吐量
  Avg time/packet: 2122.80 ns           ← 单包处理时间
```

### 多核性能
```
Per-Worker Statistics:
  Worker  0 [Core  0]: 0.15 Mpps, 1.73 Gbps
  Worker  1 [Core  1]: 0.30 Mpps, 3.47 Gbps
  
Scaling Efficiency: 125.0%              ← 扩展效率 (越接近100%越好)
```

## 五、常见问题

### Q: 链接错误 "cannot find libndpi.so"
```bash
export LD_LIBRARY_PATH=/home/yzy/nDPI/src/lib:$LD_LIBRARY_PATH
./ndpiBenchmark -h
```
或直接使用封装脚本: `./run_benchmark.sh`

### Q: 性能不理想怎么办？
1. 确认开启 `-r -t` 优化
2. 使用 `-c` 绑定CPU核心
3. 增加循环次数 `-l 1000`
4. 检查系统负载和内存

### Q: 如何验证结果正确性？
```bash
# 对比流数和协议检测
./ndpiReader -i test.pcap | grep "Unique flows"
./run_benchmark.sh -i test.pcap -n 1 -l 1 | grep "Unique flows"
```

### Q: 内存不足怎么办？
- 减小循环次数 `-l 100`
- 使用更小的PCAP文件
- 或等待未来支持流式处理的版本

## 六、性能调优建议

### 单核最大化
```bash
# 关闭超线程, 绑定物理核心, 高频率
./run_benchmark.sh -i test.pcap -n 1 -l 5000 -r -t -c 0
```

### 多核最大化
```bash
# 绑定物理核心, 避免跨NUMA
./run_benchmark.sh -i test.pcap -n 4 -l 5000 -r -t -c 0,1,2,3
```

### 最准确测试
```bash
# 大循环数, 启用所有优化, 重复3次取平均
for i in 1 2 3; do
  ./run_benchmark.sh -i test.pcap -n 1 -l 2000 -r -t -c 0
done
```

## 七、进阶用法

### 自定义协议配置
```bash
./run_benchmark.sh -i test.pcap -n 1 -l 1000 -r -t -p protos.txt
```

### 生成性能报告
```bash
./comprehensive_benchmark.sh test.pcap results/
cat results/benchmark_*.txt
```

### 结合perf分析
```bash
export LD_LIBRARY_PATH=../src/lib:$LD_LIBRARY_PATH
perf record -g ./ndpiBenchmark -i test.pcap -n 1 -l 100
perf report
```

## 八、与ndpiReader对比

| 场景 | ndpiReader | ndpiBenchmark |
|------|-----------|---------------|
| 功能验证 | ✅ 推荐 | ❌ |
| 协议分析 | ✅ 推荐 | ❌ |
| 性能测试 | ❌ 不准确 | ✅ 推荐 |
| 多核测试 | ❌ 不支持PCAP | ✅ 推荐 |
| 吞吐量测试 | ❌ 有IO瓶颈 | ✅ 推荐 |

## 九、文档资源

- **完整文档**: `README_ndpiBenchmark.md`
- **开发总结**: `DEVELOPMENT_SUMMARY.md`
- **脚本集合**:
  - `run_benchmark.sh` - 单次测试
  - `comprehensive_benchmark.sh` - 综合测试
  - `compare_tools.sh` - 对比测试

## 十、技术支持

遇到问题？检查以下文件:
1. `README_ndpiBenchmark.md` - 详细使用文档
2. `DEVELOPMENT_SUMMARY.md` - 技术实现细节
3. 运行 `./ndpiBenchmark -h` 查看帮助

---

**祝测试顺利! 🚀**
