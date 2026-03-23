# mark4: 单 Worker 直读 PCAP 识别统计

`mark4` 是在 `mark1-3` 流程风格上新增的单线程版本：
- 不再使用 reader/dispatcher + worker 队列
- 由单个 worker 线程直接读取 pcap 并做 nDPI 识别
- 输出每条流的识别耗时、识别发生在第几包
- 按协议类别汇总平均识别指标

## 构建

```bash
cmake -S mark4 -B mark4/build
cmake --build mark4/build -j4
```

如果 nDPI 不在默认路径 `$HOME/ndpi-install`：

```bash
cmake -S mark4 -B mark4/build -DNDPI_PREFIX=/path/to/ndpi-install
```

## 运行

```bash
./mark4/build/ndpiBenchmarkMark4 -i /path/to/xx.pcap
```

可选参数：
- `-c <core>`：绑定 CPU 核
- `-p <file>`：协议配置文件
- `-q`：静默模式（不打印逐流明细，仅保留总览和类别汇总）
- `-h`：帮助

## 输出说明

终端输出包含三部分：
1. 总览统计
- pcap 总包数、总字节
- 解析成功/失败包数
- pcap 总流数（Total flows）
- 已识别流数与占比

2. 逐流识别明细（默认开启）
- 每条流的 5 元组
- 识别协议、协议类别
- 识别耗时（从该流首包到识别成功）
- 在该流的第几包识别出来
- 在全局 pcap 的第几包识别出来

3. 按协议类别汇总平均值
- 每个类别的流数量
- 平均识别耗时
- 平均识别包序（flow 内）
- 平均识别包序（全局 pcap）
