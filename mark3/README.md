# mark3: nDPI Streaming Benchmark (Dispatcher + Worker)

`mark3` 在 `mark2` 基础上重构为：
- Dispatcher 层可多线程（软件 RSS）
- Worker 层保持原有 nDPI 检测与流表处理
- 新流随机分配到 worker，旧流走共享 `flow -> worker` 粘性映射
- 预处理阶段先建立 `flow -> dispatcher` 粘性映射，运行期按固定 dispatcher ID 分发
- Dispatcher 到 worker 队列支持多生产者安全入队（MPSC-safe）

## 线程模型

- `dispatcher`：读取并标准化 pcap，按共享映射分发到 worker 队列
- 预处理：离线读取/标准化 PCAP，建立每个 dispatcher 的固定包索引区间
- 运行期：dispatcher 仅处理分配给自己的索引区间（同 flow 不跨 dispatcher）
- `worker`：从各自队列消费，维护私有流表并调用 nDPI

`mark3` 的 dispatcher 与 worker 核可分别指定，不再固定单 reader 核。

## 构建

```bash
cmake -S mark3 -B mark3/build
cmake --build mark3/build -j4
```

如果 nDPI 不在默认路径 `$HOME/ndpi-install`：

```bash
cmake -S mark3 -B mark3/build -DNDPI_PREFIX=/path/to/ndpi-install
```

## 运行

```bash
./mark3/build/ndpiBenchmarkMark3 -i /path/to/xx.pcap -n 4 -c 2,3,4,5 -d 0,1
```

参数：
- `-i` 输入 pcap（必选）
- `-n` worker 数
- `-c` worker 绑核列表
- `-d` dispatcher 绑核列表（可选；不传时默认 1 个 dispatcher 且不绑核）
- `-p` 协议配置文件（可选）
- `-q` quiet 模式
