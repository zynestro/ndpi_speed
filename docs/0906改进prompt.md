你负责继续 ndpi-speed 项目的实验系统开发。请不要把 mark7/mark8/mark9 当作论文主体，它们是已有原型和实验资产；你的任务是在理解旧系统的基础上，创建一个独立的新 mark 系统，暂定命名为 mark10-risk-aware。

====================
一、论文故事线
====================

当前论文不再讲“weighted JSW + EWMA 负载均衡”，而是讲：

软件 DPI 的真实检测成本在首包到达时并不可见，只能根据首包的端口、传输协议、payload prefix 等特征得到一个历史经验先验。随着后续检测包到达，真实 CPU 工作量才逐步显现。首包预测误差在高利用率下会被放大为 p99 time-to-verdict 延迟和 verdict miss。

本文的核心问题是：

在检测成本隐藏、首包预测存在误差、检测过程逐步揭示真实成本、且 P/E 核能力不同的情况下，如何在满足 p99 time-to-verdict SLO 的前提下最大化可持续吞吐？

这里的 time-to-verdict，指从流的首包进入系统到 nDPI 完成有效协议判定的时间。

论文推荐系统名：RevealDPI 或 GuardDPI。
论文暂定标题：

Cost Is Revealed, Not Known:
Risk-Aware Flow Scheduling for Predictable Software DPI on Hybrid Cores

论文只保留三条贡献：

1. Measurement：
   量化 DPI 成本的协议内长尾、跨 trace 漂移、未知流覆盖缺口，以及 P/E 核有效速度漂移；验证首包误差在高利用率下如何放大为尾延迟和判定失败。

2. System：
   基于首包条件成本先验、检测中 CPU-time accounting、分位数/风险感知派发和有限 straggler 纠错，构建不修改 nDPI 检测逻辑的异构核 DPI 调度系统。

3. Evaluation：
   以“满足 p99 TTV SLO 时的最大可持续吞吐”为主指标，验证静态先验、流量漂移、未知流、突发、后台干扰和不同 P/E 配置下的稳定性。

重要解释：

首包不是直接测出真实成本。首包只用于选择历史经验分布：

feature bucket -> {p50, p90, p99, sample_count, confidence}

风险也不是首包直接给出的，而是由成本先验、当前 worker backlog、核速度和 deadline 共同计算：

risk(f,c) =
P((backlog_c + cost_f) / speed_c > remaining_deadline)

第一版可以不实现严格概率模型，优先实现 quantile-aware dispatch：

如果 backlog_c + q_f / speed_c <= 剩余 SLO 预算，
则认为 worker c 对该流是安全的；
在安全 worker 中选择预计完成时间最短者；
如果 E 核都不安全，再使用有限的 P 核保险容量。

P 核不是“重流专用核”，而是用来对冲高不确定性和高超时风险的保险资源。

====================
二、必须遵守的研究边界
====================

1. 不修改、覆盖或重命名 mark7/mark8/mark9。
2. 新系统必须独立目录、独立 README、独立配置和独立输出目录。
3. 不把旧实验数字当作事实。18x、1.8x、旧 throughput、旧 p99 等全部必须重新测量。
4. 不默认已有 DPDK、实时网卡、多机、DPU 或迁移实现。
5. 第一阶段优先在现有 PCAP replay/reader-worker 框架中完成可运行功能。
6. 不先实现复杂 ML、复杂理论、GPU、DPU、多机或大规模 flow migration。
7. 不把“weighted JSW + EWMA”单独包装成新算法。
8. 如果实验结果否定当前故事，必须记录并提出修改，而不是强行制造支持性结果。
9. 所有结果必须保留原始日志、配置、失败运行和异常说明。
10. 任何新增设计都要说明它解决了哪个可观测问题，以及如何通过实验验证。

====================
三、第一阶段：扫描和盘点整个实验环境
====================

先不要写新算法代码。先扫描当前机器上与 ndpi-speed 相关的全部文件和目录，重点包括：

/Users/wanghao137/WORKSPACE/ndpi-speed-0625/
/Users/wanghao137/WORKSPACE/_Markdown/1000.P.Projects/ndpi-speed/

如果路径不存在，请自行寻找 ndpi-speed、mark7、mark8、mark9、nDPI、DPDK、pcap 相关目录。

请重点梳理 mark1 到 mark9。对于每一个 mark，记录：

1. 所在路径和代码是否真实存在。
2. 该 mark 的主要目标。
3. 相对于前一个 mark 的变化。
4. 输入格式和输出格式。
5. reader、dispatcher、worker 的架构。
6. flow affinity 是如何实现的。
7. 当前使用的调度策略。
8. 成本模型是 bucket、均值、连续值还是 Oracle。
9. 是否有 P/E 核能力建模。
10. 是否有 added_cost、retired_cost、pending_cost 或 residual-work 记账。
11. 是否有 worker feedback、EWMA、quantile 或 histogram。
12. 是否有丢包、queue guard、fallback、backpressure。
13. 编译命令、运行命令、配置文件和 trace。
14. 已有输出是否可以复现。
15. 哪些部分适合复用，哪些部分存在语义或实验风险。

同时扫描全局实验设置：

1. CPU 型号、P/E 核编号、核绑定方式。
2. 是否关闭超线程、DVFS、Turbo、频率变化。
3. reader/dispatcher/worker 的核分配。
4. 队列容量、队列溢出行为和丢包路径。
5. nDPI 版本、编译选项和检测入口。
6. trace 文件、trace 生成方式、流量混合方式。
7. 成本 profiling 脚本和单位。
8. latency、throughput、p99 的计算方式。
9. 是否存在把 PCAP replay 时间误当成真实网络到达时间的问题。
10. 是否存在旧结果、美化数据、缺少重复运行或数据泄漏。

请先输出一个 MARK_INVENTORY.md，至少包含：

- 每个 mark 的用途和状态；
- 推荐复用的代码；
- 不应复用的代码；
- 当前最可信的 baseline；