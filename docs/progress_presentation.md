# ndpi-speed 项目进展汇报（修订版）

---

## 1. 整体框架

### 一句话说明

在异构多核上做 DPI，利用"协议不同→检测代价不同"这个特点，让调度器知道每条流大概要花多久，然后把流分配到最合适的核上。检测完成后，用实际耗时修正之前的估计，让系统越跑越准。

### 架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OFFLINE（一次性）                                  │
│                                                                      │
│  pcap traces ──▶ nDPI 全量检测 ──▶ 统计每种协议平均耗时             │
│                                      │                               │
│                                      ▼                               │
│                              ┌──────────────┐                        │
│                              │ Rule Table   │                        │
│                              │              │                        │
│                              │ port → proto │                        │
│                              │ proto → cost │                        │
│                              └──────┬───────┘                        │
└─────────────────────────────────────┼────────────────────────────────┘
                                      │ 初始代价值
                                      ▼
                              ┌──────────────┐
                              │ Adaptive     │◀─────── EWMA 更新 ◀──┐
                              │ Cost Table   │                       │
                              │              │                       │
                              │ proto → cost │                       │
                              │ (可变,在线修)│                       │
                              └──────┬───────┘                       │
                                     │ 查表得到                      │
                                     │ 代价估计                      │
                                     ▼                               │
┌─────────────────────────────────────────────────────────────────┐  │
│                    ONLINE（逐流）                                 │  │
│                                                                   │  │
│  packets ──▶ [是新流?]                                           │  │
│                │                                                  │  │
│         Yes   │   No (旧流 → 按之前分配走,不变)                  │  │
│                ▼                                                  │  │
│         Rule Table 查表                                          │  │
│         port → proto_hint → 代价估计                             │  │
│                │                                                  │  │
│                ▼                                                  │  │
│         代价加权调度 (JSW)                                        │  │
│         对每个核算分:                                             │  │
│           score = 该核当前待处理总代价 + 新流估计代价/核速度      │  │
│         选分数最低的核                                            │  │
│                │                                                  │  │
│                ▼                                                  │  │
│         ┌─────────────────────────────────────┐                  │  │
│         │         Workers (P核 + E核)          │                  │  │
│         │                                     │                  │  │
│         │  [P0] [P1] ... [P7] [E0] [E1]...[E7]│                  │  │
│         │         │                           │                  │  │
│         │         ▼ nDPI 检测                 │                  │  │
│         │         │                           │                  │  │
│         │         ▼ 检测完成                  │                  │  │
│         │   得到: 实际协议 + 实际耗时          │                  │  │
│         │         │                           │                  │  │
│         └─────────┼───────────────────────────┘                  │  │
│                   │                                               │  │
│                   │ feedback: (协议ID, 实际耗时, 核类型)          │  │
│                   └───────────────────────────────────────────────┼──┘
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### 数据流总结

```
离线: pcap → nDPI检测 → 统计 → Rule Table (port→proto→初始代价)
在线: 新流首包 → 查表得代价 → 选最优核 → nDPI检测 → 回写实际代价 → 更新表
                                                          ↑___________↓
                                                          闭环反馈
```

---

## 2. 离线部分：Rule Table 怎么建

### 输入

mark5 的 profiling 输出 CSV，每行一条流：
```
flow_id, dst_port, protocol, detecting_time_ms, ...
```

### 建表流程

两个版本的区别：

| | mark7（GLOBECOM版） | mark9（新版） |
|---|---|---|
| 聚类 | 先对协议做 k-means(k=3) 分 Easy/Mid/Hard | 不聚类 |
| 输出 | port → bucket (3档) | port → proto_hint (协议ID) |
| 代价值 | 3个桶的均值(2/7/15μs) | per-protocol 连续值 |

**mark7 旧版流程**（论文中 GLOBECOM 基线的做法）：
```
Step 1: 统计每种协议的平均检测耗时 W_us
Step 2: 对 log(W_us) 做 1D k-means (k=3) → Easy / Middle / Hard 三档
        Easy: DNS(2.1), NTP(3.8), ICMP(1.5) ...
        Middle: HTTP(5.5), TLS(8.7) ...  
        Hard: Telnet(28), SSH(12), MongoDB(14) ...
Step 3: 每条流按其协议所属的档打标签
Step 4: 对每个端口, 看所有流的 bucket 分布:
        port 53: 99.8% Easy → 规则: port 53 → Easy
        port 443: 99.1% Middle → 规则: port 443 → Middle
Step 5: 低纯度端口用 prefix 消歧 (同下)
```

**mark9 新版流程**（升级后的做法）：
```
Step 1: 统计每种协议的平均检测耗时
        DNS → 2.1μs, TLS → 8.7μs, SSH → 12.3μs, ...
        (不做聚类, 保留连续值)
        
Step 2: 对每个端口, 看它历史上跑的都是什么协议 (纯度检查)
        port 53:  99.8% 是 DNS                  → 纯度≥0.90, 直接映射
        port 443: 99.1% 是 TLS                  → 纯度≥0.90, 直接映射
        port 8080: 60% HTTP + 30% WebSocket + 10% 其他 → 纯度<0.90, 歧义

Step 3: 低纯度端口, 尝试用 payload 前缀进一步消歧
        port 8080 + 前缀 0x16 → 94% 是 TLS     → 加一条 prefix 规则
        port 8080 + 前缀 "GET" → 97% 是 HTTP   → 加一条 prefix 规则
        
Step 4: 仍然搞不定的 → 标记 UNKNOWN, 运行时走 fallback

输出:
  proto_lookup_table.json — {port → proto_hint}
  proto_cost_prior.csv   — {proto → 平均代价μs (P核/E核分别)}
```

### 建表伪代码

```python
# === Phase 1: 协议代价统计 ===
for proto in all_protocols:
    cost_prior[proto] = mean(detecting_time of all flows with this proto)

# === Phase 2: 端口 → 协议映射 (纯度驱动) ===
for port in all_ports:
    flows = all_flows_on_port(port)
    dominant_proto = most_common_protocol(flows)
    purity = count(dominant_proto) / count(flows)
    
    if purity >= 0.90 and count(flows) >= min_support:
        port_rules[port] = dominant_proto       # 高纯度: 直接映射
    else:
        ambiguous_ports.append(port)            # 低纯度: 需要消歧

# === Phase 3: Prefix 消歧 ===
for port in ambiguous_ports:
    flows = all_flows_on_port(port)
    for prefix_len in [1, 2, 4]:               # 逐级尝试更长前缀
        for prefix_val, sub_flows in group_by_prefix(flows, prefix_len):
            sub_dominant = most_common_protocol(sub_flows)
            sub_purity = count(sub_dominant) / count(sub_flows)
            if sub_purity >= 0.90 and count(sub_flows) >= min_support:
                prefix_rules[port][prefix_val] = sub_dominant
```

### 关键参数

| 参数 | 值 | 含义 |
|------|-----|------|
| purity_threshold | 0.90 | 低于此纯度的端口需要消歧 |
| min_support | 5 | 少于5条流的规则不可信,丢弃 |
| prefix_len | 1/2/4 bytes | payload 前缀检查深度 |

---

## 3. 在线部分：调度 + 反馈

### 调度算法伪代码

```
输入: 新流 f 的首包
输出: 分配到哪个核

1. cost_est = lookup(f.dst_port, f.payload_prefix)
   // 查表得到该流的预估检测代价(μs)

2. for each worker c:
     if queue_depth[c] > MAX:  skip  // 过载保护
     pending[c] = added_cost[c] - retired_cost[c]  // 该核当前未完成的总代价
     score[c] = pending[c] + cost_est / speed[core_type(c)]
     // P核 speed=1.8, E核 speed=1.0 (P核更快,同样的活花更少时间)
     
3. best = argmin(score)
4. 把 f 绑定到 best, 后续所有包都走这个核
5. added_cost[best] += cost_est  // 记账
```

### 反馈机制伪代码

```
=== Worker 侧 (每条流检测完成时) ===

actual_cost = 实测耗时 (从首包入队到协议确认的总时间)
proto_id = nDPI 最终识别出的协议
core_type = 当前核是P还是E

feedback_ring.push(proto_id, actual_cost, core_type)
// 无锁ring, worker写dispatcher读, ring满就丢(不阻塞worker)


=== Dispatcher 侧 (每256次调度执行一次) ===

for each (proto, actual, core) in all_feedback_rings:
    old = adaptive_cost_table[proto]
    adaptive_cost_table[proto] = 0.95 × old + 0.05 × actual
    //                           ^^^^         ^^^^
    //                         保留旧值      吸收新值
    // α=0.05 → 慢速平滑(稳态)
    // α=0.30 → 快速追踪(检测到连续偏差过大时临时切换)
```

### 冷启动 → 稳态

```
刚启动时: adaptive_cost_table 全空 (sample_count=0)
  → 每次查表走 fallback: 用离线 Rule Table 的静态值
  
跑了几百条流后: 高频协议(DNS/TLS/HTTP)率先积累够8个样本
  → 这些协议切换到 adaptive 值
  
稳态: 几乎所有协议都有在线修正值
  → 代价估计精度接近 Oracle (真实值)
```

---

## 4. 论文贡献 (Contributions)

1. **系统性实测**：在 i9-14900 (8P+16E) 上对 67 种协议做 P/E 分核 profiling，发现三个特性:
   - O1: 代价差异 18× 且排序跨 trace 稳定
   - O2: P/E 加速比跨协议近似恒定 ~1.8×
   - O3: 离线代价表存在固有偏差且偏差不稳定（数据集有限 + 运行环境不同）→ 必须在线修正

2. **首包代价估计**：端口纯度驱动的分层规则表 + prefix消歧, O(1)查表解决bootstrapping

3. **闭环自适应调度**：EWMA 反馈修正 + 漂移检测 + 核能力在线标定

4. **理论保证**：收敛 O(1/√N), 竞争比 1+O(δ), 漂移误差 O(v/α)

5. **系统实现 + 全面评估**：6策略对比, 含漂移/冷启动/消融实验

---

## 5. 实验设计 (Evaluation)

### 5.1 对比方案

| 方案 | 说明 | 代价感知 | 核感知 | 在线适应 |
|------|------|---------|--------|---------|
| RSS | 哈希散列 | ✗ | ✗ | ✗ |
| JSQ | 最短队列 | ✗ | ✗ | ✗ |
| Static Pool | 按协议分组到固定核 | 粗 | ✗ | ✗ |
| Static Ours | 静态代价加权JSW (不更新) | ✓ | ✓ | ✗ |
| **Adaptive** | 闭环EWMA (本文方案) | ✓ | ✓ | **✓** |
| Oracle | 用真实代价 (理论上界) | 完美 | ✓ | — |

### 5.2 实验列表

| #   | 实验           | 展示什么                | 预期结论                              |
| --- | ------------ | ------------------- | --------------------------------- |
| 1   | **稳态性能对比**   | 吞吐+延迟(6方案)          | Adaptive≈Static≈Oracle >> RSS/JSQ |
| 2   | **漂移场景** ★核心 | Trace A→B切换后的性能时间序列 | Static退化不恢复; Adaptive自动恢复         |
| 3   | **冷启动收敛**    | 从空表到稳态的收敛曲线         | ~数百流收敛到<5%误差                      |
| 4   | **消融实验**     | 逐步去组件看贡献            | 每层独立贡献显著                          |
| 5   | **鲁棒性**      | 不同heavy-flow比例      | 越极端优势越大                           |
| 6   | **负载均衡度**    | per-worker工作量CV     | Adaptive CV<0.1                   |
| 7   | **开销分析**     | feedback的额外cycles   | <100ns/flow, 可忽略                  |

### 5.3 漂移实验详细设计（论文核心新实验）

```
实验流程:
  1. 准备两个分布不同的 trace
     Trace A: 企业流量 (HTTP/DNS/SMTP为主, 轻流多)
     Trace B: 娱乐流量 (视频/游戏/P2P为主, 重流多)
     
  2. 拼接: cat A.pcap B.pcap > drift.pcap
  
  3. 分别用 Static 和 Adaptive 跑同一个 drift.pcap
  
  4. 以时间窗口(或每1000流)为粒度统计 p99延迟
  
预期图形:
  
  p99延迟
  │
  │        ┌──── Static (切换后不恢复)
  │        │
  │   ─────┤    ┌──── Adaptive (V型恢复)
  │        │    │
  │        │    └────── 回到正常
  │────────┼────────────────────────── 时间
  │        ↑
  │    Trace切换点
```

---

## 6. 论文大纲 (10页 IEEE double-column)

```
§I.   Introduction                              ~1.5页
§II.  Measurement & Motivation                  ~1.5页
§III. System Design                             ~3.0页
      §III-A Framework Overview (架构图)
      §III-B First-Packet Cost Estimation (Rule Table)
      §III-C Cost-Aware Heterogeneous Dispatch (JSW)
      §III-D Online Feedback Correction (EWMA) ← 核心新增
§IV.  Theoretical Analysis                      ~1.0页
§V.   Evaluation                                ~2.5页
§VI.  Related Work                              ~0.5页
§VII. Conclusion                                ~0.3页
```

§III-A/B/C 主体可从 GLOBECOM 论文改写扩展（已有英文稿）。
§III-D + §IV + §V 的漂移/冷启动/消融 是全新内容。

---

## 7. 当前状态

| 模块 | 状态 |
|------|------|
| mark7 (开环系统) | ✅ 可运行 |
| mark8 (EWMA闭环) | ✅ 代码已写, 待Linux测试 |
| mark9 (per-proto规则表) | ✅ 代码已写, 待训练+测试 |
| 实验数据 | ❌ 需规范复测 |
| 论文正文 | 大纲已定, 待撰写 |
