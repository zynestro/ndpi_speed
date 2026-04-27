# Paper Experiment Plan for mark5 / mark6

## 1. Immediate Clarification: How to Understand Current mark6

### 1.1 Correct mental model

If we temporarily ignore `Preprocess Time`, current `mark6` can be understood as:

```text
hardware RSS / input backend
  -> dispatch stage
      -> flow affinity lookup
      -> first-flow worker assignment
      -> worker queue enqueue
  -> worker stage
      -> parse
      -> worker-private flow table
      -> nDPI detection
      -> protocol accounting
```

This is a useful abstraction for the paper because the controlled experiment is
about scheduling policy, not about disk IO.

However, the exact current implementation is:

```text
pcap preload / software simulated RSS
  -> dispatcher shards
  -> worker queues
  -> worker nDPI processing
```

The preprocess stage is not literally hardware RSS. It currently performs:

- `pcap_next_ex()`;
- link-layer normalization;
- packet parsing;
- bidirectional flow-key construction;
- `flow_hash` computation;
- `dispatcher_id = flow_hash % num_dispatchers`;
- packet copy into `dispatch_packet_t`.

In a DPDK implementation, parts of this would move:

- pcap IO disappears;
- hardware RSS can deliver packets to RX queues;
- mbuf pointers replace copied pcap packet buffers;
- software still needs enough parsing/key normalization if hardware RSS does
  not provide the exact canonical bidirectional key required by the scheduler.

### 1.2 What happens when a flow enters dispatch

For packets with a valid flow key:

1. Preprocess has already built a canonical bidirectional `flow_key`.
2. Preprocess has already computed `flow_hash`.
3. Preprocess assigns `dispatcher_id = flow_hash % num_dispatchers`.
4. Dispatcher calls `dispatch_lookup_or_assign()`.
5. Dispatch checks the shard-local affinity table.
6. If this is an existing flow, dispatch returns the previously assigned worker.
7. If this is a new flow, dispatch calculates a cost bucket and runs the current
   policy to pick a worker.
8. Dispatcher enqueues the packet to that worker.
9. Worker consumes the packet and runs its private nDPI state.

Core code references:

- canonical flow key and hash in preprocess: `mark6/src/reader.c:317-327`
- dispatcher id from hash: `mark6/src/reader.c:338-343`
- dispatch call with precomputed hash: `mark6/src/reader.c:456-462`
- affinity lookup and first-flow assignment: `mark6/src/dispatch.c:208-294`
- cost-aware worker selection: `mark6/src/dispatch.c:75-113`
- worker consume loop: `mark6/src/worker.c:384-409`

### 1.3 Important nuance: bidirectional hash

The “two directions hash to the same flow” property comes from the canonical
`flow_key`, not from ordinary NIC RSS alone.

Current software does:

```text
packet -> parsed 5-tuple -> canonical bidirectional flow_key -> flow_key_hash
```

So A->B and B->A map to the same dispatch entry. If real hardware RSS is used,
we must confirm whether the NIC RSS configuration is symmetric and whether its
tuple definition matches our flow affinity requirement. Otherwise, the DPDK path
still needs software canonicalization before dispatch.

## 2. Hash Cost and Time Accounting

### 2.1 Current hash time

Using the representative run:

```text
Total Elapsed Time:              14.198593 s
Preprocess Time:                 12.863259 s
Preprocess hash:                  1.061632 s
Elapsed Time (No Preprocess):     1.335334 s
Dispatch flow->worker map:        1.185542 s
Dispatch enqueue:                 1.494571 s
```

The current `Preprocess hash` bucket is not just the hash function alone. It
includes:

- Ethernet/IP/TCP/UDP parse;
- canonical flow key construction;
- flow hash;
- dst port and payload prefix extraction.

Code reference:

- timed region begins before parse: `mark6/src/reader.c:306`
- parse/key/hash/prefix work: `mark6/src/reader.c:317-327`
- timed region ends: `mark6/src/reader.c:333-336`

Approximate ratios:

```text
Preprocess hash / Total Elapsed     = 1.061632 / 14.198593 ~= 7.5%
Preprocess hash / Preprocess        = 1.061632 / 12.863259 ~= 8.3%
Preprocess hash / No-Preprocess     = 1.061632 / 1.335334 ~= 79.5%
```

The last ratio is not a fair “current dispatch cost” comparison because this
hash work is intentionally excluded from `Elapsed Time (No Preprocess)`. It is
useful only as a warning: if a live implementation has to do full software
parse+canonical hash before dispatch, that cost is large enough to matter.

For packet-level intuition, on the Monday trace with roughly 11.66M packets:

```text
1.061632 s / 11.655M packets ~= 91 ns/packet
```

This is small per packet, but large in aggregate.

### 2.2 Current throughput denominator

Current `mark6` throughput uses:

```text
effective_elapsed_sec = total_elapsed_sec - preprocess_sec
throughput_mpps       = total_packets / effective_elapsed_sec / 1e6
bandwidth_gbps        = total_bytes * 8 / effective_elapsed_sec / 1e9
```

Code references:

- effective elapsed: `mark6/src/main.c:41-43`
- throughput and bandwidth: `mark6/src/main.c:85-87`
- printed values: `mark6/src/main.c:126-129`

This means current `Throughput` is not disk-to-result throughput. It is an
offline replay effective throughput after preload.

Paper wording should be explicit:

> We report effective replay throughput over the dispatch-and-worker interval,
> excluding the offline pcap preload stage.

If the paper also reports end-to-end offline throughput, use:

```text
end_to_end_mpps = total_packets / total_elapsed_sec / 1e6
```

Both numbers are valid, but they answer different questions.

### 2.3 Why Dispatch(Read) can exceed wall-clock

`Dispatch(Read) Time` is the sum of per-dispatcher measured time components:

```text
Dispatch(Read) = sum(dispatcher flow->worker + enqueue + other)
```

Because multiple dispatchers run in parallel, this cumulative CPU-time-like
number can be greater than the real wall-clock `Elapsed Time (No Preprocess)`.

Code references:

- dispatcher local timers: `mark6/src/reader.c:433-435`
- merge into reader context: `mark6/src/reader.c:383-391`
- final `read_time_ns`: `mark6/src/reader.c:107-109`

Likewise, worker sub-components such as `Process nDPI` are cumulative across
workers, while `Process Time` is the maximum worker processing time.

Code references:

- max worker process time: `mark6/src/main.c:67-69`
- cumulative worker sub-components: `mark6/src/main.c:73-82`

## 3. DPDK vs Current pcap Replay

### 3.1 Which is faster?

It depends on the boundary.

For raw input, DPDK is expected to be much faster than current pcap input:

- DPDK avoids `pcap_next_ex()`;
- DPDK avoids disk/file parsing during the hot path;
- DPDK receives packets in bursts;
- DPDK passes mbuf pointers instead of copying pcap bytes.

But current `mark6` effective throughput excludes pcap preload. It measures only
the in-memory dispatch+worker interval. That number can be higher than a real
DPDK end-to-end number because it ignores NIC RX, mbuf allocation/recycling,
PCIe, memory placement, burst scheduling, and driver overhead.

### 3.2 Recommended paper framing

Use current pcap replay for controlled policy comparison:

```text
Same trace, same workers, same cost table, same replay input.
Compare only scheduling policy behavior.
```

Use DPDK as a separate system validation:

```text
Real RX path, hardware queues/RSS, realistic packet ingress.
Compare Ours against DPDK RSS baseline.
```

Avoid putting pcap replay effective throughput and DPDK live-RX throughput in
one figure as if they are the same metric. If both appear, label them clearly:

- `offline replay effective throughput`;
- `DPDK live-RX end-to-end throughput`.

## 4. Paper Structure Assessment

### 4.1 Overall assessment

The paper can be split cleanly:

1. `mark5`: measurement study and offline profiling evidence.
2. `mark6`: scheduling design and evaluation prototype.

The measurement side is currently stronger than the evaluation side.

`mark5` already supports a strong story:

- protocol detection cost differs significantly;
- P/E behavior differs but is relatively stable;
- first-packet-visible features can be used to build a lookup table;
- hardware counters explain part of the behavior.

`mark6` currently supports:

- an executable cost-aware scheduling prototype;
- hash-only baseline;
- per-worker/P/E load observation;
- dispatch overhead observation.

`mark6` does not yet fully support a paper-grade evaluation matrix because it
lacks runtime policy baselines, structured output, repeated trials, and true
tail latency metrics.

## 5. Section II Measurement Study: Review and Required Additions

### 5.1 Strengths of the current outline

The proposed Measurement Study section is well motivated:

- It is explicitly your measurement, not background.
- It isolates P/E cores and protocol costs.
- It connects directly to the design need for cost-aware scheduling.
- It naturally explains why offline cost modeling is plausible.

### 5.2 Suggested refinements

#### Current O1: protocol cost differs significantly

Keep this, but report both:

- flow-weighted distribution;
- protocol-weighted distribution.

Reason: a trace dominated by ICMP or one large protocol can make flow-weighted
means look overly stable. A protocol-weighted view prevents the claim from being
over-dominated by popular protocols.

Recommended figures:

- Figure 1(a): per-protocol detection cost, P/E side-by-side.
- Figure 1(b): detection cost CDF or violin plot.
- Optional: top-k protocols plus an “others” group for readability.

Recommended statistics:

- min / median / p90 / p99 protocol cost;
- max/min ratio;
- Spearman correlation across traces;
- number of protocols and flows after filtering.

#### Current O2: P/E speedup approximately stable

This is good, but phrase carefully. Current evidence supports “relatively
stable across many protocols,” not necessarily perfectly constant.

Recommended metrics:

- median E/P detection-time ratio;
- interquartile range;
- coefficient of variation;
- per-trace boxplot of E/P speedup;
- IPC ratio and LLC miss ratio correlation.

Recommended figure:

- Figure 2(a): E/P detection cost ratio by protocol.
- Figure 2(b): IPC and LLC miss ratio summary or scatter.

#### Add O3: first-packet features are usable but imperfect

This observation is important for the bootstrapping problem:

```text
The scheduler needs cost before nDPI identifies the protocol.
```

Existing mark5 data already has first-packet signature outputs. The paper should
show lookup quality:

- coverage;
- purity;
- bucket accuracy;
- default bucket rate;
- how many rules come from port-only vs port+prefix.

This turns the design transition from “we measured protocol cost” into “we can
estimate cost before classification.”

### 5.3 Dataset table is needed

Add a compact dataset table:

```text
Trace | Packets | Bytes | Flows | Detected Flows | Top Protocols | Avg Packet Size
```

This defends representativeness and helps reviewers interpret protocol skew.

## 6. Section IV Evaluation: Review and Required Additions

### 6.1 Current outline strength

The proposed baselines table is directionally right:

```text
RSS | JSQ | Static Pool | Ours | Oracle
```

The axes are also right:

- load-aware;
- cost-aware;
- core-aware;
- dynamic.

### 6.2 Current risk

The current implementation only directly supports:

- hash-only target, which can stand in for RSS-like flow hash;
- cost-aware-jsw target, which is an early Ours prototype.

It does not yet implement:

- JSQ as a first-class policy;
- Static Pool;
- Oracle;
- structured CSV/JSON output;
- true p50/p99 latency.

So the paper should not yet claim a complete evaluation until those are added.

### 6.3 Recommended baseline definitions

#### RSS / Hash

Policy:

```text
worker = flow_hash % num_workers
```

Purpose:

- baseline for hardware RSS-like flow affinity;
- no load awareness;
- no cost awareness;
- no core awareness.

Current implementation:

- `ndpiBenchmarkMark6Hash`

Needed improvement:

- expose as runtime `--policy rss` instead of compile-only target.

#### JSQ

Policy:

```text
worker = argmin(queue_depth)
```

For first-flow assignment only. Existing flows keep affinity.

Purpose:

- load-aware;
- not cost-aware;
- not core-aware.

Needed implementation:

- add dispatch policy branch using `queue_depth`;
- optionally use packets pending or estimated pending bytes.

#### Static Pool

Policy example:

```text
Easy    -> E-core pool
Middle  -> mixed pool or P/E weighted pool
Hard    -> P-core pool
within pool: round-robin or hash
```

Purpose:

- cost-aware and core-aware;
- not dynamically load-aware.

Needed implementation:

- bucket-to-core-type mapping;
- per-pool worker selection.

#### Ours

Current policy:

```text
score = pending_cost(worker) + cost_profile[core_type][bucket] + P_bias
worker = argmin(score)
```

Purpose:

- load-aware;
- cost-aware;
- core-aware;
- dynamic.

Current implementation:

- `mark6/src/dispatch.c:75-113`

Needed improvement:

- make policy selectable at runtime;
- tune or justify `P_bias`;
- report placement by bucket and core type.

#### Oracle

Policy options:

1. Trace oracle:
   - knows true flow protocol or true measured flow cost from profiling;
   - uses that cost before scheduling.

2. Offline scheduler oracle:
   - has the entire trace;
   - can compute near-optimal assignment or use greedy list scheduling.

Recommended for paper:

- Use trace oracle as a practical upper bound.
- Avoid claiming global optimality unless a real offline optimizer is built.

Needed implementation:

- generate `flow_key -> true_cost` or `signature -> true_cost` table;
- mark6 loads oracle table and uses true bucket/cost for first-flow assignment.

### 6.4 Metrics to add

#### Already available

- throughput Mpps;
- bandwidth Gbps;
- cycles per packet;
- dispatch flow->worker time;
- dispatch enqueue time;
- process parse / flow / nDPI breakdown;
- per-worker packets/bytes/flows;
- P/E load summary.

#### Needs structure, not necessarily new instrumentation

- CSV/JSON run summary;
- worker stats CSV;
- dispatch stats CSV;
- P/E placement summary;
- load imbalance metrics:
  - max/min worker packets;
  - max/min worker bytes;
  - coefficient of variation;
  - Gini coefficient;
  - max worker processing time / mean worker processing time.

#### Needs new instrumentation

- p50/p99 per-packet sojourn latency;
- p50/p99 queue waiting time;
- p50/p99 dispatch decision time;
- sampled per-packet latency histogram.

Because latency instrumentation can disturb throughput, implement a sampling
mode:

```text
--latency-sample-rate 1024
```

or fixed-size reservoir sampling.

## 7. Current Distance from the Paper Vision

### 7.1 Measurement Study readiness

Estimated readiness: high.

Already available:

- mark5 profiling runs;
- P/E time and hardware summaries;
- protocol-level plots;
- lookup training outputs;
- first-packet signature summaries.

Still needed:

- dataset table;
- cross-trace correlation numbers;
- speedup ratio CV/IQR;
- flow-cost CDF;
- lookup coverage/purity figure;
- careful wording about trace skew.

### 7.2 Evaluation readiness

Estimated readiness: medium-low.

Already available:

- controlled replay platform;
- hash-only comparison target;
- cost-aware prototype;
- dispatch optimization;
- detailed stdout stats.

Still needed:

- runtime policy framework;
- JSQ baseline;
- Static Pool baseline;
- Oracle baseline;
- structured output;
- batch runner;
- plotting scripts;
- repeated runs with error bars;
- latency or queue waiting metric.

### 7.3 Design readiness

Estimated readiness: medium.

The conceptual design is coherent:

```text
Offline profiling -> first-packet cost estimate -> dynamic heterogeneous scheduling
```

But the implementation must close the loop:

```text
mark5 cost table -> mark6 policies -> structured evaluation -> paper figures
```

## 8. Recommended Engineering Roadmap

### Phase 1: Make mark6 results paper-plot ready

Goal:

Turn stdout into structured experiment output.

Implement:

- `--output-dir <dir>`;
- `run_summary.csv/json`;
- `worker_stats.csv`;
- `dispatch_stats.csv`;
- `core_type_summary.csv`;
- `policy_config.json`.

Files likely touched:

- `mark6/src/main.c`;
- `mark6/include/ndpi_benchmark.h`;
- maybe new `mark6/src/result_writer.c`.

Acceptance:

- One run produces stable machine-readable output.
- Existing stdout remains available.
- Batch scripts no longer need fragile regex parsing.

### Phase 2: Runtime policy framework

Goal:

Replace compile-time policy split with:

```text
--policy rss|jsq|static-pool|ours|oracle
```

Implement:

- `dispatch_policy_t` enum;
- policy parser;
- dispatch context stores policy;
- dispatch assignment switch.

Files likely touched:

- `mark6/src/main.c`;
- `mark6/src/dispatch.c`;
- `mark6/include/benchmark_internal.h`;
- `mark6/include/ndpi_benchmark.h`.

Acceptance:

- One binary can run all non-oracle policies.
- `ndpiBenchmarkMark6Hash` can be retained for compatibility but is no longer
  required for experiments.

### Phase 3: Add missing baselines

Implement:

- RSS/hash;
- JSQ;
- Static Pool;
- Ours;
- Oracle-lite.

Acceptance:

- Same trace and same core list can run all baselines.
- Output records policy name and parameters.

### Phase 4: Add latency and overhead metrics

Implement:

- sampled queue waiting time;
- sampled dispatch decision time;
- p50/p99 from histograms;
- load imbalance metrics.

Acceptance:

- throughput-only mode has low overhead;
- latency mode is explicitly enabled and documented;
- p50/p99 are available for Figure 4.

### Phase 5: Batch runner and plotter

Implement:

- `mark6/run_mark6_matrix.py`;
- `mark6/plot_mark6_results.py`.

Experiment matrix:

```text
policies = rss, jsq, static-pool, ours, oracle
traces = Monday, 201706251400, seed_1500b, cap_traffic, selected normal traces
repeats = 5
core_sets = P-only, E-only, P+E
```

Acceptance:

- produces one experiment directory per batch;
- generates CSV summary and paper-ready plots.

## 9. Suggested Paper Figures After Engineering Completion

### Measurement figures

1. Protocol detection cost by protocol, P/E side-by-side.
2. E/P speedup ratio by protocol.
3. First-packet lookup quality:
   - coverage;
   - purity;
   - bucket confusion.
4. Optional: flow detection cost CDF.

### Evaluation figures

1. Overall throughput by policy.
2. p50/p99 queue or sojourn latency by policy.
3. Ablation:
   - RSS;
   - JSQ;
   - JSQ + cost;
   - JSQ + cost + core speed;
   - Ours + overload guard;
   - Oracle.
4. Robustness:
   - encrypted/unknown ratio;
   - short-flow vs long-flow mix;
   - trace-to-trace variation.
5. Micro-analysis:
   - P/E byte and flow share;
   - bucket placement by core type;
   - dispatch overhead ns/pkt.

## 10. Suggested Wording Adjustments for the Paper

### 10.1 Be careful with “RSS”

Current preprocess is a software simulation of RSS-like partitioning. In the
paper, write:

> In the offline replay, we pre-partition packets by a canonical flow hash to
> emulate the flow affinity provided by RSS. In the DPDK implementation, this
> stage can be mapped to hardware RX queues when symmetric RSS is available.

### 10.2 Be careful with throughput

Write:

> Unless otherwise stated, replay throughput excludes the offline pcap preload
> stage and measures the dispatch-and-worker interval.

If reporting end-to-end pcap throughput, label it separately.

### 10.3 Be careful with “Oracle”

Unless implementing a true optimizer, call it:

```text
Trace-informed oracle
```

or:

```text
Oracle cost estimator
```

not “optimal scheduler.”

### 10.4 Be careful with P/E speedup constancy

Use:

> approximately stable

rather than:

> constant

Then report median, IQR, and CV.

## 11. Final Assessment

The paper direction is sound:

```text
Measurement shows protocol and core heterogeneity.
First-packet features provide a usable cost prior.
Dynamic dispatch can use that prior to place flows on heterogeneous cores.
```

Current implementation status:

- `mark5`: close to paper-ready for Measurement Study;
- `mark6`: good prototype, but not yet paper-ready for full Evaluation.

Minimum engineering needed before strong evaluation claims:

1. structured mark6 output;
2. runtime baseline policies;
3. repeated batch runs;
4. load-balance metrics;
5. latency or queue-waiting metric if the paper claims latency benefit.

With those completed, the current outline can support a credible systems paper
story. Without them, §IV should be framed conservatively as a prototype
feasibility study rather than a complete scheduler evaluation.
