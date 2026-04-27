# mark6 Dispatch Bottleneck Notes

## Current conclusion

The observed P-core preference is consistent with a dispatch-side bottleneck, not
just with the cost-aware worker policy itself.

In the measured run, the dispatcher spent much more time feeding packets than
workers spent processing them:

- `Dispatch flow->worker map`: 8.29 s
- `Dispatch enqueue`: 5.72 s
- max worker `Process Time`: 1.65 s

That means workers usually drain input faster than dispatchers can provide it.
When the worker queues do not build meaningful backlog, the cost-aware JSW
policy sees little pending work on either P or E workers. In that state the
measured P-core advantage dominates, so assignments naturally stay biased toward
P workers.

DPDK can remove pcap input overhead, but it does not remove the software
dispatch bottleneck. If dispatch remains slower than nDPI processing, faster
packet input only moves the bottleneck to the dispatch map/enqueue stage.

## Code-level causes found

### `flow->worker map`

`dispatch_lookup_or_assign()` uses one global mutex for the whole affinity
table. All dispatcher threads serialize on this lock even though preprocessing
already routes each flow to one dispatcher by `flow_hash % num_dispatchers`.

The same hot path recomputes `flow_key_hash()` even though preprocessing already
computed the hash.

### `enqueue`

Each worker queue has a single producer mutex. Multiple dispatchers targeting
the same worker serialize on `packet_queue_push()`.

The batch queue API is currently a no-op wrapper around single-packet push, so
`NDPI_BENCHMARK_BATCH` does not reduce lock or atomic traffic.

Queue slots reserve `MAX_PACKET_SIZE` bytes per packet. In mark6 the preloaded
packet is capped at 1400 bytes, so the queue ring pays a large memory/cache/TLB
cost for unused space.

## First optimization stage

The first stage should keep behavior stable while removing the obvious
serialization and memory-amplification costs:

1. Shard the dispatch affinity table by dispatcher id.
2. Pass the precomputed flow hash into dispatch lookup.
3. Make the queue packet buffer size configurable and set mark6 to a 2048-byte
   queue slot, safely above the 1400-byte preprocessed packet cap.
4. Make the existing producer cache API publish batches instead of delegating to
   single-packet push.

These changes do not alter nDPI processing or flow-key semantics.
