# Scripts Layout

`scripts/` is now organized by purpose, with English folder names so the directory is easier to scan.

## Folder Structure

### `setup/`

Environment preparation before running benchmarks.

- `setup/prepare_benchmark_env.sh`
  - Switches the machine to a more stable benchmark state.
  - Can set performance mode, optionally disable SMT, estimate P-core/E-core groups, and write `setup/benchmark_env.sh`.

### `data/`

Traffic and PCAP preparation utilities.

- `data/generate_1500b_pcap.py`
  - Generates a synthetic PCAP with mixed protocols and configurable target size.

- `data/cap-pcap.sh`
  - Captures a small real-traffic PCAP by running `tcpdump` while generating DNS/HTTP/TLS/SSH traffic.

### `benchmarks/`

Benchmark runners grouped by mark generation.

#### `benchmarks/mark0/`

- `benchmark_sweep_mark0.py`
  - Sweeps an early benchmark binary across worker counts and loop counts.

#### `benchmarks/mark1/`

- `benchmark_sweep_mark1.py`
  - Main worker-count sweep for mark1.

- `benchmark_sweep_mark1_singlecore.py`
  - Single-worker, per-core sweep for mark1.

- `run_mark1_sweep_all_10g.sh`
  - Wrapper that runs the mark1 sweep against `input/seed_10G.pcap`.

#### `benchmarks/mark2/`

- `benchmark_sweep_mark2.py`
  - mark2 sweep with `worker_count` and `worker_core` modes.

#### `benchmarks/mark3/`

- `benchmark_sweep_mark3.py`
  - Flexible mark3 sweep using worker core sets and reader core sets.

- `sweep3.yaml`
  - Example config file for the mark3 sweep script.

### `analysis/`

Post-run analysis and visualization helpers.

#### `analysis/cpu/`

- `core_hash_boxplot_32.py`
  - Per-core single-thread SHA256 throughput benchmark with boxplot output.

- `wsl_vcpu_singlethread_bench.py`
  - Single-thread vCPU distribution benchmark for Linux/WSL environments.

#### `analysis/plots/`

- `plot_0306_main_time_compare.py`
  - Builds a fixed comparison dashboard for a specific set of archived runs.

- `plot_mark3_core_diff.py`
  - Draws a heatmap of timing deltas across mark3 worker cores.

- `plot_mark4_proto_summary.py`
  - Builds a dashboard for `mark4` `proto_category_summary.csv`.
  - Highlights top proto+category rows by flow count and cost, and also writes an aggregated category CSV.

- `plot_process_time_variants.py`
  - Compares `process_time_sec` across several implementation variants.

- `plot_proto_bucket_compare.py`
  - Plots protocol performance by Easy/Mid/Hard buckets.
  - Note: this script still expects the older mark4 CSV field `avg_detect_latency_ms`.

- `replot_mark3_dashboard_from_csv.py`
  - Rebuilds a mark3 dashboard from an existing CSV without rerunning the benchmark.

### `legacy/`

Older or ad hoc entry points that are still kept for reference.

- `legacy/run.sh`
  - A small collection of hand-written benchmark command examples.

## Practical Flow

If you want a clean workflow, a good order is:

1. Run `setup/prepare_benchmark_env.sh`.
2. Prepare input data with `data/generate_1500b_pcap.py` or `data/cap-pcap.sh`.
3. Run the appropriate sweep in `benchmarks/mark1`, `benchmarks/mark2`, or `benchmarks/mark3`.
4. Use `analysis/plots/` or `analysis/cpu/` for follow-up analysis.

## Notes

- The directory names are intentionally broad and stable, so new scripts can be added without reshuffling everything again.
- `plot_proto_bucket_compare.py` still follows the older mark4 CSV schema and may need a later update.
