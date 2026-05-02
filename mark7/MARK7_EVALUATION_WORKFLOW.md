# mark7 evaluation workflow

This document records the paper-evaluation path used by mark5 + mark7.

## Output layout

All new evaluation output is under the repository-level `evaluation/` directory,
which is ignored by git:

```text
evaluation/
  mark5/
    batch_<timestamp>/
  mark7/
    batch_<timestamp>/
      raw/<run_id>/
      derived/
      plots/
```

## Figure 1: mark5 measurement

Run mark5 time-only profiling over all input pcaps:

```bash
./mark5/run_mark5_batch.sh input
```

The batch writes:

```text
evaluation/mark5/batch_<ts>/manifest.json
evaluation/mark5/batch_<ts>/figure1_time/figure1_protocol_table.csv
evaluation/mark5/batch_<ts>/figure1_time/figure1_protocol_detecting_cost.pdf
```

Protocols containing `.` are folded to their parent protocol before aggregation.
Figure 1(a) uses `avg_detecting_total_ms` and stacks:

```text
detection_only
flow_table + other
```

Figure 1(b) uses:

```text
slow_over_fast_total = slow avg_detecting_total_ms / fast avg_detecting_total_ms
```

The horizontal reference line is the mean speedup unless `--ratio-line` is set.

## Oracle cost table

mark5 now exports `flow_hash` in `time_flow_profile.csv`. Convert a mark5 flow
CSV to the mark7 oracle format with:

```bash
python3 mark7/scripts/build_oracle_cost_table.py \
  --flow-csv evaluation/mark5/batch_<ts>/.../time_flow_profile.csv \
  --output evaluation/mark7/oracle/<trace>.oracle_cost.csv
```

The output format is:

```text
flow_hash,cost_us
```

mark7 `-P oracle` reads this file with `-O`.

## mark7 raw runs

Example overall run:

```bash
python3 mark7/scripts/run_mark7_eval.py \
  --pcap input/CIC-Monday.pcap \
  --policy rss --policy jsq --policy static --policy ours --policy oracle \
  --oracle evaluation/mark7/oracle/CIC-Monday.oracle_cost.csv \
  --tag overall \
  --workload-label CIC \
  --repeats 5
```

Each raw run writes:

```text
run_summary.csv
latency_summary.csv
worker_stats.csv
dispatch_stats.csv
policy_config.json
run_meta.json
stdout.log
stderr.log
```

`run_summary.csv` is the source for Figure 3/4/5/6. `worker_stats.csv` is the
source for Figure 7.

## Derived figure CSVs

After running a batch:

```bash
python3 mark7/scripts/prepare_figure_csvs.py \
  --batch-dir evaluation/mark7/batch_<ts>
```

This creates editable CSVs:

```text
derived/figure3_throughput.csv
derived/figure4_latency.csv
derived/figure5_robustness.csv
derived/figure6_overload.csv
derived/figure7_workload.csv
derived/figure7_workload_cv.csv
```

These files are intentionally separated from plotting so manual edits can be
made before rendering paper figures.

## Plotting

```bash
python3 mark7/scripts/plot_mark7_figures.py \
  --derived-dir evaluation/mark7/batch_<ts>/derived
```

The script writes PDF/PNG files under:

```text
evaluation/mark7/batch_<ts>/plots/
```

## Figure-specific conventions

- Figure 3 uses `throughput_pps` and annotates bars relative to RSS.
- Figure 4 uses exact per-flow detecting latency captured at first protocol
  detection: p50 and p99 in ms.
- Figure 5 expects runs tagged `robustness` and uses `workload_label` as the
  encrypted-ratio x-axis label.
- Figure 6 expects runs tagged `overload` and uses `worker_count_label` as the
  x-axis.
- Figure 7 uses per-worker `processing_time_ns` as workload and reports CV in
  `figure7_workload_cv.csv`.
