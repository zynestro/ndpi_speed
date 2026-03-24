#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


TIME_COLUMNS = [
    "elapsed_no_preprocess_sec",
    "dispatch_read_sec",
    "dispatch_enqueue_sec",
    "process_time_sec",
    "proc_ndpi_call_sec",
    "proc_ndpi_sec",
    "proc_other_sec",
    "proc_flow_sec",
    "proc_flow_init_sec",
    "proc_flowkey_lookup_sec",
    "proc_parse_sec",
    "proc_proto_check_sec",
    "dispatch_other_sec",
    "dispatch_flow_to_worker_sec",
]


def parse_worker_core(worker_set: str) -> int:
    part = worker_set.split(",")[0].strip()
    return int(part)


def load_rows(csv_path: Path) -> list[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"empty csv: {csv_path}")
    return [r for r in rows if r.get("status", "") == "ok"]


def to_float(v: str) -> float:
    if v is None or v == "":
        return float("nan")
    try:
        return float(v)
    except ValueError:
        return float("nan")


def build_diff_matrix(rows: list[dict], min_range_ms: float) -> tuple[list[int], list[str], np.ndarray]:
    rows_sorted = sorted(rows, key=lambda r: parse_worker_core(r["worker_set"]))
    cores = [parse_worker_core(r["worker_set"]) for r in rows_sorted]

    kept_cols: list[str] = []
    data_cols: list[list[float]] = []

    for col in TIME_COLUMNS:
        values = [to_float(r.get(col, "")) for r in rows_sorted]
        values = [v for v in values if not math.isnan(v)]
        if len(values) < 2:
            continue

        col_range_ms = (max(values) - min(values)) * 1000.0
        if col_range_ms < min_range_ms:
            continue

        med = statistics.median(values)
        diffs_ms = []
        for r in rows_sorted:
            v = to_float(r.get(col, ""))
            diffs_ms.append((v - med) * 1000.0 if not math.isnan(v) else np.nan)
        kept_cols.append(col.replace("_sec", ""))
        data_cols.append(diffs_ms)

    if not data_cols:
        raise ValueError(
            f"no columns passed min_range_ms={min_range_ms}; lower threshold and retry"
        )

    mat = np.array(data_cols).T  # shape: n_cores x n_metrics
    return cores, kept_cols, mat


def plot(cores: list[int], metrics: list[str], matrix: np.ndarray, out_path: Path) -> None:
    vmax = float(np.nanmax(np.abs(matrix)))
    vmax = max(vmax, 1.0)

    fig, ax = plt.subplots(figsize=(max(12, 0.9 * len(metrics) + 5), max(6, 0.6 * len(cores) + 2)))
    im = ax.imshow(matrix, cmap="RdBu_r", vmin=-vmax, vmax=vmax, aspect="auto")

    ax.set_xticks(np.arange(len(metrics)))
    ax.set_xticklabels(metrics, rotation=30, ha="right")
    ax.set_yticks(np.arange(len(cores)))
    ax.set_yticklabels([str(c) for c in cores])
    ax.set_xlabel("Time Components (only high-variance kept)")
    ax.set_ylabel("Worker Core")
    ax.set_title("mark3 Core Difference Heatmap (delta to median, ms)")

    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Delta vs Median (ms)")

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plot mark3 per-core timing differences (delta to median, ms)."
    )
    parser.add_argument(
        "--csv",
        required=True,
        help="Path to benchmark_results_*.csv produced by scripts/benchmark_sweep_mark3.py",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output png path",
    )
    parser.add_argument(
        "--min-range-ms",
        type=float,
        default=80.0,
        help="Drop columns with max-min range below this threshold (ms)",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    out_path = Path(args.out).resolve()

    rows = load_rows(csv_path)
    cores, metrics, matrix = build_diff_matrix(rows, min_range_ms=args.min_range_ms)
    plot(cores, metrics, matrix, out_path)
    print(f"Saved: {out_path}")
    print(f"Kept metrics ({len(metrics)}): {', '.join(metrics)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
