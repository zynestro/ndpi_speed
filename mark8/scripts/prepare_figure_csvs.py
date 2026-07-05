#!/usr/bin/env python3
"""Collect mark7 raw run directories into editable Figure 3-7 CSV inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


POLICY_ORDER = ["rss", "jsq", "static-pool", "static", "ours", "oracle"]
POLICY_LABEL = {
    "rss": "RSS",
    "jsq": "JSQ",
    "static": "Static Pool",
    "static-pool": "Static Pool",
    "ours": "Ours",
    "oracle": "Oracle",
}


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--batch-dir", required=True)
    ap.add_argument("--output-dir", default="", help="Default: <batch-dir>/derived")
    return ap.parse_args()


def policy_rank(policy: str) -> int:
    return POLICY_ORDER.index(policy) if policy in POLICY_ORDER else len(POLICY_ORDER)


def load_runs(batch_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    run_rows = []
    worker_rows = []
    for run_dir in sorted((batch_dir / "raw").glob("*")):
        meta_path = run_dir / "run_meta.json"
        summary_path = run_dir / "run_summary.csv"
        worker_path = run_dir / "worker_stats.csv"
        if not meta_path.exists() or not summary_path.exists():
            continue
        meta = json.loads(meta_path.read_text())
        summary = pd.read_csv(summary_path)
        for key, value in meta.items():
            if key != "cmd":
                summary[key] = value
        run_rows.append(summary)
        if worker_path.exists():
            workers = pd.read_csv(worker_path)
            for key, value in meta.items():
                if key != "cmd":
                    workers[key] = value
            worker_rows.append(workers)
    runs = pd.concat(run_rows, ignore_index=True) if run_rows else pd.DataFrame()
    workers = pd.concat(worker_rows, ignore_index=True) if worker_rows else pd.DataFrame()
    return runs, workers


def write_fig3(runs: pd.DataFrame, out_dir: Path) -> None:
    df = runs[runs["tag"].isin(["overall", ""])].copy()
    if df.empty:
        df = runs.copy()
    g = df.groupby("policy", as_index=False).agg(
        throughput_pps=("throughput_pps", "mean"),
        throughput_pps_std=("throughput_pps", "std"),
        repeats=("throughput_pps", "count"),
    )
    rss = float(g.loc[g["policy"] == "rss", "throughput_pps"].iloc[0]) if (g["policy"] == "rss").any() else np.nan
    g["relative_to_rss_pct"] = (g["throughput_pps"] / rss - 1.0) * 100.0 if rss and rss > 0 else np.nan
    g["policy_label"] = g["policy"].map(lambda p: POLICY_LABEL.get(p, p))
    g = g.sort_values("policy", key=lambda s: s.map(policy_rank))
    g.to_csv(out_dir / "figure3_throughput.csv", index=False)


def write_fig4(runs: pd.DataFrame, out_dir: Path) -> None:
    df = runs[runs["tag"].isin(["overall", ""])].copy()
    if df.empty:
        df = runs.copy()
    g = df.groupby("policy", as_index=False).agg(
        p50_ms=("detect_latency_p50_ms", "mean"),
        p99_ms=("detect_latency_p99_ms", "mean"),
        repeats=("detect_latency_p99_ms", "count"),
    )
    g["policy_label"] = g["policy"].map(lambda p: POLICY_LABEL.get(p, p))
    g = g.sort_values("policy", key=lambda s: s.map(policy_rank))
    g.to_csv(out_dir / "figure4_latency.csv", index=False)


def write_fig5(runs: pd.DataFrame, out_dir: Path) -> None:
    df = runs[(runs["tag"] == "robustness") & (runs["policy"].isin(["rss", "jsq", "ours"]))].copy()
    if df.empty:
        return
    g = df.groupby(["workload_label", "policy"], as_index=False).agg(
        throughput_pps=("throughput_pps", "mean"),
        repeats=("throughput_pps", "count"),
    )
    g["policy_label"] = g["policy"].map(lambda p: POLICY_LABEL.get(p, p))
    g.to_csv(out_dir / "figure5_robustness.csv", index=False)


def write_fig6(runs: pd.DataFrame, out_dir: Path) -> None:
    df = runs[runs["tag"] == "overload"].copy()
    if df.empty:
        return
    g = df.groupby(["worker_count_label", "policy"], as_index=False).agg(
        p99_ms=("detect_latency_p99_ms", "mean"),
        repeats=("detect_latency_p99_ms", "count"),
    )
    g["worker_count"] = pd.to_numeric(g["worker_count_label"], errors="coerce")
    g["policy_label"] = g["policy"].map(lambda p: POLICY_LABEL.get(p, p))
    g.to_csv(out_dir / "figure6_overload.csv", index=False)


def write_fig7(workers: pd.DataFrame, out_dir: Path) -> None:
    if workers.empty:
        return
    df = workers[workers["policy"].isin(["rss", "jsq", "ours"])].copy()
    if df.empty:
        return
    g = df.groupby(["policy", "worker_id", "core_id", "core_type"], as_index=False).agg(
        workload_ns=("processing_time_ns", "mean"),
        busy_ratio=("busy_ratio", "mean"),
    )
    cv_rows = []
    for policy, group in g.groupby("policy"):
        values = group["workload_ns"].to_numpy(dtype=float)
        mean = values.mean() if len(values) else 0.0
        cv = float(values.std(ddof=0) / mean) if mean > 0 else 0.0
        cv_rows.append({"policy": policy, "policy_label": POLICY_LABEL.get(policy, policy), "cv": cv})
    g["policy_label"] = g["policy"].map(lambda p: POLICY_LABEL.get(p, p))
    g.to_csv(out_dir / "figure7_workload.csv", index=False)
    pd.DataFrame(cv_rows).to_csv(out_dir / "figure7_workload_cv.csv", index=False)


def main() -> None:
    args = parse_args()
    batch_dir = Path(args.batch_dir)
    out_dir = Path(args.output_dir) if args.output_dir else batch_dir / "derived"
    out_dir.mkdir(parents=True, exist_ok=True)
    runs, workers = load_runs(batch_dir)
    if runs.empty:
        raise SystemExit(f"no runs found under {batch_dir}/raw")
    runs.to_csv(out_dir / "all_runs.csv", index=False)
    if not workers.empty:
        workers.to_csv(out_dir / "all_worker_stats.csv", index=False)
    write_fig3(runs, out_dir)
    write_fig4(runs, out_dir)
    write_fig5(runs, out_dir)
    write_fig6(runs, out_dir)
    write_fig7(workers, out_dir)
    print(out_dir)


if __name__ == "__main__":
    main()
