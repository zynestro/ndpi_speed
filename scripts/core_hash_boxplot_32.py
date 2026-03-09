#!/usr/bin/env python3
"""Per-core single-thread hash benchmark with boxplot visualization.

Use CPU affinity to pin one process to one logical core at a time.
For each core, run repeated timed hash loops and compare throughput.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import statistics
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Benchmark per-core hash throughput and draw a boxplot."
    )
    p.add_argument(
        "--seconds",
        type=float,
        default=0.5,
        help="Benchmark time per run on each core.",
    )
    p.add_argument(
        "--repeats",
        type=int,
        default=4,
        help="Repeats per core.",
    )
    p.add_argument(
        "--max-cpus",
        type=int,
        default=32,
        help="Test first N visible logical CPUs.",
    )
    p.add_argument(
        "--payload-bytes",
        type=int,
        default=64,
        help="Initial payload size for each hash loop.",
    )
    p.add_argument(
        "--outdir",
        type=Path,
        default=Path("output/core_hash_boxplot"),
        help="Base output directory; script creates a timestamped subdirectory for each run.",
    )
    p.add_argument(
        "--skip-plot",
        action="store_true",
        help="Skip plotting (useful when matplotlib is not installed).",
    )
    return p.parse_args()


def visible_cpus(limit: int) -> list[int]:
    cpus = sorted(os.sched_getaffinity(0))
    return cpus[: min(limit, len(cpus))]


def run_once(cpu: int, seconds: float, payload_bytes: int) -> float:
    os.sched_setaffinity(0, {cpu})
    seed = b"x" * payload_bytes
    digest = seed
    loops = 0
    start = time.perf_counter()
    while True:
        digest = hashlib.sha256(digest).digest()
        loops += 1
        if (loops & 0x3FF) == 0:
            elapsed = time.perf_counter() - start
            if elapsed >= seconds:
                return loops / elapsed


def save_raw(rows: list[tuple[int, int, float]], out_csv: Path) -> None:
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cpu", "repeat", "hashes_per_second"])
        w.writerows(rows)


def save_summary(per_cpu: dict[int, list[float]], out_csv: Path) -> dict[int, str]:
    means = {cpu: statistics.mean(vals) for cpu, vals in per_cpu.items()}
    median_of_means = statistics.median(means.values())
    groups = {
        cpu: ("big_like" if m >= median_of_means else "little_like")
        for cpu, m in means.items()
    }

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cpu", "group", "mean_hps", "stdev_hps", "min_hps", "max_hps"])
        for cpu in sorted(per_cpu):
            vals = per_cpu[cpu]
            stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
            w.writerow(
                [
                    cpu,
                    groups[cpu],
                    f"{statistics.mean(vals):.2f}",
                    f"{stdev:.2f}",
                    f"{min(vals):.2f}",
                    f"{max(vals):.2f}",
                ]
            )
    return groups


def plot_box(per_cpu: dict[int, list[float]], groups: dict[int, str], out_png: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        from matplotlib.patches import Patch
    except ModuleNotFoundError as e:
        raise RuntimeError(
            "matplotlib is required for plotting. Install it with "
            "`conda install matplotlib` or rerun with `--skip-plot`."
        ) from e

    cpus = sorted(per_cpu)
    data = [per_cpu[c] for c in cpus]
    labels = [f"CPU{c}" for c in cpus]
    colors = ["#2e86de" if groups[c] == "little_like" else "#e67e22" for c in cpus]

    fig, ax = plt.subplots(figsize=(max(12, len(cpus) * 0.45), 6))
    bp = ax.boxplot(data, patch_artist=True, labels=labels, showmeans=True)
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.65)

    ax.set_title("Per-core single-thread SHA256 throughput")
    ax.set_ylabel("Hashes per second")
    ax.set_xlabel("Logical CPU")
    ax.tick_params(axis="x", rotation=60)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    ax.legend(
        handles=[
            Patch(facecolor="#e67e22", alpha=0.65, label="big_like"),
            Patch(facecolor="#2e86de", alpha=0.65, label="little_like"),
        ],
        loc="best",
    )
    fig.tight_layout()
    fig.savefig(out_png, dpi=160)
    plt.close(fig)


def main() -> int:
    args = parse_args()
    cpus = visible_cpus(args.max_cpus)
    if not cpus:
        raise RuntimeError("No visible CPUs found from sched_getaffinity(0).")

    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_outdir = args.outdir / run_ts
    run_outdir.mkdir(parents=True, exist_ok=True)
    print(f"Testing {len(cpus)} CPUs: {cpus}")
    print(f"seconds={args.seconds}, repeats={args.repeats}, payload_bytes={args.payload_bytes}")
    print(f"output_dir={run_outdir}")

    raw_rows: list[tuple[int, int, float]] = []
    per_cpu: dict[int, list[float]] = defaultdict(list)
    total = len(cpus) * args.repeats
    n = 0
    for rep in range(args.repeats):
        for cpu in cpus:
            n += 1
            hps = run_once(cpu, args.seconds, args.payload_bytes)
            raw_rows.append((cpu, rep, hps))
            per_cpu[cpu].append(hps)
            print(f"[{n:>4}/{total}] cpu={cpu:>2} rep={rep} hps={hps:>12.2f}")

    raw_csv = run_outdir / "raw_per_run.csv"
    summary_csv = run_outdir / "summary_per_cpu.csv"
    fig_png = run_outdir / "boxplot_per_cpu.png"

    save_raw(raw_rows, raw_csv)
    groups = save_summary(per_cpu, summary_csv)
    if args.skip_plot:
        print("\nSkip plotting as requested (`--skip-plot`).")
    else:
        plot_box(per_cpu, groups, fig_png)

    means = {cpu: statistics.mean(vals) for cpu, vals in per_cpu.items()}
    fast = sorted(means.items(), key=lambda x: x[1], reverse=True)[:5]
    slow = sorted(means.items(), key=lambda x: x[1])[:5]
    print("\nTop 5 mean throughput CPUs:")
    for cpu, m in fast:
        print(f"  cpu={cpu:>2} mean={m:,.2f} hps group={groups[cpu]}")
    print("Bottom 5 mean throughput CPUs:")
    for cpu, m in slow:
        print(f"  cpu={cpu:>2} mean={m:,.2f} hps group={groups[cpu]}")
    print(f"\nRaw CSV: {raw_csv}")
    print(f"Summary CSV: {summary_csv}")
    if args.skip_plot:
        print("Boxplot: skipped")
    else:
        print(f"Boxplot: {fig_png}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
