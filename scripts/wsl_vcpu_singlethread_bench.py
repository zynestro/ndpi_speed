#!/usr/bin/env python3
"""Measure per-vCPU single-thread performance distribution on Linux/WSL."""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import random
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt


@dataclass
class RunResult:
    cpu: int
    repeat: int
    elapsed_s: float
    hashes: int
    hashes_per_s: float


def one_run(cpu: int, seconds: float, payload_size: int) -> RunResult:
    os.sched_setaffinity(0, {cpu})
    payload = b"x" * payload_size
    digest = payload
    hashes = 0
    start = time.perf_counter()
    while True:
        digest = hashlib.sha256(digest).digest()
        hashes += 1
        if (hashes & 0x3FF) == 0:
            now = time.perf_counter()
            if now - start >= seconds:
                elapsed = now - start
                break
    # Keep the value live so Python can't discard the loop.
    if digest[0] == 256:  # pragma: no cover
        print("unreachable")
    return RunResult(
        cpu=cpu,
        repeat=-1,
        elapsed_s=elapsed,
        hashes=hashes,
        hashes_per_s=hashes / elapsed,
    )


def write_csv(rows: list[RunResult], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cpu", "repeat", "elapsed_s", "hashes", "hashes_per_s"])
        for r in rows:
            w.writerow([r.cpu, r.repeat, f"{r.elapsed_s:.6f}", r.hashes, f"{r.hashes_per_s:.2f}"])


def plot(rows: list[RunResult], path: Path) -> None:
    by_cpu: dict[int, list[float]] = {}
    for r in rows:
        by_cpu.setdefault(r.cpu, []).append(r.hashes_per_s)
    cpus = sorted(by_cpu)
    data = [by_cpu[c] for c in cpus]
    medians = [statistics.median(v) for v in data]

    fig, ax = plt.subplots(figsize=(max(10, len(cpus) * 0.35), 6))
    ax.boxplot(data, tick_labels=[str(c) for c in cpus], showfliers=True)
    ax.plot(range(1, len(cpus) + 1), medians, color="tab:red", marker="o", linewidth=1.5, label="median")
    ax.set_title("Per-vCPU Single-Thread Throughput Distribution")
    ax.set_xlabel("vCPU index")
    ax.set_ylabel("SHA256 hashes / second")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(loc="best")
    plt.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def summarize(rows: list[RunResult]) -> str:
    by_cpu: dict[int, list[float]] = {}
    for r in rows:
        by_cpu.setdefault(r.cpu, []).append(r.hashes_per_s)
    med = {cpu: statistics.median(vals) for cpu, vals in by_cpu.items()}
    values = sorted(med.values())
    if len(values) < 2:
        return "not enough CPUs for clustering hint"
    max_gap = -1.0
    split_idx = 0
    for i in range(1, len(values)):
        gap = values[i] - values[i - 1]
        if gap > max_gap:
            max_gap = gap
            split_idx = i
    threshold = (values[split_idx - 1] + values[split_idx]) / 2.0
    fast = sorted([cpu for cpu, m in med.items() if m >= threshold])
    slow = sorted([cpu for cpu, m in med.items() if m < threshold])
    return (
        f"gap-based split threshold ~= {threshold:.2f} hashes/s | "
        f"fast-group({len(fast)}): {fast} | slow-group({len(slow)}): {slow}"
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repeats", type=int, default=6, help="runs per vCPU")
    p.add_argument("--seconds", type=float, default=0.5, help="target runtime per run")
    p.add_argument("--payload-bytes", type=int, default=1024, help="payload size for hash loop")
    p.add_argument("--seed", type=int, default=20260303, help="shuffle seed")
    p.add_argument(
        "--outdir",
        type=Path,
        default=Path("output") / "wsl_vcpu_bench",
        help="output directory for CSV and PNG",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeats <= 0:
        print("repeats must be > 0", file=sys.stderr)
        return 2
    if args.seconds <= 0:
        print("seconds must be > 0", file=sys.stderr)
        return 2

    cpus = list(range(os.cpu_count() or 1))
    args.outdir.mkdir(parents=True, exist_ok=True)

    rows: list[RunResult] = []
    rng = random.Random(args.seed)
    total = len(cpus) * args.repeats
    idx = 0
    print(f"Benchmarking {len(cpus)} vCPUs, repeats={args.repeats}, seconds={args.seconds} ...")
    for rep in range(args.repeats):
        order = cpus[:]
        rng.shuffle(order)
        for cpu in order:
            idx += 1
            res = one_run(cpu=cpu, seconds=args.seconds, payload_size=args.payload_bytes)
            res.repeat = rep
            rows.append(res)
            print(
                f"[{idx:>4}/{total}] cpu={cpu:>2} rep={rep} "
                f"rate={res.hashes_per_s:>11.2f} hashes/s"
            )

    csv_path = args.outdir / "per_vcpu_singlethread.csv"
    png_path = args.outdir / "per_vcpu_singlethread.png"
    write_csv(rows, csv_path)
    plot(rows, png_path)
    print(f"\nCSV: {csv_path}")
    print(f"PNG: {png_path}")
    print(summarize(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
