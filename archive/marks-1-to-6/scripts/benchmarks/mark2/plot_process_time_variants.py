#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt


DEFAULT_VARIANTS = {
    "mark": "20260227_223026-mark",
    "classified": "20260227_223240-classified",
    "batch": "20260227_223447-batch",
    "mem": "20260227_223648-Mem",
}


def find_csv_file(variant_dir: Path) -> Path:
    csv_files = sorted(variant_dir.glob("benchmark_results_*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No benchmark_results_*.csv found in {variant_dir}")
    return csv_files[0]


def load_workers_process_time(csv_path: Path):
    xs = []
    ys = []
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if "workers" not in (reader.fieldnames or []):
            raise ValueError(f"'workers' column not found in {csv_path}")
        if "process_time_sec" not in (reader.fieldnames or []):
            raise ValueError(f"'process_time_sec' column not found in {csv_path}")
        for row in reader:
            workers = int(row["workers"])
            process_time = float(row["process_time_sec"])
            xs.append(workers)
            ys.append(process_time)
    pairs = sorted(zip(xs, ys), key=lambda p: p[0])
    return [p[0] for p in pairs], [p[1] for p in pairs]


def main():
    parser = argparse.ArgumentParser(
        description="Plot workers vs process_time_sec for mark/classified/batch/mem variants."
    )
    parser.add_argument(
        "--output-root",
        default="output",
        help="Root folder containing benchmark output directories (default: output)",
    )
    parser.add_argument(
        "--out",
        default="output/process_time_vs_workers_variants.png",
        help="Output PNG file path",
    )
    args = parser.parse_args()

    output_root = Path(args.output_root).resolve()
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    plt.figure(figsize=(10, 6))

    for label, dirname in DEFAULT_VARIANTS.items():
        variant_dir = output_root / dirname
        csv_path = find_csv_file(variant_dir)
        workers, process_times = load_workers_process_time(csv_path)
        plt.plot(workers, process_times, marker="o", linewidth=2, label=label)

    plt.title("Process Time vs Workers (mark/classified/batch/mem)")
    plt.xlabel("Workers")
    plt.ylabel("Process Time (sec)")
    plt.grid(True, linestyle="--", alpha=0.35)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
