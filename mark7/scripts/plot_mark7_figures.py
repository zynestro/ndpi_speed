#!/usr/bin/env python3
"""Plot Figure 3-7 from editable derived CSV files."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


COLORS = {
    "RSS": "#7A8797",
    "JSQ": "#4E79A7",
    "Static Pool": "#F28E2B",
    "Ours": "#59A14F",
    "Oracle": "#B07AA1",
}


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--derived-dir", required=True)
    ap.add_argument("--output-dir", default="", help="Default: <derived-dir>/../plots")
    return ap.parse_args()


def style() -> None:
    plt.style.use("seaborn-v0_8-whitegrid")
    plt.rcParams.update({
        "figure.dpi": 160,
        "savefig.dpi": 300,
        "font.size": 9,
        "axes.labelsize": 9,
        "axes.titlesize": 10,
        "legend.fontsize": 8,
        "axes.edgecolor": "#3E4651",
        "grid.color": "#D5DAE2",
        "grid.linestyle": "--",
        "grid.linewidth": 0.5,
    })


def save(fig: plt.Figure, out_base: Path) -> None:
    fig.tight_layout()
    fig.savefig(out_base.with_suffix(".png"))
    fig.savefig(out_base.with_suffix(".pdf"))
    plt.close(fig)


def plot_fig3(path: Path, out_dir: Path) -> None:
    if not path.exists():
        return
    df = pd.read_csv(path)
    labels = df["policy_label"].tolist()
    x = np.arange(len(df))
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    bars = ax.bar(x, df["throughput_pps"], color=[COLORS.get(v, "#888") for v in labels], width=0.62)
    ax.set_xticks(x, labels)
    ax.set_ylabel("Throughput (pps)")
    ax.set_title("Figure 3: Throughput comparison")
    rss = float(df.loc[df["policy"].eq("rss"), "throughput_pps"].iloc[0]) if df["policy"].eq("rss").any() else 0.0
    for bar, value in zip(bars, df["throughput_pps"]):
        if rss > 0:
            pct = (float(value) / rss - 1.0) * 100.0
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{pct:+.0f}%",
                    ha="center", va="bottom", fontsize=8)
    save(fig, out_dir / "figure3_throughput")


def plot_fig4(path: Path, out_dir: Path) -> None:
    if not path.exists():
        return
    df = pd.read_csv(path)
    x = np.arange(len(df))
    width = 0.34
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    ax.bar(x - width / 2, df["p50_ms"], width, label="p50", color="#4E79A7")
    ax.bar(x + width / 2, df["p99_ms"], width, label="p99", color="#E15759")
    ax.set_xticks(x, df["policy_label"])
    ax.set_ylabel("Per-flow detecting latency (ms)")
    ax.set_title("Figure 4: Detecting latency")
    ax.legend(frameon=False)
    save(fig, out_dir / "figure4_latency")


def plot_fig5(path: Path, out_dir: Path) -> None:
    if not path.exists():
        return
    df = pd.read_csv(path)
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    for label, group in df.groupby("policy_label"):
        group = group.sort_values("workload_label")
        ax.plot(group["workload_label"], group["throughput_pps"], marker="o",
                linewidth=1.8, label=label, color=COLORS.get(label))
    ax.set_xlabel("Encrypted flow ratio")
    ax.set_ylabel("Throughput (pps)")
    ax.set_title("Figure 5: Robustness to encrypted traffic ratio")
    ax.legend(frameon=False)
    save(fig, out_dir / "figure5_robustness")


def plot_fig6(path: Path, out_dir: Path) -> None:
    if not path.exists():
        return
    df = pd.read_csv(path)
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    for label, group in df.groupby("policy_label"):
        group = group.sort_values("worker_count", ascending=False)
        ax.plot(group["worker_count"], group["p99_ms"], marker="o",
                linewidth=1.8, label=label, color=COLORS.get(label))
    ax.set_xlabel("Workers")
    ax.set_ylabel("p99 detecting latency (ms)")
    ax.set_title("Figure 6: Overload behavior")
    ax.invert_xaxis()
    ax.legend(frameon=False, ncol=2)
    save(fig, out_dir / "figure6_overload")


def plot_fig7(workload_path: Path, cv_path: Path, out_dir: Path) -> None:
    if not workload_path.exists():
        return
    df = pd.read_csv(workload_path)
    fig, ax = plt.subplots(figsize=(6.2, 3.2))
    labels = []
    values = []
    cvs = {}
    if cv_path.exists():
        for row in pd.read_csv(cv_path).to_dict("records"):
            cvs[row["policy_label"]] = float(row["cv"])
    for label, group in df.groupby("policy_label"):
        labels.append(f"{label}\nCV={cvs.get(label, 0.0):.2f}")
        values.append(group["workload_ns"].to_numpy(dtype=float))
    ax.boxplot(values, tick_labels=labels, patch_artist=True)
    ax.set_ylabel("Per-core workload (processing ns)")
    ax.set_title("Figure 7: Per-core workload balance")
    save(fig, out_dir / "figure7_workload")


def main() -> None:
    args = parse_args()
    derived = Path(args.derived_dir)
    out_dir = Path(args.output_dir) if args.output_dir else derived.parent / "plots"
    out_dir.mkdir(parents=True, exist_ok=True)
    style()
    plot_fig3(derived / "figure3_throughput.csv", out_dir)
    plot_fig4(derived / "figure4_latency.csv", out_dir)
    plot_fig5(derived / "figure5_robustness.csv", out_dir)
    plot_fig6(derived / "figure6_overload.csv", out_dir)
    plot_fig7(derived / "figure7_workload.csv", derived / "figure7_workload_cv.csv", out_dir)
    print(out_dir)


if __name__ == "__main__":
    main()
