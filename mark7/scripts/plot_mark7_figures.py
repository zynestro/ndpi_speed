#!/usr/bin/env python3
"""Plot mark7 Figure 3-7 from editable derived CSV files."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd


COLORS = {
    "RSS": "#7A8797",
    "JSQ": "#4E79A7",
    "Static Pool": "#F28E2B",
    "Ours": "#59A14F",
    "Oracle": "#B07AA1",
}
HATCH = {
    "RSS": "",
    "JSQ": "//",
    "Static Pool": "\\\\",
    "Ours": "",
    "Oracle": "xx",
}
POLICY_ORDER = ["RSS", "JSQ", "Static Pool", "Ours", "Oracle"]
COL_W = 3.5
COL_H = 2.4


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--derived-dir", required=True)
    parser.add_argument("--output-dir", default="", help="Default: <derived-dir>/../plots")
    parser.add_argument(
        "--figures",
        default="all",
        help="Comma-separated figures to render, e.g. 3,4,6 or all. Default: all",
    )
    return parser.parse_args()


def parse_figures(value: str) -> set[str]:
    value = value.strip().lower()
    if value in {"", "all"}:
        return {"3", "4", "5", "6", "7"}
    requested = {part.strip().removeprefix("figure") for part in value.split(",")}
    valid = {"3", "4", "5", "6", "7"}
    unknown = sorted(requested - valid)
    if unknown:
        raise SystemExit(f"unknown figure selector(s): {', '.join(unknown)}")
    return requested


def read_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, skipinitialspace=True)
    df.columns = df.columns.str.strip()
    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].astype(str).str.strip()
    return df


def style() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 8,
            "axes.labelsize": 8,
            "axes.titlesize": 9,
            "legend.fontsize": 7,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "axes.linewidth": 0.6,
            "grid.linewidth": 0.3,
            "grid.linestyle": "--",
            "grid.color": "#CCCCCC",
            "axes.grid": True,
            "axes.grid.axis": "y",
            "axes.edgecolor": "#333333",
            "axes.axisbelow": True,
            "figure.dpi": 300,
            "savefig.dpi": 300,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
        }
    )


def save(fig: plt.Figure, out_dir: Path, name: str) -> Path:
    fig.tight_layout(pad=0.3)
    pdf = out_dir / f"{name}.pdf"
    png = out_dir / f"{name}.png"
    fig.savefig(pdf)
    fig.savefig(png)
    plt.close(fig)
    return png


def ordered_labels(labels: pd.Series) -> list[str]:
    present = set(labels)
    ordered = [label for label in POLICY_ORDER if label in present]
    ordered.extend(sorted(present - set(ordered)))
    return ordered


def plot_fig3(derived: Path, out_dir: Path) -> Path | None:
    path = derived / "figure3_throughput.csv"
    if not path.exists():
        return None
    df = read_csv(path)
    labels = df["policy_label"].tolist()
    throughput = df["throughput_pps"].to_numpy(dtype=float) / 1e6
    x = np.arange(len(df))

    fig, ax = plt.subplots(figsize=(COL_W, COL_H))
    bars = ax.bar(
        x,
        throughput,
        width=0.58,
        color=[COLORS.get(label, "#888888") for label in labels],
        edgecolor="#333333",
        linewidth=0.5,
        hatch=[HATCH.get(label, "") for label in labels],
        zorder=3,
    )

    if "RSS" in labels:
        rss_val = throughput[labels.index("RSS")]
        if rss_val > 0:
            for i, (bar, val) in enumerate(zip(bars, throughput)):
                text = "baseline" if labels[i] == "RSS" else f"{(val / rss_val - 1.0) * 100.0:+.1f}%"
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.05,
                    text,
                    ha="center",
                    va="bottom",
                    fontsize=6,
                    color="#333333",
                )

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Throughput (Mpps)")
    ax.set_ylim(bottom=0)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%.1f"))
    return save(fig, out_dir, "figure3_throughput")


def plot_fig4(derived: Path, out_dir: Path) -> Path | None:
    path = derived / "figure4_latency.csv"
    if not path.exists():
        return None
    df = read_csv(path)
    labels = df["policy_label"].tolist()
    p50 = df["p50_ms"].to_numpy(dtype=float)
    p99 = df["p99_ms"].to_numpy(dtype=float)
    x = np.arange(len(df))
    width = 0.30

    fig, ax = plt.subplots(figsize=(COL_W, COL_H))
    ax.bar(
        x - width / 2,
        p50,
        width,
        label="p50",
        color="#4E79A7",
        edgecolor="#333333",
        linewidth=0.5,
        zorder=3,
    )
    ax.bar(
        x + width / 2,
        p99,
        width,
        label="p99",
        color="#E15759",
        edgecolor="#333333",
        linewidth=0.5,
        hatch="//",
        zorder=3,
    )

    for i in range(len(df)):
        ax.text(x[i] - width / 2, p50[i] + 0.08, f"{p50[i]:.2f}", ha="center", va="bottom", fontsize=5.5)
        ax.text(x[i] + width / 2, p99[i] + 0.08, f"{p99[i]:.2f}", ha="center", va="bottom", fontsize=5.5)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Per-flow detecting latency (ms)")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=True, fancybox=False, edgecolor="#999999", loc="upper right")
    return save(fig, out_dir, "figure4_latency")


def plot_fig5(derived: Path, out_dir: Path) -> Path | None:
    path = derived / "figure5_robustness.csv"
    if not path.exists():
        return None
    df = read_csv(path)
    df["throughput_mpps"] = df["throughput_pps"].astype(float) / 1e6
    policies = [label for label in ["RSS", "JSQ", "Ours"] if label in set(df["policy_label"])]

    fig, ax = plt.subplots(figsize=(COL_W, COL_H))
    markers = {"RSS": "s", "JSQ": "^", "Ours": "o"}
    linestyles = {"RSS": "--", "JSQ": "-.", "Ours": "-"}

    for policy in policies:
        group = df[df["policy_label"] == policy].copy()
        group["ratio"] = group["workload_label"].map(lambda v: float(str(v).replace("%", "")))
        group = group.sort_values("ratio")
        ax.plot(
            group["ratio"],
            group["throughput_mpps"],
            marker=markers.get(policy, "o"),
            markersize=4.5,
            linewidth=1.45,
            linestyle=linestyles.get(policy, "-"),
            label=policy,
            color=COLORS.get(policy, "#888888"),
            markeredgecolor="#333333",
            markeredgewidth=0.45,
            zorder=3,
        )

    ratios = sorted(df["workload_label"].map(lambda v: float(str(v).replace("%", ""))).unique())
    ax.set_xticks(ratios)
    ax.set_xticklabels([f"{int(r)}%" for r in ratios])
    ax.set_xlabel("Complex flow ratio")
    ax.set_ylabel("Throughput (Mpps)")
    y_min = float(df["throughput_mpps"].min())
    y_max = float(df["throughput_mpps"].max())
    y_pad = max((y_max - y_min) * 0.18, 0.25)
    ax.set_ylim(max(0.0, y_min - y_pad), y_max + y_pad)
    ax.legend(
        frameon=True,
        fancybox=False,
        edgecolor="#999999",
        loc="lower center",
        bbox_to_anchor=(0.5, 1.03),
        ncol=max(len(policies), 1),
        columnspacing=0.9,
        handlelength=1.7,
        borderpad=0.3,
    )
    return save(fig, out_dir, "figure5_robustness")


def plot_fig6(derived: Path, out_dir: Path) -> Path | None:
    path = derived / "figure6_overload.csv"
    if not path.exists():
        return None
    df = read_csv(path)
    df["worker_count"] = pd.to_numeric(df["worker_count"], errors="coerce")
    df = df.dropna(subset=["worker_count"])
    policies = ordered_labels(df["policy_label"])
    worker_counts = sorted(df["worker_count"].unique(), reverse=True)
    width = 0.7 / max(len(policies), 1)
    x = np.arange(len(worker_counts))

    fig, ax = plt.subplots(figsize=(COL_W, COL_H))
    for i, policy in enumerate(policies):
        subset = df[df["policy_label"] == policy].set_index("worker_count")
        values = [float(subset.loc[w, "p99_ms"]) if w in subset.index else 0.0 for w in worker_counts]
        offset = (i - (len(policies) - 1) / 2) * width
        ax.bar(
            x + offset,
            values,
            width,
            label=policy,
            color=COLORS.get(policy, "#888888"),
            edgecolor="#333333",
            linewidth=0.5,
            hatch=HATCH.get(policy, ""),
            zorder=3,
        )

    ax.set_xticks(x)
    ax.set_xticklabels([str(int(w)) for w in worker_counts])
    ax.set_xlabel("Workers")
    ax.set_ylabel("p99 detecting latency (ms)")
    ax.set_ylim(bottom=0)
    ax.legend(frameon=True, fancybox=False, edgecolor="#999999", loc="upper right", ncol=2, fontsize=6)
    return save(fig, out_dir, "figure6_overload")


def plot_fig7(derived: Path, out_dir: Path) -> Path | None:
    workload_path = derived / "figure7_workload.csv"
    cv_path = derived / "figure7_workload_cv.csv"
    if not workload_path.exists():
        return None
    df = read_csv(workload_path)

    cvs = {}
    if cv_path.exists():
        for row in read_csv(cv_path).to_dict("records"):
            cvs[str(row["policy_label"])] = float(row["cv"])

    data = []
    tick_labels = []
    for label in ["RSS", "JSQ", "Ours"]:
        group = df[df["policy_label"] == label]
        if group.empty:
            continue
        data.append(group["workload_ns"].to_numpy(dtype=float) / 1e6)
        tick_labels.append(f"{label}\n(CV={cvs.get(label, 0.0):.2f})")

    if not data:
        return None

    fig, ax = plt.subplots(figsize=(COL_W, COL_H))
    bp = ax.boxplot(
        data,
        tick_labels=tick_labels,
        patch_artist=True,
        widths=0.45,
        boxprops=dict(linewidth=0.7),
        whiskerprops=dict(linewidth=0.7),
        capprops=dict(linewidth=0.7),
        medianprops=dict(color="#E15759", linewidth=1.2),
        flierprops=dict(marker="o", markersize=3, markeredgewidth=0.4),
    )
    for patch, label in zip(bp["boxes"], [item.split("\n", 1)[0] for item in tick_labels]):
        patch.set_facecolor(COLORS.get(label, "#888888"))
        patch.set_alpha(0.65)
        patch.set_edgecolor("#333333")

    ax.set_ylabel("Per-core workload (ms)")
    return save(fig, out_dir, "figure7_workload")


PLOTTERS = {
    "3": plot_fig3,
    "4": plot_fig4,
    "5": plot_fig5,
    "6": plot_fig6,
    "7": plot_fig7,
}


def main() -> None:
    args = parse_args()
    derived = Path(args.derived_dir)
    out_dir = Path(args.output_dir) if args.output_dir else derived.parent / "plots"
    out_dir.mkdir(parents=True, exist_ok=True)

    style()
    generated = []
    for fig_id in sorted(parse_figures(args.figures), key=int):
        path = PLOTTERS[fig_id](derived, out_dir)
        if path is not None:
            generated.append(path.name)

    if generated:
        print(f"Plots saved to {out_dir}")
        for name in generated:
            print(f"  {name}")
    else:
        print(f"No requested figure CSVs found under {derived}")


if __name__ == "__main__":
    main()
