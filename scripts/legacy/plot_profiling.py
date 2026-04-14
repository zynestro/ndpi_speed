#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import warnings
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib import colors as mcolors
from matplotlib.gridspec import GridSpec
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from scipy.stats import linregress, pearsonr

try:
    from adjustText import adjust_text

    HAS_ADJUST_TEXT = True
except Exception:
    HAS_ADJUST_TEXT = False


NUMERIC_COLUMNS = [
    "master_proto",
    "app_proto",
    "category_id",
    "flows",
    "avg_flow_detecting_ms",
    "avg_flow_post_ms",
    "avg_flow_total_ms",
    "detecting_pkt_p50_us",
    "detecting_pkt_p99_us",
    "post_pkt_p50_us",
    "post_pkt_p99_us",
    "avg_detect_pkt_flow",
    "avg_detect_pkt_global",
]

SERIF_FAMILY = ["Times New Roman", "Times", "DejaVu Serif", "serif"]
AXIS_LABEL_SIZE = 11
TICK_LABEL_SIZE = 9
PROTO_LABEL_SIZE = 9


def assign_bucket(row: pd.Series) -> str:
    t = row["avg_flow_detecting_ms"]
    if t < 0.003:
        return "Easy"
    if t < 0.008:
        return "Middle"
    return "Hard"


BUCKET_COLORS = {
    "Easy": "#1D9E75",
    "Middle": "#534AB7",
    "Hard": "#D85A30",
}

BUCKET_ORDER = ["Easy", "Middle", "Hard"]

POST_BREAKDOWN_MAX_MS = 1.0
MIN_FLOWS = 3


def clean_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip().strip('"').strip("'").strip()


def lighten(color: str, amount: float = 0.45) -> tuple[float, float, float]:
    rgb = np.array(mcolors.to_rgb(color))
    return tuple(rgb + (1.0 - rgb) * amount)


def warn(message: str) -> None:
    print(f"Warning: {message}")


def format_flows(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M flows"
    if value >= 1_000:
        return f"{value / 1_000:.0f}K flows"
    return f"{int(round(value))} flows"


def format_cost_share(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f}M ms·flows"
    if value >= 1_000:
        return f"{value / 1_000:.2f}K ms·flows"
    return f"{value:.2f} ms·flows"


def scale_series(values: pd.Series, size_min: float, size_max: float) -> np.ndarray:
    arr = values.to_numpy(dtype=float)
    finite = np.isfinite(arr)
    if not finite.any():
        return np.full(len(arr), size_min)
    low = np.nanmin(arr)
    high = np.nanmax(arr)
    if math.isclose(low, high):
        return np.full(len(arr), (size_min + size_max) / 2.0)
    scaled = (arr - low) / (high - low)
    return size_min + scaled * (size_max - size_min)


def load_dataframe(csv_path: Path) -> pd.DataFrame:
    rows: list[list[str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row:
                continue
            if not any(clean_text(cell) for cell in row):
                continue
            rows.append([clean_text(cell) for cell in row])

    if not rows:
        raise ValueError(f"empty csv: {csv_path}")

    header_idx = None
    for idx, row in enumerate(rows):
        if row and clean_text(row[0]) == "proto_name":
            header_idx = idx
            break

    if header_idx is None:
        raise ValueError(f"could not find header row in {csv_path}")

    headers = [clean_text(cell) for cell in rows[header_idx]]
    records = []
    for raw in rows[header_idx + 1 :]:
        padded = raw + [""] * max(0, len(headers) - len(raw))
        record = {headers[i]: clean_text(padded[i]) for i in range(len(headers))}
        if not clean_text(record.get("proto_name", "")):
            continue
        records.append(record)

    if not records:
        raise ValueError(f"no data rows found in {csv_path}")

    df = pd.DataFrame.from_records(records)
    for column in df.columns:
        if df[column].dtype == object:
            df[column] = df[column].map(clean_text)

    for column in NUMERIC_COLUMNS:
        if column not in df.columns:
            raise ValueError(f"missing required column: {column}")
        df[column] = pd.to_numeric(df[column], errors="coerce")

    df = df.dropna(
        subset=[
            "proto_name",
            "flows",
            "avg_flow_detecting_ms",
            "avg_flow_post_ms",
            "avg_flow_total_ms",
            "detecting_pkt_p50_us",
            "detecting_pkt_p99_us",
            "avg_detect_pkt_flow",
        ]
    ).copy()
    df["flows"] = df["flows"].astype(int)
    df = df[df["flows"] >= MIN_FLOWS].copy()
    if df.empty:
        raise ValueError(f"no rows left after filtering flows >= {MIN_FLOWS}")

    df["bucket"] = df.apply(assign_bucket, axis=1)
    df = df.sort_values(
        by=["avg_flow_detecting_ms", "flows", "proto_name"],
        ascending=[False, False, True],
        kind="mergesort",
    ).reset_index(drop=True)
    df["plot_order"] = np.arange(len(df))
    return df


def apply_common_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": SERIF_FAMILY,
            "axes.labelsize": AXIS_LABEL_SIZE,
            "axes.titlesize": 12,
            "xtick.labelsize": TICK_LABEL_SIZE,
            "ytick.labelsize": TICK_LABEL_SIZE,
            "legend.fontsize": 9,
        }
    )


def add_text_labels(ax: plt.Axes, df: pd.DataFrame, x_col: str, y_col: str) -> None:
    if df.empty:
        return

    texts = []
    offsets = [(-10, 6), (8, 6), (-12, -8), (10, -10), (0, 10)]
    for idx, row in enumerate(df.itertuples(index=False)):
        if HAS_ADJUST_TEXT:
            texts.append(
                ax.text(
                    getattr(row, x_col),
                    getattr(row, y_col),
                    row.proto_name,
                    fontsize=PROTO_LABEL_SIZE,
                )
            )
        else:
            dx, dy = offsets[idx % len(offsets)]
            ax.annotate(
                row.proto_name,
                (getattr(row, x_col), getattr(row, y_col)),
                xytext=(dx, dy),
                textcoords="offset points",
                fontsize=PROTO_LABEL_SIZE,
            )

    if HAS_ADJUST_TEXT and texts:
        adjust_text(
            texts,
            ax=ax,
            arrowprops=dict(arrowstyle="-", color="0.5", lw=0.5),
            expand_points=(1.2, 1.2),
            expand_text=(1.05, 1.15),
        )


def maybe_warn_small_dataset(df: pd.DataFrame, context: str) -> None:
    if len(df) <= 4:
        warn(f"{context}: only {len(df)} protocols after filtering, visual separation may be limited")


def plot_complexity_scatter(ax: plt.Axes, df: pd.DataFrame) -> None:
    maybe_warn_small_dataset(df, "scatter plot")

    sizes = scale_series(np.log2(df["flows"].clip(lower=1.0)), 20.0, 300.0)
    color_values = df["bucket"].map(BUCKET_COLORS)
    ax.scatter(
        df["avg_detect_pkt_flow"],
        df["avg_flow_detecting_ms"],
        s=sizes,
        c=color_values,
        alpha=0.8,
        edgecolors="black",
        linewidths=0.4,
    )

    add_text_labels(ax, df, "avg_detect_pkt_flow", "avg_flow_detecting_ms")

    if len(df) >= 2:
        reg = linregress(df["avg_detect_pkt_flow"], df["avg_flow_detecting_ms"])
        x_line = np.linspace(df["avg_detect_pkt_flow"].min(), df["avg_detect_pkt_flow"].max(), 200)
        y_line = reg.intercept + reg.slope * x_line
        ax.plot(x_line, y_line, linestyle="--", color="0.5", linewidth=1.2)
        r2 = reg.rvalue ** 2
        ax.text(
            0.98,
            0.03,
            f"$R^2$ = {r2:.3f}",
            transform=ax.transAxes,
            ha="right",
            va="bottom",
            fontsize=9,
            bbox=dict(boxstyle="round,pad=0.25", facecolor="white", edgecolor="0.8"),
        )
    else:
        warn("scatter plot: not enough points for linear regression")

    size_levels = [df["flows"].quantile(q) for q in (0.25, 0.6, 0.9)]
    size_levels = [max(float(v), 1.0) for v in size_levels if np.isfinite(v)]
    size_handles = []
    for level in size_levels[:3]:
        size = scale_series(pd.Series([math.log2(level)]), 20.0, 300.0)[0]
        size_handles.append(
            plt.scatter([], [], s=size, facecolor="white", edgecolor="0.3", label=format_flows(level))
        )

    bucket_handles = [
        Line2D([0], [0], marker="o", color="w", label=b, markerfacecolor=BUCKET_COLORS[b], markersize=7)
        for b in BUCKET_ORDER
        if (df["bucket"] == b).any()
    ]
    legend_handles = bucket_handles + size_handles
    if legend_handles:
        ax.legend(handles=legend_handles, loc="lower right", frameon=True)

    ax.set_xlabel("Avg. packets to detect per flow")
    ax.set_ylabel("Avg. per-flow detection cost (ms)")
    ax.set_title("(a) Protocol complexity landscape")
    ax.grid(True, linestyle=":", alpha=0.25)


def plot_flow_vs_packet(fig: plt.Figure, spec, df: pd.DataFrame) -> tuple[plt.Axes, plt.Axes]:
    sub_gs = spec.subgridspec(1, 2, width_ratios=[1.1, 1.35], wspace=0.03)
    ax_left = fig.add_subplot(sub_gs[0, 0])
    ax_right = fig.add_subplot(sub_gs[0, 1], sharey=ax_left)

    y = np.arange(len(df))
    colors = df["bucket"].map(BUCKET_COLORS)

    ax_left.barh(
        y,
        df["avg_flow_detecting_ms"],
        color=colors,
        edgecolor="black",
        linewidth=0.35,
    )
    ax_left.invert_xaxis()
    ax_left.invert_yaxis()
    ax_left.set_xlabel("Per-flow detection cost (ms)")
    ax_left.set_yticks(y)
    ax_left.tick_params(axis="y", left=False, labelleft=False)
    ax_left.grid(True, axis="x", linestyle=":", alpha=0.25)

    ratios = df["detecting_pkt_p99_us"] / df["detecting_pkt_p50_us"].replace(0, np.nan)
    tail_heavy = ratios > 5.0
    for yi, row in enumerate(df.itertuples(index=False)):
        highlight = bool(tail_heavy.iloc[yi]) if np.isfinite(ratios.iloc[yi]) else False
        color = "#C0392B" if highlight else "0.55"
        ax_right.plot(
            [row.detecting_pkt_p50_us, row.detecting_pkt_p99_us],
            [yi, yi],
            color=color,
            linewidth=1.0,
            zorder=1,
        )
        ax_right.plot(
            row.detecting_pkt_p50_us,
            yi,
            marker="o",
            markersize=6,
            color=color,
            markerfacecolor=color,
            zorder=2,
        )
        ax_right.plot(
            row.detecting_pkt_p99_us,
            yi,
            marker=">",
            markersize=6,
            color=color,
            markerfacecolor=color,
            zorder=2,
        )

    ax_right.set_xlabel("Per-packet detection latency (μs)")
    ax_right.set_yticks(y)
    ax_right.set_yticklabels(df["proto_name"], fontsize=PROTO_LABEL_SIZE)
    ax_right.tick_params(axis="y", left=True, labelleft=True, pad=2)
    ax_right.grid(True, axis="x", linestyle=":", alpha=0.25)
    ax_right.set_title("(b) Per-flow cost vs per-packet latency")

    right_handles = [
        Line2D([0], [0], marker="o", color="0.35", linestyle="None", label="p50", markersize=6),
        Line2D([0], [0], marker=">", color="0.35", linestyle="None", label="p99", markersize=6),
        Line2D([0], [0], color="#C0392B", linewidth=1.2, label="p99/p50 > 5"),
    ]
    ax_right.legend(handles=right_handles, loc="lower right", frameon=True)
    return ax_left, ax_right


def plot_packet_p50_vs_flow(ax: plt.Axes, df: pd.DataFrame) -> None:
    maybe_warn_small_dataset(df, "p50 vs flow scatter")

    sizes = scale_series(df["avg_detect_pkt_flow"], 30.0, 260.0)
    ax.scatter(
        df["detecting_pkt_p50_us"],
        df["avg_flow_detecting_ms"],
        s=sizes,
        c=df["bucket"].map(BUCKET_COLORS),
        alpha=0.8,
        edgecolors="black",
        linewidths=0.4,
    )

    label_df = pd.concat(
        [
            df.nlargest(min(8, len(df)), "flows"),
            df.nlargest(min(5, len(df)), "avg_flow_detecting_ms"),
        ]
    ).drop_duplicates(subset=["proto_name"])
    add_text_labels(ax, label_df, "detecting_pkt_p50_us", "avg_flow_detecting_ms")

    if len(df) >= 2:
        reg = linregress(df["detecting_pkt_p50_us"], df["avg_flow_detecting_ms"])
        x_line = np.linspace(df["detecting_pkt_p50_us"].min(), df["detecting_pkt_p50_us"].max(), 200)
        ax.plot(x_line, reg.intercept + reg.slope * x_line, linestyle="--", color="0.5", linewidth=1.2)
        if len(df) >= 3:
            corr, p_value = pearsonr(df["detecting_pkt_p50_us"], df["avg_flow_detecting_ms"])
            stat_text = f"r = {corr:.3f}\np = {p_value:.3g}"
            if corr < 0:
                stat_text += "\n\nNegative correlation:\nhigh per-packet cost ≠\nhigh per-flow cost"
            ax.text(
                0.98,
                0.03,
                stat_text,
                transform=ax.transAxes,
                ha="right",
                va="bottom",
                fontsize=9,
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor="0.8"),
            )
        else:
            warn("p50 vs flow scatter: not enough points for Pearson correlation")
    else:
        warn("p50 vs flow scatter: not enough points for regression")

    ax.set_xlabel("Per-packet detection latency p50 (μs)")
    ax.set_ylabel("Avg. per-flow detection cost (ms)")
    ax.set_title("(c) Can per-packet latency predict per-flow cost?")
    ax.grid(True, linestyle=":", alpha=0.25)


def plot_breakdown(ax: plt.Axes, df: pd.DataFrame) -> None:
    filtered = df[df["avg_flow_post_ms"] <= POST_BREAKDOWN_MAX_MS].copy()
    if filtered.empty:
        warn(
            f"breakdown chart: no rows left after filtering avg_flow_post_ms <= {POST_BREAKDOWN_MAX_MS:.1f} ms; using all rows"
        )
        filtered = df.copy()
    elif len(filtered) < len(df):
        warn(
            f"breakdown chart: filtered {len(df) - len(filtered)} protocol(s) with avg_flow_post_ms > {POST_BREAKDOWN_MAX_MS:.1f} ms"
        )

    y = np.arange(len(filtered))
    detecting = filtered["avg_flow_detecting_ms"]
    post = filtered["avg_flow_post_ms"]
    total = filtered["avg_flow_total_ms"].replace(0, np.nan)
    percent = 100.0 * detecting / total

    ax.barh(y, detecting, color="#534AB7", label="Detection", edgecolor="black", linewidth=0.35)
    ax.barh(
        y,
        post,
        left=detecting,
        color="#AFA9EC",
        label="Post-detection",
        edgecolor="black",
        linewidth=0.35,
    )
    ax.set_yticks(y)
    ax.set_yticklabels(filtered["proto_name"], fontsize=PROTO_LABEL_SIZE)
    ax.invert_yaxis()
    ax.set_xlabel("Avg. per-flow processing time (ms)")
    ax.set_title("(d) Detection vs post-detection cost breakdown")
    ax.grid(True, axis="x", linestyle=":", alpha=0.25)
    ax.legend(loc="upper center", ncol=2, frameon=True)

    x_pad = float((detecting + post).max()) * 0.015 if len(filtered) else 0.01
    for yi, (end_x, pct) in enumerate(zip((detecting + post).to_numpy(), percent.to_numpy())):
        if np.isfinite(pct):
            ax.text(end_x + x_pad, yi, f"{pct:.0f}%", va="center", ha="left", fontsize=8, color="0.45")


def autopct_none(_pct: float) -> str:
    return ""


def plot_bucket_pies(fig: plt.Figure, spec, df: pd.DataFrame) -> tuple[plt.Axes, plt.Axes]:
    sub_gs = spec.subgridspec(1, 2, wspace=0.28)
    ax_left = fig.add_subplot(sub_gs[0, 0])
    ax_right = fig.add_subplot(sub_gs[0, 1])

    flow_totals = df.groupby("bucket")["flows"].sum().reindex(BUCKET_ORDER, fill_value=0.0)
    cost_totals = (
        (df["flows"] * df["avg_flow_detecting_ms"])
        .groupby(df["bucket"])
        .sum()
        .reindex(BUCKET_ORDER, fill_value=0.0)
    )

    flow_sum = flow_totals.sum()
    cost_sum = cost_totals.sum()
    colors = [BUCKET_COLORS[bucket] for bucket in BUCKET_ORDER]

    flow_labels = [
        f"{bucket}\n{(value / flow_sum * 100.0 if flow_sum else 0.0):.1f}%\n({format_flows(value)})"
        for bucket, value in flow_totals.items()
    ]
    cost_labels = [
        f"{bucket}\n{(value / cost_sum * 100.0 if cost_sum else 0.0):.1f}%\n({format_cost_share(value)})"
        for bucket, value in cost_totals.items()
    ]

    ax_left.pie(
        flow_totals.to_numpy(),
        labels=flow_labels,
        colors=colors,
        startangle=90,
        counterclock=False,
        labeldistance=1.08,
        wedgeprops=dict(linewidth=0.8, edgecolor="white"),
        textprops=dict(fontsize=9),
        autopct=autopct_none,
    )
    ax_left.set_title("Flow count distribution", fontsize=11)

    ax_right.pie(
        cost_totals.to_numpy(),
        labels=cost_labels,
        colors=colors,
        startangle=90,
        counterclock=False,
        labeldistance=1.08,
        wedgeprops=dict(linewidth=0.8, edgecolor="white"),
        textprops=dict(fontsize=9),
        autopct=autopct_none,
    )
    ax_right.set_title("Detection cost distribution", fontsize=11)

    flow_share = flow_totals / flow_sum if flow_sum else flow_totals * 0.0
    cost_share = cost_totals / cost_sum if cost_sum else cost_totals * 0.0
    asym = (cost_share - flow_share).sort_values(ascending=False)
    if not asym.empty and asym.iloc[0] > 0.05:
        bucket = asym.index[0]
        fig.text(
            0.5,
            (ax_left.get_position().y0 + ax_left.get_position().y1) / 2.0,
            f"{bucket} is cost-heavy:\n{cost_share[bucket] * 100:.1f}% cost vs {flow_share[bucket] * 100:.1f}% flows",
            ha="center",
            va="center",
            fontsize=9,
            color=BUCKET_COLORS[bucket],
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=BUCKET_COLORS[bucket], alpha=0.9),
        )

    title_y = max(ax_left.get_position().y1, ax_right.get_position().y1) + 0.02
    fig.text(0.5, title_y, "(e) Flow count vs detection cost by complexity bucket", ha="center", va="bottom", fontsize=12)
    return ax_left, ax_right


def build_figure(df: pd.DataFrame) -> plt.Figure:
    apply_common_style()
    fig = plt.figure(figsize=(12, 28), dpi=300)
    gs = GridSpec(5, 1, figure=fig, hspace=0.35)

    ax1 = fig.add_subplot(gs[0, 0])
    plot_complexity_scatter(ax1, df)

    plot_flow_vs_packet(fig, gs[1, 0], df)

    ax3 = fig.add_subplot(gs[2, 0])
    plot_packet_p50_vs_flow(ax3, df)

    ax4 = fig.add_subplot(gs[3, 0])
    plot_breakdown(ax4, df)

    plot_bucket_pies(fig, gs[4, 0], df)
    fig.tight_layout()
    return fig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a 5-panel PDF analysis for nDPI protocol profiling CSV output."
    )
    parser.add_argument("--input", required=True, help="Input profiling CSV file")
    parser.add_argument(
        "--output",
        default="protocol_profiling_analysis.pdf",
        help="Output PDF path (default: protocol_profiling_analysis.pdf)",
    )
    return parser.parse_args()


def main() -> int:
    warnings.filterwarnings("ignore", category=UserWarning, module="matplotlib")
    args = parse_args()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    if not input_path.exists():
        raise SystemExit(f"input csv not found: {input_path}")

    df = load_dataframe(input_path)
    if len(df) <= 4:
        warn("overall dataset is very small; some plots may be visually sparse")
    if not HAS_ADJUST_TEXT:
        warn("adjustText not available; falling back to fixed label offsets")

    fig = build_figure(df)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)

    print(f"Saved: {output_path}")
    print(f"Protocols plotted: {len(df)}")
    print(f"Sorted by: avg_flow_detecting_ms descending")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
