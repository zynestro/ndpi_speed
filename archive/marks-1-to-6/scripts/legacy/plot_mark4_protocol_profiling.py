#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D
from mpl_toolkits.axes_grid1.inset_locator import inset_axes

try:
    from adjustText import adjust_text
    HAS_ADJUST_TEXT = True
except Exception:
    HAS_ADJUST_TEXT = False


COLOR_MAP = {
    "Easy": "#2E8B57",
    "Medium": "#1F77B4",
    "Hard": "#C0392B",
}


def clean_text(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip().strip('"').strip("'").strip()


def to_float(value: str | None) -> float:
    try:
        return float(clean_text(value))
    except Exception:
        return float("nan")


def to_int(value: str | None) -> int:
    try:
        return int(float(clean_text(value)))
    except Exception:
        return 0


def read_csv_rows(csv_path: Path) -> list[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        rows = [row for row in reader if row and any(cell.strip() for cell in row)]

    if not rows:
        raise ValueError(f"empty csv: {csv_path}")

    header_idx = None
    for idx, row in enumerate(rows):
        first = clean_text(row[0]) if row else ""
        if first == "proto_name":
            header_idx = idx
            break

    if header_idx is None:
        raise ValueError(f"could not find proto_name header row in csv: {csv_path}")

    headers = [clean_text(h) for h in rows[header_idx]]
    out = []
    for raw in rows[header_idx + 1:]:
        if not raw:
            continue
        if clean_text(raw[0]).startswith("#"):
            continue
        padded = raw + [""] * max(0, len(headers) - len(raw))
        row = {headers[i]: clean_text(padded[i]) for i in range(len(headers))}
        out.append(row)
    return out


def assign_bucket(row: dict) -> str:
    avg_detect_pkt_flow = float(row["avg_detect_pkt_flow"])
    detecting_pkt_p50_us = float(row["detecting_pkt_p50_us"])

    if avg_detect_pkt_flow < 2 and detecting_pkt_p50_us < 2.0:
        return "Easy"
    if 2 <= avg_detect_pkt_flow <= 8 and detecting_pkt_p50_us < 1.0:
        return "Medium"
    return "Hard"


def preprocess_rows(rows: list[dict]) -> list[dict]:
    numeric_fields = [
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

    cleaned = []
    for row in rows:
        parsed = dict(row)
        for field in numeric_fields:
            if field == "flows":
                parsed[field] = to_int(row.get(field))
            else:
                parsed[field] = to_float(row.get(field))
        if parsed["flows"] < 10:
            continue
        parsed["proto_name"] = clean_text(parsed.get("proto_name", ""))
        parsed["category_name"] = clean_text(parsed.get("category_name", ""))
        parsed["bucket"] = assign_bucket(parsed)
        cleaned.append(parsed)

    if not cleaned:
        raise ValueError("no rows left after filtering flows >= 10")
    return cleaned


def weighted_avg(rows: list[dict], value_key: str) -> float:
    total_weight = sum(r["flows"] for r in rows)
    if total_weight <= 0:
        return 0.0
    return sum(r["flows"] * r[value_key] for r in rows) / total_weight


def build_scatter(ax, rows: list[dict]) -> None:
    for bucket in ["Easy", "Medium", "Hard"]:
        bucket_rows = [r for r in rows if r["bucket"] == bucket]
        if not bucket_rows:
            continue
        xs = [r["avg_detect_pkt_flow"] for r in bucket_rows]
        ys = [r["detecting_pkt_p50_us"] for r in bucket_rows]
        sizes = [130.0 * math.log10(max(r["flows"], 1)) ** 1.6 for r in bucket_rows]
        ax.scatter(
            xs,
            ys,
            s=sizes,
            c=COLOR_MAP[bucket],
            alpha=0.75,
            edgecolors="black",
            linewidths=0.45,
            label=bucket,
        )

    ax.axvline(2, color="0.55", linestyle="--", linewidth=1.0)
    ax.axvline(8, color="0.82", linestyle="--", linewidth=0.9)
    ax.axhline(1.0, color="0.55", linestyle="--", linewidth=1.0)
    ax.axhline(2.0, color="0.82", linestyle="--", linewidth=0.9)
    ax.axvspan(0.8, 2, color=COLOR_MAP["Easy"], alpha=0.05)
    ax.axvspan(2, 8, color=COLOR_MAP["Medium"], alpha=0.05)
    ax.axvspan(8, max(r["avg_detect_pkt_flow"] for r in rows) * 1.15, color=COLOR_MAP["Hard"], alpha=0.04)

    top15 = sorted(rows, key=lambda r: r["flows"], reverse=True)[:15]
    texts = []
    for row in top15:
        texts.append(
            ax.text(
                row["avg_detect_pkt_flow"],
                row["detecting_pkt_p50_us"],
                row["proto_name"],
                fontsize=8,
                color="black",
            )
        )
    if HAS_ADJUST_TEXT and texts:
        adjust_text(
            texts,
            ax=ax,
            arrowprops=dict(arrowstyle="-", color="0.45", lw=0.5),
            expand_points=(1.15, 1.15),
            expand_text=(1.1, 1.2),
        )

    ax.set_xscale("log")
    ax.set_xlabel("Avg. Packets per Flow (Detection Phase)")
    ax.set_ylabel("Per-Packet Detection Latency (μs, p50)")
    ax.set_title("(a) Protocol Complexity Landscape")
    ax.grid(True, which="both", alpha=0.25, linestyle=":")
    ax.legend(loc="upper right", frameon=True, fontsize=9)


def build_top20_bar(ax, rows: list[dict]) -> None:
    top20 = sorted(rows, key=lambda r: r["avg_flow_detecting_ms"], reverse=True)[:20]
    labels = [r["proto_name"] for r in reversed(top20)]
    values = [r["avg_flow_detecting_ms"] for r in reversed(top20)]
    colors = [COLOR_MAP[r["bucket"]] for r in reversed(top20)]

    ax.barh(labels, values, color=colors, edgecolor="black", linewidth=0.4)
    ax.set_xlabel("Avg. Flow Detection Cost (ms)")
    ax.set_title("(b) Per-Flow Detection Cost (Top 20)")
    ax.grid(True, axis="x", alpha=0.25, linestyle=":")


def build_grouped_latency(ax, rows: list[dict]) -> None:
    buckets = ["Easy", "Medium", "Hard"]
    p50_vals = []
    p99_vals = []

    for bucket in buckets:
        bucket_rows = [r for r in rows if r["bucket"] == bucket]
        p50_vals.append(weighted_avg(bucket_rows, "detecting_pkt_p50_us"))
        p99_vals.append(weighted_avg(bucket_rows, "detecting_pkt_p99_us"))

    x = np.arange(len(buckets))
    width = 0.34
    ax.bar(x - width / 2, p50_vals, width, label="p50", color="#5DA5DA", edgecolor="black", linewidth=0.5)
    ax.bar(x + width / 2, p99_vals, width, label="p99", color="#F15854", edgecolor="black", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(buckets)
    ax.set_ylabel("Per-Packet Latency (μs)")
    ax.set_title("(c) Latency Distribution by Complexity Bucket")
    ax.grid(True, axis="y", alpha=0.25, linestyle=":")
    ax.legend(loc="upper left", frameon=True, fontsize=9)


def build_dual_pie(ax, rows: list[dict]) -> None:
    ax.set_title("(d) Flow Count vs. Detection Cost Share")
    ax.axis("off")

    buckets = ["Easy", "Medium", "Hard"]
    flow_share = []
    cost_share = []
    for bucket in buckets:
        bucket_rows = [r for r in rows if r["bucket"] == bucket]
        flow_share.append(sum(r["flows"] for r in bucket_rows))
        cost_share.append(sum(r["flows"] * r["avg_flow_detecting_ms"] for r in bucket_rows))

    colors = [COLOR_MAP[b] for b in buckets]

    left_ax = inset_axes(ax, width="47%", height="78%", loc="center left", borderpad=1.2)
    right_ax = inset_axes(ax, width="47%", height="78%", loc="center right", borderpad=1.2)

    left_ax.pie(
        flow_share,
        labels=buckets,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        textprops={"fontsize": 8},
    )
    left_ax.set_title("Flow Share", fontsize=10)

    right_ax.pie(
        cost_share,
        labels=buckets,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        textprops={"fontsize": 8},
    )
    right_ax.set_title("Detection Cost Share", fontsize=10)


def make_figure(rows: list[dict], out_path: Path) -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })

    fig, axes = plt.subplots(2, 2, figsize=(14, 10), dpi=300)

    build_scatter(axes[0, 0], rows)
    build_top20_bar(axes[0, 1], rows)
    build_grouped_latency(axes[1, 0], rows)
    build_dual_pie(axes[1, 1], rows)

    proxy_handles = [
        Line2D([0], [0], marker="o", color="w", label=b, markerfacecolor=COLOR_MAP[b],
               markeredgecolor="black", markersize=8)
        for b in ["Easy", "Medium", "Hard"]
    ]
    fig.legend(proxy_handles, ["Easy", "Medium", "Hard"], loc="upper right", frameon=True, bbox_to_anchor=(0.98, 0.98))

    fig.tight_layout()
    fig.subplots_adjust(wspace=0.27, hspace=0.28)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, format="pdf", dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a 2x2 protocol profiling figure for mark4 CSV output."
    )
    parser.add_argument("-csv", help="Path to proto_category_summary.csv")
    parser.add_argument(
        "-o",
        "--output",
        default="protocol_profiling_analysis.pdf",
        help="Output PDF path",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    out_path = Path(args.output).resolve()
    rows = preprocess_rows(read_csv_rows(csv_path))
    make_figure(rows, out_path)
    print(f"Saved: {out_path}")
    if not HAS_ADJUST_TEXT:
        print("Note: adjustText not installed; labels were placed without collision optimization.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
