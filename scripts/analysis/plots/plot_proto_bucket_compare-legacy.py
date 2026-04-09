#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch


BUCKETS = {
    "Easy": [
        "DNS",
        "NTP",
        "MDNS",
        "DHCP",
    ],
    "Mid": [
        "HTTP",
        "HTTP_Proxy",
        "MySQL",
        "MessagePack",
        "JSON",
    ],
    "Hard": [
        "TLS",
        "TLS.Mozilla",
        "TLS.Canonical",
        "SSH",
        "HTTP_Connect",
        "HTTP_Connect.Microsoft365",
        "HTTP_Connect.Github",
        "HTTP_Connect.Azure",
    ],
}

BUCKET_COLORS = {
    "Easy": "#2ca02c",
    "Mid": "#1f77b4",
    "Hard": "#d62728",
}


def load_aggregated_proto_metrics(csv_path: Path) -> dict[str, dict[str, float]]:
    sums = defaultdict(lambda: {"flows": 0.0, "lat_sum": 0.0, "pkt_sum": 0.0})

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        required = {"proto_name", "flows", "avg_detect_latency_ms", "avg_detect_pkt_flow"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"missing required columns: {', '.join(sorted(missing))}")

        for row in reader:
            proto = (row.get("proto_name") or "").strip().strip('"')
            if not proto:
                continue
            flows = float(row.get("flows") or 0.0)
            latency = float(row.get("avg_detect_latency_ms") or 0.0)
            pkt_flow = float(row.get("avg_detect_pkt_flow") or 0.0)
            sums[proto]["flows"] += flows
            sums[proto]["lat_sum"] += latency * flows
            sums[proto]["pkt_sum"] += pkt_flow * flows

    out: dict[str, dict[str, float]] = {}
    for proto, v in sums.items():
        flows = v["flows"]
        if flows <= 0:
            continue
        out[proto] = {
            "flows": flows,
            "avg_detect_latency_ms": v["lat_sum"] / flows,
            "avg_detect_pkt_flow": v["pkt_sum"] / flows,
        }
    return out


def build_ordered_rows(agg: dict[str, dict[str, float]]) -> tuple[list[dict], list[int]]:
    rows: list[dict] = []
    boundaries: list[int] = []

    for bucket, protos in BUCKETS.items():
        for proto in protos:
            if proto not in agg:
                continue
            rows.append(
                {
                    "proto_name": proto,
                    "bucket": bucket,
                    "color": BUCKET_COLORS[bucket],
                    "avg_detect_latency_ms": agg[proto]["avg_detect_latency_ms"],
                    "avg_detect_pkt_flow": agg[proto]["avg_detect_pkt_flow"],
                }
            )
        boundaries.append(len(rows))

    if not rows:
        raise ValueError("no protocol rows after filtering with bucket definitions")
    return rows, boundaries


def plot_two_bar_charts(rows: list[dict], boundaries: list[int], out_path: Path) -> None:
    x = list(range(len(rows)))
    labels = [r["proto_name"] for r in rows]
    colors = [r["color"] for r in rows]
    latency = [r["avg_detect_latency_ms"] for r in rows]
    pkt_flow = [r["avg_detect_pkt_flow"] for r in rows]

    plt.rcdefaults()
    fig, axes = plt.subplots(1, 2, figsize=(22, 8), sharex=True)
    fig.suptitle("nDPI Protocol Detection Performance by Difficulty Bucket", fontsize=13)

    charts = [
        (axes[0], latency, "avg_detect_latency_ms", "Latency (ms)"),
        (axes[1], pkt_flow, "avg_detect_pkt_flow", "Packets / Flow"),
    ]

    for ax, values, title, ylabel in charts:
        ax.bar(x, values, color=colors, edgecolor="black", linewidth=0.4)
        ax.set_title(title)
        ax.set_xlabel("Protocol")
        ax.set_ylabel(ylabel)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=35, ha="right")
        ax.grid(True, axis="y", linestyle="--", alpha=0.35)

        for b in boundaries[:-1]:
            ax.axvline(b - 0.5, color="#444444", linestyle=":", linewidth=1.0, alpha=0.6)

    legend_items = [Patch(facecolor=BUCKET_COLORS[k], edgecolor="black", label=k) for k in ["Easy", "Mid", "Hard"]]
    fig.legend(handles=legend_items, loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 0.985))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout(rect=[0, 0.02, 1, 0.93])
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plot avg_detect_latency_ms and avg_detect_pkt_flow by protocol with Easy/Mid/Hard bucket colors."
    )
    parser.add_argument(
        "--csv",
        required=True,
        help="Path to proto_category_summary.csv",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Output PNG path (default: <csv_dir>/proto_bucket_perf_compare.png)",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    out_path = Path(args.out).resolve() if args.out else (csv_path.parent / "proto_bucket_perf_compare.png")

    agg = load_aggregated_proto_metrics(csv_path)
    rows, boundaries = build_ordered_rows(agg)
    plot_two_bar_charts(rows, boundaries, out_path)
    print(f"Saved: {out_path}")
    print(f"Protocols plotted: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
