#!/usr/bin/env python3
"""Generate paper Figure 1 from a time-only mark5 batch.

The script reads a batch ``manifest.json``, loads each successful P/E
``time_flow_profile.csv``, folds dotted protocol names into their parent
protocol, and aggregates from flow rows.  Aggregating from flow rows avoids
giving small pcaps the same weight as large pcaps.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


TIME_FLOW_CSV = "time_flow_profile.csv"
CORE_KEYS = {"P": "p_time", "E": "e_time"}
DEFAULT_METRICS = [
    "detect_pkt_in_flow",
    "detecting_total_ms",
    "detecting_detection_only_ms",
    "detecting_flow_table_ms",
    "detecting_other_ms",
    "post_total_ms",
    "post_detection_only_ms",
    "post_flow_table_ms",
    "post_other_ms",
    "detecting_bytes",
    "packets_in_flow",
    "bytes_in_flow",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build parent-protocol P/E detecting-cost Figure 1 from a mark5 time-only batch."
    )
    parser.add_argument("--manifest", required=True, help="Path to batch manifest.json")
    parser.add_argument("--output-dir", default=None, help="Output directory; default: <batch_dir>/figure1_time")
    parser.add_argument("--max-protocols", type=int, default=15, help="If exceeded, keep low/high edges only")
    parser.add_argument("--edge-count", type=int, default=6, help="Protocols kept from each edge when truncating")
    parser.add_argument("--ratio-line", type=float, default=0.0, help="Horizontal reference line in subplot b; <=0 uses the mean speedup")
    parser.add_argument("--include-not-detected", action="store_true", help="Keep NOT_DETECTED rows")
    parser.add_argument("--top-error", choices=["sem", "std", "none"], default="std", help="Error bar on stacked totals")
    return parser.parse_args()


def protocol_parent(protocol: str) -> str:
    protocol = str(protocol).strip()
    if "." in protocol:
        return protocol.split(".", 1)[0]
    return protocol


def strip_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out.columns = [str(col).strip() for col in out.columns]
    for col in out.columns:
        if out[col].dtype == object or pd.api.types.is_string_dtype(out[col]):
            out[col] = out[col].astype(str).str.strip()
    return out


def load_flow_csv(path: Path, core_label: str, pcap_name: str) -> pd.DataFrame:
    df = strip_dataframe(pd.read_csv(path, dtype=str))
    if "protocol" not in df.columns:
        raise ValueError(f"Missing protocol column: {path}")
    df["protocol_parent"] = df["protocol"].map(protocol_parent)
    df["core_label"] = core_label
    df["pcap_name"] = pcap_name
    for col in DEFAULT_METRICS + ["protocol_detected", "master_proto", "app_proto", "category_id"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    return df


def collect_flows(manifest: dict) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    missing: list[str] = []
    for entry in manifest.get("pcaps", []):
        pcap_name = entry.get("name", "unknown")
        runs = entry.get("runs", {})
        for core_label, key in CORE_KEYS.items():
            run = runs.get(key)
            if not run or run.get("status") != "success" or not run.get("output_dir"):
                missing.append(f"{pcap_name}:{key}")
                continue
            csv_path = Path(run["output_dir"]) / TIME_FLOW_CSV
            if not csv_path.exists():
                missing.append(f"{pcap_name}:{key}:{csv_path}")
                continue
            frames.append(load_flow_csv(csv_path, core_label, pcap_name))
    if not frames:
        raise RuntimeError("No successful P/E time_flow_profile.csv files found in manifest.")
    flows = pd.concat(frames, ignore_index=True)
    flows.attrs["missing_runs"] = missing
    return flows


def collect_parent_summary_streaming(manifest: dict, include_not_detected: bool) -> tuple[pd.DataFrame, int, list[str]]:
    groups: dict[tuple[str, str], dict] = {}
    missing: list[str] = []
    total_rows = 0

    metric_cols = DEFAULT_METRICS

    for entry in manifest.get("pcaps", []):
        pcap_name = entry.get("name", "unknown")
        runs = entry.get("runs", {})
        for core_label, key in CORE_KEYS.items():
            run = runs.get(key)
            if not run or run.get("status") != "success" or not run.get("output_dir"):
                missing.append(f"{pcap_name}:{key}")
                continue
            csv_path = Path(run["output_dir"]) / TIME_FLOW_CSV
            if not csv_path.exists():
                missing.append(f"{pcap_name}:{key}:{csv_path}")
                continue

            with csv_path.open(newline="") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames or "protocol" not in reader.fieldnames:
                    raise ValueError(f"Missing protocol column: {csv_path}")
                for row in reader:
                    total_rows += 1
                    protocol = str(row.get("protocol", "")).strip()
                    parent = protocol_parent(protocol)
                    detected = int(float(str(row.get("protocol_detected", "1")).strip() or 0))
                    if not include_not_detected and (parent == "NOT_DETECTED" or detected != 1):
                        continue

                    gkey = (core_label, parent)
                    group = groups.get(gkey)
                    if group is None:
                        group = {
                            "core_label": core_label,
                            "protocol": parent,
                            "protocol_detected": 0,
                            "master_proto_values": set(),
                            "app_proto_values": set(),
                            "category_id_values": set(),
                            "category_name": "MIXED",
                            "flows": 0,
                            "source_protocols": set(),
                            "pcaps": set(),
                            "sum": defaultdict(float),
                            "sumsq": defaultdict(float),
                        }
                        groups[gkey] = group

                    group["flows"] += 1
                    group["protocol_detected"] = max(group["protocol_detected"], detected)
                    group["source_protocols"].add(protocol)
                    group["pcaps"].add(pcap_name)
                    cat_name = str(row.get("category_name", "")).strip()
                    if cat_name and group["category_name"] == "MIXED":
                        group["category_name"] = cat_name

                    for source_col, target_set in (
                        ("master_proto", group["master_proto_values"]),
                        ("app_proto", group["app_proto_values"]),
                        ("category_id", group["category_id_values"]),
                    ):
                        value = str(row.get(source_col, "")).strip()
                        if value:
                            try:
                                target_set.add(int(float(value)))
                            except ValueError:
                                pass

                    for col in metric_cols:
                        try:
                            value = float(str(row.get(col, "0")).strip() or 0.0)
                        except ValueError:
                            value = 0.0
                        group["sum"][col] += value
                        group["sumsq"][col] += value * value

    rows = []
    for group in groups.values():
        flows = int(group["flows"])
        row = {
            "core_label": group["core_label"],
            "protocol": group["protocol"],
            "protocol_detected": group["protocol_detected"],
            "master_proto": next(iter(group["master_proto_values"])) if len(group["master_proto_values"]) == 1 else -1,
            "app_proto": next(iter(group["app_proto_values"])) if len(group["app_proto_values"]) == 1 else -1,
            "category_name": group["category_name"],
            "category_id": next(iter(group["category_id_values"])) if len(group["category_id_values"]) == 1 else -1,
            "flows": flows,
            "source_protocols": "|".join(sorted(group["source_protocols"])),
            "pcaps": "|".join(sorted(group["pcaps"])),
        }
        for col in metric_cols:
            avg = group["sum"][col] / flows if flows else 0.0
            var = group["sumsq"][col] / flows - avg * avg if flows else 0.0
            row[f"avg_{col}"] = avg
            row[f"var_{col}"] = max(0.0, var)
        row["avg_detecting_non_detection_ms"] = max(
            0.0,
            row.get("avg_detecting_total_ms", 0.0) - row.get("avg_detecting_detection_only_ms", 0.0),
        )
        rows.append(row)

    if not rows:
        raise RuntimeError("No flow rows remain after filtering.")

    summary = pd.DataFrame(rows)
    summary = summary.sort_values(["core_label", "avg_detecting_total_ms"], ascending=[True, False]).reset_index(drop=True)
    return summary, total_rows, missing


def variance(series: pd.Series) -> float:
    values = pd.to_numeric(series, errors="coerce").dropna()
    return float(values.var(ddof=0)) if len(values) else 0.0


def first_nonempty(series: pd.Series, default: str) -> str:
    for value in series:
        if pd.notna(value) and str(value).strip():
            return str(value).strip()
    return default


def aggregate_parent_protocols(flows: pd.DataFrame, include_not_detected: bool) -> pd.DataFrame:
    df = flows.copy()
    if not include_not_detected:
        df = df[(df["protocol_parent"] != "NOT_DETECTED") & (df.get("protocol_detected", 1) == 1)].copy()
    if df.empty:
        raise RuntimeError("No flow rows remain after filtering.")

    metric_cols = [col for col in DEFAULT_METRICS if col in df.columns]
    rows = []
    for (core_label, protocol), group in df.groupby(["core_label", "protocol_parent"], sort=False):
        row = {
            "core_label": core_label,
            "protocol": protocol,
            "protocol_detected": int(group.get("protocol_detected", pd.Series([1])).max()),
            "master_proto": -1,
            "app_proto": -1,
            "category_name": first_nonempty(group.get("category_name", pd.Series(dtype=str)), "MIXED"),
            "category_id": -1,
            "flows": int(len(group)),
            "source_protocols": "|".join(sorted(set(group["protocol"].astype(str)))),
            "pcaps": "|".join(sorted(set(group["pcap_name"].astype(str)))),
        }
        for col in ("master_proto", "app_proto", "category_id"):
            if col in group.columns:
                unique = sorted(set(int(v) for v in pd.to_numeric(group[col], errors="coerce").dropna()))
                row[col] = unique[0] if len(unique) == 1 else -1
        for col in metric_cols:
            values = pd.to_numeric(group[col], errors="coerce").fillna(0)
            row[f"avg_{col}"] = float(values.mean())
            row[f"var_{col}"] = variance(values)
        row["avg_detecting_non_detection_ms"] = max(
            0.0,
            row.get("avg_detecting_total_ms", 0.0) - row.get("avg_detecting_detection_only_ms", 0.0),
        )
        rows.append(row)

    out = pd.DataFrame(rows)
    return out.sort_values(["core_label", "avg_detecting_total_ms"], ascending=[True, False]).reset_index(drop=True)


def build_plot_table(summary: pd.DataFrame, max_protocols: int, edge_count: int) -> pd.DataFrame:
    p = summary[summary["core_label"] == "P"].set_index("protocol")
    e = summary[summary["core_label"] == "E"].set_index("protocol")
    protocols = sorted(set(p.index) & set(e.index))
    if not protocols:
        raise RuntimeError("No parent protocols are present in both P and E summaries.")

    rows = []
    for protocol in protocols:
        p_row = p.loc[protocol]
        e_row = e.loc[protocol]
        p_total = float(p_row["avg_detecting_total_ms"])
        e_total = float(e_row["avg_detecting_total_ms"])
        p_det = float(p_row["avg_detecting_detection_only_ms"])
        e_det = float(e_row["avg_detecting_detection_only_ms"])
        rows.append(
            {
                "protocol": protocol,
                "sort_cost_ms": (p_total + e_total) / 2.0,
                "p_flows": int(p_row["flows"]),
                "e_flows": int(e_row["flows"]),
                "p_total_ms": p_total,
                "e_total_ms": e_total,
                "p_detection_only_ms": p_det,
                "e_detection_only_ms": e_det,
                "p_other_ms": max(0.0, p_total - p_det),
                "e_other_ms": max(0.0, e_total - e_det),
                "p_total_sem_ms": math.sqrt(max(float(p_row.get("var_detecting_total_ms", 0.0)), 0.0) / max(int(p_row["flows"]), 1)),
                "e_total_sem_ms": math.sqrt(max(float(e_row.get("var_detecting_total_ms", 0.0)), 0.0) / max(int(e_row["flows"]), 1)),
                "p_total_std_ms": math.sqrt(max(float(p_row.get("var_detecting_total_ms", 0.0)), 0.0)),
                "e_total_std_ms": math.sqrt(max(float(e_row.get("var_detecting_total_ms", 0.0)), 0.0)),
                "slow_over_fast_total": e_total / p_total if p_total > 0 else np.nan,
            }
        )

    out = pd.DataFrame(rows).sort_values("sort_cost_ms", ascending=True).reset_index(drop=True)
    out["selected_for_plot"] = True
    if len(out) > max_protocols:
        edge_count = max(1, min(edge_count, max_protocols // 2))
        keep_idx = set(out.head(edge_count).index) | set(out.tail(edge_count).index)
        out["selected_for_plot"] = out.index.isin(keep_idx)
    return out


def configure_style() -> None:
    plt.style.use("seaborn-v0_8-whitegrid")
    plt.rcParams.update(
        {
            "figure.dpi": 160,
            "savefig.dpi": 300,
            "font.size": 9,
            "axes.labelsize": 9,
            "axes.titlesize": 10,
            "axes.titleweight": "semibold",
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.fontsize": 8,
            "axes.edgecolor": "#3E4651",
            "axes.linewidth": 0.8,
            "grid.color": "#D5DAE2",
            "grid.linestyle": "--",
            "grid.linewidth": 0.5,
        }
    )


def selected_with_gap(plot_df: pd.DataFrame) -> pd.DataFrame:
    selected = plot_df[plot_df["selected_for_plot"]].copy()
    if len(selected) == len(plot_df):
        return selected.reset_index(drop=True)

    low = selected[selected.index < plot_df.index.max() / 2.0]
    high = selected[selected.index >= plot_df.index.max() / 2.0]
    gap = {col: np.nan for col in selected.columns}
    gap["protocol"] = "..."
    gap["selected_for_plot"] = True
    return pd.concat([low, pd.DataFrame([gap]), high], ignore_index=True)


def plot_figure(plot_df: pd.DataFrame, output_base: Path, ratio_line: float, error_kind: str) -> None:
    configure_style()
    shown = selected_with_gap(plot_df)
    labels = shown["protocol"].tolist()
    x = np.arange(len(shown))
    width = 0.36

    p_color = "#2F6DAE"
    e_color = "#C76E2A"
    p_light = "#9DBFE2"
    e_light = "#E7B486"

    fig, axes = plt.subplots(
        2,
        1,
        figsize=(7.2, 5.2),
        sharex=True,
        constrained_layout=True,
        gridspec_kw={"height_ratios": [1.35, 1.0], "hspace": 0.08},
    )
    ax = axes[0]
    valid = shown["protocol"] != "..."

    ax.bar(x[valid] - width / 2, shown.loc[valid, "p_detection_only_ms"], width, color=p_color, label="P detection-only")
    ax.bar(
        x[valid] - width / 2,
        shown.loc[valid, "p_other_ms"],
        width,
        bottom=shown.loc[valid, "p_detection_only_ms"],
        color=p_light,
        label="P other",
    )
    ax.bar(x[valid] + width / 2, shown.loc[valid, "e_detection_only_ms"], width, color=e_color, label="E detection-only")
    ax.bar(
        x[valid] + width / 2,
        shown.loc[valid, "e_other_ms"],
        width,
        bottom=shown.loc[valid, "e_detection_only_ms"],
        color=e_light,
        label="E other",
    )

    if error_kind != "none":
        suffix = "sem_ms" if error_kind == "sem" else "std_ms"
        ax.errorbar(
            x[valid] - width / 2,
            shown.loc[valid, "p_total_ms"],
            yerr=shown.loc[valid, f"p_total_{suffix}"],
            fmt="none",
            ecolor="#27313C",
            elinewidth=0.7,
            capsize=2,
        )
        ax.errorbar(
            x[valid] + width / 2,
            shown.loc[valid, "e_total_ms"],
            yerr=shown.loc[valid, f"e_total_{suffix}"],
            fmt="none",
            ecolor="#27313C",
            elinewidth=0.7,
            capsize=2,
        )

    ax.set_ylabel("Detecting cost (ms)")
    ax.set_title("(a) Per-protocol detecting cost")
    ax.legend(ncol=2, frameon=False, loc="upper left")
    ax.grid(axis="x", visible=False)

    ax = axes[1]
    speedups = shown.loc[valid, "slow_over_fast_total"]
    mean_ratio = float(pd.to_numeric(speedups, errors="coerce").dropna().mean()) if ratio_line <= 0.0 else ratio_line
    ax.bar(x[valid], speedups, width=0.58, color="#5D6470")
    if math.isfinite(mean_ratio) and mean_ratio > 0.0:
        ax.axhline(mean_ratio, color="#B23A48", linestyle="--", linewidth=1.0, label=f"mean {mean_ratio:.2f}x")
    ax.set_ylabel("Slow / fast ratio")
    ax.set_title("(b) P/E ratio per protocol")
    ax.legend(frameon=False, loc="upper left")
    ax.grid(axis="x", visible=False)
    ax.set_xticks(x, labels)
    ax.tick_params(axis="x", rotation=35)
    for tick in ax.get_xticklabels():
        tick.set_horizontalalignment("right")

    fig.savefig(output_base.with_suffix(".png"))
    fig.savefig(output_base.with_suffix(".pdf"))
    plt.close(fig)


def main() -> None:
    args = parse_args()
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text())
    batch_dir = Path(manifest.get("batch_dir", manifest_path.parent))
    output_dir = Path(args.output_dir) if args.output_dir else batch_dir / "figure1_time"
    output_dir.mkdir(parents=True, exist_ok=True)

    summary, flow_rows, missing_runs = collect_parent_summary_streaming(
        manifest,
        include_not_detected=args.include_not_detected,
    )
    plot_table = build_plot_table(summary, max_protocols=args.max_protocols, edge_count=args.edge_count)

    summary.to_csv(output_dir / "time_protocol_parent_summary_by_core.csv", index=False)
    for core_label in ("P", "E"):
        summary[summary["core_label"] == core_label].drop(columns=["core_label"]).to_csv(
            output_dir / f"{core_label.lower()}_time_protocol_parent_summary.csv",
            index=False,
        )
    plot_table.to_csv(output_dir / "figure1_protocol_table.csv", index=False)
    plot_figure(plot_table, output_dir / "figure1_protocol_detecting_cost", args.ratio_line, args.top_error)

    report = {
        "manifest": str(manifest_path),
        "output_dir": str(output_dir),
        "flow_rows": int(flow_rows),
        "parent_protocol_rows": int(len(summary)),
        "protocols_in_both_cores": int(len(plot_table)),
        "selected_protocols": plot_table.loc[plot_table["selected_for_plot"], "protocol"].tolist(),
        "missing_runs": missing_runs,
        "parent_protocol_rule": "protocol.split('.', 1)[0]",
        "aggregation": "streaming CSV aggregation by core_label and parent protocol",
        "figure_png": str(output_dir / "figure1_protocol_detecting_cost.png"),
        "figure_pdf": str(output_dir / "figure1_protocol_detecting_cost.pdf"),
    }
    (output_dir / "figure1_summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    print(f"Saved time-only Figure 1 outputs to: {output_dir}")


if __name__ == "__main__":
    main()
