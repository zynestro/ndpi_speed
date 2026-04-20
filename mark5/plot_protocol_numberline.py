#!/usr/bin/env python3
"""为协议画像 CSV 画一维数轴分布图。

输入通常是 ``protocol_profile_averaged.csv``，默认关心：

- ``profile_avg_detecting_flow_table_ms``

图形形式是“一条横向数轴 + 每个协议一个点 + 轻微纵向避让”，
适合观察某一列在协议集合上的整体分布、稠密区和离群点。
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


DEFAULT_COLUMN = "profile_avg_detecting_detection_only_ms"
FIXED_FAMILY_COLORS = {
    "TLS": "#355C7D",
    "HTTP": "#F18F01",
    "QUIC": "#5C8001",
    "DNS": "#7B2CBF",
    "SSH": "#C44900",
    "Kerberos": "#2A9D8F",
    "LDAP": "#6C757D",
    "FTP_CONTROL": "#B56576",
}


def default_output_name(value_col: str) -> str:
    """根据列名生成稳定、可读且不含空格的默认文件名。"""
    suffix = value_col
    if suffix.startswith("profile_"):
        suffix = suffix[len("profile_"):]
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", suffix).strip("_")
    if not suffix:
        suffix = "value"
    return f"protocol_numberline_{suffix}.png"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Plot a one-dimensional number-line distribution from protocol_profile_averaged.csv"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input CSV path, e.g. protocol_profile_averaged.csv",
    )
    parser.add_argument(
        "--column",
        default=DEFAULT_COLUMN,
        help=f"Numeric column to visualize (default: {DEFAULT_COLUMN})",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output PNG path (default: derived from the selected column under <input_dir>/)",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=8,
        help="Annotate the top N largest values",
    )
    parser.add_argument(
        "--min-flows",
        type=int,
        default=0,
        help="Keep only protocols with profile_flows >= this threshold",
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Custom plot title",
    )
    return parser.parse_args()


def strip_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(col).strip() for col in df.columns]
    for col in df.columns:
        if pd.api.types.is_string_dtype(df[col]) or df[col].dtype == object:
            df[col] = df[col].astype(str).str.strip()
    return df


def load_profile_csv(csv_path: Path, value_col: str, min_flows: int) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {csv_path}")

    df = pd.read_csv(csv_path, dtype=str)
    df = strip_dataframe(df)

    required_cols = {"protocol", value_col}
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        raise KeyError(f"Missing required columns: {missing}")

    if "profile_flows" in df.columns:
        df["profile_flows"] = pd.to_numeric(df["profile_flows"], errors="coerce")
    else:
        df["profile_flows"] = np.nan

    df[value_col] = pd.to_numeric(df[value_col], errors="coerce")
    if "protocol_label" not in df.columns:
        df["protocol_label"] = df["protocol"]
    if "family" not in df.columns:
        df["family"] = "Unknown"

    df = df[df[value_col].notna()].copy()
    if min_flows > 0:
        df = df[df["profile_flows"].fillna(0) >= min_flows].copy()
    if df.empty:
        raise ValueError("No rows remain after filtering; nothing to plot.")

    df.sort_values(by=value_col, inplace=True, kind="mergesort")
    df.reset_index(drop=True, inplace=True)
    return df


def configure_style():
    plt.style.use("seaborn-v0_8-whitegrid")
    plt.rcParams.update({
        "figure.dpi": 160,
        "savefig.dpi": 220,
        "font.size": 10,
        "axes.labelsize": 11,
        "axes.titlesize": 12,
        "axes.titleweight": "semibold",
        "grid.color": "#D7DCE5",
        "grid.linestyle": "--",
        "grid.linewidth": 0.6,
        "axes.edgecolor": "#444A57",
        "axes.linewidth": 0.8,
    })


def build_palette(families: list[str]) -> dict[str, tuple[float, float, float, float]]:
    unique = list(dict.fromkeys(families))
    palette = {}
    dynamic = [family for family in unique if family not in FIXED_FAMILY_COLORS]
    cmap = plt.get_cmap("tab20")
    for family, color in FIXED_FAMILY_COLORS.items():
        if family in unique:
            palette[family] = color
    for idx, family in enumerate(dynamic):
        palette[family] = cmap(idx % 20)
    return palette


def compute_swarm_offsets(values: np.ndarray) -> np.ndarray:
    """给一维数轴上的点一个稳定的小幅纵向避让。

    做法不是完整 beeswarm，而是按 x 方向最小间隔做简单堆叠。
    目标是让密集点别完全重叠，同时保持图还是“以数轴为主”。
    """
    n = len(values)
    if n == 0:
        return np.array([], dtype=float)
    if n == 1:
        return np.array([0.0], dtype=float)

    span = float(values.max() - values.min())
    proximity = span * 0.025 if span > 0 else max(abs(float(values[0])) * 0.05, 1e-6)

    offsets = np.zeros(n, dtype=float)
    levels = [0.0, 0.08, -0.08, 0.16, -0.16, 0.24, -0.24, 0.32, -0.32]
    recent: list[tuple[float, float]] = []

    for i, x in enumerate(values):
        recent = [(rx, ry) for rx, ry in recent if abs(x - rx) <= proximity]
        used = {round(ry, 4) for _, ry in recent}
        y = 0.0
        for candidate in levels:
            if round(candidate, 4) not in used:
                y = candidate
                break
        offsets[i] = y
        recent.append((float(x), float(y)))

    return offsets


def annotate_top_points(ax, df: pd.DataFrame, value_col: str, offsets: np.ndarray, top_n: int):
    if top_n <= 0:
        return
    top = df.nlargest(top_n, value_col)
    for idx in top.index:
        row = df.loc[idx]
        ax.annotate(
            str(row["protocol_label"]),
            xy=(row[value_col], offsets[idx]),
            xytext=(6, 8 if offsets[idx] <= 0 else -12),
            textcoords="offset points",
            fontsize=8,
            color="#243447",
            arrowprops={
                "arrowstyle": "-",
                "color": "#7A8797",
                "lw": 0.7,
                "shrinkA": 0,
                "shrinkB": 4,
            },
        )


def plot_numberline(df: pd.DataFrame, value_col: str, output_path: Path, title: str | None, top_n: int):
    values = df[value_col].to_numpy(dtype=float)
    offsets = compute_swarm_offsets(values)
    palette = build_palette(df["family"].astype(str).tolist())
    colors = [palette.get(str(family), "#7A8797") for family in df["family"]]

    q1, median, q3 = np.quantile(values, [0.25, 0.5, 0.75])
    vmin = float(values.min())
    vmax = float(values.max())

    fig, ax = plt.subplots(figsize=(12, 3.8))
    ax.axhline(0.0, color="#AAB4C3", linewidth=1.2, zorder=1)
    ax.scatter(values, offsets, s=54, c=colors, alpha=0.9, edgecolors="white", linewidths=0.8, zorder=3)

    ax.axvspan(q1, q3, color="#DCEBFA", alpha=0.65, zorder=0)
    ax.axvline(median, color="#1D3557", linestyle="--", linewidth=1.2, zorder=2)
    ax.axvline(q1, color="#5C6773", linestyle=":", linewidth=1.0, zorder=2)
    ax.axvline(q3, color="#5C6773", linestyle=":", linewidth=1.0, zorder=2)

    annotate_top_points(ax, df, value_col, offsets, top_n)

    ax.set_yticks([])
    ax.set_xlabel(value_col)
    ax.set_ylim(-0.42, 0.42)
    pad = (vmax - vmin) * 0.08 if vmax > vmin else max(vmax * 0.2, 1e-6)
    ax.set_xlim(vmin - pad, vmax + pad)
    ax.grid(axis="x", alpha=0.35)
    ax.grid(axis="y", visible=False)

    plot_title = title or f"Distribution of {value_col}"
    ax.set_title(plot_title)

    subtitle = (
        f"n={len(df)} protocols | min={vmin:.6f} | q1={q1:.6f} | median={median:.6f} | "
        f"q3={q3:.6f} | max={vmax:.6f}"
    )
    ax.text(
        0.01,
        1.04,
        subtitle,
        transform=ax.transAxes,
        ha="left",
        va="bottom",
        fontsize=9,
        color="#4E5D6C",
    )

    family_items = list(dict.fromkeys(df["family"].astype(str).tolist()))
    handles = [
        plt.Line2D([0], [0], marker="o", color="w", label=family,
                   markerfacecolor=palette[family], markeredgecolor="white", markersize=7)
        for family in family_items[:10]
    ]
    if handles:
        ax.legend(handles=handles, frameon=False, ncols=min(5, len(handles)), loc="lower right")

    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)

    summary = {
        "input_rows": int(len(df)),
        "column": value_col,
        "min": vmin,
        "q1": float(q1),
        "median": float(median),
        "q3": float(q3),
        "max": vmax,
        "output_png": str(output_path),
    }
    summary_path = output_path.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return summary_path


def main():
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else input_path.parent / default_output_name(args.column)
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    configure_style()
    df = load_profile_csv(input_path, args.column, args.min_flows)
    summary_path = plot_numberline(df, args.column, output_path, args.title, args.top_n)

    print(f"Saved plot: {output_path}")
    print(f"Saved summary: {summary_path}")


if __name__ == "__main__":
    main()
