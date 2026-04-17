#!/usr/bin/env python3
"""针对一组 P/E 核运行结果做协议级分析和绘图。

这个脚本读取四个已经准备好的 summary 目录：
- P-core time summary
- P-core hardware summary
- E-core time summary
- E-core hardware summary

基于这些输入，它会构造两张分析表：
1. ``profile_df``：把 P-core 和 E-core 做平均后的协议画像表。
2. ``cross_df``：同时保留 P/E 两边指标，方便直接做跨核比值比较。

随后它会输出两份 CSV 和七张图。

换句话说：
- ``plot_protocol_manifest.py`` 负责决定“处理哪些数据集”。
- 这个文件负责决定“怎样对齐协议”和“具体画什么图”。
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


TIME_FILE = "time_protocol_summary.csv"
HW_FILE = "hardware_protocol_summary.csv"

PLOT_FILES = {
    "time_components": "protocol_time_components.png",
    "hw_llc_ipc": "protocol_hw_llc_ipc.png",
    "hw_branch": "protocol_hw_branch.png",
    "scatter_time_llc": "scatter_time_vs_llc.png",
    "scatter_time_ipc": "scatter_time_vs_ipc.png",
    "cross_time_ratio": "cross_core_detecting_ratio.png",
    "cross_ipc_llc_ratio": "cross_core_ipc_llc_ratio.png",
}

TIME_COLS = [
    "avg_detecting_total_ms",
    "avg_detecting_detection_only_ms",
    "avg_detecting_flow_table_ms",
    "avg_detecting_other_ms",
    "avg_detecting_detection_ratio",
    "avg_detecting_flow_table_ratio",
    "avg_detecting_other_ratio",
]

HW_COLS = [
    "avg_detecting_ipc",
    "avg_detecting_llc_misses",
    "avg_detecting_llc_miss_ratio",
    "avg_detecting_branch_miss_per_kinst",
]

META_COLS = [
    "protocol",
    "protocol_detected",
    "master_proto",
    "app_proto",
    "category_name",
    "category_id",
    "flows",
]

KEY_COLS = ["protocol"]
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


def repo_root() -> Path:
    """返回仓库根目录，用于生成默认输出路径。"""
    return Path(__file__).resolve().parent.parent


def parse_args():
    """解析协议级绘图需要的命令行参数。"""
    parser = argparse.ArgumentParser(
        description="Plot seven protocol-level figures from P/E core mark5 summary directories."
    )
    parser.add_argument("--p-time-dir", required=True, help="Directory containing P-core time_protocol_summary.csv")
    parser.add_argument("--p-hw-dir", required=True, help="Directory containing P-core hardware_protocol_summary.csv")
    parser.add_argument("--e-time-dir", required=True, help="Directory containing E-core time_protocol_summary.csv")
    parser.add_argument("--e-hw-dir", required=True, help="Directory containing E-core hardware_protocol_summary.csv")
    parser.add_argument("--p-label", default="P-core", help="Label for the performance core data")
    parser.add_argument("--e-label", default="E-core", help="Label for the efficiency core data")
    parser.add_argument("--output-dir", default=None, help="Directory to write figures and merged csv tables")
    parser.add_argument("--top-n", type=int, default=0, help="Optional limit for protocol bars; 0 means keep all")
    parser.add_argument("--min-flows", type=int, default=50, help="Minimum flow count required on both cores")
    parser.add_argument("--include-not-detected", action="store_true", help="Keep NOT_DETECTED in the plots")
    parser.add_argument("--log-llc", action="store_true", help="Use log scale for LLC-related axes")
    return parser.parse_args()


def configure_style():
    """为所有输出图片设置统一的 matplotlib 风格。"""
    plt.style.use("seaborn-v0_8-whitegrid")
    plt.rcParams.update({
        "figure.dpi": 160,
        "savefig.dpi": 220,
        "font.size": 10,
        "axes.labelsize": 11,
        "axes.titlesize": 12,
        "axes.titleweight": "semibold",
        "legend.fontsize": 9,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "grid.color": "#D7DCE5",
        "grid.linestyle": "--",
        "grid.linewidth": 0.6,
        "axes.edgecolor": "#444A57",
        "axes.linewidth": 0.8,
    })


def strip_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """在数值转换前，先清理表头和字符串单元格里的空白。"""
    df = df.copy()
    df.columns = [str(col).strip() for col in df.columns]
    for col in df.columns:
        if pd.api.types.is_string_dtype(df[col]) or df[col].dtype == object:
            df[col] = df[col].astype(str).str.strip()
    return df


def load_summary_csv(run_dir: Path, filename: str) -> pd.DataFrame:
    """读取一份 summary CSV，并尽量把可转的列转成数值。

    ``protocol`` 和 ``category_name`` 保持字符串。
    其余列默认按数值处理，因为后续聚合和绘图都依赖数值列。
    """
    csv_path = run_dir / filename
    if not csv_path.exists():
        raise FileNotFoundError(f"Missing required file: {csv_path}")
    df = pd.read_csv(csv_path, dtype=str)
    df = strip_dataframe(df)
    for col in df.columns:
        if col not in {"protocol", "category_name"}:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def aggregate_protocol_rows(df: pd.DataFrame) -> pd.DataFrame:
    """把同一张 summary 表里重复出现的 protocol 行再聚合一次。

    正常情况下，一个 protocol 应该只对应一行。这里加这一层是为了兜底：
    如果同一个 protocol 出现了多行，就再按协议合并一次。

    聚合规则：
    - ``flows`` 做求和。
    - 所有 ``avg_*`` / ``var_*`` 列都按 ``flows`` 做加权平均。

    这样在协议重复出现时，样本大的那一行权重更高，不会和很小的样本
    被同等对待。
    """
    df = df.copy()
    avg_cols = [col for col in df.columns if col.startswith("avg_")]
    var_cols = [col for col in df.columns if col.startswith("var_")]

    def summarize(group: pd.DataFrame) -> pd.Series:
        flows = group["flows"].fillna(0).to_numpy(dtype=float)
        total_flows = float(flows.sum())
        if total_flows <= 0:
            # 兜底逻辑：如果所有 flow 数都缺失或为 0，就退回到等权平均，
            # 至少保证还能稳定地产出一行结果。
            weights = np.full(len(group), 1.0 / max(len(group), 1))
        else:
            weights = flows / total_flows

        row = {
            "protocol": group.name,
            "protocol_detected": group["protocol_detected"].max(),
            "flows": total_flows,
        }
        for col in avg_cols + var_cols:
            values = group[col].fillna(0).to_numpy(dtype=float)
            row[col] = float(np.sum(values * weights))
        return pd.Series(row)

    return df.groupby("protocol", as_index=False, sort=False).apply(summarize, include_groups=False)


def load_core_summary(time_dir: Path, hw_dir: Path) -> pd.DataFrame:
    """构造某一种核心类型的一张合并 summary 表。

    步骤是：
    1. 读取并去重 time summary。
    2. 读取并去重 hardware summary。
    3. 按 ``protocol`` 把两者合并。

    这里以 time 表中的元数据为主，只从 hardware 表里追加非元数据列，
    避免描述性字段重复。
    """
    time_df = aggregate_protocol_rows(load_summary_csv(time_dir, TIME_FILE))
    hw_df = aggregate_protocol_rows(load_summary_csv(hw_dir, HW_FILE))

    hw_keep = KEY_COLS + [col for col in hw_df.columns if col not in META_COLS]
    merged = time_df.merge(hw_df[hw_keep], on=KEY_COLS, how="inner", validate="one_to_one")
    return merged


def add_protocol_labels(df: pd.DataFrame) -> pd.DataFrame:
    """补一个显示标签列，供图上的标注使用。"""
    df = df.copy()
    df["protocol_label"] = df["protocol"]
    return df


def protocol_family(protocol: str) -> str:
    """把协议名映射成“协议家族”，用于分组上色。

    例如：
    - ``TLS.Google`` -> ``TLS``
    - ``HTTP.Facebook`` -> ``HTTP``
    - ``DNS`` -> ``DNS``
    """
    if protocol == "NOT_DETECTED":
        return protocol
    if "." in protocol:
        return protocol.split(".", 1)[0]
    return protocol


def build_family_palette(families: list[str]) -> dict[str, str]:
    """为协议家族分配颜色。

    一些常见家族使用固定颜色，保证不同运行之间的视觉一致性；
    其余家族则按出现顺序从 ``tab20`` 里取色。
    """
    result = {}
    dynamic_families = [family for family in families if family not in FIXED_FAMILY_COLORS]
    cmap = plt.get_cmap("tab20")
    for family, color in FIXED_FAMILY_COLORS.items():
        if family in families:
            result[family] = color
    for idx, family in enumerate(dynamic_families):
        result[family] = cmap(idx % 20)
    return result


def lighten_color(color: str, amount: float) -> tuple[float, float, float]:
    """把颜色往白色方向混合，生成同一色系的浅色。"""
    rgb = np.array(plt.matplotlib.colors.to_rgb(color))
    white = np.array([1.0, 1.0, 1.0])
    mixed = rgb + (white - rgb) * amount
    return tuple(np.clip(mixed, 0.0, 1.0))


def safe_ratio(num: pd.Series, den: pd.Series) -> pd.Series:
    """计算比值，并把除零结果转成 NaN。"""
    den = den.replace(0, np.nan)
    return num / den


def build_analysis_frames(p_df: pd.DataFrame,
                          e_df: pd.DataFrame,
                          min_flows: int,
                          include_not_detected: bool) -> tuple[pd.DataFrame, pd.DataFrame]:
    """构造所有图都会用到的两张核心分析表。

    ``p_df`` 和 ``e_df`` 都是已经在各自核心内部合并好的 summary。
    这里会先按 protocol 对齐，再做筛选，然后生成：

    - ``profile_df``：
      把 P/E 两边做平均后的协议画像表，用于主画像类图表。

    - ``cross_df``：
      同时保留 P 和 E 两边指标，用于跨核比值类图表。
    """
    joined = p_df.merge(e_df, on=KEY_COLS, suffixes=("_p", "_e"), how="inner", validate="one_to_one")
    if not include_not_detected:
        joined = joined[joined["protocol"] != "NOT_DETECTED"].copy()

    # 只保留在两类核心上都有足够样本量的协议。
    # 这里取两边 flow 数的最小值来判断，避免某协议仅仅因为在一边很多、
    # 另一边很少，也被保留下来。
    joined["flows_min"] = joined[["flows_p", "flows_e"]].min(axis=1)
    joined = joined[joined["flows_min"] >= min_flows].copy()

    for col in TIME_COLS + HW_COLS:
        # ``profile_*`` 列取 P-core 和 E-core 的简单平均，
        # 用来得到一组主图里可直接使用的“代表性协议点”。
        joined[f"profile_{col}"] = joined[[f"{col}_p", f"{col}_e"]].mean(axis=1)

    joined["profile_flows"] = joined[["flows_p", "flows_e"]].mean(axis=1)
    # 跨核比较指标，命名里直接写明了比值方向。
    joined["ratio_detecting_time_e_over_p"] = safe_ratio(
        joined["avg_detecting_detection_only_ms_e"],
        joined["avg_detecting_detection_only_ms_p"],
    )
    joined["ratio_ipc_p_over_e"] = safe_ratio(
        joined["avg_detecting_ipc_p"],
        joined["avg_detecting_ipc_e"],
    )
    joined["ratio_llc_miss_ratio_e_over_p"] = safe_ratio(
        joined["avg_detecting_llc_miss_ratio_e"],
        joined["avg_detecting_llc_miss_ratio_p"],
    )

    # 无效比值可能产生 inf，这里统一换成 NaN，便于后面的绘图处理。
    joined = joined.replace([np.inf, -np.inf], np.nan)
    # 初始顺序先按平均总检测时间从大到小排，后面再按 family 重排，
    # 方便柱状图阅读。
    joined = joined.sort_values("profile_avg_detecting_total_ms", ascending=False).reset_index(drop=True)

    profile_cols = [
        "protocol",
        "profile_flows",
        "profile_avg_detecting_total_ms",
        "profile_avg_detecting_detection_only_ms",
        "profile_avg_detecting_flow_table_ms",
        "profile_avg_detecting_other_ms",
        "profile_avg_detecting_detection_ratio",
        "profile_avg_detecting_flow_table_ratio",
        "profile_avg_detecting_other_ratio",
        "profile_avg_detecting_ipc",
        "profile_avg_detecting_llc_misses",
        "profile_avg_detecting_llc_miss_ratio",
        "profile_avg_detecting_branch_miss_per_kinst",
    ]
    profile_df = joined[profile_cols].copy()
    profile_df = add_protocol_labels(profile_df)
    profile_df["family"] = profile_df["protocol"].map(protocol_family)

    cross_cols = [
        "protocol",
        "flows_p",
        "flows_e",
        "avg_detecting_detection_only_ms_p",
        "avg_detecting_detection_only_ms_e",
        "avg_detecting_ipc_p",
        "avg_detecting_ipc_e",
        "avg_detecting_llc_miss_ratio_p",
        "avg_detecting_llc_miss_ratio_e",
        "ratio_detecting_time_e_over_p",
        "ratio_ipc_p_over_e",
        "ratio_llc_miss_ratio_e_over_p",
    ]
    cross_df = joined[cross_cols].copy()
    cross_df = add_protocol_labels(cross_df)
    cross_df["family"] = cross_df["protocol"].map(protocol_family)
    return profile_df, cross_df


def default_output_dir() -> Path:
    """未指定输出目录时，自动生成带时间戳的目录名。"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return repo_root() / "output" / f"plots_{ts}"


def save_tables(profile_df: pd.DataFrame, cross_df: pd.DataFrame, output_dir: Path):
    """保存两张分析表，并额外写一份简短的输出摘要 JSON。"""
    profile_df.to_csv(output_dir / "protocol_profile_averaged.csv", index=False)
    cross_df.to_csv(output_dir / "protocol_profile_cross_core.csv", index=False)
    summary = {
        "protocol_count_profile": int(len(profile_df)),
        "protocol_count_cross_core": int(len(cross_df)),
        "generated_files": PLOT_FILES,
    }
    (output_dir / "plot_summary.json").write_text(json.dumps(summary, indent=2))


def finalize_axis(ax, xlabel=None, ylabel=None, title=None):
    """统一设置坐标轴标签、标题和网格样式。"""
    if xlabel:
        ax.set_xlabel(xlabel)
    if ylabel:
        ax.set_ylabel(ylabel)
    if title:
        ax.set_title(title, pad=10)
    ax.grid(axis="y", alpha=0.55)
    ax.set_axisbelow(True)


def rotate_protocol_labels(ax):
    """旋转 x 轴标签，避免协议名过密时难以阅读。"""
    ax.tick_params(axis="x", rotation=35)
    for label in ax.get_xticklabels():
        label.set_horizontalalignment("right")


def build_protocol_palette(df: pd.DataFrame) -> dict[str, str]:
    """只为当前数据里实际出现的 family 构造配色表。"""
    families = list(dict.fromkeys(df["family"].tolist()))
    return build_family_palette(families)


def style_protocol_axis(ax, df: pd.DataFrame):
    """把 x 轴渲染成按协议家族分组的形式。

    每个连续 family 块只在第一个位置显示 family 名称，并在不同 family
    之间画浅色分隔线。这样协议很多时，横轴会更容易读。
    """
    x = np.arange(len(df))
    family_labels = []
    prev_family = None
    boundaries = []
    for idx, family in enumerate(df["family"]):
        if family != prev_family:
            family_labels.append(family)
            if idx > 0:
                boundaries.append(idx - 0.5)
            prev_family = family
        else:
            family_labels.append("")

    ax.set_xticks(x, family_labels)
    rotate_protocol_labels(ax)
    ax.set_xlabel("Protocol entries grouped by family")
    for boundary in boundaries:
        ax.axvline(boundary, color="#C7CDD8", linewidth=0.8, linestyle=":")


def plot_time_components(df: pd.DataFrame, output_path: Path, family_palette: dict[str, str]):
    """绘制协议级时间组成堆叠柱状图。

    每根柱子代表一个协议，堆叠部分表示平均 detecting 阶段时间被拆成：
    - detection-only
    - flow-table
    - other
    """
    fig, ax = plt.subplots(figsize=(12, 6))
    x = np.arange(len(df))
    det = df["profile_avg_detecting_detection_only_ms"].to_numpy()
    ft = df["profile_avg_detecting_flow_table_ms"].to_numpy()
    other = df["profile_avg_detecting_other_ms"].to_numpy()

    base_colors = [family_palette.get(fam, "#9AA5B1") for fam in df["family"]]
    det_colors = [lighten_color(c, 0.10) for c in base_colors]
    ft_colors = [lighten_color(c, 0.35) for c in base_colors]
    other_colors = [lighten_color(c, 0.60) for c in base_colors]

    ax.bar(x, det, color=det_colors, label="Detection-only")
    ax.bar(x, ft, bottom=det, color=ft_colors, label="Flow-table")
    ax.bar(x, other, bottom=det + ft, color=other_colors, label="Other")
    style_protocol_axis(ax, df)
    finalize_axis(
        ax,
        ylabel="Average detecting-stage time per flow (ms)",
        title="Protocol Time Composition (family-colored, P/E average)",
    )
    ax.legend(frameon=False, ncols=3, loc="upper right")
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def plot_hw_llc_ipc(df: pd.DataFrame, output_path: Path, log_llc: bool, family_palette: dict[str, str]):
    """绘制硬件画像图，上半部分是 LLC miss ratio，下半部分是 IPC。"""
    fig, axes = plt.subplots(2, 1, figsize=(12, 8), sharex=True, height_ratios=[1.15, 1.0])
    x = np.arange(len(df))
    colors = [family_palette.get(fam, "#9AA5B1") for fam in df["family"]]
    axes[0].bar(x, df["profile_avg_detecting_llc_miss_ratio"], color=colors, width=0.72)
    axes[1].bar(x, df["profile_avg_detecting_ipc"], color=colors, width=0.72)
    style_protocol_axis(axes[1], df)
    finalize_axis(axes[0], ylabel="Average LLC miss ratio", title="Protocol Hardware Profile: LLC Miss Ratio")
    finalize_axis(axes[1], ylabel="Average IPC", title="Protocol Hardware Profile: IPC")
    if log_llc:
        axes[0].set_yscale("log")
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def plot_branch(df: pd.DataFrame, output_path: Path, family_palette: dict[str, str]):
    """绘制每个协议的 branch miss 强度图。"""
    fig, ax = plt.subplots(figsize=(12, 5.5))
    x = np.arange(len(df))
    colors = [family_palette.get(fam, "#9AA5B1") for fam in df["family"]]
    ax.bar(x, df["profile_avg_detecting_branch_miss_per_kinst"], color=colors, width=0.72)
    style_protocol_axis(ax, df)
    finalize_axis(
        ax,
        ylabel="Average branch misses per kinst",
        title="Protocol Branch-Miss Intensity (family-colored, P/E average)",
    )
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def annotate_top_points(ax, df: pd.DataFrame, x_col: str, y_col: str, top_n: int = 10):
    """在散点图里给 x 值最大的前 N 个点加上文字标注。"""
    top = df.nlargest(top_n, x_col)
    for _, row in top.iterrows():
        ax.annotate(
            row["protocol_label"],
            (row[x_col], row[y_col]),
            textcoords="offset points",
            xytext=(4, 3),
            fontsize=8,
            color="#2F3640",
        )


def plot_scatter(df: pd.DataFrame, x_col: str, y_col: str, output_path: Path,
                 title: str, xlabel: str, ylabel: str, family_palette: dict[str, str],
                 log_y: bool = False):
    """绘制两个协议指标之间的散点图，并按 family 着色。"""
    fig, ax = plt.subplots(figsize=(8, 6))
    colors = [family_palette.get(fam, "#9AA5B1") for fam in df["family"]]
    ax.scatter(df[x_col], df[y_col], s=48, color=colors, alpha=0.9, edgecolors="white", linewidths=0.4)
    annotate_top_points(ax, df, x_col, y_col)
    finalize_axis(ax, xlabel=xlabel, ylabel=ylabel, title=title)
    if log_y:
        ax.set_yscale("log")
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def plot_cross_time_ratio(df: pd.DataFrame, output_path: Path, e_label: str, p_label: str,
                          family_palette: dict[str, str]):
    """绘制每个协议的 E-core / P-core detection-only 时间比值图。"""
    fig, ax = plt.subplots(figsize=(12, 5.5))
    x = np.arange(len(df))
    colors = [family_palette.get(fam, "#9AA5B1") for fam in df["family"]]
    ax.bar(x, df["ratio_detecting_time_e_over_p"], color=colors, width=0.72)
    ax.axhline(1.0, color="#444A57", linewidth=1.0, linestyle="--")
    style_protocol_axis(ax, df)
    finalize_axis(
        ax,
        ylabel=f"{e_label} / {p_label}",
        title="Cross-core Detecting-Time Ratio",
    )
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def plot_cross_ipc_llc_ratio(df: pd.DataFrame, output_path: Path, p_label: str, e_label: str,
                             family_palette: dict[str, str]):
    """绘制两个跨核比较图：IPC 比值和 LLC miss-ratio 比值。"""
    fig, axes = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
    x = np.arange(len(df))
    colors = [family_palette.get(fam, "#9AA5B1") for fam in df["family"]]
    axes[0].bar(x, df["ratio_ipc_p_over_e"], color=colors, width=0.72)
    axes[1].bar(x, df["ratio_llc_miss_ratio_e_over_p"], color=colors, width=0.72)
    axes[0].axhline(1.0, color="#444A57", linewidth=1.0, linestyle="--")
    axes[1].axhline(1.0, color="#444A57", linewidth=1.0, linestyle="--")
    style_protocol_axis(axes[1], df)
    finalize_axis(axes[0], ylabel=f"{p_label} / {e_label}", title="Cross-core IPC Ratio")
    finalize_axis(axes[1], ylabel=f"{e_label} / {p_label}", title="Cross-core LLC Miss-Ratio")
    fig.tight_layout()
    fig.savefig(output_path)
    plt.close(fig)


def main():
    """读取输入，生成协议视图，然后输出表格和图片。"""
    args = parse_args()
    configure_style()

    p_time_dir = Path(args.p_time_dir)
    p_hw_dir = Path(args.p_hw_dir)
    e_time_dir = Path(args.e_time_dir)
    e_hw_dir = Path(args.e_hw_dir)
    output_dir = Path(args.output_dir) if args.output_dir else default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    p_df = load_core_summary(p_time_dir, p_hw_dir)
    e_df = load_core_summary(e_time_dir, e_hw_dir)
    profile_df, cross_df = build_analysis_frames(
        p_df,
        e_df,
        min_flows=args.min_flows,
        include_not_detected=args.include_not_detected,
    )

    if profile_df.empty or cross_df.empty:
        raise RuntimeError("No protocols remain after filtering; try lowering --min-flows or keeping NOT_DETECTED.")

    # 最终显示顺序：
    # - 先按 family 分组，让相关协议挨在一起
    # - family 内部再按平均总检测时间降序
    profile_df = profile_df.sort_values(["family", "profile_avg_detecting_total_ms"], ascending=[True, False]).reset_index(drop=True)
    # cross-core 表强制跟主 profile 表保持同样的协议顺序，
    # 这样不同图之间视觉上能一一对齐。
    cross_df = cross_df.set_index("protocol").loc[profile_df["protocol"]].reset_index()

    if args.top_n and args.top_n > 0:
        # 如果限制 top_n，是在排序完成之后截断，
        # 因而保留的是当前显示顺序最前面的若干协议。
        profile_df = profile_df.head(args.top_n).copy()
        cross_df = cross_df.head(args.top_n).copy()

    family_palette = build_protocol_palette(profile_df)

    # 先把派生表落盘，再基于同一批内存数据出图，
    # 保证 CSV 和图片使用的是完全一致的结果。
    save_tables(profile_df, cross_df, output_dir)
    plot_time_components(profile_df, output_dir / PLOT_FILES["time_components"], family_palette)
    plot_hw_llc_ipc(profile_df, output_dir / PLOT_FILES["hw_llc_ipc"], log_llc=args.log_llc, family_palette=family_palette)
    plot_branch(profile_df, output_dir / PLOT_FILES["hw_branch"], family_palette)
    plot_scatter(
        profile_df,
        "profile_avg_detecting_detection_only_ms",
        "profile_avg_detecting_llc_miss_ratio",
        output_dir / PLOT_FILES["scatter_time_llc"],
        "Protocol Detection-only Time vs LLC Miss Ratio",
        "Average detection-only time per flow (ms)",
        "Average LLC miss ratio",
        family_palette=family_palette,
        log_y=args.log_llc,
    )
    plot_scatter(
        profile_df,
        "profile_avg_detecting_detection_only_ms",
        "profile_avg_detecting_ipc",
        output_dir / PLOT_FILES["scatter_time_ipc"],
        "Protocol Detection-only Time vs IPC",
        "Average detection-only time per flow (ms)",
        "Average IPC",
        family_palette=family_palette,
    )
    plot_cross_time_ratio(cross_df, output_dir / PLOT_FILES["cross_time_ratio"], args.e_label, args.p_label, family_palette)
    plot_cross_ipc_llc_ratio(cross_df, output_dir / PLOT_FILES["cross_ipc_llc_ratio"], args.p_label, args.e_label, family_palette)

    print(f"Saved 7 figures and 2 merged csv tables to: {output_dir}")


if __name__ == "__main__":
    main()
