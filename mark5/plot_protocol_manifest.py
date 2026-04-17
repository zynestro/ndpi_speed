#!/usr/bin/env python3
"""批处理级别的协议画像绘图调度脚本。

这个脚本位于 ``plot_protocol_profiles.py`` 的上一层。

它的职责是：
1. 读取 mark5 生成的 batch manifest。
2. 找出同时具备四类成功运行结果的 pcap 条目。
3. 对每个有效 pcap 调用一次 ``plot_protocol_profiles.py``，
   生成该 pcap 自己的协议画像报告。
4. 把所有 pcap 的逐 flow CSV 汇总成协议级 summary CSV。
5. 再调用一次 ``plot_protocol_profiles.py``，
   对合并后的 summary 生成整批数据的总览图。

所以这个文件本身不负责画图，它负责准备输入并把真正的分析/绘图工作
交给 ``plot_protocol_profiles.py``。
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


TIME_SUMMARY_COLUMNS = [
    "protocol",
    "protocol_detected",
    "master_proto",
    "app_proto",
    "category_name",
    "category_id",
    "flows",
    "avg_detect_pkt_in_flow",
    "var_detect_pkt_in_flow",
    "avg_detecting_bytes",
    "var_detecting_bytes",
    "avg_packets_in_flow",
    "var_packets_in_flow",
    "avg_bytes_in_flow",
    "var_bytes_in_flow",
    "avg_detecting_total_ms",
    "var_detecting_total_ms",
    "avg_detecting_detection_only_ms",
    "var_detecting_detection_only_ms",
    "avg_detecting_flow_table_ms",
    "var_detecting_flow_table_ms",
    "avg_detecting_other_ms",
    "var_detecting_other_ms",
    "avg_detecting_detection_ratio",
    "var_detecting_detection_ratio",
    "avg_detecting_flow_table_ratio",
    "var_detecting_flow_table_ratio",
    "avg_detecting_other_ratio",
    "var_detecting_other_ratio",
    "avg_post_total_ms",
    "var_post_total_ms",
    "avg_post_detection_only_ms",
    "var_post_detection_only_ms",
    "avg_post_flow_table_ms",
    "var_post_flow_table_ms",
    "avg_post_other_ms",
    "var_post_other_ms",
    "avg_post_detection_ratio",
    "var_post_detection_ratio",
    "avg_post_flow_table_ratio",
    "var_post_flow_table_ratio",
    "avg_post_other_ratio",
    "var_post_other_ratio",
]

HW_SUMMARY_COLUMNS = [
    "protocol",
    "protocol_detected",
    "master_proto",
    "app_proto",
    "category_name",
    "category_id",
    "flows",
    "avg_detect_pkt_in_flow",
    "var_detect_pkt_in_flow",
    "avg_detecting_bytes",
    "var_detecting_bytes",
    "avg_packets_in_flow",
    "var_packets_in_flow",
    "avg_bytes_in_flow",
    "var_bytes_in_flow",
    "avg_detecting_instructions",
    "var_detecting_instructions",
    "avg_detecting_cycles",
    "var_detecting_cycles",
    "avg_detecting_ipc",
    "var_detecting_ipc",
    "avg_detecting_llc_misses",
    "var_detecting_llc_misses",
    "avg_detecting_llc_refs",
    "var_detecting_llc_refs",
    "avg_detecting_llc_miss_ratio",
    "var_detecting_llc_miss_ratio",
    "avg_detecting_branch_misses",
    "var_detecting_branch_misses",
    "avg_detecting_branch_miss_per_kinst",
    "var_detecting_branch_miss_per_kinst",
    "avg_post_instructions",
    "var_post_instructions",
    "avg_post_cycles",
    "var_post_cycles",
    "avg_post_ipc",
    "var_post_ipc",
    "avg_post_llc_misses",
    "var_post_llc_misses",
    "avg_post_llc_refs",
    "var_post_llc_refs",
    "avg_post_llc_miss_ratio",
    "var_post_llc_miss_ratio",
    "avg_post_branch_misses",
    "var_post_branch_misses",
    "avg_post_branch_miss_per_kinst",
    "var_post_branch_miss_per_kinst",
]


def repo_root() -> Path:
    """返回仓库根目录，方便稳定定位同级脚本。"""
    return Path(__file__).resolve().parent.parent


def parse_args():
    """解析批量绘图所需的命令行参数。"""
    parser = argparse.ArgumentParser(
        description="Generate per-pcap and merged protocol plots from a mark5 batch manifest."
    )
    parser.add_argument("--manifest", required=True, help="Path to batch manifest.json")
    parser.add_argument("--output-dir", default=None, help="Directory to write per-pcap and merged plots")
    parser.add_argument("--min-flows", type=int, default=50, help="Minimum flow threshold for plotting")
    parser.add_argument("--include-not-detected", action="store_true", help="Keep NOT_DETECTED in plots")
    parser.add_argument("--log-llc", action="store_true", help="Use log scale for LLC-related plots")
    return parser.parse_args()


def parse_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """清理表头和字符串单元格里的首尾空白。

    这些 CSV 可能来自不同工具，列名或内容里如果混入空格，
    后面的分组和数值转换就容易出问题，所以先统一做一次清洗。
    """
    out = df.copy()
    out.columns = [str(col).strip() for col in out.columns]
    for col in out.columns:
      if out[col].dtype == object:
        out[col] = out[col].astype(str).str.strip()
    return out


def variance(series: pd.Series) -> float:
    """计算总体方差；如果序列为空则返回 0。"""
    return float(series.var(ddof=0)) if len(series) else 0.0


def first_nonempty(series: pd.Series, default):
    """返回序列里第一个非空值。

    当多条 flow 记录汇总成一个协议行时，像 ``category_name`` 这类
    元数据通常应该是一致的。这里直接取第一个可用值；如果整列都为空，
    就退回到 ``default``。
    """
    for value in series:
        if pd.notna(value) and str(value) != "":
            return value
    return default


def aggregate_time_flow(csv_paths: list[Path]) -> pd.DataFrame:
    """把多份 ``time_flow_profile.csv`` 合并成一份协议级 summary。

    输入粒度：
    - 一行代表一个 flow

    输出粒度：
    - 一行代表一个 protocol

    对每个 protocol，会统计其 flow 数量，并对逐 flow 的时间指标计算
    ``avg_*`` / ``var_*``。
    """
    frames = [parse_numeric(pd.read_csv(path)) for path in csv_paths]
    df = pd.concat(frames, ignore_index=True)
    metric_cols = [
        "detect_pkt_in_flow",
        "detecting_bytes",
        "packets_in_flow",
        "bytes_in_flow",
        "detecting_total_ms",
        "detecting_detection_only_ms",
        "detecting_flow_table_ms",
        "detecting_other_ms",
        "detecting_detection_ratio",
        "detecting_flow_table_ratio",
        "detecting_other_ratio",
        "post_total_ms",
        "post_detection_only_ms",
        "post_flow_table_ms",
        "post_other_ms",
        "post_detection_ratio",
        "post_flow_table_ratio",
        "post_other_ratio",
    ]
    for col in metric_cols + ["protocol_detected", "master_proto", "app_proto", "category_id"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    rows = []
    for protocol, group in df.groupby("protocol", sort=False):
        # 元数据列会从多行折叠成一行；``flows`` 就是该协议贡献的
        # flow 行数。
        row = {
            "protocol": protocol,
            "protocol_detected": int(group["protocol_detected"].max()),
            "master_proto": int(first_nonempty(group["master_proto"], 0)),
            "app_proto": int(first_nonempty(group["app_proto"], 0)),
            "category_name": first_nonempty(group["category_name"], "NOT_DETECTED"),
            "category_id": int(first_nonempty(group["category_id"], 0)),
            "flows": int(len(group)),
        }
        for metric in metric_cols:
            # 均值/方差直接在该协议原始的逐 flow 数值上计算。
            row[f"avg_{metric}"] = float(group[metric].mean())
            row[f"var_{metric}"] = variance(group[metric])
        rows.append(row)

    out = pd.DataFrame(rows)
    return out[TIME_SUMMARY_COLUMNS].sort_values("flows", ascending=False)


def aggregate_hw_flow(csv_paths: list[Path]) -> pd.DataFrame:
    """把多份 ``hardware_flow_profile.csv`` 合并成一份协议级 summary。

    它和 ``aggregate_time_flow`` 是硬件计数器版本的对应实现。
    聚合规则完全一致：先按 protocol 分组，再统计 flow 数量，
    然后对逐 flow 指标计算协议级均值和方差。
    """
    frames = [parse_numeric(pd.read_csv(path)) for path in csv_paths]
    df = pd.concat(frames, ignore_index=True)
    metric_cols = [
        "detect_pkt_in_flow",
        "detecting_bytes",
        "packets_in_flow",
        "bytes_in_flow",
        "detecting_instructions",
        "detecting_cycles",
        "detecting_ipc",
        "detecting_llc_misses",
        "detecting_llc_refs",
        "detecting_llc_miss_ratio",
        "detecting_branch_misses",
        "detecting_branch_miss_per_kinst",
        "post_instructions",
        "post_cycles",
        "post_ipc",
        "post_llc_misses",
        "post_llc_refs",
        "post_llc_miss_ratio",
        "post_branch_misses",
        "post_branch_miss_per_kinst",
    ]
    for col in metric_cols + ["protocol_detected", "master_proto", "app_proto", "category_id"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    rows = []
    for protocol, group in df.groupby("protocol", sort=False):
        row = {
            "protocol": protocol,
            "protocol_detected": int(group["protocol_detected"].max()),
            "master_proto": int(first_nonempty(group["master_proto"], 0)),
            "app_proto": int(first_nonempty(group["app_proto"], 0)),
            "category_name": first_nonempty(group["category_name"], "NOT_DETECTED"),
            "category_id": int(first_nonempty(group["category_id"], 0)),
            "flows": int(len(group)),
        }
        for metric in metric_cols:
            row[f"avg_{metric}"] = float(group[metric].mean())
            row[f"var_{metric}"] = variance(group[metric])
        rows.append(row)

    out = pd.DataFrame(rows)
    return out[HW_SUMMARY_COLUMNS].sort_values("flows", ascending=False)


def required_run_dirs(entry: dict) -> dict[str, Path] | None:
    """返回一个 manifest 条目所需的四个运行目录。

    只有当下面四类运行都存在且状态为成功时，这个 pcap 才算可用：
    - ``p_time``
    - ``p_hw``
    - ``e_time``
    - ``e_hw``

    只要有任意一个缺失、失败，或者没有输出目录，就返回 ``None``，
    让调用方直接跳过这个 pcap。
    """
    runs = entry.get("runs", {})
    required = ["p_time", "p_hw", "e_time", "e_hw"]
    result = {}
    for key in required:
        run = runs.get(key)
        if not run or run.get("status") != "success" or not run.get("output_dir"):
            return None
        result[key] = Path(run["output_dir"])
    return result


def run_plot_protocol_profiles(run_dirs: dict[str, Path], output_dir: Path, args):
    """对一组完整运行结果调用底层绘图脚本。

    ``plot_protocol_profiles.py`` 期望输入的是已经准备好的协议级 summary
    目录。这里把绘图相关参数一并透传下去，保证单个 pcap 和总汇总两种
    运行方式的行为一致。
    """
    cmd = [
        sys.executable,
        str(repo_root() / "mark5" / "plot_protocol_profiles.py"),
        "--p-time-dir",
        str(run_dirs["p_time"]),
        "--p-hw-dir",
        str(run_dirs["p_hw"]),
        "--e-time-dir",
        str(run_dirs["e_time"]),
        "--e-hw-dir",
        str(run_dirs["e_hw"]),
        "--output-dir",
        str(output_dir),
        "--min-flows",
        str(args.min_flows),
    ]
    if args.include_not_detected:
        cmd.append("--include-not-detected")
    if args.log_llc:
        cmd.append("--log-llc")
    subprocess.run(cmd, check=True)


def write_merged_summaries(manifest_data: dict, merged_root: Path):
    """把所有有效 pcap 合并成协议级 summary CSV。

    这里会把所有有效 pcap 的逐 flow CSV 分成四个桶：
    - P-core time
    - P-core hardware
    - E-core time
    - E-core hardware

    每个桶独立聚合成一份协议级 summary CSV。之后再把这些合并后的
    summary 交给 ``plot_protocol_profiles.py``，生成整批数据的总图。
    """
    buckets = {
        "p_time": [],
        "p_hw": [],
        "e_time": [],
        "e_hw": [],
    }
    for entry in manifest_data["pcaps"]:
        run_dirs = required_run_dirs(entry)
        if not run_dirs:
            continue
        # 这里特意合并原始的逐 flow CSV，而不是已经做过协议汇总的 CSV。
        # 这样最终的均值/方差才是基于所有 pcap 的完整 flow 集合计算出来的。
        buckets["p_time"].append(run_dirs["p_time"] / "time_flow_profile.csv")
        buckets["p_hw"].append(run_dirs["p_hw"] / "hardware_flow_profile.csv")
        buckets["e_time"].append(run_dirs["e_time"] / "time_flow_profile.csv")
        buckets["e_hw"].append(run_dirs["e_hw"] / "hardware_flow_profile.csv")

    merged_dirs = {}
    for key in buckets:
        target_dir = merged_root / key
        target_dir.mkdir(parents=True, exist_ok=True)
        merged_dirs[key] = target_dir

    aggregate_time_flow(buckets["p_time"]).to_csv(merged_dirs["p_time"] / "time_protocol_summary.csv", index=False)
    aggregate_hw_flow(buckets["p_hw"]).to_csv(merged_dirs["p_hw"] / "hardware_protocol_summary.csv", index=False)
    aggregate_time_flow(buckets["e_time"]).to_csv(merged_dirs["e_time"] / "time_protocol_summary.csv", index=False)
    aggregate_hw_flow(buckets["e_hw"]).to_csv(merged_dirs["e_hw"] / "hardware_protocol_summary.csv", index=False)
    return merged_dirs


def main():
    """先生成每个 pcap 的图，再生成整批合并后的图。"""
    args = parse_args()
    manifest_path = Path(args.manifest)
    manifest_data = json.loads(manifest_path.read_text())
    batch_dir = Path(manifest_data.get("batch_dir", manifest_path.parent))
    output_dir = Path(args.output_dir) if args.output_dir else (batch_dir / "plots")
    output_dir.mkdir(parents=True, exist_ok=True)

    successful_entries = []
    for entry in manifest_data["pcaps"]:
        run_dirs = required_run_dirs(entry)
        if not run_dirs:
            continue
        successful_entries.append((entry, run_dirs))
        per_pcap_out = output_dir / entry["name"]
        per_pcap_out.mkdir(parents=True, exist_ok=True)
        # 每个 pcap 单独一个输出目录。
        run_plot_protocol_profiles(run_dirs, per_pcap_out, args)

    if not successful_entries:
        raise RuntimeError("No complete pcap groups found in manifest.")

    merged_root = output_dir / "_merged_summaries"
    merged_run_dirs = write_merged_summaries(manifest_data, merged_root)
    combined_out = output_dir / "_combined"
    combined_out.mkdir(parents=True, exist_ok=True)
    # 最后再生成一套覆盖所有有效 pcap 的全局汇总报告。
    run_plot_protocol_profiles(merged_run_dirs, combined_out, args)

    summary = {
        "manifest": str(manifest_path),
        "batch_dir": str(batch_dir),
        "plots_dir": str(output_dir),
        "pcap_count": len(successful_entries),
        "combined_dir": str(combined_out),
    }
    (output_dir / "plot_manifest_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"Saved per-pcap and combined plots to: {output_dir}")


if __name__ == "__main__":
    main()
