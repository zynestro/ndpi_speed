#!/usr/bin/env python3
"""合并协议级 CSV。

这个脚本会对输入 CSV 做两轮聚合：

1. 按完全相同的 ``protocol`` 合并。
   例如把多行 ``TLS`` 合成一行。

2. 按带 ``.`` 的协议父类再合并。
   例如把 ``TLS.Google``、``TLS.Mozilla``、``TLS.Facebook`` 这类
   协议合并到父类 ``TLS``。

两轮结果会分别输出为两份新的 CSV。
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def parse_args():
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="按 protocol 和父类 protocol 聚合 CSV")
    parser.add_argument("--input", required=True, help="输入 CSV 路径")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="输出目录；默认写到输入文件所在目录",
    )
    parser.add_argument(
        "--exact-name",
        default=None,
        help="第一轮精确合并输出文件名；默认 <输入名>_merged_exact.csv",
    )
    parser.add_argument(
        "--parent-name",
        default=None,
        help="第二轮父类合并输出文件名；默认 <输入名>_merged_parent.csv",
    )
    return parser.parse_args()


def strip_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """清理表头和字符串单元格的首尾空白。"""
    out = df.copy()
    out.columns = [str(col).strip() for col in out.columns]
    for col in out.columns:
        if out[col].dtype == object or pd.api.types.is_string_dtype(out[col]):
            out[col] = out[col].astype(str).str.strip()
    return out


def load_csv(csv_path: Path) -> pd.DataFrame:
    """读取 CSV，并把非文本列尽量转成数值。"""
    df = pd.read_csv(csv_path, dtype=str)
    df = strip_dataframe(df)
    for col in df.columns:
        if col not in {"protocol", "category_name"}:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def protocol_parent(name: str) -> str:
    """返回协议的父类名。

    规则很简单：
    - 含 ``.`` 时，取第一个 ``.`` 前面的部分
    - 不含 ``.`` 时，父类就是它自己
    """
    if "." in name:
        return name.split(".", 1)[0]
    return name


def first_nonempty(series: pd.Series, default):
    """取第一项非空值；如果没有则回退到默认值。"""
    for value in series:
        if pd.notna(value) and str(value) != "":
            return value
    return default


def collapse_numeric_meta(series: pd.Series, default: int = -1) -> int:
    """聚合数值型元数据列。

    如果所有非空值一致，则保留该值；否则说明这个聚合组内部本来就混合了
    不同的元数据，这里统一写成 ``-1``。
    """
    values = [value for value in series if pd.notna(value)]
    if not values:
        return default
    uniq = pd.Index(values).unique()
    if len(uniq) == 1:
        return int(uniq[0])
    return default


def collapse_text_meta(series: pd.Series, default: str = "MIXED") -> str:
    """聚合文本型元数据列。"""
    values = [str(value) for value in series if pd.notna(value) and str(value) != ""]
    if not values:
        return default
    uniq = pd.Index(values).unique()
    if len(uniq) == 1:
        return str(uniq[0])
    return default


def weighted_average(values: pd.Series, weights: np.ndarray) -> float:
    """按给定权重计算加权平均。"""
    array = pd.to_numeric(values, errors="coerce").fillna(0).to_numpy(dtype=float)
    return float(np.sum(array * weights))


def aggregate_by_protocol(df: pd.DataFrame, group_col: str) -> pd.DataFrame:
    """按指定列聚合整张协议表。

    聚合规则：
    - ``flows`` 求和
    - ``avg_*`` / ``var_*`` 按 ``flows`` 做加权平均
    - ``protocol_detected`` 取最大值
    - ``master_proto`` / ``app_proto`` / ``category_id`` 如果冲突则写成 ``-1``
    - ``category_name`` 如果冲突则写成 ``MIXED``
    """
    avg_var_cols = [col for col in df.columns if col.startswith("avg_") or col.startswith("var_")]

    rows = []
    for group_name, group in df.groupby(group_col, sort=False):
        flows = pd.to_numeric(group["flows"], errors="coerce").fillna(0).to_numpy(dtype=float)
        total_flows = float(flows.sum())
        if total_flows > 0:
            weights = flows / total_flows
        else:
            weights = np.full(len(group), 1.0 / max(len(group), 1))

        row = {
            "protocol": group_name,
            "protocol_detected": int(pd.to_numeric(group["protocol_detected"], errors="coerce").fillna(0).max()),
            "master_proto": collapse_numeric_meta(pd.to_numeric(group["master_proto"], errors="coerce")),
            "app_proto": collapse_numeric_meta(pd.to_numeric(group["app_proto"], errors="coerce")),
            "category_name": collapse_text_meta(group["category_name"]),
            "category_id": collapse_numeric_meta(pd.to_numeric(group["category_id"], errors="coerce")),
            "flows": int(total_flows),
            "merged_rows": int(len(group)),
            "source_protocols": "|".join(group["protocol"].astype(str).tolist()),
        }

        for col in avg_var_cols:
            row[col] = weighted_average(group[col], weights)

        rows.append(row)

    out = pd.DataFrame(rows)

    # 尽量保持和原始 CSV 接近的列顺序，新增列放在后面。
    preferred_order = [
        "protocol",
        "protocol_detected",
        "master_proto",
        "app_proto",
        "category_name",
        "category_id",
        "flows",
    ]
    metric_cols = [col for col in df.columns if col.startswith("avg_") or col.startswith("var_")]
    extra_cols = ["merged_rows", "source_protocols"]
    final_cols = [col for col in preferred_order if col in out.columns]
    final_cols.extend([col for col in metric_cols if col in out.columns])
    final_cols.extend([col for col in extra_cols if col in out.columns])
    return out[final_cols].sort_values("flows", ascending=False).reset_index(drop=True)


def main():
    """执行两轮聚合并写出结果。"""
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir) if args.output_dir else input_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = input_path.stem
    exact_name = args.exact_name or f"{stem}_merged_exact.csv"
    parent_name = args.parent_name or f"{stem}_merged_parent.csv"

    df = load_csv(input_path)
    if "protocol" not in df.columns:
        raise ValueError("输入 CSV 缺少 protocol 列")
    if "flows" not in df.columns:
        raise ValueError("输入 CSV 缺少 flows 列")

    # 第一轮：完全相同的 protocol 合并。
    exact_df = aggregate_by_protocol(df, "protocol")
    exact_path = output_dir / exact_name
    exact_df.to_csv(exact_path, index=False)

    # 第二轮：按父类协议合并。这里基于原始输入直接做父类聚合，
    # 这样像 TLS 和 TLS.Google 都会统一落到 TLS。
    parent_input = df.copy()
    parent_input["protocol_parent"] = parent_input["protocol"].astype(str).map(protocol_parent)
    parent_df = aggregate_by_protocol(parent_input, "protocol_parent")
    parent_path = output_dir / parent_name
    parent_df.to_csv(parent_path, index=False)

    print(f"精确 protocol 合并结果: {exact_path}")
    print(f"父类 protocol 合并结果: {parent_path}")


if __name__ == "__main__":
    main()
