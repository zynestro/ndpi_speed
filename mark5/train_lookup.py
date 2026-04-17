#!/usr/bin/env python3
"""从 mark5 的 CSV 训练成本分桶 lookup。

支持两种输入：

1. flow 模式
   输入逐流 CSV（旧版/兼容版 flow_profile.csv）
   输出：
   - 协议成本桶
   - 基于 port/prefix 的 lookup 规则

2. profile 模式
   输入 protocol_profile_averaged.csv
   输出：
   - 协议成本桶
   - family 成本桶
   - protocol/family 级 lookup

注意：
- protocol_profile_averaged.csv 不包含端口和 payload prefix，因此不能训练
  port/prefix 规则；只能训练 protocol/family 级规则。
- 默认用 detection-only 成本来分桶，但可以通过 --cost-column 切换为整个
  detecting 阶段成本。
"""

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


BUCKET_LABELS_3 = ["Easy", "Middle", "Hard"]
FLOW_MODE = "flow"
PROFILE_MODE = "profile"


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def mean(values):
    return sum(values) / len(values) if values else 0.0


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train cost-bucket lookup from mark5 flow/profile CSV"
    )
    parser.add_argument("--input", default=None, help="输入 CSV 路径")
    parser.add_argument(
        "--run-dir",
        default=None,
        help="运行目录；flow 模式下可直接给 run 目录，profile 模式下可给 _combined 所在目录",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="输出目录；默认是输入文件所在目录下的 lookup",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", FLOW_MODE, PROFILE_MODE],
        default="auto",
        help="输入类型；默认自动识别",
    )
    parser.add_argument(
        "--cost-column",
        default="auto",
        help=(
            "分桶依据列；默认自动选择。"
            "flow 模式常用 detecting_detection_only_ms / detecting_total_ms；"
            "profile 模式常用 profile_avg_detecting_detection_only_ms / "
            "profile_avg_detecting_total_ms"
        ),
    )
    parser.add_argument(
        "--purity",
        type=float,
        default=0.95,
        help="flow 模式下保留规则所需 purity 阈值",
    )
    parser.add_argument(
        "--min-support",
        type=int,
        default=20,
        help="flow 模式下保留规则所需最小支持度",
    )
    parser.add_argument(
        "--default-bucket",
        default="Middle",
        help="未命中规则时的默认桶",
    )
    return parser.parse_args()


def parse_int(value, default=0):
    if value is None or value == "":
        return default
    return int(float(value))


def parse_float(value, default=0.0):
    if value is None or value == "":
        return default
    return float(value)


def protocol_family(protocol: str) -> str:
    if "." in protocol:
        return protocol.split(".", 1)[0]
    return protocol


def latest_csv_candidates(output_root: Path):
    candidates = []
    if not output_root.exists():
        return candidates
    for path in output_root.rglob("protocol_profile_averaged.csv"):
        candidates.append(path)
    for path in output_root.rglob("flow_profile.csv"):
        candidates.append(path)
    for path in output_root.rglob("time_flow_profile.csv"):
        candidates.append(path)
    return candidates


def resolve_paths(args):
    output_root = repo_root() / "output"

    if args.input:
        input_path = Path(args.input)
    elif args.run_dir:
        run_dir = Path(args.run_dir)
        profile_candidate = run_dir / "plots" / "_combined" / "protocol_profile_averaged.csv"
        if profile_candidate.exists():
            input_path = profile_candidate
        else:
            input_path = run_dir / "flow_profile.csv"
    else:
        candidates = latest_csv_candidates(output_root)
        if not candidates:
            raise FileNotFoundError(f"No supported CSV found under {output_root}")
        input_path = max(candidates, key=lambda path: path.stat().st_mtime)

    if not input_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")

    output_dir = Path(args.output_dir) if args.output_dir else (input_path.parent / "lookup")
    return input_path, output_dir


def read_csv_rows(csv_path: Path):
    with csv_path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader), list(reader.fieldnames or [])


def detect_mode(fieldnames, preferred_mode):
    if preferred_mode in {FLOW_MODE, PROFILE_MODE}:
        return preferred_mode

    columns = set(fieldnames)
    if "profile_avg_detecting_detection_only_ms" in columns or "profile_avg_detecting_total_ms" in columns:
        return PROFILE_MODE
    if "flow_id" in columns and "protocol" in columns:
        return FLOW_MODE

    raise ValueError("无法自动识别输入模式，请显式指定 --mode flow 或 --mode profile")


def resolve_cost_column(mode: str, requested: str, fieldnames):
    columns = set(fieldnames)
    if requested != "auto":
        if requested not in columns:
            raise ValueError(f"指定的成本列不存在: {requested}")
        return requested

    if mode == FLOW_MODE:
        for candidate in ("detecting_detection_only_ms", "detecting_total_ms", "detecting_cost_ms"):
            if candidate in columns:
                return candidate
    else:
        for candidate in (
            "profile_avg_detecting_detection_only_ms",
            "profile_avg_detecting_total_ms",
        ):
            if candidate in columns:
                return candidate

    raise ValueError("找不到可用的成本列，请通过 --cost-column 显式指定")


def load_flow_rows(csv_path: Path):
    rows, fieldnames = read_csv_rows(csv_path)
    flows = []
    for row in rows:
        flows.append({
            "flow_id": parse_int(row.get("flow_id")),
            "dst_port": parse_int(row.get("dst_port") or row.get("server_port")),
            "server_port": parse_int(row.get("server_port") or row.get("dst_port")),
            "prefix_1": row.get("prefix_1", ""),
            "prefix_2": row.get("prefix_2", ""),
            "prefix_4": row.get("prefix_4", ""),
            "protocol_detected": parse_int(row.get("protocol_detected")),
            "protocol": row.get("protocol", "NOT_DETECTED"),
            "family": protocol_family(row.get("protocol", "NOT_DETECTED")),
        })
    return flows, fieldnames, rows


def load_profile_rows(csv_path: Path):
    rows, fieldnames = read_csv_rows(csv_path)
    profiles = []
    for row in rows:
        protocol = row.get("protocol", "NOT_DETECTED")
        family = row.get("family") or protocol_family(protocol)
        profiles.append({
            "protocol": protocol,
            "family": family,
            "flow_count": parse_float(row.get("profile_flows"), 0.0),
            "raw": row,
        })
    return profiles, fieldnames


def initial_centers(values, k):
    sorted_values = sorted(values)
    centers = []
    for i in range(k):
        idx = round(i * (len(sorted_values) - 1) / max(1, k - 1))
        centers.append(sorted_values[idx])
    return centers


def kmeans_1d(values, k=3, max_iter=100):
    unique_count = len(set(values))
    if unique_count == 0:
        return [], []
    k = min(k, unique_count)
    centers = initial_centers(values, k)
    assignments = [0] * len(values)

    for _ in range(max_iter):
        changed = False
        for idx, value in enumerate(values):
            best = min(range(k), key=lambda c: abs(value - centers[c]))
            if assignments[idx] != best:
                assignments[idx] = best
                changed = True

        new_centers = centers[:]
        for c in range(k):
            cluster_values = [value for value, assign in zip(values, assignments) if assign == c]
            if cluster_values:
                new_centers[c] = mean(cluster_values)

        if not changed and all(abs(a - b) < 1e-12 for a, b in zip(centers, new_centers)):
            centers = new_centers
            break
        centers = new_centers

    return assignments, centers


def bucket_name_map(centers):
    order = sorted(range(len(centers)), key=lambda i: centers[i])
    if len(centers) == 1:
        return {order[0]: "Middle"}
    if len(centers) == 2:
        return {order[0]: "Easy", order[1]: "Hard"}
    return {cluster_id: label for cluster_id, label in zip(order, BUCKET_LABELS_3)}


def dominant_bucket(rows):
    counts = Counter(row["bucket"] for row in rows if row.get("bucket"))
    if not counts:
        return None, 0, 0.0
    bucket, count = counts.most_common(1)[0]
    purity = count / len(rows) if rows else 0.0
    return bucket, count, purity


def weighted_dominant_bucket(rows):
    bucket_weights = Counter()
    total_weight = 0.0
    for row in rows:
        weight = float(row.get("flow_count", 0.0))
        bucket = row.get("bucket")
        if not bucket or weight <= 0.0:
            continue
        bucket_weights[bucket] += weight
        total_weight += weight
    if not bucket_weights or total_weight <= 0.0:
        return None, 0.0, 0.0
    bucket, weight = bucket_weights.most_common(1)[0]
    purity = weight / total_weight
    return bucket, weight, purity


def build_protocol_buckets_from_flows(flows, cost_column, raw_rows):
    detected_flows = []
    for flow, raw in zip(flows, raw_rows):
        if flow["protocol_detected"] == 1 and flow["protocol"] != "NOT_DETECTED":
            row = dict(flow)
            row["cost_ms"] = parse_float(raw.get(cost_column))
            detected_flows.append(row)

    protocols = defaultdict(list)
    for flow in detected_flows:
        protocols[flow["protocol"]].append(flow)

    if not protocols:
        return {}, []

    protocol_rows = []
    log_values = []
    for protocol_name, items in protocols.items():
        cost_ms = mean([item["cost_ms"] for item in items])
        w_bucket_us = max(cost_ms * 1000.0, 1e-6)
        protocol_rows.append({
            "protocol": protocol_name,
            "family": protocol_family(protocol_name),
            "flow_count": len(items),
            "cost_column": cost_column,
            "cost_ms": cost_ms,
            "W_bucket_us": w_bucket_us,
        })
        log_values.append(math.log(w_bucket_us))

    assignments, centers = kmeans_1d(log_values, k=3)
    cluster_to_bucket = bucket_name_map(centers)
    protocol_table = {}
    for row, assign, log_w in zip(protocol_rows, assignments, log_values):
        row["log_W"] = log_w
        row["cluster_id"] = assign
        row["cluster_center_log_W"] = centers[assign]
        row["bucket"] = cluster_to_bucket[assign]
        protocol_table[row["protocol"]] = row

    protocol_rows.sort(key=lambda row: row["W_bucket_us"])
    return protocol_table, protocol_rows


def build_protocol_buckets_from_profiles(profile_rows, cost_column):
    filtered = []
    for item in profile_rows:
        protocol = item["protocol"]
        if protocol == "NOT_DETECTED":
            continue
        cost_ms = parse_float(item["raw"].get(cost_column))
        flow_count = float(item["flow_count"])
        if flow_count <= 0.0:
            continue
        filtered.append({
            "protocol": protocol,
            "family": item["family"],
            "flow_count": flow_count,
            "cost_column": cost_column,
            "cost_ms": cost_ms,
            "W_bucket_us": max(cost_ms * 1000.0, 1e-6),
        })

    if not filtered:
        return {}, []

    log_values = [math.log(row["W_bucket_us"]) for row in filtered]
    assignments, centers = kmeans_1d(log_values, k=3)
    cluster_to_bucket = bucket_name_map(centers)

    protocol_table = {}
    for row, assign, log_w in zip(filtered, assignments, log_values):
        row["log_W"] = log_w
        row["cluster_id"] = assign
        row["cluster_center_log_W"] = centers[assign]
        row["bucket"] = cluster_to_bucket[assign]
        protocol_table[row["protocol"]] = row

    filtered.sort(key=lambda row: row["W_bucket_us"])
    return protocol_table, filtered


def build_family_table(protocol_rows):
    family_groups = defaultdict(list)
    for row in protocol_rows:
        family_groups[row["family"]].append(row)

    family_rows = []
    family_table = {}
    for family, rows in sorted(family_groups.items()):
        bucket, support_flows, purity = weighted_dominant_bucket(rows)
        total_flows = sum(float(row["flow_count"]) for row in rows)
        avg_cost_ms = (
            sum(float(row["cost_ms"]) * float(row["flow_count"]) for row in rows) / total_flows
            if total_flows > 0.0 else 0.0
        )
        item = {
            "family": family,
            "bucket": bucket or "Middle",
            "support_flows": support_flows,
            "total_flows": total_flows,
            "protocol_count": len(rows),
            "purity": purity,
            "avg_cost_ms": avg_cost_ms,
        }
        family_rows.append(item)
        family_table[family] = item

    family_rows.sort(key=lambda row: row["avg_cost_ms"])
    return family_table, family_rows


def apply_protocol_buckets(flows, protocol_table):
    labeled_flows = []
    for flow in flows:
        row = dict(flow)
        proto = row["protocol"]
        if proto in protocol_table:
            row["bucket"] = protocol_table[proto]["bucket"]
            labeled_flows.append(row)
    return labeled_flows


def build_flow_lookup_rules(all_flows, labeled_flows, purity_threshold, min_support, default_bucket):
    port_groups = defaultdict(list)
    for flow in labeled_flows:
        port_groups[flow["dst_port"]].append(flow)

    port_table = {}
    special_rules = {}
    covered_flow_ids = set()
    ambiguous_ports = []
    rule_rows = []

    for port, rows in sorted(port_groups.items()):
        bucket, support, purity = dominant_bucket(rows)
        if support >= min_support and purity >= purity_threshold:
            port_table[str(port)] = bucket
            rule_rows.append({
                "level": "port",
                "port": port,
                "prefix_type": "",
                "prefix_value": "",
                "bucket": bucket,
                "support": support,
                "purity": purity,
            })
            for row in rows:
                covered_flow_ids.add(row["flow_id"])
        else:
            ambiguous_ports.append(port)

    for port in ambiguous_ports:
        port_rows = [row for row in port_groups[port] if row["flow_id"] not in covered_flow_ids]
        if not port_rows:
            continue

        port_rule = {"prefix_1": {}, "prefix_2": {}, "prefix_4": {}}
        for prefix_key in ("prefix_1", "prefix_2", "prefix_4"):
            unresolved = [row for row in port_rows if row["flow_id"] not in covered_flow_ids]
            subgroups = defaultdict(list)
            for row in unresolved:
                prefix_value = row[prefix_key]
                if prefix_value:
                    subgroups[prefix_value].append(row)

            for prefix_value, rows in sorted(subgroups.items()):
                bucket, support, purity = dominant_bucket(rows)
                if support >= min_support and purity >= purity_threshold:
                    port_rule[prefix_key][prefix_value] = {
                        "bucket": bucket,
                        "support": support,
                        "purity": purity,
                    }
                    rule_rows.append({
                        "level": "special",
                        "port": port,
                        "prefix_type": prefix_key,
                        "prefix_value": prefix_value,
                        "bucket": bucket,
                        "support": support,
                        "purity": purity,
                    })
                    for row in rows:
                        covered_flow_ids.add(row["flow_id"])

        if any(port_rule[key] for key in port_rule):
            special_rules[str(port)] = port_rule

    coverage_labeled = len(covered_flow_ids) / len(labeled_flows) if labeled_flows else 0.0
    coverage_all = len(covered_flow_ids) / len(all_flows) if all_flows else 0.0

    lookup = {
        "mode": FLOW_MODE,
        "default_bucket": default_bucket,
        "port_table": port_table,
        "special_rules": {
            port: {
                key: {prefix: rule["bucket"] for prefix, rule in rules.items()}
                for key, rules in port_rule.items()
            }
            for port, port_rule in special_rules.items()
        },
    }

    report = {
        "mode": FLOW_MODE,
        "total_flows": len(all_flows),
        "labeled_flows": len(labeled_flows),
        "covered_labeled_flows": len(covered_flow_ids),
        "coverage_labeled": coverage_labeled,
        "coverage_all_flows": coverage_all,
        "default_bucket": default_bucket,
        "purity_threshold": purity_threshold,
        "min_support": min_support,
        "port_rule_count": len(port_table),
        "special_rule_count": sum(
            len(rules["prefix_1"]) + len(rules["prefix_2"]) + len(rules["prefix_4"])
            for rules in special_rules.values()
        ),
    }

    return lookup, report, rule_rows


def build_profile_lookup(protocol_rows, family_table, default_bucket, cost_column):
    lookup = {
        "mode": PROFILE_MODE,
        "default_bucket": default_bucket,
        "cost_column": cost_column,
        "protocol_table": {row["protocol"]: row["bucket"] for row in protocol_rows},
        "family_table": {family: item["bucket"] for family, item in family_table.items()},
    }

    rule_rows = []
    for row in protocol_rows:
        rule_rows.append({
            "level": "protocol",
            "name": row["protocol"],
            "bucket": row["bucket"],
            "support_flows": row["flow_count"],
            "support_protocols": 1,
            "purity": 1.0,
        })
    for family, item in sorted(family_table.items()):
        rule_rows.append({
            "level": "family",
            "name": family,
            "bucket": item["bucket"],
            "support_flows": item["total_flows"],
            "support_protocols": item["protocol_count"],
            "purity": item["purity"],
        })

    report = {
        "mode": PROFILE_MODE,
        "protocol_count": len(protocol_rows),
        "family_count": len(family_table),
        "default_bucket": default_bucket,
        "cost_column": cost_column,
        "protocol_rules": len(protocol_rows),
        "family_rules": len(family_table),
    }
    return lookup, report, rule_rows


def write_protocol_table(path: Path, rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "protocol",
                "family",
                "flow_count",
                "cost_column",
                "cost_ms",
                "W_bucket_us",
                "log_W",
                "cluster_id",
                "cluster_center_log_W",
                "bucket",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_family_table(path: Path, rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "family",
                "bucket",
                "support_flows",
                "total_flows",
                "protocol_count",
                "purity",
                "avg_cost_ms",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_flow_lookup_table_csv(path: Path, rule_rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["level", "port", "prefix_type", "prefix_value", "bucket", "support", "purity"],
        )
        writer.writeheader()
        for row in rule_rows:
            writer.writerow(row)


def write_profile_lookup_table_csv(path: Path, rule_rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["level", "name", "bucket", "support_flows", "support_protocols", "purity"],
        )
        writer.writeheader()
        for row in rule_rows:
            writer.writerow(row)


def main():
    args = parse_args()
    input_path, output_dir = resolve_paths(args)
    output_dir.mkdir(parents=True, exist_ok=True)

    _, fieldnames = read_csv_rows(input_path)
    mode = detect_mode(fieldnames, args.mode)
    cost_column = resolve_cost_column(mode, args.cost_column, fieldnames)

    if mode == FLOW_MODE:
        all_flows, _, raw_rows = load_flow_rows(input_path)
        protocol_table, protocol_rows = build_protocol_buckets_from_flows(
            all_flows, cost_column, raw_rows
        )
        labeled_flows = apply_protocol_buckets(all_flows, protocol_table)
        lookup, report, rule_rows = build_flow_lookup_rules(
            all_flows,
            labeled_flows,
            purity_threshold=args.purity,
            min_support=args.min_support,
            default_bucket=args.default_bucket,
        )

        write_protocol_table(output_dir / "protocol_weight_table.csv", protocol_rows)
        write_flow_lookup_table_csv(output_dir / "lookup_table.csv", rule_rows)

    else:
        profile_rows, _ = load_profile_rows(input_path)
        protocol_table, protocol_rows = build_protocol_buckets_from_profiles(
            profile_rows, cost_column
        )
        family_table, family_rows = build_family_table(protocol_rows)
        lookup, report, rule_rows = build_profile_lookup(
            protocol_rows,
            family_table,
            default_bucket=args.default_bucket,
            cost_column=cost_column,
        )

        write_protocol_table(output_dir / "protocol_weight_table.csv", protocol_rows)
        write_family_table(output_dir / "family_weight_table.csv", family_rows)
        write_profile_lookup_table_csv(output_dir / "lookup_table.csv", rule_rows)

    with (output_dir / "lookup_table.json").open("w") as f:
        json.dump(lookup, f, indent=2, sort_keys=True)

    with (output_dir / "training_report.json").open("w") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    print(f"Input: {input_path}")
    print(f"Mode: {mode}")
    print(f"Cost column: {cost_column}")
    print(f"Output dir: {output_dir}")
    print(f"Protocols: {len(protocol_rows)}")
    if mode == PROFILE_MODE:
        print(f"Families: {len(family_rows)}")
        print(f"Protocol rules: {report['protocol_rules']}")
        print(f"Family rules: {report['family_rules']}")
    else:
        print(f"Labeled flows: {report['labeled_flows']}")
        print(f"Covered labeled flows: {report['covered_labeled_flows']}")
        print(f"Coverage over labeled flows: {report['coverage_labeled']:.4f}")
        print(f"Coverage over all flows: {report['coverage_all_flows']:.4f}")
        print(f"Port rules: {report['port_rule_count']}")
        print(f"Special rules: {report['special_rule_count']}")


if __name__ == "__main__":
    main()
