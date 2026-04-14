#!/usr/bin/env python3

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


BUCKET_LABELS_3 = ["Easy", "Middle", "Hard"]


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def mean(values):
    return sum(values) / len(values) if values else 0.0


def parse_args():
    root = repo_root()
    default_output_dir = root / "output"
    parser = argparse.ArgumentParser(description="Train port/prefix lookup rules from mark5 flow_profile.csv")
    parser.add_argument("--input", default=None,
                        help="Input flow_profile.csv")
    parser.add_argument("--run-dir", default=None,
                        help="mark5 run output directory, e.g. output/20260412_123456")
    parser.add_argument("--output-dir", default=None,
                        help="Directory to write trained tables; default is the same run directory")
    parser.add_argument("--purity", type=float, default=0.95,
                        help="Purity threshold for keeping a rule")
    parser.add_argument("--min-support", type=int, default=20,
                        help="Minimum flow count for keeping a rule")
    parser.add_argument("--default-bucket", default="Middle",
                        help="Default bucket for unmatched flows")
    return parser.parse_args()


def parse_int(value, default=0):
    if value is None or value == "":
        return default
    return int(value)


def parse_float(value, default=0.0):
    if value is None or value == "":
        return default
    return float(value)


def load_flows(csv_path: Path):
    flows = []
    with csv_path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append({
                "flow_id": parse_int(row.get("flow_id")),
                "dst_port": parse_int(row.get("dst_port")),
                "server_port": parse_int(row.get("server_port")),
                "prefix_1": row.get("prefix_1", ""),
                "prefix_2": row.get("prefix_2", ""),
                "prefix_4": row.get("prefix_4", ""),
                "protocol_detected": parse_int(row.get("protocol_detected")),
                "protocol": row.get("protocol", "NOT_DETECTED"),
                "detecting_cost_ms": parse_float(row.get("detecting_cost_ms")),
                "detecting_detection_only_ms": parse_float(row.get("detecting_detection_only_ms")),
            })
    return flows


def latest_run_dir(output_root: Path):
    candidates = []
    for child in output_root.iterdir():
        if child.is_dir() and (child / "flow_profile.csv").exists():
            candidates.append(child)
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.name)


def resolve_paths(args):
    output_root = repo_root() / "output"

    if args.input:
        input_path = Path(args.input)
        run_dir = input_path.parent
    elif args.run_dir:
        run_dir = Path(args.run_dir)
        input_path = run_dir / "flow_profile.csv"
    else:
        run_dir = latest_run_dir(output_root)
        if run_dir is None:
            raise FileNotFoundError(
                f"No run directory with flow_profile.csv found under {output_root}"
            )
        input_path = run_dir / "flow_profile.csv"

    output_dir = Path(args.output_dir) if args.output_dir else (run_dir / "lookup")
    return input_path, run_dir, output_dir


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


def build_protocol_table(flows):
    detected_flows = [
        flow for flow in flows
        if flow["protocol_detected"] == 1 and flow["protocol"] != "NOT_DETECTED"
    ]
    protocols = defaultdict(list)
    for flow in detected_flows:
        protocols[flow["protocol"]].append(flow)

    if not protocols:
        return {}, []

    protocol_rows = []
    log_values = []
    for protocol_name, items in protocols.items():
        w_detecting_us = mean([flow["detecting_cost_ms"] for flow in items]) * 1000.0
        w_detection_only_us = mean([flow["detecting_detection_only_ms"] for flow in items]) * 1000.0
        w_bucket_us = w_detection_only_us if w_detection_only_us > 0.0 else 1e-6
        protocol_rows.append({
            "protocol": protocol_name,
            "W_detecting_us": w_detecting_us,
            "W_detection_only_us": w_detection_only_us,
            "W_bucket_us": w_bucket_us,
            "flow_count": len(items),
        })
        log_values.append(math.log(w_bucket_us))

    assignments, centers = kmeans_1d(log_values, k=3)
    cluster_to_bucket = bucket_name_map(centers)
    protocol_table = {}
    for row, assign, log_w in zip(protocol_rows, assignments, log_values):
        row["log_W"] = log_w
        row["cluster_id"] = assign
        row["bucket"] = cluster_to_bucket[assign]
        row["cluster_center_log_W"] = centers[assign]
        protocol_table[row["protocol"]] = row

    protocol_rows.sort(key=lambda row: row["W_bucket_us"])
    return protocol_table, protocol_rows


def apply_protocol_buckets(flows, protocol_table):
    labeled_flows = []
    for flow in flows:
        row = dict(flow)
        proto = row["protocol"]
        if proto in protocol_table:
            row["bucket"] = protocol_table[proto]["bucket"]
            labeled_flows.append(row)
    return labeled_flows


def build_rules(all_flows, labeled_flows, purity_threshold, min_support, default_bucket):
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
        "total_flows": len(all_flows),
        "labeled_flows": len(labeled_flows),
        "covered_labeled_flows": len(covered_flow_ids),
        "coverage_labeled": coverage_labeled,
        "coverage_all_flows": coverage_all,
        "w_basis": "detecting_detection_only_ms",
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


def write_protocol_table(path: Path, rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "protocol",
                "W_detecting_us",
                "W_detection_only_us",
                "W_bucket_us",
                "flow_count",
                "log_W",
                "cluster_id",
                "cluster_center_log_W",
                "bucket",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_lookup_table_csv(path: Path, rule_rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["level", "port", "prefix_type", "prefix_value", "bucket", "support", "purity"],
        )
        writer.writeheader()
        for row in rule_rows:
            writer.writerow(row)


def main():
    args = parse_args()
    input_path, run_dir, output_dir = resolve_paths(args)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_flows = load_flows(input_path)
    protocol_table, protocol_rows = build_protocol_table(all_flows)
    labeled_flows = apply_protocol_buckets(all_flows, protocol_table)
    lookup, report, rule_rows = build_rules(
        all_flows,
        labeled_flows,
        purity_threshold=args.purity,
        min_support=args.min_support,
        default_bucket=args.default_bucket,
    )

    write_protocol_table(output_dir / "protocol_weight_table.csv", protocol_rows)
    write_lookup_table_csv(output_dir / "lookup_table.csv", rule_rows)

    with (output_dir / "lookup_table.json").open("w") as f:
        json.dump(lookup, f, indent=2, sort_keys=True)

    with (output_dir / "training_report.json").open("w") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    print(f"Input: {input_path}")
    print(f"Run dir: {run_dir}")
    print(f"Output dir: {output_dir}")
    print(f"Protocols: {len(protocol_rows)}")
    print(f"Labeled flows: {report['labeled_flows']}")
    print(f"Covered labeled flows: {report['covered_labeled_flows']}")
    print(f"Coverage over labeled flows: {report['coverage_labeled']:.4f}")
    print(f"Coverage over all flows: {report['coverage_all_flows']:.4f}")
    print(f"Port rules: {report['port_rule_count']}")
    print(f"Special rules: {report['special_rule_count']}")


if __name__ == "__main__":
    main()
