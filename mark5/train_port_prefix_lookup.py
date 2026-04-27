#!/usr/bin/env python3
"""Train a port/payload-prefix cost-bucket lookup from mark5 time CSVs.

Pipeline:
1. Read per-flow profiling rows.
2. Compute protocol W = mean(flow detecting cost) * 1000 us.
3. Cluster log(W) into Easy/Middle/Hard.
4. Label flows by their protocol bucket.
5. Learn high-purity dst-port rules, then prefix_1/prefix_2/prefix_4 rules
   for ambiguous ports.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


BUCKET_LABELS = ["Easy", "Middle", "Hard"]
DEFAULT_RUN_DIR = "output/20260424_232908"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train Easy/Middle/Hard lookup rules from mark5 flow/profile CSVs."
    )
    parser.add_argument(
        "--run-dir",
        default=DEFAULT_RUN_DIR,
        help=f"mark5 run directory (default: {DEFAULT_RUN_DIR})",
    )
    parser.add_argument("--flow-csv", default=None, help="Override per-flow CSV path.")
    parser.add_argument(
        "--protocol-csv",
        default=None,
        help="Optional protocol summary CSV path for cross-check metadata.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: <flow-csv directory>/lookup_port_prefix).",
    )
    parser.add_argument(
        "--cost-column",
        default="detecting_total_ms",
        help="Per-flow cost column used as detecting_cost (default: detecting_total_ms).",
    )
    parser.add_argument(
        "--purity",
        type=float,
        default=0.95,
        help="Minimum dominant-bucket purity for a rule (default: 0.95).",
    )
    parser.add_argument(
        "--min-support",
        type=int,
        default=1,
        help="Minimum flow count for a rule (default: 1, matching the pseudocode).",
    )
    parser.add_argument(
        "--default-bucket",
        default="Middle",
        choices=BUCKET_LABELS,
        help="Bucket used when lookup misses (default: Middle).",
    )
    parser.add_argument(
        "--write-enriched-flows",
        action="store_true",
        help="Also write per-flow rows with derived prefix_1/prefix_2 and learned bucket.",
    )
    return parser.parse_args()


def resolve_paths(args: argparse.Namespace) -> tuple[Path, Path | None, Path]:
    run_dir = Path(args.run_dir)
    flow_csv = Path(args.flow_csv) if args.flow_csv else run_dir / "time_flow_profile.csv"
    protocol_csv = (
        Path(args.protocol_csv)
        if args.protocol_csv
        else run_dir / "time_protocol_summary.csv"
    )
    if not protocol_csv.exists():
        protocol_csv = None
    output_dir = Path(args.output_dir) if args.output_dir else flow_csv.parent / "lookup_port_prefix"
    return flow_csv, protocol_csv, output_dir


def clean_row(row: dict[str, str]) -> dict[str, str]:
    return {
        (key.strip() if key is not None else ""): (value.strip() if value is not None else "")
        for key, value in row.items()
    }


def read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        rows = [clean_row(row) for row in reader]
        fieldnames = [name.strip() for name in (reader.fieldnames or [])]
    return rows, fieldnames


def parse_int(value: str | None, default: int = 0) -> int:
    if value is None or value == "":
        return default
    return int(float(value))


def parse_float(value: str | None, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    return float(value)


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def normalize_prefix(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if value.lower().startswith("0x"):
        value = value[2:]
    return value.upper()


def prefix_slice(prefix_4: str, byte_count: int) -> str:
    prefix_4 = normalize_prefix(prefix_4)
    needed = byte_count * 2
    return prefix_4[:needed] if len(prefix_4) >= needed else ""


def load_flows(flow_csv: Path, cost_column: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows, fieldnames = read_csv(flow_csv)
    if cost_column not in fieldnames:
        raise ValueError(f"cost column not found in flow CSV: {cost_column}")
    if "protocol" not in fieldnames:
        raise ValueError("flow CSV must contain protocol")
    if "server_port" not in fieldnames and "dst_port" not in fieldnames:
        raise ValueError("flow CSV must contain server_port or dst_port")

    flows: list[dict[str, Any]] = []
    for row in rows:
        protocol = row.get("protocol") or "NOT_DETECTED"
        protocol_detected = parse_int(row.get("protocol_detected"), 1 if protocol != "NOT_DETECTED" else 0)
        prefix_4 = normalize_prefix(row.get("prefix_4", ""))
        flows.append(
            {
                "flow_id": parse_int(row.get("flow_id"), len(flows) + 1),
                "dst_port": parse_int(row.get("dst_port") or row.get("server_port")),
                "prefix_1": normalize_prefix(row.get("prefix_1", "")) or prefix_slice(prefix_4, 1),
                "prefix_2": normalize_prefix(row.get("prefix_2", "")) or prefix_slice(prefix_4, 2),
                "prefix_4": prefix_4,
                "protocol": protocol,
                "protocol_detected": protocol_detected,
                "detecting_cost_ms": parse_float(row.get(cost_column)),
                "bucket": "",
                "covered_by": "",
                "lookup_bucket": "",
            }
        )
    return flows, fieldnames


def load_protocol_summary(protocol_csv: Path | None, cost_column: str) -> dict[str, dict[str, Any]]:
    if protocol_csv is None:
        return {}
    rows, _ = read_csv(protocol_csv)
    avg_col = {
        "detecting_total_ms": "avg_detecting_total_ms",
        "detecting_detection_only_ms": "avg_detecting_detection_only_ms",
        "detecting_flow_table_ms": "avg_detecting_flow_table_ms",
        "detecting_other_ms": "avg_detecting_other_ms",
    }.get(cost_column)

    summaries: dict[str, dict[str, Any]] = {}
    for row in rows:
        protocol = row.get("protocol", "").strip()
        if not protocol:
            continue
        summaries[protocol] = {
            "summary_flows": parse_float(row.get("flows")),
            "summary_cost_ms": parse_float(row.get(avg_col)) if avg_col else 0.0,
        }
    return summaries


def initial_centers(values: list[float], k: int) -> list[float]:
    sorted_values = sorted(values)
    if not sorted_values:
        return []
    centers = []
    for i in range(k):
        idx = round(i * (len(sorted_values) - 1) / max(1, k - 1))
        centers.append(sorted_values[idx])
    return centers


def kmeans_1d(values: list[float], k: int = 3, max_iter: int = 100) -> tuple[list[int], list[float]]:
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

        next_centers = centers[:]
        for cluster in range(k):
            cluster_values = [
                value for value, assigned in zip(values, assignments) if assigned == cluster
            ]
            if cluster_values:
                next_centers[cluster] = mean(cluster_values)

        if not changed and all(abs(a - b) < 1e-12 for a, b in zip(centers, next_centers)):
            centers = next_centers
            break
        centers = next_centers

    return assignments, centers


def bucket_name_map(centers: list[float]) -> dict[int, str]:
    order = sorted(range(len(centers)), key=lambda idx: centers[idx])
    if len(order) == 1:
        return {order[0]: "Middle"}
    if len(order) == 2:
        return {order[0]: "Easy", order[1]: "Hard"}
    return {cluster_id: label for cluster_id, label in zip(order, BUCKET_LABELS)}


def build_protocol_table(
    flows: list[dict[str, Any]], summaries: dict[str, dict[str, Any]], cost_column: str
) -> list[dict[str, Any]]:
    by_protocol: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        if flow["protocol_detected"] != 1 or flow["protocol"] == "NOT_DETECTED":
            continue
        by_protocol[flow["protocol"]].append(flow)

    protocol_rows: list[dict[str, Any]] = []
    log_values: list[float] = []
    for protocol, items in sorted(by_protocol.items()):
        cost_ms = mean([float(item["detecting_cost_ms"]) for item in items])
        w_us = max(cost_ms * 1000.0, 1e-9)
        summary = summaries.get(protocol, {})
        row = {
            "protocol": protocol,
            "flow_count": len(items),
            "cost_column": cost_column,
            "mean_detecting_cost_ms": cost_ms,
            "W_us": w_us,
            "log_W": math.log(w_us),
            "summary_flows": summary.get("summary_flows", ""),
            "summary_cost_ms": summary.get("summary_cost_ms", ""),
        }
        protocol_rows.append(row)
        log_values.append(row["log_W"])

    if not protocol_rows:
        raise ValueError("no detected protocol rows found in flow CSV")

    assignments, centers = kmeans_1d(log_values, k=3)
    cluster_to_bucket = bucket_name_map(centers)
    for row, assigned in zip(protocol_rows, assignments):
        row["cluster_id"] = assigned
        row["cluster_center_log_W"] = centers[assigned]
        row["cluster_center_W_us"] = math.exp(centers[assigned])
        row["bucket"] = cluster_to_bucket[assigned]

    protocol_rows.sort(key=lambda row: row["W_us"])
    return protocol_rows


def label_flows(flows: list[dict[str, Any]], protocol_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    protocol_to_bucket = {row["protocol"]: row["bucket"] for row in protocol_rows}
    labeled = []
    for flow in flows:
        bucket = protocol_to_bucket.get(flow["protocol"])
        if bucket:
            flow["bucket"] = bucket
            labeled.append(flow)
    return labeled


def build_bucket_representatives(protocol_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compute one scheduling representative cost per bucket.

    The representative is the flow-weighted arithmetic mean of protocol W_us
    inside each bucket.  K-means already groups protocols in log-space, but the
    dispatch cost should reflect the traffic mix seen in profiling, so protocols
    with more flows carry more weight.
    """
    rows: list[dict[str, Any]] = []
    for bucket in BUCKET_LABELS:
        items = [row for row in protocol_rows if row.get("bucket") == bucket]
        if not items:
            rows.append(
                {
                    "bucket": bucket,
                    "representative_W_us": 0.0,
                    "protocol_count": 0,
                    "flow_count": 0,
                    "cluster_center_W_us": 0.0,
                    "min_W_us": 0.0,
                    "max_W_us": 0.0,
                }
            )
            continue

        flow_count = sum(int(row["flow_count"]) for row in items)
        weighted_sum = sum(float(row["W_us"]) * int(row["flow_count"]) for row in items)
        representative = weighted_sum / flow_count if flow_count else mean([float(row["W_us"]) for row in items])
        cluster_centers = [float(row["cluster_center_W_us"]) for row in items]
        values = [float(row["W_us"]) for row in items]
        rows.append(
            {
                "bucket": bucket,
                "representative_W_us": representative,
                "protocol_count": len(items),
                "flow_count": flow_count,
                "cluster_center_W_us": mean(cluster_centers),
                "min_W_us": min(values),
                "max_W_us": max(values),
            }
        )
    return rows


def dominant_bucket(rows: list[dict[str, Any]]) -> tuple[str, int, float]:
    counts = Counter(row["bucket"] for row in rows if row.get("bucket"))
    if not counts:
        return "", 0, 0.0
    bucket, count = counts.most_common(1)[0]
    return bucket, count, count / len(rows) if rows else 0.0


def mark_covered(rows: list[dict[str, Any]], rule_name: str, bucket: str, covered_ids: set[int]) -> None:
    for row in rows:
        row["covered_by"] = rule_name
        row["lookup_bucket"] = bucket
        covered_ids.add(int(row["flow_id"]))


def build_lookup_rules(
    flows: list[dict[str, Any]],
    labeled_flows: list[dict[str, Any]],
    purity_threshold: float,
    min_support: int,
    default_bucket: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    port_groups: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for flow in labeled_flows:
        port_groups[int(flow["dst_port"])].append(flow)

    port_table: dict[str, str] = {}
    special_rules: dict[str, dict[str, dict[str, str]]] = {}
    rule_rows: list[dict[str, Any]] = []
    ambiguous_ports: list[int] = []
    covered_ids: set[int] = set()

    for port, rows in sorted(port_groups.items()):
        bucket, support, purity = dominant_bucket(rows)
        if support >= min_support and purity >= purity_threshold:
            port_table[str(port)] = bucket
            mark_covered(rows, f"port:{port}", bucket, covered_ids)
            rule_rows.append(
                {
                    "level": "port",
                    "port": port,
                    "prefix_type": "",
                    "prefix_value": "",
                    "bucket": bucket,
                    "support": support,
                    "total": len(rows),
                    "purity": purity,
                }
            )
        else:
            ambiguous_ports.append(port)

    for port in ambiguous_ports:
        port_rule: dict[str, dict[str, str]] = {"prefix_1": {}, "prefix_2": {}, "prefix_4": {}}
        for prefix_key in ("prefix_1", "prefix_2", "prefix_4"):
            unresolved = [
                row for row in port_groups[port] if int(row["flow_id"]) not in covered_ids
            ]
            subgroups: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in unresolved:
                prefix_value = row.get(prefix_key, "")
                if prefix_value:
                    subgroups[prefix_value].append(row)

            for prefix_value, rows in sorted(subgroups.items()):
                bucket, support, purity = dominant_bucket(rows)
                if support >= min_support and purity >= purity_threshold:
                    port_rule[prefix_key][prefix_value] = bucket
                    mark_covered(
                        rows,
                        f"{port}:{prefix_key}:{prefix_value}",
                        bucket,
                        covered_ids,
                    )
                    rule_rows.append(
                        {
                            "level": "special",
                            "port": port,
                            "prefix_type": prefix_key,
                            "prefix_value": prefix_value,
                            "bucket": bucket,
                            "support": support,
                            "total": len(rows),
                            "purity": purity,
                        }
                    )

        if any(port_rule[key] for key in port_rule):
            special_rules[str(port)] = port_rule

    for flow in flows:
        if not flow["lookup_bucket"]:
            flow["lookup_bucket"] = default_bucket

    lookup = {
        "default_bucket": default_bucket,
        "purity_threshold": purity_threshold,
        "min_support": min_support,
        "port_table": port_table,
        "special_rules": special_rules,
    }
    report = {
        "total_flows": len(flows),
        "labeled_flows": len(labeled_flows),
        "covered_labeled_flows": len(covered_ids),
        "coverage_labeled": len(covered_ids) / len(labeled_flows) if labeled_flows else 0.0,
        "coverage_all_flows": len(covered_ids) / len(flows) if flows else 0.0,
        "port_rule_count": len(port_table),
        "special_rule_count": sum(
            len(rules["prefix_1"]) + len(rules["prefix_2"]) + len(rules["prefix_4"])
            for rules in special_rules.values()
        ),
        "ambiguous_port_count": len(ambiguous_ports),
        "default_bucket": default_bucket,
        "purity_threshold": purity_threshold,
        "min_support": min_support,
    }
    return lookup, rule_rows, report


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    flow_csv, protocol_csv, output_dir = resolve_paths(args)
    if not flow_csv.exists():
        raise FileNotFoundError(f"flow CSV not found: {flow_csv}")
    output_dir.mkdir(parents=True, exist_ok=True)

    flows, _ = load_flows(flow_csv, args.cost_column)
    summaries = load_protocol_summary(protocol_csv, args.cost_column)
    protocol_rows = build_protocol_table(flows, summaries, args.cost_column)
    bucket_representatives = build_bucket_representatives(protocol_rows)
    labeled_flows = label_flows(flows, protocol_rows)
    lookup, rule_rows, report = build_lookup_rules(
        flows,
        labeled_flows,
        purity_threshold=args.purity,
        min_support=args.min_support,
        default_bucket=args.default_bucket,
    )

    report.update(
        {
            "flow_csv": str(flow_csv),
            "protocol_csv": str(protocol_csv) if protocol_csv else "",
            "output_dir": str(output_dir),
            "cost_column": args.cost_column,
            "protocol_count": len(protocol_rows),
            "bucket_representatives": {
                row["bucket"]: row["representative_W_us"] for row in bucket_representatives
            },
            "bucket_representative_method": "flow_weighted_mean_protocol_W_us",
        }
    )

    write_csv(
        output_dir / "protocol_weight_table.csv",
        protocol_rows,
        [
            "protocol",
            "flow_count",
            "cost_column",
            "mean_detecting_cost_ms",
            "W_us",
            "log_W",
            "cluster_id",
            "cluster_center_log_W",
            "cluster_center_W_us",
            "bucket",
            "summary_flows",
            "summary_cost_ms",
        ],
    )
    write_csv(
        output_dir / "lookup_table.csv",
        rule_rows,
        ["level", "port", "prefix_type", "prefix_value", "bucket", "support", "total", "purity"],
    )
    write_csv(
        output_dir / "bucket_representatives.csv",
        bucket_representatives,
        [
            "bucket",
            "representative_W_us",
            "protocol_count",
            "flow_count",
            "cluster_center_W_us",
            "min_W_us",
            "max_W_us",
        ],
    )
    if args.write_enriched_flows:
        write_csv(
            output_dir / "flow_bucket_table.csv",
            flows,
            [
                "flow_id",
                "dst_port",
                "prefix_1",
                "prefix_2",
                "prefix_4",
                "protocol",
                "protocol_detected",
                "detecting_cost_ms",
                "bucket",
                "covered_by",
                "lookup_bucket",
            ],
        )

    with (output_dir / "lookup_table.json").open("w") as f:
        json.dump(lookup, f, indent=2, sort_keys=True)
    with (output_dir / "training_report.json").open("w") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    print(f"Flow CSV: {flow_csv}")
    print(f"Protocol CSV: {protocol_csv or '(not used)'}")
    print(f"Output dir: {output_dir}")
    print(f"Cost column: {args.cost_column}")
    print(f"Protocols: {len(protocol_rows)}")
    print("Bucket representatives (flow-weighted mean protocol W_us):")
    for row in bucket_representatives:
        print(
            f"  {row['bucket']}: {row['representative_W_us']:.6f} us "
            f"(protocols={row['protocol_count']}, flows={row['flow_count']}, "
            f"cluster_center={row['cluster_center_W_us']:.6f} us, "
            f"range={row['min_W_us']:.6f}-{row['max_W_us']:.6f} us)"
        )
    print(f"Labeled flows: {report['labeled_flows']} / {report['total_flows']}")
    print(f"Coverage labeled: {report['coverage_labeled']:.4f}")
    print(f"Coverage all: {report['coverage_all_flows']:.4f}")
    print(f"Port rules: {report['port_rule_count']}")
    print(f"Special rules: {report['special_rule_count']}")


if __name__ == "__main__":
    main()
