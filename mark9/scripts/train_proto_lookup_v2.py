#!/usr/bin/env python3
"""mark9 Proto-Level Lookup Table Trainer (v2) — streaming edition

Pipeline:
1. Pass 1: stream CSV → accumulate port→proto counts + proto→cost sums
2. Determine port_rules + ambiguous_ports from pass 1 counters
3. Pass 2: stream CSV → accumulate prefix disambiguation counts (ambiguous ports only)
4. Output: proto_lookup_table.json (v2) + proto_cost_prior.csv

The v2 format replaces mark7's 3-bucket output with per-protocol proto_hint,
enabling the EWMA adaptive cost table to use fine-grained cost priors.

Memory: O(unique_ports × unique_protos) ≈ tens of MB, instead of O(rows) ≈ 15 GB.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_RUN_DIR = "output/20260424_232908"
BUCKET_LABELS = ["Easy", "Middle", "Hard"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train mark9 v2 proto-level lookup table from mark5 flow CSV."
    )
    parser.add_argument(
        "--run-dir",
        default=DEFAULT_RUN_DIR,
        help=f"mark5 run directory (default: {DEFAULT_RUN_DIR})",
    )
    parser.add_argument("--flow-csv", default=None, help="Override per-flow CSV path.")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: <run-dir>/proto_lookup_v2).",
    )
    parser.add_argument(
        "--cost-column",
        default="detecting_total_ms",
        help="Per-flow cost column (default: detecting_total_ms).",
    )
    parser.add_argument(
        "--purity",
        type=float,
        default=0.90,
        help="Minimum purity for port->proto rule (default: 0.90, relaxed from mark7's 0.95).",
    )
    parser.add_argument(
        "--min-support",
        type=int,
        default=5,
        help="Minimum flow count for a rule (default: 5).",
    )
    return parser.parse_args()


def resolve_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    run_dir = Path(args.run_dir)
    flow_csv = Path(args.flow_csv) if args.flow_csv else run_dir / "time_flow_profile.csv"
    output_dir = (
        Path(args.output_dir) if args.output_dir else run_dir / "proto_lookup_v2"
    )
    return flow_csv, output_dir


# ── lightweight row parser (returns plain tuple, not dict) ──────────────

def parse_float(val: str | None, default: float = 0.0) -> float:
    if val is None or val == "":
        return default
    return float(val)


def parse_int(val: str | None, default: int = 0) -> int:
    if val is None or val == "":
        return default
    return int(float(val))


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


# ── Pass 1: stream CSV → accumulate port→proto counts + proto→cost sums ─

def pass1(
    flow_csv: Path, cost_column: str,
) -> tuple[dict[int, Counter], dict[str, tuple[float, int]], set[int]]:
    """Stream CSV once. Return (port_counter, proto_cost_accum, all_ports).

    port_counter:  {port: Counter({proto_name: count, ...})}
    proto_cost_accum: {proto_name: (sum_cost_ms, count)}
    all_ports: set of all dst_port values (for summary reporting)
    """
    port_counter: dict[int, Counter] = defaultdict(Counter)
    proto_cost_accum: dict[str, tuple[float, int]] = defaultdict(lambda: (0.0, 0))
    all_ports: set[int] = set()

    with flow_csv.open("r", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = [name.strip() for name in (reader.fieldnames or [])]

        if cost_column not in fieldnames:
            raise ValueError(f"cost column not found: {cost_column}")
        if "protocol" not in fieldnames:
            raise ValueError("flow CSV must contain 'protocol' column")

        for row in reader:
            protocol = (row.get("protocol") or "NOT_DETECTED").strip()
            if protocol == "NOT_DETECTED":
                continue

            # protocol_detected
            pd_val = (row.get("protocol_detected") or "1").strip()
            protocol_detected = int(float(pd_val)) if pd_val else 1
            if protocol_detected != 1:
                continue

            port_str = (row.get("dst_port") or row.get("server_port") or "").strip()
            if not port_str:
                continue
            dst_port = int(float(port_str))

            all_ports.add(dst_port)
            port_counter[dst_port][protocol] += 1

            cost_ms = parse_float((row.get(cost_column) or "").strip())
            prev_sum, prev_cnt = proto_cost_accum[protocol]
            proto_cost_accum[protocol] = (prev_sum + cost_ms, prev_cnt + 1)

    return dict(port_counter), dict(proto_cost_accum), all_ports


# ── Pass 2: stream CSV → accumulate prefix disambiguation (ambiguous ports only) ─

def pass2(
    flow_csv: Path, cost_column: str, ambiguous_ports: set[int],
) -> dict[int, dict[str, dict[str, Counter]]]:
    """Stream CSV again. Only process flows whose dst_port is in ambiguous_ports.

    Returns: {port: {"prefix_1": {prefix_val: Counter}, "prefix_2": {...}, "prefix_4": {...}}}
    """
    prefix_data: dict[int, dict[str, dict[str, Counter]]] = defaultdict(
        lambda: {"prefix_1": defaultdict(Counter), "prefix_2": defaultdict(Counter), "prefix_4": defaultdict(Counter)}
    )

    with flow_csv.open("r", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            protocol = (row.get("protocol") or "NOT_DETECTED").strip()
            if protocol == "NOT_DETECTED":
                continue

            pd_val = (row.get("protocol_detected") or "1").strip()
            protocol_detected = int(float(pd_val)) if pd_val else 1
            if protocol_detected != 1:
                continue

            port_str = (row.get("dst_port") or row.get("server_port") or "").strip()
            if not port_str:
                continue
            dst_port = int(float(port_str))

            if dst_port not in ambiguous_ports:
                continue

            prefix_4 = normalize_prefix(row.get("prefix_4", ""))
            for prefix_key, prefix_val in [
                ("prefix_1", normalize_prefix(row.get("prefix_1", "")) or prefix_slice(prefix_4, 1)),
                ("prefix_2", normalize_prefix(row.get("prefix_2", "")) or prefix_slice(prefix_4, 2)),
                ("prefix_4", prefix_4),
            ]:
                if prefix_val:
                    prefix_data[dst_port][prefix_key][prefix_val][protocol] += 1

    # Convert to plain dicts for downstream use
    result: dict[int, dict[str, dict[str, Counter]]] = {}
    for port, by_key in prefix_data.items():
        result[port] = {}
        for pkey, by_val in by_key.items():
            result[port][pkey] = dict(by_val)
    return result


# ── Rule builders (operate on counters, not raw flows) ──────────────────

def compute_proto_costs(
    proto_cost_accum: dict[str, tuple[float, int]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for proto, (sum_ms, cnt) in sorted(proto_cost_accum.items()):
        result[proto] = {
            "mean_cost_us": (sum_ms / cnt) * 1000.0,  # ms → us
            "flow_count": cnt,
        }
    return result


def build_port_rules(
    port_counter: dict[int, Counter],
    purity_threshold: float,
    min_support: int,
) -> tuple[dict[str, dict[str, Any]], set[int]]:
    """Build port -> proto_hint rules from aggregated counters."""
    port_rules: dict[str, dict[str, Any]] = {}
    ambiguous_ports: set[int] = set()

    for port, proto_counts in sorted(port_counter.items()):
        total = sum(proto_counts.values())
        dominant_proto, dominant_count = proto_counts.most_common(1)[0]
        purity = dominant_count / total

        if purity >= purity_threshold and total >= min_support:
            port_rules[str(port)] = {
                "proto_hint": dominant_proto,
                "purity": round(purity, 4),
                "support": total,
            }
        else:
            ambiguous_ports.add(port)

    return port_rules, ambiguous_ports


def build_prefix_rules(
    prefix_data: dict[int, dict[str, dict[str, Counter]]],
    ambiguous_ports: set[int],
    purity_threshold: float,
    min_support: int,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Build prefix disambiguation rules from pass 2 data."""
    prefix_rules: dict[str, dict[str, dict[str, Any]]] = {}

    for port in sorted(ambiguous_ports):
        if port not in prefix_data:
            continue

        port_rule: dict[str, dict[str, Any]] = {}
        by_key = prefix_data[port]

        for prefix_key in ("prefix_1", "prefix_2", "prefix_4"):
            by_val = by_key.get(prefix_key, {})
            for prefix_val, proto_counts in sorted(by_val.items()):
                sub_total = sum(proto_counts.values())
                sub_dominant, sub_count = proto_counts.most_common(1)[0]
                sub_purity = sub_count / sub_total

                if sub_purity >= purity_threshold and sub_total >= min_support:
                    prefix_len = int(prefix_key[-1])
                    port_rule[prefix_val] = {
                        "proto_hint": sub_dominant,
                        "prefix_len": prefix_len,
                        "purity": round(sub_purity, 4),
                    }

        if port_rule:
            prefix_rules[str(port)] = port_rule

    return prefix_rules


# ── Main ────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    flow_csv, output_dir = resolve_paths(args)

    if not flow_csv.exists():
        raise FileNotFoundError(f"flow CSV not found: {flow_csv}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Pass 1: port→proto + proto→cost ──
    print("Pass 1/2: streaming CSV, accumulating port→proto + proto→cost ...")
    port_counter, proto_cost_accum, all_ports = pass1(flow_csv, args.cost_column)
    print(f"  Unique ports: {len(all_ports)}, unique protocols: {len(proto_cost_accum)}")

    proto_costs = compute_proto_costs(proto_cost_accum)
    port_rules, ambiguous_ports = build_port_rules(
        port_counter, args.purity, args.min_support
    )
    print(f"  Port rules: {len(port_rules)}, ambiguous: {len(ambiguous_ports)}")

    # ── Pass 2: prefix disambiguation ──
    prefix_rules: dict[str, dict[str, dict[str, Any]]] = {}
    if ambiguous_ports:
        print(f"Pass 2/2: streaming CSV, accumulating prefix data for {len(ambiguous_ports)} ambiguous ports ...")
        prefix_data = pass2(flow_csv, args.cost_column, ambiguous_ports)
        prefix_rules = build_prefix_rules(
            prefix_data, ambiguous_ports, args.purity, args.min_support
        )
        print(f"  Prefix rules: {len(prefix_rules)} ports with sub-rules")
    else:
        print("Pass 2/2: skipped (no ambiguous ports)")

    # ── Build proto_cost_prior ──
    proto_cost_prior = {
        name: round(info["mean_cost_us"], 3)
        for name, info in sorted(proto_costs.items(), key=lambda x: x[1]["mean_cost_us"])
    }

    # ── Write v2 JSON ──
    output = {
        "version": 2,
        "description": "mark9 proto-level lookup table",
        "purity_threshold": args.purity,
        "min_support": args.min_support,
        "port_rules": port_rules,
        "prefix_rules": prefix_rules,
        "proto_cost_prior": proto_cost_prior,
        "default_proto_hint": "UNKNOWN",
    }

    json_path = output_dir / "proto_lookup_table.json"
    with json_path.open("w") as f:
        json.dump(output, f, indent=2)

    csv_path = output_dir / "proto_cost_prior.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["protocol", "mean_cost_us", "flow_count"])
        for name, info in sorted(proto_costs.items(), key=lambda x: x[1]["mean_cost_us"]):
            writer.writerow([name, f"{info['mean_cost_us']:.3f}", info["flow_count"]])

    # ── Summary ──
    print(f"\nFlow CSV: {flow_csv}")
    print(f"Output dir: {output_dir}")
    print(f"Cost column: {args.cost_column}")
    print(f"Purity threshold: {args.purity}")
    print(f"Min support: {args.min_support}")
    print(f"Protocols in cost table: {len(proto_costs)}")
    print(f"Port rules: {len(port_rules)}/{len(all_ports)} ports")
    print(f"Prefix disambiguation: {len(prefix_rules)} ports with sub-rules")
    unresolved = len(ambiguous_ports) - len(prefix_rules)
    print(f"Ambiguous (fallback): {unresolved} ports")
    print(f"\nOutput files:")
    print(f"  {json_path}")
    print(f"  {csv_path}")


if __name__ == "__main__":
    main()
