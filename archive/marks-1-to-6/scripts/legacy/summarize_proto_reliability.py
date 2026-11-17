#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
import statistics
from collections import defaultdict
from pathlib import Path


FILENAME_RE = re.compile(r"^(?P<pcap>.+)_core(?P<core>\d+)_.*\.csv$")
METRIC_FIELDS = ["avg_flow_detecting_ms", "detecting_pkt_p50_us"]


def normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {str(k).strip(): str(v).strip() for k, v in row.items()}


def to_float(value: str) -> float:
    try:
        return float(value)
    except Exception:
        return float("nan")


def parse_name(csv_path: Path) -> tuple[str, str]:
    match = FILENAME_RE.match(csv_path.name)
    if not match:
        raise ValueError(
            f"cannot parse pcap/core from filename: {csv_path.name} "
            "(expected something like normal_1_core0_proto_category_summary_merged.csv)"
        )
    return match.group("pcap"), match.group("core")


def load_proto_rows(csv_path: Path) -> dict[str, dict[str, float]]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        rows = [normalize_row(row) for row in reader]

    out: dict[str, dict[str, float]] = {}
    for row in rows:
        proto = row.get("proto_name", "").strip()
        if not proto:
            continue
        out[proto] = {field: to_float(row.get(field, "")) for field in METRIC_FIELDS}
    return out


def collect(input_dir: Path) -> dict[str, dict[str, dict[str, list[float]]]]:
    grouped: dict[str, dict[str, dict[str, list[float]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )

    for csv_path in sorted(input_dir.glob("*.csv")):
        pcap_name, core = parse_name(csv_path)
        proto_rows = load_proto_rows(csv_path)
        for proto_name, metrics in proto_rows.items():
            for field, value in metrics.items():
                grouped[core][proto_name][field].append(value)
            grouped[core][proto_name]["pcap_names"].append(pcap_name)
    return grouped


def build_rows(core_data: dict[str, dict[str, list[float]]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for proto_name, metric_map in core_data.items():
        detecting_vals = metric_map["avg_flow_detecting_ms"]
        p50_vals = metric_map["detecting_pkt_p50_us"]
        pcap_names = sorted(metric_map["pcap_names"])

        n = len(pcap_names)
        row = {
            "proto_name": proto_name,
            "pcap_count": str(n),
            "pcap_names": ",".join(pcap_names),
            "avg_flow_detecting_ms_mean": f"{statistics.mean(detecting_vals):.6f}",
            "avg_flow_detecting_ms_var": f"{(statistics.variance(detecting_vals) if n > 1 else 0.0):.6f}",
            "detecting_pkt_p50_us_mean": f"{statistics.mean(p50_vals):.6f}",
            "detecting_pkt_p50_us_var": f"{(statistics.variance(p50_vals) if n > 1 else 0.0):.6f}",
        }
        rows.append(row)

    rows.sort(key=lambda row: row["proto_name"])
    return rows


def write_rows(rows: list[dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "proto_name",
                "pcap_count",
                "pcap_names",
                "avg_flow_detecting_ms_mean",
                "avg_flow_detecting_ms_var",
                "detecting_pkt_p50_us_mean",
                "detecting_pkt_p50_us_var",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize merged proto CSVs by core and compute per-proto mean/variance across pcaps."
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        help="Directory containing files like normal_1_core0_proto_category_summary_merged.csv",
    )
    parser.add_argument(
        "--out-dir",
        default="",
        help="Output directory. Default: <input-dir>/proto_reliability_summary",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.exists():
        raise SystemExit(f"input dir not found: {input_dir}")

    out_dir = Path(args.out_dir).resolve() if args.out_dir else (input_dir / "proto_reliability_summary")
    grouped = collect(input_dir)
    if not grouped:
        raise SystemExit(f"no csv files found in: {input_dir}")

    for core, core_data in sorted(grouped.items(), key=lambda item: int(item[0])):
        out_path = out_dir / f"core{core}_proto_reliability_summary.csv"
        rows = build_rows(core_data)
        write_rows(rows, out_path)
        print(f"Saved: {out_path} ({len(rows)} protos)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
