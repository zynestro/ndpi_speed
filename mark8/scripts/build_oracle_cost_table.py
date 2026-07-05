#!/usr/bin/env python3
"""Build a mark7 oracle cost table from mark5 time_flow_profile.csv."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--flow-csv", required=True, help="mark5 time_flow_profile.csv with flow_hash")
    ap.add_argument("--output", required=True, help="Output CSV path: flow_hash,cost_us")
    ap.add_argument("--cost-column", default="detecting_total_ms", help="Cost column in milliseconds")
    ap.add_argument("--detected-only", action="store_true", help="Keep only protocol_detected=1 rows")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    flow_csv = Path(args.flow_csv)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    with flow_csv.open(newline="") as src, out.open("w", newline="") as dst:
        reader = csv.DictReader(src)
        if "flow_hash" not in (reader.fieldnames or []):
            raise SystemExit(f"{flow_csv} has no flow_hash column; rebuild mark5 first")
        if args.cost_column not in (reader.fieldnames or []):
            raise SystemExit(f"{flow_csv} has no {args.cost_column} column")

        writer = csv.DictWriter(dst, fieldnames=["flow_hash", "cost_us"])
        writer.writeheader()
        rows = 0
        for row in reader:
            if args.detected_only and str(row.get("protocol_detected", "")).strip() != "1":
                continue
            flow_hash = str(row.get("flow_hash", "")).strip()
            if not flow_hash:
                continue
            try:
                cost_ms = float(str(row.get(args.cost_column, "0")).strip() or 0.0)
            except ValueError:
                continue
            writer.writerow({"flow_hash": flow_hash, "cost_us": f"{cost_ms * 1000.0:.6f}"})
            rows += 1

    print(f"Wrote {rows} oracle rows: {out}")


if __name__ == "__main__":
    main()
