#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


WEIGHTED_FIELDS = [
    "avg_flow_detecting_ms",
    "avg_flow_post_ms",
    "avg_flow_total_ms",
    "detecting_pkt_p50_us",
    "detecting_pkt_p99_us",
    "post_pkt_p50_us",
    "post_pkt_p99_us",
    "avg_detect_pkt_flow",
    "avg_detect_pkt_global",
]

OUTPUT_FIELDS = [
    "proto_name",
    "master_proto",
    "app_proto",
    "category_name",
    "category_id",
    "flows",
    *WEIGHTED_FIELDS,
]


def normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {str(key).strip(): str(value).strip().strip('"') for key, value in row.items()}


def to_int(value: str) -> int:
    try:
        return int(float(value))
    except Exception:
        return 0


def to_float(value: str) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def fmt_int(value: int) -> str:
    return str(value)


def fmt_float(value: float) -> str:
    return f"{value:.6f}"


def load_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        rows = [normalize_row(row) for row in reader]
    if not rows:
        raise ValueError(f"empty csv: {csv_path}")
    return rows


def base_proto_name(name: str) -> str:
    return name.split(".", 1)[0].strip()


def group_key_proto(row: dict[str, str]) -> str:
    return row["proto_name"]


def group_key_base_proto(row: dict[str, str]) -> str:
    return base_proto_name(row["proto_name"])


def aggregate_rows(rows: list[dict[str, str]], key_fn) -> list[dict[str, str]]:
    grouped: dict[str, dict] = {}

    for row in rows:
        group_name = key_fn(row)
        flows = to_int(row.get("flows", "0"))
        state = grouped.setdefault(
            group_name,
            {
                "proto_name": group_name,
                "flows": 0,
                "weighted_sums": defaultdict(float),
                "label_counts": defaultdict(int),
            },
        )

        state["flows"] += flows
        for field in WEIGHTED_FIELDS:
            state["weighted_sums"][field] += to_float(row.get(field, "0")) * flows

        label_key = (
            to_int(row.get("master_proto", "0")),
            to_int(row.get("app_proto", "0")),
            row.get("category_name", ""),
            to_int(row.get("category_id", "0")),
        )
        state["label_counts"][label_key] += flows

    out: list[dict[str, str]] = []
    for proto_name, state in grouped.items():
        flows = state["flows"]
        if flows <= 0:
            continue

        dominant = max(
            state["label_counts"].items(),
            key=lambda item: (item[1], item[0][0], item[0][1], item[0][3], item[0][2]),
        )[0]
        master_proto, app_proto, category_name, category_id = dominant

        row = {
            "proto_name": proto_name,
            "master_proto": fmt_int(master_proto),
            "app_proto": fmt_int(app_proto),
            "category_name": category_name,
            "category_id": fmt_int(category_id),
            "flows": fmt_int(flows),
        }
        for field in WEIGHTED_FIELDS:
            row[field] = fmt_float(state["weighted_sums"][field] / flows)
        out.append(row)

    out.sort(key=lambda row: to_int(row["flows"]), reverse=True)
    return out


def write_rows(rows: list[dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)


def resolve_output_path(csv_path: Path, out_path: str) -> Path:
    if out_path:
        candidate = Path(out_path)
        if candidate.is_absolute():
            return candidate.resolve()
        return (csv_path.parent / candidate).resolve()
    return csv_path.with_name(f"{csv_path.stem}_merged.csv")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Merge mark4 proto_category_summary.csv by proto_name, then by dotted proto prefix."
    )
    parser.add_argument("--csv", required=True, help="Input proto_category_summary.csv path")
    parser.add_argument(
        "--out",
        default="",
        help="Output CSV path. Relative paths are resolved under the input CSV directory.",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    if not csv_path.exists():
        raise SystemExit(f"csv not found: {csv_path}")

    out_path = resolve_output_path(csv_path, args.out)
    rows = load_rows(csv_path)
    merged_by_proto = aggregate_rows(rows, group_key_proto)
    merged_by_base = aggregate_rows(merged_by_proto, group_key_base_proto)
    write_rows(merged_by_base, out_path)

    print(f"Loaded rows: {len(rows)}")
    print(f"After proto merge: {len(merged_by_proto)}")
    print(f"After dotted-prefix merge: {len(merged_by_base)}")
    print(f"Saved: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
