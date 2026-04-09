#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def to_float(value: str) -> float:
    try:
        return float(value)
    except Exception:
        return float("nan")


def to_int(value: str) -> int:
    try:
        return int(float(value))
    except Exception:
        return 0


def load_rows(csv_path: Path) -> list[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"empty csv: {csv_path}")
    return rows


def row_label(row: dict) -> str:
    return f"{row['proto_name']} | {row['category_name']}"


def aggregate_by_category(rows: list[dict]) -> list[dict]:
    agg: dict[str, dict] = defaultdict(lambda: {
        "category_name": "",
        "flows": 0,
        "sum_detecting": 0.0,
        "sum_post": 0.0,
        "sum_total": 0.0,
    })

    for row in rows:
        cat = row["category_name"]
        flows = to_int(row["flows"])
        detecting = to_float(row["avg_flow_detecting_ms"])
        post = to_float(row["avg_flow_post_ms"])
        total = to_float(row["avg_flow_total_ms"])

        st = agg[cat]
        st["category_name"] = cat
        st["flows"] += flows
        st["sum_detecting"] += detecting * flows
        st["sum_post"] += post * flows
        st["sum_total"] += total * flows

    out = []
    for cat, st in agg.items():
        flows = st["flows"]
        if flows <= 0:
            continue
        out.append({
            "category_name": cat,
            "flows": flows,
            "avg_flow_detecting_ms": st["sum_detecting"] / flows,
            "avg_flow_post_ms": st["sum_post"] / flows,
            "avg_flow_total_ms": st["sum_total"] / flows,
        })
    out.sort(key=lambda x: x["flows"], reverse=True)
    return out


def make_dashboard(rows: list[dict], out_png: Path, top_n: int, min_flows: int) -> None:
    filtered = [r for r in rows if to_int(r["flows"]) >= min_flows]
    if not filtered:
        raise ValueError(f"no rows left after min_flows={min_flows}")

    top_flow_rows = sorted(filtered, key=lambda r: to_int(r["flows"]), reverse=True)[:top_n]
    top_total_rows = sorted(filtered, key=lambda r: to_float(r["avg_flow_total_ms"]), reverse=True)[:top_n]
    top_detect_rows = sorted(filtered, key=lambda r: to_float(r["avg_flow_detecting_ms"]), reverse=True)[:top_n]
    cat_rows = aggregate_by_category(filtered)[:top_n]

    fig, axes = plt.subplots(2, 2, figsize=(18, 11))

    ax = axes[0, 0]
    labels = [row_label(r) for r in reversed(top_flow_rows)]
    vals = [to_int(r["flows"]) for r in reversed(top_flow_rows)]
    ax.barh(labels, vals, color="#4C78A8")
    ax.set_title(f"Top {len(top_flow_rows)} Proto+Category by Flow Count")
    ax.set_xlabel("Flows")
    ax.grid(axis="x", alpha=0.3)

    ax = axes[0, 1]
    x = [to_float(r["avg_flow_detecting_ms"]) for r in filtered]
    y = [to_float(r["avg_flow_post_ms"]) for r in filtered]
    s = [max(20.0, math.sqrt(max(1, to_int(r["flows"]))) * 3.0) for r in filtered]
    ax.scatter(x, y, s=s, alpha=0.55, color="#F58518", edgecolors="black", linewidths=0.3)
    for r in sorted(filtered, key=lambda r: to_int(r["flows"]), reverse=True)[: min(10, len(filtered))]:
        ax.annotate(
            row_label(r),
            (to_float(r["avg_flow_detecting_ms"]), to_float(r["avg_flow_post_ms"])),
            fontsize=8,
            alpha=0.85,
        )
    ax.set_title("Detecting vs Post Cost")
    ax.set_xlabel("avg_flow_detecting_ms")
    ax.set_ylabel("avg_flow_post_ms")
    ax.grid(alpha=0.3)

    ax = axes[1, 0]
    labels = [row_label(r) for r in reversed(top_total_rows)]
    vals = [to_float(r["avg_flow_total_ms"]) for r in reversed(top_total_rows)]
    ax.barh(labels, vals, color="#54A24B")
    ax.set_title(f"Top {len(top_total_rows)} by avg_flow_total_ms")
    ax.set_xlabel("Milliseconds")
    ax.grid(axis="x", alpha=0.3)

    ax = axes[1, 1]
    cats = [r["category_name"] for r in reversed(cat_rows)]
    detecting = [to_float(r["avg_flow_detecting_ms"]) for r in reversed(cat_rows)]
    post = [to_float(r["avg_flow_post_ms"]) for r in reversed(cat_rows)]
    y_pos = range(len(cats))
    ax.barh(list(y_pos), detecting, color="#E45756", label="detecting")
    ax.barh(list(y_pos), post, left=detecting, color="#72B7B2", label="post")
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(cats)
    ax.set_title(f"Top {len(cat_rows)} Categories by Flow Count")
    ax.set_xlabel("Weighted avg flow cost (ms)")
    ax.grid(axis="x", alpha=0.3)
    ax.legend(loc="best")

    fig.suptitle("mark4 Proto+Category Summary Dashboard", fontsize=14)
    fig.tight_layout(rect=[0, 0.02, 1, 0.96])
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=170)
    plt.close(fig)


def write_category_csv(rows: list[dict], out_csv: Path) -> None:
    cats = aggregate_by_category(rows)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "category_name",
                "flows",
                "avg_flow_detecting_ms",
                "avg_flow_post_ms",
                "avg_flow_total_ms",
            ],
        )
        writer.writeheader()
        writer.writerows(cats)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Visualize mark4 proto_category_summary.csv"
    )
    parser.add_argument("--csv", required=True, help="Path to mark4 proto_category_summary.csv")
    parser.add_argument(
        "--out",
        default="",
        help="Output PNG path (default: <csv_dir>/mark4_proto_dashboard.png)",
    )
    parser.add_argument(
        "--category-csv",
        default="",
        help="Optional category summary CSV path (default: <csv_dir>/mark4_category_summary.csv)",
    )
    parser.add_argument("--top-n", type=int, default=15, help="Top N rows to highlight")
    parser.add_argument("--min-flows", type=int, default=10, help="Ignore rows below this flow count")
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    if not csv_path.exists():
        raise SystemExit(f"csv not found: {csv_path}")

    out_png = Path(args.out).resolve() if args.out else (csv_path.parent / "mark4_proto_dashboard.png")
    cat_csv = Path(args.category_csv).resolve() if args.category_csv else (csv_path.parent / "mark4_category_summary.csv")

    rows = load_rows(csv_path)
    make_dashboard(rows, out_png, top_n=args.top_n, min_flows=args.min_flows)
    write_category_csv(rows, cat_csv)

    print(f"Saved: {out_png}")
    print(f"Saved: {cat_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
