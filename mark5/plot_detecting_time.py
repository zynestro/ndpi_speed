#!/usr/bin/env python3

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


BUCKET_LABELS_3 = ["Easy", "Middle", "Hard"]
BUCKET_COLORS = {
    "Easy": "#4CAF50",
    "Middle": "#FF9800",
    "Hard": "#F44336",
}
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def parse_args():
    parser = argparse.ArgumentParser(description="Visualize detecting_cost_ms from mark5 flow_profile.csv")
    parser.add_argument("--input", default=None, help="Input flow_profile.csv")
    parser.add_argument("--run-dir", default=None, help="Run directory under output/, e.g. output/20260412_123456")
    parser.add_argument("--output-dir", default=None, help="Directory to write plots; default is the same run directory")
    parser.add_argument("--top-n", type=int, default=20, help="Top protocols to show in the mean bar chart")
    parser.add_argument("--min-protocol-flows", type=int, default=5, help="Min flows per protocol to include in protocol charts")
    return parser.parse_args()


def parse_int(value, default=0):
    if value is None or value == "":
        return default
    return int(value)


def parse_float(value, default=0.0):
    if value is None or value == "":
        return default
    return float(value)


def latest_run_dir(output_root: Path):
    candidates = []
    if not output_root.exists():
        return None
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
            raise FileNotFoundError(f"No run directory with flow_profile.csv found under {output_root}")
        input_path = run_dir / "flow_profile.csv"

    output_dir = Path(args.output_dir) if args.output_dir else (run_dir / "plot")
    return input_path, run_dir, output_dir


def load_flows(csv_path: Path):
    flows = []
    with csv_path.open("r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append({
                "flow_id": parse_int(row.get("flow_id")),
                "protocol_detected": parse_int(row.get("protocol_detected")),
                "protocol": row.get("protocol", "NOT_DETECTED"),
                "detecting_cost_ms": parse_float(row.get("detecting_cost_ms")),
                "detecting_detection_only_ms": parse_float(row.get("detecting_detection_only_ms")),
            })
    return flows


def mean(values):
    return sum(values) / len(values) if values else 0.0


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


def protocol_rows_from_flows(flows, min_protocol_flows):
    grouped = defaultdict(list)
    for flow in flows:
        if flow["protocol_detected"] == 1 and flow["protocol"] != "NOT_DETECTED":
            grouped[flow["protocol"]].append(flow["detecting_detection_only_ms"])

    rows = []
    log_values = []
    for protocol, values in grouped.items():
        if len(values) < min_protocol_flows:
            continue
        w_mean_us = mean(values) * 1000.0
        if w_mean_us <= 0.0:
            w_mean_us = 1e-6
        rows.append({
            "protocol": protocol,
            "flow_count": len(values),
            "detecting_detection_only_mean_ms": mean(values),
            "W_mean_us": w_mean_us,
            "log_W": math.log(w_mean_us),
        })
        log_values.append(math.log(w_mean_us))

    assignments, centers = kmeans_1d(log_values, k=3)
    cluster_to_bucket = bucket_name_map(centers)
    for row, assign in zip(rows, assignments):
        row["cluster_id"] = assign
        row["bucket"] = cluster_to_bucket[assign]
        row["cluster_center_log_W"] = centers[assign]

    rows.sort(key=lambda row: row["W_mean_us"])
    return rows, centers


def save_flow_histogram(flows, output_path: Path):
    values = [flow["detecting_detection_only_ms"] for flow in flows]
    if not values:
        return

    plt.figure(figsize=(10, 6))
    plt.hist(values, bins=80, color="#1f77b4", alpha=0.85)
    plt.xlabel("detecting_detection_only_ms per flow")
    plt.ylabel("Flow count")
    plt.title("Per-flow Detecting-Only Cost Distribution")
    plt.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def save_flow_histogram_log(flows, output_path: Path):
    values = [max(flow["detecting_detection_only_ms"], 1e-6) for flow in flows]
    if not values:
        return

    log_values = [math.log10(v) for v in values]
    plt.figure(figsize=(10, 6))
    plt.hist(log_values, bins=80, color="#6a5acd", alpha=0.85)
    plt.xlabel("log10(detecting_detection_only_ms)")
    plt.ylabel("Flow count")
    plt.title("Per-flow Detecting-Only Cost Distribution (log scale)")
    plt.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def save_protocol_bar(rows, output_path: Path, top_n: int):
    if not rows:
        return
    top_rows = sorted(rows, key=lambda row: row["detecting_detection_only_mean_ms"], reverse=True)[:top_n]
    labels = [row["protocol"] for row in top_rows]
    values = [row["detecting_detection_only_mean_ms"] for row in top_rows]
    colors = [BUCKET_COLORS.get(row["bucket"], "#888888") for row in top_rows]

    plt.figure(figsize=(12, max(6, len(top_rows) * 0.35)))
    plt.barh(labels, values, color=colors)
    plt.xlabel("Average detecting_detection_only_ms")
    plt.ylabel("Protocol")
    plt.title(f"Top {len(top_rows)} Protocols by Average Detecting-Only Cost")
    plt.gca().invert_yaxis()
    plt.grid(axis="x", alpha=0.2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def save_protocol_bucket_plot(rows, output_path: Path):
    if not rows:
        return

    xs = list(range(len(rows)))
    ys = [row["W_mean_us"] for row in rows]
    colors = [BUCKET_COLORS.get(row["bucket"], "#888888") for row in rows]

    plt.figure(figsize=(12, 6))
    plt.scatter(xs, ys, c=colors, s=45, alpha=0.9)
    plt.yscale("log")
    plt.xlabel("Protocols sorted by W_mean_us")
    plt.ylabel("W_mean_us (log scale)")
    plt.title("Protocol Detecting Cost Means and Bucket Assignment")
    plt.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=180)
    plt.close()


def write_protocol_table(rows, output_path: Path):
    with output_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "protocol",
                "flow_count",
                "detecting_detection_only_mean_ms",
                "W_mean_us",
                "log_W",
                "cluster_id",
                "cluster_center_log_W",
                "bucket",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    args = parse_args()
    input_path, run_dir, output_dir = resolve_paths(args)
    output_dir.mkdir(parents=True, exist_ok=True)

    flows = load_flows(input_path)
    protocol_rows, centers = protocol_rows_from_flows(flows, args.min_protocol_flows)

    save_flow_histogram(flows, output_dir / "detecting_only_cost_hist.png")
    save_flow_histogram_log(flows, output_dir / "detecting_only_cost_hist_log.png")
    save_protocol_bar(protocol_rows, output_dir / "protocol_detecting_only_mean_top.png", args.top_n)
    save_protocol_bucket_plot(protocol_rows, output_dir / "protocol_bucket_scatter.png")
    write_protocol_table(protocol_rows, output_dir / "protocol_detecting_only_means.csv")

    summary = {
        "input": str(input_path),
        "run_dir": str(run_dir),
        "output_dir": str(output_dir),
        "flow_count": len(flows),
        "overall_detecting_detection_only_mean_ms": mean([flow["detecting_detection_only_ms"] for flow in flows]),
        "w_basis": "detecting_detection_only_ms",
        "protocol_count": len(protocol_rows),
        "bucket_centers_log_W": centers,
        "bucket_centers_W_mean_us": [math.exp(center) for center in centers],
    }
    with (output_dir / "detecting_only_time_plot_summary.json").open("w") as f:
        json.dump(summary, f, indent=2)

    print(f"Input: {input_path}")
    print(f"Run dir: {run_dir}")
    print(f"Output dir: {output_dir}")
    print(f"Flow count: {summary['flow_count']}")
    print(f"Overall mean detecting_detection_only_ms: {summary['overall_detecting_detection_only_mean_ms']:.6f}")
    print(f"Protocol count used for buckets: {summary['protocol_count']}")
    if centers:
        print("Bucket centers (W_mean_us): " + ", ".join(f"{math.exp(center):.3f}" for center in centers))


if __name__ == "__main__":
    main()
