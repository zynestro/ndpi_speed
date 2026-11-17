#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception as e:
    raise SystemExit(
        "matplotlib is required for this script. Install python3-matplotlib first. "
        f"Import error: {e}"
    )


DEFAULT_VARIANTS = {
    "mark": "20260306_095830-mark",
    "classified": "20260306_100137-classified",
    "batch": "20260306_100436-batch",
}

METRICS = [
    ("pcap-next", "read_pcap_sec"),
    ("enqueue", "read_enqueue_sec"),
    ("parse", "proc_parse_sec"),
    ("flow", "proc_flow_sec"),
    ("ndpi", "proc_ndpi_sec"),
    ("other", "proc_other_sec"),
]

COLORS = {
    "mark": "#1f77b4",
    "classified": "#ff7f0e",
    "batch": "#2ca02c",
}


def find_csv_file(variant_dir: Path) -> Path:
    csv_files = sorted(variant_dir.glob("benchmark_results_*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No benchmark_results_*.csv found in {variant_dir}")
    return csv_files[0]


def load_csv_rows(csv_path: Path):
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []
        rows = list(reader)
    if not headers:
        raise ValueError(f"CSV has no header: {csv_path}")
    return rows, headers


def write_combined_all_csv(out_path: Path, data, source_dirs, all_headers):
    headers = ["variant", "source_dir"] + all_headers
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for variant in ["mark", "classified", "batch"]:
            for row in data[variant]:
                out_row = {h: "" for h in headers}
                out_row["variant"] = variant
                out_row["source_dir"] = source_dirs[variant]
                for h in all_headers:
                    if h in row:
                        out_row[h] = row[h]
                writer.writerow(out_row)


def write_metric_long_csv(out_path: Path, data):
    headers = ["variant", "workers", "metric", "column", "time_sec"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for variant in ["mark", "classified", "batch"]:
            for row in data[variant]:
                for metric_name, col in METRICS:
                    writer.writerow(
                        {
                            "variant": variant,
                            "workers": row["workers"],
                            "metric": metric_name,
                            "column": col,
                            "time_sec": row[col],
                        }
                    )


def main():
    parser = argparse.ArgumentParser(description="3x2 dashboard for main time breakdown")
    parser.add_argument("--output-root", default="output", help="Root output directory")
    parser.add_argument(
        "--result-dir",
        default="output/20260306_main_time_compare",
        help="Directory for generated files",
    )
    parser.add_argument(
        "--out",
        default="output/20260306_main_time_compare/main_time_dashboard_0306_matplotlib.png",
        help="Output PNG path for 3x2 dashboard",
    )
    args = parser.parse_args()

    output_root = Path(args.output_root).resolve()
    result_dir = Path(args.result_dir).resolve()
    out_png = Path(args.out).resolve()

    rows_by_variant = {}
    source_dirs = {}
    all_headers = []

    for variant, dirname in DEFAULT_VARIANTS.items():
        csv_path = find_csv_file(output_root / dirname)
        rows, headers = load_csv_rows(csv_path)
        rows_by_variant[variant] = rows
        source_dirs[variant] = dirname
        for h in headers:
            if h not in all_headers:
                all_headers.append(h)

    worker_set = set()
    for rows in rows_by_variant.values():
        for row in rows:
            worker_set.add(int(row["workers"]))
    workers = sorted(worker_set)

    write_combined_all_csv(result_dir / "combined_all_rows_0306.csv", rows_by_variant, source_dirs, all_headers)
    write_metric_long_csv(result_dir / "combined_main_time_long_0306.csv", rows_by_variant)

    plt.rcdefaults()
    fig, axes = plt.subplots(3, 2, figsize=(18, 12))
    fig.suptitle(
        "0306 Main Time Dashboard | mark vs classified vs batch",
        fontsize=13,
    )

    for ax, (metric_name, col) in zip(axes.flat, METRICS):
        for variant in ["mark", "classified", "batch"]:
            series = {int(r["workers"]): float(r[col]) for r in rows_by_variant[variant]}
            xs = [w for w in workers if w in series]
            ys = [series[w] for w in xs]
            ax.plot(
                xs,
                ys,
                marker="o",
                markersize=6,
                linewidth=2,
                label=variant,
                color=COLORS[variant],
            )

        ax.set_title(f"{metric_name} vs workers")
        ax.set_xlabel("Workers")
        ax.set_ylabel("Time (s)")
        ax.set_xticks(workers)
        ax.set_ylim(bottom=0)
        ax.grid(True, alpha=0.3)
        ax.legend(loc="best")

    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout(rect=[0, 0.02, 1, 0.95])
    fig.savefig(out_png, dpi=180)
    plt.close(fig)

    print(f"Saved: {out_png}")
    print(f"Saved: {result_dir / 'combined_all_rows_0306.csv'}")
    print(f"Saved: {result_dir / 'combined_main_time_long_0306.csv'}")


if __name__ == "__main__":
    main()
