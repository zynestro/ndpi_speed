#!/usr/bin/env python3
"""
mark2 Benchmark 扫描脚本
- 单基线版本（ndpiBenchmarkMark2）
- 默认 reader 绑核 -r 0
- 默认 worker 顺序绑核 -c 1..N
  说明：
  - 单次 benchmark 运行会同时启动 N 个 worker，并分别固定绑定到 N 个核（不是单 worker 轮流跑多核）
  - sweep 是按 workers 配置逐次运行（例如先 1，再 2，再 3...），每次重启一个新进程
"""

import argparse
import csv
import os
import re
import statistics
import subprocess
import sys
from datetime import datetime

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not found, will skip plotting")


def get_worker_cores(n: int) -> str:
    # 对于 workers=n，生成 "1,2,...,n"。
    # 这表示一次运行内的 N 个 worker 分别绑定到这些核。
    return ",".join(str(i) for i in range(1, n + 1))


def build_benchmark_cmd(binary_path: str, pcap_file: str, num_workers: int, quiet: bool = True) -> list[str]:
    # 单次运行命令：-n 指定 worker 数，-c 指定每个 worker 的目标 core 列表。
    cmd = [
        binary_path,
        "-i", pcap_file,
        "-n", str(num_workers),
        "-c", get_worker_cores(num_workers),
        "-r", "0",
    ]
    if quiet:
        cmd.append("-q")
    return cmd


def run_benchmark(binary_path: str, pcap_file: str, num_workers: int, quiet: bool = True) -> dict | None:
    cmd = build_benchmark_cmd(binary_path, pcap_file, num_workers, quiet=quiet)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"  Timeout! (workers={num_workers})")
        return None

    output = (result.stdout or "") + (result.stderr or "")
    metrics: dict[str, float | int | list[float]] = {}

    patterns = {
        "bandwidth_gbps": r"Bandwidth:\s+([\d.]+)\s+Gbps",
        "throughput_mpps": r"Throughput:\s+([\d.]+)\s+Mpps",
        "cycles_per_pkt": r"Cycles per packet:\s+([\d.]+)",
        "elapsed_sec": r"Elapsed Time:\s+([\d.]+)\s+seconds",
        "read_time_sec": r"Read Time:\s+([\d.]+)\s+seconds",
        "read_pcap_sec": r"Read pcap_next_ex:\s+([\d.]+)\s+seconds",
        "read_hash_sec": r"Read hash:\s+([\d.]+)\s+seconds",
        "read_rss_lookup_sec": r"Read rss_lookup:\s+([\d.]+)\s+seconds",
        "read_enqueue_sec": r"Read enqueue:\s+([\d.]+)\s+seconds",
        "read_other_sec": r"Read other:\s+([\d.]+)\s+seconds",
        "process_time_sec": r"Process Time:\s+([\d.]+)\s+seconds",
        "proc_parse_sec": r"Process parse:\s+([\d.]+)\s+seconds",
        "proc_flowkey_lookup_sec": r"Process flowkey_lookup:\s+([\d.]+)\s+seconds",
        "proc_flow_init_sec": r"Process flow_init:\s+([\d.]+)\s+seconds",
        "proc_flow_sec": r"Process flow:\s+([\d.]+)\s+seconds",
        "proc_ndpi_call_sec": r"Process nDPI call:\s+([\d.]+)\s+seconds",
        "proc_proto_check_sec": r"Process proto_check:\s+([\d.]+)\s+seconds",
        "proc_ndpi_sec": r"Process nDPI:\s+([\d.]+)\s+seconds",
        "proc_classified_fastpath_sec": r"Process classified_fastpath:\s+([\d.]+)\s+seconds",
        "proc_other_sec": r"Process other:\s+([\d.]+)\s+seconds",
        "total_packets": r"Total Packets:\s+(\d+)",
        "scaling_efficiency": r"Scaling Efficiency:\s+([\d.]+)%",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, output)
        if m:
            if key == "total_packets":
                metrics[key] = int(m.group(1))
            else:
                metrics[key] = float(m.group(1))

    m = re.search(r"Per-Core Process Time \(sec\):\s*([0-9.,\s]+)", output)
    if m:
        vals = []
        for item in m.group(1).split(","):
            item = item.strip()
            if item:
                vals.append(float(item))
        if len(vals) < 32:
            vals.extend([0.0] * (32 - len(vals)))
        metrics["proc_core_sec"] = vals[:32]
    else:
        metrics["proc_core_sec"] = [0.0] * 32

    if "bandwidth_gbps" not in metrics:
        return None
    return metrics


def run_sweep(binary_path: str, pcap_file: str, worker_range, output_dir: str) -> dict:
    results = {
        "workers": [],
        "bandwidth": [],
        "throughput": [],
        "cycles": [],
        "efficiency": [],
        "elapsed_sec": [],
        "read_time_sec": [],
        "process_time_sec": [],
        "read_pcap_sec": [],
        "read_hash_sec": [],
        "read_rss_lookup_sec": [],
        "read_enqueue_sec": [],
        "read_other_sec": [],
        "proc_parse_sec": [],
        "proc_flowkey_lookup_sec": [],
        "proc_flow_init_sec": [],
        "proc_flow_sec": [],
        "proc_ndpi_call_sec": [],
        "proc_proto_check_sec": [],
        "proc_ndpi_sec": [],
        "proc_classified_fastpath_sec": [],
        "proc_other_sec": [],
        "proc_core_sec": [],
    }

    total_tests = len(worker_range)
    print(f"\n{'='*60}")
    print(f"Starting mark2 benchmark sweep: {total_tests} tests")
    print(f"Workers: {list(worker_range)}")
    print(f"{'='*60}\n")

    for i, workers in enumerate(worker_range, start=1):
        # 这里是 sweep 的“跨运行遍历”：每个 workers 值会独立运行一次 benchmark 进程。
        print(f"[{i}/{total_tests}] Testing: workers={workers}...", end=" ", flush=True)
        metrics = run_benchmark(binary_path, pcap_file, workers)
        if not metrics:
            print("Failed!")
            continue

        bw = float(metrics.get("bandwidth_gbps", 0))
        tp = float(metrics.get("throughput_mpps", 0))
        cy = float(metrics.get("cycles_per_pkt", 0))
        print(f"Bandwidth: {bw:.2f} Gbps, {tp:.2f} Mpps, {cy:.1f} cycles/pkt")

        results["workers"].append(workers)
        results["bandwidth"].append(bw)
        results["throughput"].append(tp)
        results["cycles"].append(cy)
        results["efficiency"].append(float(metrics.get("scaling_efficiency", 0)))
        results["elapsed_sec"].append(float(metrics.get("elapsed_sec", 0)))
        results["read_time_sec"].append(float(metrics.get("read_time_sec", 0)))
        results["process_time_sec"].append(float(metrics.get("process_time_sec", 0)))
        results["read_pcap_sec"].append(float(metrics.get("read_pcap_sec", 0)))
        results["read_hash_sec"].append(float(metrics.get("read_hash_sec", 0)))
        results["read_rss_lookup_sec"].append(float(metrics.get("read_rss_lookup_sec", 0)))
        results["read_enqueue_sec"].append(float(metrics.get("read_enqueue_sec", 0)))
        results["read_other_sec"].append(float(metrics.get("read_other_sec", 0)))
        results["proc_parse_sec"].append(float(metrics.get("proc_parse_sec", 0)))
        results["proc_flowkey_lookup_sec"].append(float(metrics.get("proc_flowkey_lookup_sec", 0)))
        results["proc_flow_init_sec"].append(float(metrics.get("proc_flow_init_sec", 0)))
        results["proc_flow_sec"].append(float(metrics.get("proc_flow_sec", 0)))
        results["proc_ndpi_call_sec"].append(float(metrics.get("proc_ndpi_call_sec", 0)))
        results["proc_proto_check_sec"].append(float(metrics.get("proc_proto_check_sec", 0)))
        results["proc_ndpi_sec"].append(float(metrics.get("proc_ndpi_sec", 0)))
        results["proc_classified_fastpath_sec"].append(float(metrics.get("proc_classified_fastpath_sec", 0)))
        results["proc_other_sec"].append(float(metrics.get("proc_other_sec", 0)))
        results["proc_core_sec"].append(list(metrics.get("proc_core_sec", [0.0] * 32)))

    return results


def plot_results(results: dict, output_dir: str, worker_range, binary_path: str, pcap_file: str, timestamp: str):
    if not HAS_MATPLOTLIB:
        print("\nSkipping plots (matplotlib not available)")
        return None

    workers = results["workers"]
    fig, axes = plt.subplots(2, 2, figsize=(18, 10))

    ax = axes[0, 0]
    if workers:
        box_data = []
        medians = []
        for i, w in enumerate(workers):
            per_core = results["proc_core_sec"][i]
            upper = min(w, 31)
            samples = [per_core[c] for c in range(1, upper + 1)] if upper >= 1 else [0.0]
            if not samples:
                samples = [0.0]
            box_data.append(samples)
            medians.append(statistics.median(samples))
        ax.boxplot(box_data, tick_labels=[str(w) for w in workers], showfliers=True)
        ax.plot(range(1, len(medians) + 1), medians, color="tab:red", marker="o", linewidth=1.5, label="median")
        ax.legend()
    ax.set_xlabel("Workers")
    ax.set_ylabel("Process Time per Active Core (s)")
    ax.set_title("Process Distribution Boxplot by Worker Count")
    ax.grid(True, axis="y", alpha=0.3)

    ax = axes[0, 1]
    if workers:
        ax.plot(workers, results["elapsed_sec"], marker="o", linewidth=2, label="Elapsed Time")
        ax.plot(workers, results["read_time_sec"], marker="s", linewidth=2, label="Read Time")
        ax.plot(workers, results["process_time_sec"], marker="^", linewidth=2, label="Process Time (max)")
    ax.set_xlabel("Workers")
    ax.set_ylabel("Time (s)")
    ax.set_title("Elapsed / Read / Process(max) vs Workers")
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(worker_range))
    ax.legend()

    ax = axes[1, 0]
    if workers:
        ax.plot(workers, results["read_pcap_sec"], marker="o", linewidth=2, label="pcap_next_ex")
        ax.plot(workers, results["read_hash_sec"], marker="^", linewidth=2, label="hash")
        ax.plot(workers, results["read_rss_lookup_sec"], marker="d", linewidth=2, label="rss_lookup")
        ax.plot(workers, results["read_enqueue_sec"], marker="s", linewidth=2, label="enqueue")
        ax.plot(workers, results["read_other_sec"], marker="x", linewidth=2, label="other")
    ax.set_xlabel("Workers")
    ax.set_ylabel("Time (s)")
    ax.set_title("Reader Breakdown vs Workers")
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(worker_range))
    ax.legend(loc="best")

    ax = axes[1, 1]
    if workers:
        ax.plot(workers, results["proc_parse_sec"], marker="o", linewidth=1.8, label="parse")
        ax.plot(workers, results["proc_flowkey_lookup_sec"], marker="v", linewidth=1.8, label="flowkey_lookup")
        ax.plot(workers, results["proc_flow_init_sec"], marker="P", linewidth=1.8, label="flow_init")
        ax.plot(workers, results["proc_ndpi_call_sec"], marker="*", linewidth=1.8, label="ndpi_call")
        ax.plot(workers, results["proc_proto_check_sec"], marker="X", linewidth=1.8, label="proto_check")
        ax.plot(workers, results["proc_classified_fastpath_sec"], marker="h", linewidth=1.8, label="classified_fastpath")
        ax.plot(workers, results["proc_flow_sec"], marker="s", linewidth=1.8, label="flow")
        ax.plot(workers, results["proc_ndpi_sec"], marker="^", linewidth=1.8, label="ndpi")
        ax.plot(workers, results["proc_other_sec"], marker="d", linewidth=1.8, label="other")
    ax.set_xlabel("Workers")
    ax.set_ylabel("Time (s)")
    ax.set_title("Process Breakdown vs Workers")
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(worker_range))
    ax.legend(loc="best")

    fig.suptitle(
        f"mark2 Benchmark Dashboard | binary={os.path.basename(binary_path)} | input={os.path.basename(pcap_file)} | ts={timestamp}",
        fontsize=13
    )
    fig.tight_layout(rect=[0, 0.02, 1, 0.94])
    out_png = os.path.join(output_dir, f"benchmark_dashboard_{timestamp}.png")
    fig.savefig(out_png, dpi=150)
    plt.close(fig)
    print(f"Saved: {out_png}")
    return out_png


def save_csv(results: dict, output_dir: str, timestamp: str) -> str:
    csv_path = os.path.join(output_dir, f"benchmark_results_{timestamp}.csv")
    core_headers = [f"proc_core_{i:02d}_sec" for i in range(32)]
    headers = [
        "workers", "bandwidth_gbps", "throughput_mpps", "cycles_per_pkt",
        "scaling_efficiency", "elapsed_sec", "read_time_sec", "process_time_sec",
        "read_pcap_sec", "read_hash_sec", "read_rss_lookup_sec", "read_enqueue_sec", "read_other_sec",
        "proc_parse_sec", "proc_flowkey_lookup_sec", "proc_flow_init_sec", "proc_flow_sec",
        "proc_ndpi_call_sec", "proc_proto_check_sec", "proc_ndpi_sec",
        "proc_classified_fastpath_sec", "proc_other_sec"
    ] + core_headers

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for i in range(len(results["workers"])):
            row = [
                results["workers"][i],
                f"{results['bandwidth'][i]:.2f}",
                f"{results['throughput'][i]:.2f}",
                f"{results['cycles'][i]:.2f}",
                f"{results['efficiency'][i]:.1f}",
                f"{results['elapsed_sec'][i]:.6f}",
                f"{results['read_time_sec'][i]:.6f}",
                f"{results['process_time_sec'][i]:.6f}",
                f"{results['read_pcap_sec'][i]:.6f}",
                f"{results['read_hash_sec'][i]:.6f}",
                f"{results['read_rss_lookup_sec'][i]:.6f}",
                f"{results['read_enqueue_sec'][i]:.6f}",
                f"{results['read_other_sec'][i]:.6f}",
                f"{results['proc_parse_sec'][i]:.6f}",
                f"{results['proc_flowkey_lookup_sec'][i]:.6f}",
                f"{results['proc_flow_init_sec'][i]:.6f}",
                f"{results['proc_flow_sec'][i]:.6f}",
                f"{results['proc_ndpi_call_sec'][i]:.6f}",
                f"{results['proc_proto_check_sec'][i]:.6f}",
                f"{results['proc_ndpi_sec'][i]:.6f}",
                f"{results['proc_classified_fastpath_sec'][i]:.6f}",
                f"{results['proc_other_sec'][i]:.6f}",
            ]
            row.extend(f"{v:.6f}" for v in results["proc_core_sec"][i][:32])
            writer.writerow(row)

    print(f"Saved: {csv_path}")
    return csv_path


def make_run_output_dir(output_base_dir: str, now: datetime) -> str:
    ts_dir = now.strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_base_dir, ts_dir)
    os.makedirs(run_dir, exist_ok=True)
    return run_dir


def append_run_log(log_path: str, timestamp: str, binary_path: str, pcap_file: str, worker_range) -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a") as f:
        f.write(f"\n[{timestamp}] mark2_sweep_start\n")
        f.write(f"binary: {binary_path}\n")
        f.write(f"input: {pcap_file}\n")
        f.write(f"workers: {','.join(str(w) for w in worker_range)}\n")


def print_summary(results: dict):
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")
    if not results["bandwidth"]:
        print("No results collected!")
        return
    max_bw_idx = results["bandwidth"].index(max(results["bandwidth"]))
    min_cy_idx = results["cycles"].index(min(results["cycles"]))
    print(f"\nHighest Bandwidth: {results['bandwidth'][max_bw_idx]:.2f} Gbps "
          f"(workers={results['workers'][max_bw_idx]})")
    print(f"Lowest Cycles/Pkt: {results['cycles'][min_cy_idx]:.2f} "
          f"(workers={results['workers'][min_cy_idx]})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="mark2 Benchmark 自动化参数扫描（无 loops）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i input/seed_10G.pcap --workers 1,2,4,8
  %(prog)s -i input/seed_10G.pcap -b mark2/build/ndpiBenchmarkMark2 --workers 1-16
"""
    )
    parser.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    parser.add_argument("-b", "--binary", default="mark2/build/ndpiBenchmarkMark2",
                        help="mark2 benchmark 可执行文件路径")
    parser.add_argument("-w", "--workers", default="1-31",
                        help="Worker 列表，支持范围 '1-16' 或列表 '1,2,4,8'")
    parser.add_argument("-o", "--output", default="output", help="输出根目录")
    args = parser.parse_args()

    if "-" in args.workers:
        start, end = map(int, args.workers.split("-"))
        worker_range = range(start, end + 1)
    else:
        worker_range = [int(x) for x in args.workers.split(",")]

    if not os.path.exists(args.input):
        print(f"Error: PCAP file not found: {args.input}")
        return 1
    if not os.path.exists(args.binary):
        print(f"Error: Benchmark binary not found: {args.binary}")
        return 1

    now = datetime.now()
    ts = now.strftime("%Y%m%d_%H%M%S")
    run_output_dir = make_run_output_dir(args.output, now)
    run_log_path = os.path.join(args.output, "run.log")
    print(f"Output directory: {run_output_dir}")
    append_run_log(run_log_path, ts, args.binary, args.input, worker_range)
    print(f"Run log appended: {run_log_path}")

    results = run_sweep(args.binary, args.input, worker_range, run_output_dir)
    if results["bandwidth"]:
        save_csv(results, run_output_dir, ts)
        plot_results(results, run_output_dir, worker_range, args.binary, args.input, ts)
        print_summary(results)
    else:
        print("No results to save!")

    print(f"\n{'='*60}")
    print("Done!")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
