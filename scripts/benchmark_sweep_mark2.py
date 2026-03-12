#!/usr/bin/env python3
"""
mark2 Benchmark 扫描脚本
- 单基线版本（ndpiBenchmarkMark2）
- 默认 reader 绑核 -r 0
- 支持两种 sweep 模式：
  1) worker_count: sweep 值为 K 时，运行 -n K -c 1..K -r 0
  2) worker_core:  sweep 值为 C 时，运行 -n 1 -c C   -r 0
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


MODE_WORKER_COUNT = "worker_count"
MODE_WORKER_CORE = "worker_core"


def get_worker_cores_for_count(n: int) -> str:
    return ",".join(str(i) for i in range(1, n + 1))


def build_benchmark_cmd(
    binary_path: str,
    pcap_file: str,
    sweep_value: int,
    mode: str,
    quiet: bool = True,
) -> list[str]:
    if mode == MODE_WORKER_COUNT:
        num_workers = sweep_value
        core_list = get_worker_cores_for_count(num_workers)
    else:
        num_workers = 1
        core_list = str(sweep_value)

    cmd = [
        binary_path,
        "-i", pcap_file,
        "-n", str(num_workers),
        "-c", core_list,
        "-r", "0",
    ]
    if quiet:
        cmd.append("-q")
    return cmd


def run_benchmark(
    binary_path: str,
    pcap_file: str,
    sweep_value: int,
    mode: str,
    quiet: bool = True,
) -> dict | None:
    cmd = build_benchmark_cmd(binary_path, pcap_file, sweep_value, mode, quiet=quiet)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        if mode == MODE_WORKER_COUNT:
            print(f"  Timeout! (workers={sweep_value})")
        else:
            print(f"  Timeout! (worker_core={sweep_value})")
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


def run_sweep(binary_path: str, pcap_file: str, sweep_values, output_dir: str, mode: str) -> dict:
    results = {
        "sweep_values": [],
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

    total_tests = len(sweep_values)
    print(f"\n{'='*60}")
    print(f"Starting mark2 benchmark sweep: {total_tests} tests")
    if mode == MODE_WORKER_COUNT:
        print(f"Mode: {MODE_WORKER_COUNT} (run: -n K -c 1..K)")
        print(f"Workers: {list(sweep_values)}")
    else:
        print(f"Mode: {MODE_WORKER_CORE} (run: -n 1 -c C)")
        print(f"Worker cores: {list(sweep_values)}")
    print(f"{'='*60}\n")

    for i, sweep_value in enumerate(sweep_values, start=1):
        if mode == MODE_WORKER_COUNT:
            print(f"[{i}/{total_tests}] Testing: workers={sweep_value}...", end=" ", flush=True)
        else:
            print(f"[{i}/{total_tests}] Testing: worker_core={sweep_value}...", end=" ", flush=True)

        metrics = run_benchmark(binary_path, pcap_file, sweep_value, mode)
        if not metrics:
            print("Failed!")
            continue

        bw = float(metrics.get("bandwidth_gbps", 0))
        tp = float(metrics.get("throughput_mpps", 0))
        cy = float(metrics.get("cycles_per_pkt", 0))
        print(f"Bandwidth: {bw:.2f} Gbps, {tp:.2f} Mpps, {cy:.1f} cycles/pkt")

        results["sweep_values"].append(sweep_value)
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


def plot_results(results: dict, output_dir: str, sweep_values, mode: str, binary_path: str, pcap_file: str, timestamp: str):
    if not HAS_MATPLOTLIB:
        print("\nSkipping plots (matplotlib not available)")
        return None

    x_values = results["sweep_values"]
    x_label = "Workers" if mode == MODE_WORKER_COUNT else "Worker Core ID"
    x_title_suffix = "Worker Count" if mode == MODE_WORKER_COUNT else "Worker Core"
    fig, axes = plt.subplots(2, 2, figsize=(18, 10))

    ax = axes[0, 0]
    if x_values:
        box_data = []
        medians = []
        for i, x in enumerate(x_values):
            per_core = results["proc_core_sec"][i]
            if mode == MODE_WORKER_COUNT:
                upper = min(int(x), 31)
                samples = [per_core[c] for c in range(1, upper + 1)] if upper >= 1 else [0.0]
            else:
                core = int(x)
                samples = [per_core[core]] if 0 <= core < len(per_core) else [0.0]
            if not samples:
                samples = [0.0]
            box_data.append(samples)
            medians.append(statistics.median(samples))
        ax.boxplot(box_data, tick_labels=[str(x) for x in x_values], showfliers=True)
        ax.plot(range(1, len(medians) + 1), medians, color="tab:red", marker="o", linewidth=1.5, label="median")
        ax.legend()
    ax.set_xlabel(x_label)
    ax.set_ylabel("Process Time per Active Core (s)")
    ax.set_title(f"Process Distribution Boxplot by {x_title_suffix}")
    ax.grid(True, axis="y", alpha=0.3)

    ax = axes[0, 1]
    if x_values:
        ax.plot(x_values, results["elapsed_sec"], marker="o", linewidth=2, label="Elapsed Time")
        ax.plot(x_values, results["read_time_sec"], marker="s", linewidth=2, label="Read Time")
        ax.plot(x_values, results["process_time_sec"], marker="^", linewidth=2, label="Process Time (max)")
    ax.set_xlabel(x_label)
    ax.set_ylabel("Time (s)")
    ax.set_title(f"Elapsed / Read / Process(max) vs {x_title_suffix}")
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(sweep_values))
    ax.legend()

    ax = axes[1, 0]
    if x_values:
        ax.plot(x_values, results["read_pcap_sec"], marker="o", linewidth=2, label="pcap_next_ex")
        ax.plot(x_values, results["read_hash_sec"], marker="^", linewidth=2, label="hash")
        ax.plot(x_values, results["read_rss_lookup_sec"], marker="d", linewidth=2, label="rss_lookup")
        ax.plot(x_values, results["read_enqueue_sec"], marker="s", linewidth=2, label="enqueue")
        ax.plot(x_values, results["read_other_sec"], marker="x", linewidth=2, label="other")
    ax.set_xlabel(x_label)
    ax.set_ylabel("Time (s)")
    ax.set_title(f"Reader Breakdown vs {x_title_suffix}")
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(sweep_values))
    ax.legend(loc="best")

    ax = axes[1, 1]
    if x_values:
        ax.plot(x_values, results["proc_parse_sec"], marker="o", linewidth=1.8, label="parse")
        ax.plot(x_values, results["proc_flowkey_lookup_sec"], marker="v", linewidth=1.8, label="flowkey_lookup")
        ax.plot(x_values, results["proc_flow_init_sec"], marker="P", linewidth=1.8, label="flow_init")
        ax.plot(x_values, results["proc_ndpi_call_sec"], marker="*", linewidth=1.8, label="ndpi_call")
        ax.plot(x_values, results["proc_proto_check_sec"], marker="X", linewidth=1.8, label="proto_check")
        ax.plot(x_values, results["proc_classified_fastpath_sec"], marker="h", linewidth=1.8, label="classified_fastpath")
        ax.plot(x_values, results["proc_flow_sec"], marker="s", linewidth=1.8, label="flow")
        ax.plot(x_values, results["proc_ndpi_sec"], marker="^", linewidth=1.8, label="ndpi")
        ax.plot(x_values, results["proc_other_sec"], marker="d", linewidth=1.8, label="other")
    ax.set_xlabel(x_label)
    ax.set_ylabel("Time (s)")
    ax.set_title(f"Process Breakdown vs {x_title_suffix}")
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(sweep_values))
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


def save_csv(results: dict, output_dir: str, timestamp: str, mode: str) -> str:
    csv_path = os.path.join(output_dir, f"benchmark_results_{timestamp}.csv")
    core_headers = [f"proc_core_{i:02d}_sec" for i in range(32)]
    sweep_col = "workers" if mode == MODE_WORKER_COUNT else "worker_core"
    headers = [
        sweep_col, "bandwidth_gbps", "throughput_mpps", "cycles_per_pkt",
        "scaling_efficiency", "elapsed_sec", "read_time_sec", "process_time_sec",
        "read_pcap_sec", "read_hash_sec", "read_rss_lookup_sec", "read_enqueue_sec", "read_other_sec",
        "proc_parse_sec", "proc_flowkey_lookup_sec", "proc_flow_init_sec", "proc_flow_sec",
        "proc_ndpi_call_sec", "proc_proto_check_sec", "proc_ndpi_sec",
        "proc_classified_fastpath_sec", "proc_other_sec"
    ] + core_headers

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for i in range(len(results["sweep_values"])):
            row = [
                results["sweep_values"][i],
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


def append_run_log(log_path: str, timestamp: str, binary_path: str, pcap_file: str, sweep_values, mode: str) -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a") as f:
        f.write(f"\n[{timestamp}] mark2_sweep_start\n")
        f.write(f"binary: {binary_path}\n")
        f.write(f"input: {pcap_file}\n")
        f.write(f"mode: {mode}\n")
        if mode == MODE_WORKER_COUNT:
            f.write(f"workers: {','.join(str(v) for v in sweep_values)}\n")
        else:
            f.write(f"worker_cores: {','.join(str(v) for v in sweep_values)}\n")


def print_summary(results: dict, mode: str):
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")
    if not results["bandwidth"]:
        print("No results collected!")
        return
    max_bw_idx = results["bandwidth"].index(max(results["bandwidth"]))
    min_cy_idx = results["cycles"].index(min(results["cycles"]))
    if mode == MODE_WORKER_COUNT:
        print(f"\nHighest Bandwidth: {results['bandwidth'][max_bw_idx]:.2f} Gbps "
              f"(workers={results['sweep_values'][max_bw_idx]})")
        print(f"Lowest Cycles/Pkt: {results['cycles'][min_cy_idx]:.2f} "
              f"(workers={results['sweep_values'][min_cy_idx]})")
    else:
        print(f"\nHighest Bandwidth: {results['bandwidth'][max_bw_idx]:.2f} Gbps "
              f"(worker_core={results['sweep_values'][max_bw_idx]})")
        print(f"Lowest Cycles/Pkt: {results['cycles'][min_cy_idx]:.2f} "
              f"(worker_core={results['sweep_values'][min_cy_idx]})")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="mark2 Benchmark 自动化参数扫描（支持 worker_count / worker_core 两种模式）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 模式1: 扫 worker 数量 (K -> -n K -c 1..K)
  %(prog)s -i input/seed_10G.pcap --mode worker_count --workers 1,2,4,8
  # 模式2: 扫 worker 绑核 (C -> -n 1 -c C)
  %(prog)s -i input/seed_10G.pcap --mode worker_core --workers 1-16
"""
    )
    parser.add_argument("-i", "--input", required=True, help="输入 PCAP 文件路径")
    parser.add_argument("-b", "--binary", default="mark2/build/ndpiBenchmarkMark2",
                        help="mark2 benchmark 可执行文件路径")
    parser.add_argument("-m", "--mode", choices=[MODE_WORKER_COUNT, MODE_WORKER_CORE],
                        default=MODE_WORKER_CORE,
                        help="sweep 模式: worker_count(扫worker数) / worker_core(扫单worker绑核)")
    parser.add_argument("-w", "--workers", default="1-31",
                        help="sweep 值列表，支持范围 '1-16' 或列表 '1,2,4,8'")
    parser.add_argument("-o", "--output", default="output", help="输出根目录")
    args = parser.parse_args()

    if "-" in args.workers:
        start, end = map(int, args.workers.split("-"))
        sweep_values = range(start, end + 1)
    else:
        sweep_values = [int(x) for x in args.workers.split(",")]

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
    print(f"Mode: {args.mode}")
    append_run_log(run_log_path, ts, args.binary, args.input, sweep_values, args.mode)
    print(f"Run log appended: {run_log_path}")

    results = run_sweep(args.binary, args.input, sweep_values, run_output_dir, args.mode)
    if results["bandwidth"]:
        save_csv(results, run_output_dir, ts, args.mode)
        plot_results(results, run_output_dir, sweep_values, args.mode, args.binary, args.input, ts)
        print_summary(results, args.mode)
    else:
        print("No results to save!")

    print(f"\n{'='*60}")
    print("Done!")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
