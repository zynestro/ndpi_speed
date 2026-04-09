#!/usr/bin/env python3
"""
mark1 单 worker 逐核扫描脚本

规则：
- reader 固定绑核到 31
- 每次只启动 1 个 worker
- worker 绑核遍历: 0,2,4,...,30
- 输出 CSV + 2x2 dashboard（与 benchmark_sweep_mark1.py 同风格）
"""

import argparse
import csv
import os
import re
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


def build_cmd(binary_path: str, pcap_file: str, worker_core: int, reader_core: int, quiet: bool = True) -> list[str]:
    cmd = [
        binary_path,
        "-i", pcap_file,
        "-n", "1",
        "-c", str(worker_core),
        "-r", str(reader_core),
    ]
    if quiet:
        cmd.append("-q")
    return cmd


def parse_metrics(output: str) -> dict:
    metrics = {}
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
    }
    for k, p in patterns.items():
        m = re.search(p, output)
        if m:
            metrics[k] = int(m.group(1)) if k == "total_packets" else float(m.group(1))
    return metrics


def run_once(binary_path: str, pcap_file: str, worker_core: int, reader_core: int, quiet: bool = True) -> dict | None:
    cmd = build_cmd(binary_path, pcap_file, worker_core, reader_core, quiet=quiet)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print(f"  timeout on core={worker_core}")
        return None

    out = (r.stdout or "") + (r.stderr or "")
    metrics = parse_metrics(out)
    if "throughput_mpps" not in metrics:
        return None
    return metrics


def save_csv(results: list[dict], out_dir: str, ts: str) -> str:
    path = os.path.join(out_dir, f"benchmark_results_{ts}.csv")
    headers = [
        "worker_core", "reader_core",
        "bandwidth_gbps", "throughput_mpps", "cycles_per_pkt",
        "elapsed_sec", "read_time_sec", "process_time_sec",
        "read_pcap_sec", "read_hash_sec", "read_rss_lookup_sec",
        "read_enqueue_sec", "read_other_sec",
        "proc_parse_sec", "proc_flowkey_lookup_sec", "proc_flow_init_sec",
        "proc_flow_sec", "proc_ndpi_call_sec", "proc_proto_check_sec", "proc_ndpi_sec",
        "proc_classified_fastpath_sec", "proc_other_sec",
        "total_packets",
    ]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for row in results:
            w.writerow(row)
    return path


def plot_results(results: list[dict], out_dir: str, ts: str, binary_path: str, pcap_file: str) -> str | None:
    if not HAS_MATPLOTLIB:
        print("matplotlib not found, skip plotting")
        return None

    x = [r["worker_core"] for r in results]
    fig, axes = plt.subplots(2, 2, figsize=(18, 10))

    ax = axes[0, 0]
    ax.plot(x, [r["throughput_mpps"] for r in results], marker="o", linewidth=2, label="Throughput (Mpps)")
    ax.plot(x, [r["bandwidth_gbps"] for r in results], marker="s", linewidth=2, label="Bandwidth (Gbps)")
    ax.set_xlabel("Worker Core")
    ax.set_ylabel("Value")
    ax.set_title("Throughput / Bandwidth vs Worker Core")
    ax.grid(True, alpha=0.3)
    ax.legend()

    ax = axes[0, 1]
    ax.plot(x, [r["elapsed_sec"] for r in results], marker="o", linewidth=2, label="Elapsed Time")
    ax.plot(x, [r["read_time_sec"] for r in results], marker="s", linewidth=2, label="Read Time")
    ax.plot(x, [r["process_time_sec"] for r in results], marker="^", linewidth=2, label="Process Time")
    ax.set_xlabel("Worker Core")
    ax.set_ylabel("Time (s)")
    ax.set_title("Elapsed / Read / Process vs Worker Core")
    ax.grid(True, alpha=0.3)
    ax.legend()

    ax = axes[1, 0]
    ax.plot(x, [r["read_pcap_sec"] for r in results], marker="o", linewidth=2, label="pcap_next_ex")
    ax.plot(x, [r["read_hash_sec"] for r in results], marker="^", linewidth=2, label="hash")
    ax.plot(x, [r["read_rss_lookup_sec"] for r in results], marker="d", linewidth=2, label="rss_lookup")
    ax.plot(x, [r["read_enqueue_sec"] for r in results], marker="s", linewidth=2, label="enqueue")
    ax.plot(x, [r["read_other_sec"] for r in results], marker="x", linewidth=2, label="other")
    ax.set_xlabel("Worker Core")
    ax.set_ylabel("Time (s)")
    ax.set_title("Reader Breakdown vs Worker Core")
    ax.grid(True, alpha=0.3)
    ax.legend()

    ax = axes[1, 1]
    ax.plot(x, [r["proc_parse_sec"] for r in results], marker="o", linewidth=1.8, label="parse")
    ax.plot(x, [r["proc_flowkey_lookup_sec"] for r in results], marker="v", linewidth=1.8, label="flowkey_lookup")
    ax.plot(x, [r["proc_flow_init_sec"] for r in results], marker="P", linewidth=1.8, label="flow_init")
    ax.plot(x, [r["proc_ndpi_call_sec"] for r in results], marker="*", linewidth=1.8, label="ndpi_call")
    ax.plot(x, [r["proc_proto_check_sec"] for r in results], marker="X", linewidth=1.8, label="proto_check")
    ax.plot(x, [r["proc_classified_fastpath_sec"] for r in results], marker="h", linewidth=1.8, label="classified_fastpath")
    ax.plot(x, [r["proc_flow_sec"] for r in results], marker="s", linewidth=1.8, label="flow")
    ax.plot(x, [r["proc_ndpi_sec"] for r in results], marker="^", linewidth=1.8, label="ndpi")
    ax.plot(x, [r["proc_other_sec"] for r in results], marker="d", linewidth=1.8, label="other")
    ax.set_xlabel("Worker Core")
    ax.set_ylabel("Time (s)")
    ax.set_title("Process Breakdown vs Worker Core")
    ax.grid(True, alpha=0.3)
    ax.legend()

    fig.suptitle(
        f"mark1 Single-Worker Core Sweep | binary={os.path.basename(binary_path)} | input={os.path.basename(pcap_file)} | ts={ts}",
        fontsize=13
    )
    fig.tight_layout(rect=[0, 0.02, 1, 0.94])

    out_png = os.path.join(out_dir, f"benchmark_dashboard_{ts}.png")
    fig.savefig(out_png, dpi=150)
    plt.close(fig)
    return out_png


def main() -> int:
    parser = argparse.ArgumentParser(
        description="mark1 单 worker 逐核扫描（reader固定31）"
    )
    parser.add_argument("-i", "--input",  help="PCAP 文件路径", default = "/home/zync/WORKSPACE/ndpi_speed/input/seed_10G.pcap")
    parser.add_argument("-b", "--binary", default="./mark1/build/ndpiBenchmark", help="benchmark binary 路径")
    parser.add_argument("-o", "--output", default="output", help="输出根目录")
    parser.add_argument("--reader-core", type=int, default=31, help="reader 绑核（默认31，仅用于写入结果）")
    parser.add_argument("--worker-cores", default="0,2,4,6,8,10,12,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30",
                        help="worker 核列表（逗号分隔）")
    parser.add_argument("--verbose", action="store_true", help="关闭 quiet，打印更多 benchmark 输出")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: PCAP not found: {args.input}")
        return 1
    if not os.path.exists(args.binary):
        print(f"Error: binary not found: {args.binary}")
        return 1

    worker_cores = [int(x.strip()) for x in args.worker_cores.split(",") if x.strip()]
    now = datetime.now()
    ts = now.strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(args.output, f"{ts}-singlecore")
    os.makedirs(out_dir, exist_ok=True)

    print(f"Output directory: {out_dir}")
    print(f"Reader core fixed: {args.reader_core}")
    print(f"Worker cores: {worker_cores}")

    results: list[dict] = []
    total = len(worker_cores)
    for i, core in enumerate(worker_cores, start=1):
        print(f"[{i}/{total}] core={core} ... ", end="", flush=True)
        m = run_once(args.binary, args.input, core, args.reader_core, quiet=(not args.verbose))
        if not m:
            print("failed")
            continue
        row = {
            "worker_core": core,
            "reader_core": args.reader_core,
            "bandwidth_gbps": m.get("bandwidth_gbps", 0.0),
            "throughput_mpps": m.get("throughput_mpps", 0.0),
            "cycles_per_pkt": m.get("cycles_per_pkt", 0.0),
            "elapsed_sec": m.get("elapsed_sec", 0.0),
            "read_time_sec": m.get("read_time_sec", 0.0),
            "process_time_sec": m.get("process_time_sec", 0.0),
            "read_pcap_sec": m.get("read_pcap_sec", 0.0),
            "read_hash_sec": m.get("read_hash_sec", 0.0),
            "read_rss_lookup_sec": m.get("read_rss_lookup_sec", 0.0),
            "read_enqueue_sec": m.get("read_enqueue_sec", 0.0),
            "read_other_sec": m.get("read_other_sec", 0.0),
            "proc_parse_sec": m.get("proc_parse_sec", 0.0),
            "proc_flowkey_lookup_sec": m.get("proc_flowkey_lookup_sec", 0.0),
            "proc_flow_init_sec": m.get("proc_flow_init_sec", 0.0),
            "proc_flow_sec": m.get("proc_flow_sec", 0.0),
            "proc_ndpi_call_sec": m.get("proc_ndpi_call_sec", 0.0),
            "proc_proto_check_sec": m.get("proc_proto_check_sec", 0.0),
            "proc_ndpi_sec": m.get("proc_ndpi_sec", 0.0),
            "proc_classified_fastpath_sec": m.get("proc_classified_fastpath_sec", 0.0),
            "proc_other_sec": m.get("proc_other_sec", 0.0),
            "total_packets": m.get("total_packets", 0),
        }
        results.append(row)
        print(f"{row['throughput_mpps']:.2f} Mpps, {row['bandwidth_gbps']:.2f} Gbps")

    if not results:
        print("No results collected")
        return 2

    csv_path = save_csv(results, out_dir, ts)
    png_path = plot_results(results, out_dir, ts, args.binary, args.input)

    print("\nDone.")
    print(f"CSV: {csv_path}")
    if png_path:
        print(f"PNG: {png_path}")
    else:
        print("PNG: skipped (matplotlib not installed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
