#!/usr/bin/env python3
"""
mark1 Streaming Benchmark 扫描脚本
- 不使用 loops
- 不带 -r / -t
- 默认 reader 绑核 -r 0
- 默认 worker 顺序绑核 -c 0,1,2,...
"""

import subprocess
import re
import argparse
import os
import sys
import csv
import statistics
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not found, will skip plotting")
    print("Install with: pip install matplotlib")


def get_worker_cores(n):
    """生成 worker 绑核列表（从 1 开始顺序编号）"""
    return ','.join(str(i) for i in range(1, n + 1))


def build_benchmark_cmd(binary_path, pcap_file, num_workers, quiet=True):
    core_list = get_worker_cores(num_workers)
    cmd = [
        binary_path,
        '-i', pcap_file,
        '-n', str(num_workers),
        '-c', core_list,
        '-r', '0',
    ]
    if quiet:
        cmd.append('-q')
    return cmd


def run_benchmark(binary_path, pcap_file, num_workers, quiet=True):
    """运行 mark1 benchmark 并解析结果"""
    cmd = build_benchmark_cmd(binary_path, pcap_file, num_workers, quiet=quiet)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr

        metrics = {}

        match = re.search(r'Bandwidth:\s+([\d.]+)\s+Gbps', output)
        if match:
            metrics['bandwidth_gbps'] = float(match.group(1))

        match = re.search(r'Throughput:\s+([\d.]+)\s+Mpps', output)
        if match:
            metrics['throughput_mpps'] = float(match.group(1))

        match = re.search(r'Cycles per packet:\s+([\d.]+)', output)
        if match:
            metrics['cycles_per_pkt'] = float(match.group(1))

        match = re.search(r'Elapsed Time:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['elapsed_sec'] = float(match.group(1))

        match = re.search(r'Read Time:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['read_time_sec'] = float(match.group(1))

        match = re.search(r'Read pcap_next_ex:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['read_pcap_sec'] = float(match.group(1))

        match = re.search(r'Read hash:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['read_hash_sec'] = float(match.group(1))

        match = re.search(r'Read rss_lookup:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['read_rss_lookup_sec'] = float(match.group(1))

        match = re.search(r'Read enqueue:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['read_enqueue_sec'] = float(match.group(1))

        match = re.search(r'Read other:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['read_other_sec'] = float(match.group(1))

        match = re.search(r'Process Time:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['process_time_sec'] = float(match.group(1))

        match = re.search(r'Process parse:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_parse_sec'] = float(match.group(1))

        match = re.search(r'Process flowkey_lookup:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_flowkey_lookup_sec'] = float(match.group(1))

        match = re.search(r'Process flow_init:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_flow_init_sec'] = float(match.group(1))

        match = re.search(r'Process flow:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_flow_sec'] = float(match.group(1))

        match = re.search(r'Process nDPI call:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_ndpi_call_sec'] = float(match.group(1))

        match = re.search(r'Process proto_check:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_proto_check_sec'] = float(match.group(1))

        match = re.search(r'Process nDPI:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_ndpi_sec'] = float(match.group(1))

        match = re.search(r'Process classified_fastpath:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_classified_fastpath_sec'] = float(match.group(1))

        match = re.search(r'Process other:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['proc_other_sec'] = float(match.group(1))

        match = re.search(r'Per-Core Process Time \(sec\):\s*([0-9.,\s]+)', output)
        if match:
            raw = match.group(1).strip()
            vals = []
            for item in raw.split(','):
                item = item.strip()
                if not item:
                    continue
                vals.append(float(item))
            if len(vals) < 32:
                vals.extend([0.0] * (32 - len(vals)))
            metrics['proc_core_sec'] = vals[:32]
        else:
            metrics['proc_core_sec'] = [0.0] * 32

        match = re.search(r'Total Packets:\s+(\d+)', output)
        if match:
            metrics['total_packets'] = int(match.group(1))

        match = re.search(r'Scaling Efficiency:\s+([\d.]+)%', output)
        if match:
            metrics['scaling_efficiency'] = float(match.group(1))

        return metrics

    except subprocess.TimeoutExpired:
        print(f"  Timeout! (workers={num_workers})")
        return None
    except Exception as e:
        print(f"  Error: {e}")
        return None


def run_sweep(binary_path, pcap_file, worker_range, output_dir):
    results = {
        'workers': [],
        'bandwidth': [],
        'throughput': [],
        'cycles': [],
        'efficiency': [],
        'elapsed_sec': [],
        'read_time_sec': [],
        'process_time_sec': [],
        'read_pcap_sec': [],
        'read_hash_sec': [],
        'read_rss_lookup_sec': [],
        'read_enqueue_sec': [],
        'read_other_sec': [],
        'proc_parse_sec': [],
        'proc_flowkey_lookup_sec': [],
        'proc_flow_init_sec': [],
        'proc_flow_sec': [],
        'proc_ndpi_call_sec': [],
        'proc_proto_check_sec': [],
        'proc_ndpi_sec': [],
        'proc_classified_fastpath_sec': [],
        'proc_other_sec': [],
        'proc_core_sec': []
    }

    total_tests = len(worker_range)
    current_test = 0

    print(f"\n{'='*60}")
    print(f"Starting mark1 benchmark sweep: {total_tests} tests")
    print(f"Workers: {list(worker_range)}")
    print(f"{'='*60}\n")

    for workers in worker_range:
        current_test += 1
        print(f"[{current_test}/{total_tests}] Testing: workers={workers}...", end=' ', flush=True)

        metrics = run_benchmark(binary_path, pcap_file, workers)

        if metrics and 'bandwidth_gbps' in metrics:
            bw = metrics['bandwidth_gbps']
            tp = metrics.get('throughput_mpps', 0)
            cy = metrics.get('cycles_per_pkt', 0)
            ef = metrics.get('scaling_efficiency', 0)
            et = metrics.get('elapsed_sec', 0)
            rt = metrics.get('read_time_sec', 0)
            pt = metrics.get('process_time_sec', 0)
            rp = metrics.get('read_pcap_sec', 0)
            r_hash = metrics.get('read_hash_sec', 0)
            r_rss = metrics.get('read_rss_lookup_sec', 0)
            rq = metrics.get('read_enqueue_sec', 0)
            r_other = metrics.get('read_other_sec', 0)
            p_parse = metrics.get('proc_parse_sec', 0)
            p_flowkey_lookup = metrics.get('proc_flowkey_lookup_sec', 0)
            p_init = metrics.get('proc_flow_init_sec', 0)
            p_flow = metrics.get('proc_flow_sec', 0)
            p_ndpi_call = metrics.get('proc_ndpi_call_sec', 0)
            p_proto_chk = metrics.get('proc_proto_check_sec', 0)
            p_ndpi = metrics.get('proc_ndpi_sec', 0)
            p_cls_fp = metrics.get('proc_classified_fastpath_sec', 0)
            p_other = metrics.get('proc_other_sec', 0)
            p_core = metrics.get('proc_core_sec', [0.0] * 32)

            print(f"Bandwidth: {bw:.2f} Gbps, {tp:.2f} Mpps, {cy:.1f} cycles/pkt")

            results['workers'].append(workers)
            results['bandwidth'].append(bw)
            results['throughput'].append(tp)
            results['cycles'].append(cy)
            results['efficiency'].append(ef)
            results['elapsed_sec'].append(et)
            results['read_time_sec'].append(rt)
            results['process_time_sec'].append(pt)
            results['read_pcap_sec'].append(rp)
            results['read_hash_sec'].append(r_hash)
            results['read_rss_lookup_sec'].append(r_rss)
            results['read_enqueue_sec'].append(rq)
            results['read_other_sec'].append(r_other)
            results['proc_parse_sec'].append(p_parse)
            results['proc_flowkey_lookup_sec'].append(p_flowkey_lookup)
            results['proc_flow_init_sec'].append(p_init)
            results['proc_flow_sec'].append(p_flow)
            results['proc_ndpi_call_sec'].append(p_ndpi_call)
            results['proc_proto_check_sec'].append(p_proto_chk)
            results['proc_ndpi_sec'].append(p_ndpi)
            results['proc_classified_fastpath_sec'].append(p_cls_fp)
            results['proc_other_sec'].append(p_other)
            results['proc_core_sec'].append(p_core)
        else:
            print("Failed!")

    return results


def make_run_output_dir(output_base_dir, now):
    ts_dir = now.strftime('%Y%m%d_%H%M%S')
    run_dir = os.path.join(output_base_dir, ts_dir)
    os.makedirs(run_dir, exist_ok=True)
    return run_dir


def append_run_log(log_path, timestamp, binary_path, pcap_file, worker_range):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a') as f:
        f.write(f"\n[{timestamp}] sweep_start\n")
        f.write(f"binary: {binary_path}\n")
        f.write(f"input: {pcap_file}\n")
        f.write(f"workers: {','.join(str(w) for w in worker_range)}\n")


def plot_results(results, output_dir, worker_range, binary_path, pcap_file, timestamp):
    if not HAS_MATPLOTLIB:
        print("\nSkipping plots (matplotlib not available)")
        return

    os.makedirs(output_dir, exist_ok=True)
    fig, axes = plt.subplots(2, 2, figsize=(18, 10))
    workers = results['workers']

    ax = axes[0, 0]
    if workers:
        box_data = []
        medians = []
        for i, w in enumerate(workers):
            per_core = results['proc_core_sec'][i]
            upper = min(w, 31)
            samples = [per_core[c] for c in range(1, upper + 1)] if upper >= 1 else []
            if not samples:
                samples = [0.0]
            box_data.append(samples)
            medians.append(statistics.median(samples))
        ax.boxplot(box_data, tick_labels=[str(w) for w in workers], showfliers=True)
        ax.plot(range(1, len(medians) + 1), medians, color='tab:red', marker='o', linewidth=1.5, label='median')
        ax.legend()
    ax.set_xlabel('Workers')
    ax.set_ylabel('Process Time per Active Core (s)')
    ax.set_title('Process Distribution Boxplot by Worker Count')
    ax.grid(True, axis='y', alpha=0.3)

    ax = axes[0, 1]
    if workers:
        ax.plot(workers, [results['elapsed_sec'][i] for i in range(len(workers))],
                marker='o', linewidth=2, markersize=6, label='Elapsed Time')
        ax.plot(workers, results['read_time_sec'],
                marker='s', linewidth=2, markersize=6, label='Read Time')
        ax.plot(workers, results['process_time_sec'],
                marker='^', linewidth=2, markersize=6, label='Process Time (max)')
    ax.set_xlabel('Workers')
    ax.set_ylabel('Time (s)')
    ax.set_title('Elapsed / Read / Process(max) vs Workers')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(worker_range))
    ax.legend()

    ax = axes[1, 0]
    if workers:
        ax.plot(workers, results['read_pcap_sec'],
                marker='o', linewidth=2, markersize=6, label='pcap_next_ex')
        ax.plot(workers, results['read_hash_sec'],
                marker='^', linewidth=2, markersize=5, label='hash')
        ax.plot(workers, results['read_rss_lookup_sec'],
                marker='d', linewidth=2, markersize=5, label='rss_lookup')
        ax.plot(workers, results['read_enqueue_sec'],
                marker='s', linewidth=2, markersize=6, label='enqueue')
        ax.plot(workers, results['read_other_sec'],
                marker='x', linewidth=2, markersize=5, label='other')
    ax.set_xlabel('Workers')
    ax.set_ylabel('Time (s)')
    ax.set_title('Reader Breakdown vs Workers')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(worker_range))
    ax.legend()

    ax = axes[1, 1]
    if workers:
        ax.plot(workers, results['proc_parse_sec'],
                marker='o', linewidth=1.8, markersize=4, label='parse')
        ax.plot(workers, results['proc_flowkey_lookup_sec'],
                marker='v', linewidth=1.8, markersize=4, label='flowkey_lookup')
        ax.plot(workers, results['proc_flow_init_sec'],
                marker='P', linewidth=1.8, markersize=4, label='flow_init')
        ax.plot(workers, results['proc_ndpi_call_sec'],
                marker='*', linewidth=1.8, markersize=5, label='ndpi_call')
        ax.plot(workers, results['proc_proto_check_sec'],
                marker='X', linewidth=1.8, markersize=4, label='proto_check')
        ax.plot(workers, results['proc_classified_fastpath_sec'],
                marker='h', linewidth=1.8, markersize=4, label='classified_fastpath')
        ax.plot(workers, results['proc_flow_sec'],
                marker='s', linewidth=1.8, markersize=4, label='flow')
        ax.plot(workers, results['proc_ndpi_sec'],
                marker='^', linewidth=1.8, markersize=4, label='ndpi')
        ax.plot(workers, results['proc_other_sec'],
                marker='d', linewidth=1.8, markersize=4, label='other')
    ax.set_xlabel('Workers')
    ax.set_ylabel('Time (s)')
    ax.set_title('Process Breakdown (parse/flow/ndpi/other)')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(list(worker_range))
    ax.legend(loc='best')

    fig.suptitle(
        f"mark1 Benchmark Dashboard | binary={os.path.basename(binary_path)} | input={os.path.basename(pcap_file)} | ts={timestamp}",
        fontsize=13
    )
    fig.tight_layout(rect=[0, 0.02, 1, 0.94])

    out_png = os.path.join(output_dir, f'benchmark_dashboard_{timestamp}.png')
    fig.savefig(out_png, dpi=150)
    plt.close(fig)
    print(f"Saved: {out_png}")
    return out_png


def save_csv(results, output_dir, timestamp):
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, f'benchmark_results_{timestamp}.csv')

    core_headers = [f'proc_core_{i:02d}_sec' for i in range(32)]
    headers = [
        'workers', 'bandwidth_gbps', 'throughput_mpps', 'cycles_per_pkt',
        'scaling_efficiency', 'elapsed_sec', 'read_time_sec', 'process_time_sec',
        'read_pcap_sec', 'read_hash_sec', 'read_rss_lookup_sec',
        'read_enqueue_sec', 'read_other_sec', 'proc_parse_sec', 'proc_flowkey_lookup_sec',
        'proc_flow_init_sec', 'proc_flow_sec', 'proc_ndpi_call_sec',
        'proc_proto_check_sec', 'proc_ndpi_sec', 'proc_classified_fastpath_sec', 'proc_other_sec'
    ] + core_headers

    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for i in range(len(results['workers'])):
            row = [
                results['workers'][i],
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
            row.extend(f"{v:.6f}" for v in results['proc_core_sec'][i][:32])
            writer.writerow(row)

    print(f"Saved: {csv_path}")
    return csv_path


def print_summary(results):
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")

    if not results['bandwidth']:
        print("No results collected!")
        return

    max_bw_idx = results['bandwidth'].index(max(results['bandwidth']))
    print(f"\nHighest Bandwidth: {results['bandwidth'][max_bw_idx]:.2f} Gbps "
          f"(workers={results['workers'][max_bw_idx]})")

    min_cy_idx = results['cycles'].index(min(results['cycles']))
    print(f"Lowest Cycles/Pkt: {results['cycles'][min_cy_idx]:.2f} "
          f"(workers={results['workers'][min_cy_idx]})")


def main():
    parser = argparse.ArgumentParser(
        description='mark1 Benchmark 自动化参数扫描（无 loops、无 -r/-t）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -i test.pcap --workers 1,2,4,8
  %(prog)s -i test.pcap -b ./build/ndpiBenchmark --workers 1-16
        '''
    )

    parser.add_argument('-i', '--input', required=True,
                        help='输入 PCAP 文件路径')
    parser.add_argument('-b', '--binary', default='./ndpiBenchmark',
                        help='ndpiBenchmark 可执行文件路径 (默认: ./ndpiBenchmark)')
    parser.add_argument('-w', '--workers', default='1-31',
                        help='Worker 数量列表，支持范围 "1-16" 或列表 "1,2,4,8" (默认: 1,2,4,8,12,16)')
    default_output = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output')
    parser.add_argument('-o', '--output', default=default_output,
                        help='输出根目录 (默认: <repo>/output, 会按完整时间戳自动建子目录)')

    args = parser.parse_args()

    if '-' in args.workers:
        start, end = map(int, args.workers.split('-'))
        worker_range = range(start, end + 1)
    else:
        worker_range = [int(x) for x in args.workers.split(',')]

    if not os.path.exists(args.input):
        print(f"Error: PCAP file not found: {args.input}")
        sys.exit(1)

    if not os.path.exists(args.binary):
        print(f"Error: Benchmark binary not found: {args.binary}")
        print(f"Try: -b ./build/ndpiBenchmark")
        sys.exit(1)

    now = datetime.now()
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    run_output_dir = make_run_output_dir(args.output, now)
    run_log_path = os.path.join(args.output, 'run.log')
    print(f"Output directory: {run_output_dir}")
    append_run_log(run_log_path, timestamp, args.binary, args.input, worker_range)
    print(f"Run log appended: {run_log_path}")

    results = run_sweep(args.binary, args.input, worker_range, run_output_dir)

    if results['bandwidth']:
        save_csv(results, run_output_dir, timestamp)
        plot_results(results, run_output_dir, worker_range, args.binary, args.input, timestamp)
        print_summary(results)
    else:
        print("No results to save!")

    print(f"\n{'='*60}")
    print("Done!")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
