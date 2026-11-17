#!/usr/bin/env python3
"""
nDPI Benchmark 自动化测试脚本
自动测试不同 worker 数量和循环次数下的性能，并生成折线图
"""

import subprocess
import re
import argparse
import os
import sys
from datetime import datetime

# 尝试导入绘图库
try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # 无头模式，适合服务器
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not found, will skip plotting")
    print("Install with: pip install matplotlib")


def get_physical_cores(n):
    """生成物理核心列表（偶数编号）"""
    return ','.join(str(i * 2) for i in range(n))


def run_benchmark(binary_path, pcap_file, num_workers, num_loops, quiet=True):
    """运行 benchmark 并解析结果"""
    
    core_list = get_physical_cores(num_workers)
    
    cmd = [
        binary_path,
        '-i', pcap_file,
        '-n', str(num_workers),
        '-l', str(num_loops),
        '-c', core_list,
        '-r', '-t'  # 启用随机化和时间戳抖动
    ]
    
    if quiet:
        cmd.append('-q')
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        
        # 解析结果
        metrics = {}
        
        # 解析 Bandwidth
        match = re.search(r'Bandwidth:\s+([\d.]+)\s+Gbps', output)
        if match:
            metrics['bandwidth_gbps'] = float(match.group(1))
        
        # 解析 Throughput
        match = re.search(r'Throughput:\s+([\d.]+)\s+Mpps', output)
        if match:
            metrics['throughput_mpps'] = float(match.group(1))
        
        # 解析 Cycles per packet
        match = re.search(r'Cycles per packet:\s+([\d.]+)', output)
        if match:
            metrics['cycles_per_pkt'] = float(match.group(1))
        
        # 解析 Elapsed Time
        match = re.search(r'Elapsed Time:\s+([\d.]+)\s+seconds', output)
        if match:
            metrics['elapsed_sec'] = float(match.group(1))
        
        # 解析 Total Packets
        match = re.search(r'Total Packets:\s+(\d+)', output)
        if match:
            metrics['total_packets'] = int(match.group(1))
        
        # 解析 Scaling Efficiency
        match = re.search(r'Scaling Efficiency:\s+([\d.]+)%', output)
        if match:
            metrics['scaling_efficiency'] = float(match.group(1))
        
        return metrics
        
    except subprocess.TimeoutExpired:
        print(f"  Timeout! (workers={num_workers}, loops={num_loops})")
        return None
    except Exception as e:
        print(f"  Error: {e}")
        return None


def run_sweep(binary_path, pcap_file, worker_range, loop_values, output_dir):
    """执行参数扫描测试"""
    
    results = {
        'workers': [],
        'loops': [],
        'bandwidth': [],
        'throughput': [],
        'cycles': [],
        'efficiency': []
    }
    
    # 按 loops 分组的结果，用于绘图
    results_by_loops = {}
    
    total_tests = len(worker_range) * len(loop_values)
    current_test = 0
    
    print(f"\n{'='*60}")
    print(f"Starting benchmark sweep: {total_tests} tests")
    print(f"Workers: {list(worker_range)}")
    print(f"Loops: {loop_values}")
    print(f"{'='*60}\n")
    
    for loops in loop_values:
        results_by_loops[loops] = {'workers': [], 'bandwidth': [], 'throughput': [], 'cycles': []}
        
        for workers in worker_range:
            current_test += 1
            print(f"[{current_test}/{total_tests}] Testing: workers={workers}, loops={loops}...", end=' ', flush=True)
            
            metrics = run_benchmark(binary_path, pcap_file, workers, loops)
            
            if metrics and 'bandwidth_gbps' in metrics:
                bw = metrics['bandwidth_gbps']
                tp = metrics.get('throughput_mpps', 0)
                cy = metrics.get('cycles_per_pkt', 0)
                ef = metrics.get('scaling_efficiency', 0)
                
                print(f"Bandwidth: {bw:.2f} Gbps, {tp:.2f} Mpps, {cy:.1f} cycles/pkt")
                
                results['workers'].append(workers)
                results['loops'].append(loops)
                results['bandwidth'].append(bw)
                results['throughput'].append(tp)
                results['cycles'].append(cy)
                results['efficiency'].append(ef)
                
                results_by_loops[loops]['workers'].append(workers)
                results_by_loops[loops]['bandwidth'].append(bw)
                results_by_loops[loops]['throughput'].append(tp)
                results_by_loops[loops]['cycles'].append(cy)
            else:
                print("Failed!")
    
    return results, results_by_loops


def plot_results(results_by_loops, output_dir, worker_range):
    """生成折线图"""
    
    if not HAS_MATPLOTLIB:
        print("\nSkipping plots (matplotlib not available)")
        return
    
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 图1: Bandwidth vs Workers (不同 loops)
    plt.figure(figsize=(12, 6))
    
    for loops, data in sorted(results_by_loops.items()):
        if data['workers']:
            plt.plot(data['workers'], data['bandwidth'], 
                    marker='o', linewidth=2, markersize=6,
                    label=f'loops={loops}')
    
    plt.xlabel('Number of Workers', fontsize=12)
    plt.ylabel('Bandwidth (Gbps)', fontsize=12)
    plt.title('nDPI Benchmark: Bandwidth vs Worker Count', fontsize=14)
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    plt.xticks(list(worker_range))
    
    # 添加 100 Gbps 参考线
    plt.axhline(y=100, color='r', linestyle='--', alpha=0.5, label='100 Gbps target')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'bandwidth_vs_workers_{timestamp}.png'), dpi=150)
    print(f"\nSaved: bandwidth_vs_workers_{timestamp}.png")
    
    # 图2: Throughput vs Workers
    plt.figure(figsize=(12, 6))
    
    for loops, data in sorted(results_by_loops.items()):
        if data['workers']:
            plt.plot(data['workers'], data['throughput'],
                    marker='s', linewidth=2, markersize=6,
                    label=f'loops={loops}')
    
    plt.xlabel('Number of Workers', fontsize=12)
    plt.ylabel('Throughput (Mpps)', fontsize=12)
    plt.title('nDPI Benchmark: Throughput vs Worker Count', fontsize=14)
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    plt.xticks(list(worker_range))
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'throughput_vs_workers_{timestamp}.png'), dpi=150)
    print(f"Saved: throughput_vs_workers_{timestamp}.png")
    
    # 图3: Cycles per packet vs Workers
    plt.figure(figsize=(12, 6))
    
    for loops, data in sorted(results_by_loops.items()):
        if data['workers']:
            plt.plot(data['workers'], data['cycles'],
                    marker='^', linewidth=2, markersize=6,
                    label=f'loops={loops}')
    
    plt.xlabel('Number of Workers', fontsize=12)
    plt.ylabel('Cycles per Packet', fontsize=12)
    plt.title('nDPI Benchmark: CPU Efficiency vs Worker Count', fontsize=14)
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    plt.xticks(list(worker_range))
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'cycles_vs_workers_{timestamp}.png'), dpi=150)
    print(f"Saved: cycles_vs_workers_{timestamp}.png")
    
    # 图4: 综合对比图 (2x2)
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 4.1 Bandwidth
    ax = axes[0, 0]
    for loops, data in sorted(results_by_loops.items()):
        if data['workers']:
            ax.plot(data['workers'], data['bandwidth'], marker='o', label=f'loops={loops}')
    ax.set_xlabel('Workers')
    ax.set_ylabel('Bandwidth (Gbps)')
    ax.set_title('Bandwidth')
    ax.legend(loc='best', fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.axhline(y=100, color='r', linestyle='--', alpha=0.5)
    
    # 4.2 Throughput
    ax = axes[0, 1]
    for loops, data in sorted(results_by_loops.items()):
        if data['workers']:
            ax.plot(data['workers'], data['throughput'], marker='s', label=f'loops={loops}')
    ax.set_xlabel('Workers')
    ax.set_ylabel('Throughput (Mpps)')
    ax.set_title('Throughput')
    ax.legend(loc='best', fontsize=8)
    ax.grid(True, alpha=0.3)
    
    # 4.3 Cycles per packet
    ax = axes[1, 0]
    for loops, data in sorted(results_by_loops.items()):
        if data['workers']:
            ax.plot(data['workers'], data['cycles'], marker='^', label=f'loops={loops}')
    ax.set_xlabel('Workers')
    ax.set_ylabel('Cycles/Packet')
    ax.set_title('CPU Efficiency (lower is better)')
    ax.legend(loc='best', fontsize=8)
    ax.grid(True, alpha=0.3)
    
    # 4.4 Scaling efficiency (bandwidth per worker)
    ax = axes[1, 1]
    for loops, data in sorted(results_by_loops.items()):
        if data['workers'] and len(data['workers']) > 0:
            # 计算每个worker的平均带宽
            bw_per_worker = [bw / w for bw, w in zip(data['bandwidth'], data['workers'])]
            ax.plot(data['workers'], bw_per_worker, marker='d', label=f'loops={loops}')
    ax.set_xlabel('Workers')
    ax.set_ylabel('Gbps per Worker')
    ax.set_title('Scaling Efficiency')
    ax.legend(loc='best', fontsize=8)
    ax.grid(True, alpha=0.3)
    
    plt.suptitle('nDPI Benchmark Summary', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'summary_{timestamp}.png'), dpi=150)
    print(f"Saved: summary_{timestamp}.png")
    
    plt.close('all')


def save_csv(results, output_dir):
    """保存结果到 CSV"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_path = os.path.join(output_dir, f'benchmark_results_{timestamp}.csv')
    
    with open(csv_path, 'w') as f:
        f.write('workers,loops,bandwidth_gbps,throughput_mpps,cycles_per_pkt,scaling_efficiency\n')
        for i in range(len(results['workers'])):
            f.write(f"{results['workers'][i]},{results['loops'][i]},"
                   f"{results['bandwidth'][i]:.2f},{results['throughput'][i]:.2f},"
                   f"{results['cycles'][i]:.2f},{results['efficiency'][i]:.1f}\n")
    
    print(f"Saved: {csv_path}")
    return csv_path


def print_summary(results, results_by_loops):
    """打印结果摘要"""
    print(f"\n{'='*60}")
    print("RESULTS SUMMARY")
    print(f"{'='*60}")
    
    if not results['bandwidth']:
        print("No results collected!")
        return
    
    print(f"\nBest configurations:")
    
    # 找最高带宽
    max_bw_idx = results['bandwidth'].index(max(results['bandwidth']))
    print(f"  Highest Bandwidth: {results['bandwidth'][max_bw_idx]:.2f} Gbps "
          f"(workers={results['workers'][max_bw_idx]}, loops={results['loops'][max_bw_idx]})")
    
    # 找最低 cycles
    min_cy_idx = results['cycles'].index(min(results['cycles']))
    print(f"  Lowest Cycles/Pkt: {results['cycles'][min_cy_idx]:.2f} "
          f"(workers={results['workers'][min_cy_idx]}, loops={results['loops'][min_cy_idx]})")
    
    # 按 loops 打印
    print(f"\nResults by loop count:")
    for loops in sorted(results_by_loops.keys()):
        data = results_by_loops[loops]
        if data['bandwidth']:
            max_bw = max(data['bandwidth'])
            max_bw_workers = data['workers'][data['bandwidth'].index(max_bw)]
            print(f"  loops={loops}: max {max_bw:.2f} Gbps @ {max_bw_workers} workers")


def main():
    parser = argparse.ArgumentParser(
        description='nDPI Benchmark 自动化参数扫描',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # 快速测试
  %(prog)s -i test.pcap --workers 1,2,4,8 --loops 100
  
  # 完整扫描
  %(prog)s -i test.pcap --workers 1-16 --loops 10,100,1000
  
  # 自定义 benchmark 路径
  %(prog)s -i test.pcap -b ./build/ndpiBenchmark --workers 1-8
        '''
    )
    
    parser.add_argument('-i', '--input', required=True,
                        help='输入 PCAP 文件路径')
    parser.add_argument('-b', '--binary', default='./ndpiBenchmark',
                        help='ndpiBenchmark 可执行文件路径 (默认: ./ndpiBenchmark)')
    parser.add_argument('-w', '--workers', default='1-32',
                        help='Worker 数量列表，支持范围 "1-16" 或列表 "1,2,4,8" (默认: 1,2,4,8,12,16)')
    parser.add_argument('-l', '--loops', default='1,100,1000',
                        help='循环次数列表 (默认: 100,1000)')
    parser.add_argument('-o', '--output', default='/home/zync/WORKSPACE/ndpi_speed/mark0/benchmark_results',
                        help='输出目录 (默认: ./benchmark_results)')
    
    args = parser.parse_args()
    
    # 解析 workers 参数
    if '-' in args.workers:
        start, end = map(int, args.workers.split('-'))
        worker_range = range(start, end + 1)
    else:
        worker_range = [int(x) for x in args.workers.split(',')]
    
    # 解析 loops 参数
    loop_values = [int(x) for x in args.loops.split(',')]
    
    # 检查文件存在
    if not os.path.exists(args.input):
        print(f"Error: PCAP file not found: {args.input}")
        sys.exit(1)
    
    if not os.path.exists(args.binary):
        print(f"Error: Benchmark binary not found: {args.binary}")
        print(f"Try: -b ./build/ndpiBenchmark")
        sys.exit(1)
    
    # 运行扫描
    results, results_by_loops = run_sweep(
        args.binary, args.input, worker_range, loop_values, args.output
    )
    
    # 保存和绘图
    if results['bandwidth']:
        save_csv(results, args.output)
        plot_results(results_by_loops, args.output, worker_range)
        print_summary(results, results_by_loops)
    else:
        print("No results to save!")
    
    print(f"\n{'='*60}")
    print("Done!")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
