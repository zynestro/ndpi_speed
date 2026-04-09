#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
from typing import List

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def to_float(v: str) -> float:
    try:
        return float(v)
    except Exception:
        return float('nan')


def load_rows(csv_path: str) -> List[dict]:
    with open(csv_path, newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    rows.sort(key=lambda r: int(r['task_id']))
    return rows


def plot(csv_path: str, out_png: str) -> None:
    rows = load_rows(csv_path)
    task_ids = [int(r['task_id']) for r in rows]

    fig, axes = plt.subplots(2, 2, figsize=(18, 10))

    # 1) keep unchanged: bandwidth
    ax = axes[0, 0]
    ax.plot(task_ids, [to_float(r['bandwidth_gbps']) for r in rows], marker='o', linewidth=2)
    ax.set_xlabel('Task ID')
    ax.set_ylabel('Bandwidth (Gbps)')
    ax.set_title('Task vs Bandwidth')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(task_ids)

    # 2) remove elapsed total
    ax = axes[0, 1]
    ax.plot(task_ids, [to_float(r['elapsed_no_preprocess_sec']) for r in rows], marker='D', linewidth=2,
            label='Elapsed (No Preprocess)')
    ax.plot(task_ids, [to_float(r['dispatch_read_sec']) for r in rows], marker='s', linewidth=2, label='Read')
    ax.plot(task_ids, [to_float(r['process_time_sec']) for r in rows], marker='^', linewidth=2, label='Process')
    ax.set_xlabel('Task ID')
    ax.set_ylabel('Time (s)')
    ax.set_title('Task vs Elapsed(NoPre) / Read / Process')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(task_ids)
    ax.legend(loc='best')

    # 3) remove dispatch_read
    ax = axes[1, 0]
    ax.plot(task_ids, [to_float(r['dispatch_flow_to_worker_sec']) for r in rows], marker='^', linewidth=2,
            label='flow_to_worker')
    ax.plot(task_ids, [to_float(r['dispatch_enqueue_sec']) for r in rows], marker='s', linewidth=2,
            label='enqueue')
    ax.plot(task_ids, [to_float(r['dispatch_other_sec']) for r in rows], marker='x', linewidth=2,
            label='other')
    ax.set_xlabel('Task ID')
    ax.set_ylabel('Time (s)')
    ax.set_title('Task vs Reader Breakdown (No dispatch_read)')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(task_ids)
    ax.legend(loc='best')

    # 4) keep unchanged: process breakdown 9 metrics
    ax = axes[1, 1]
    ax.plot(task_ids, [to_float(r['proc_parse_sec']) for r in rows], marker='o', linewidth=1.8, label='parse')
    ax.plot(task_ids, [to_float(r['proc_flowkey_lookup_sec']) for r in rows], marker='v', linewidth=1.8,
            label='flowkey_lookup')
    ax.plot(task_ids, [to_float(r['proc_flow_init_sec']) for r in rows], marker='P', linewidth=1.8,
            label='flow_init')
    ax.plot(task_ids, [to_float(r['proc_flow_sec']) for r in rows], marker='s', linewidth=1.8, label='flow')
    ax.plot(task_ids, [to_float(r['proc_ndpi_call_sec']) for r in rows], marker='*', linewidth=1.8,
            label='ndpi_call')
    ax.plot(task_ids, [to_float(r['proc_proto_check_sec']) for r in rows], marker='X', linewidth=1.8,
            label='proto_check')
    ax.plot(task_ids, [to_float(r['proc_ndpi_sec']) for r in rows], marker='^', linewidth=1.8, label='ndpi')
    ax.plot(task_ids, [to_float(r['proc_classified_fastpath_sec']) for r in rows], marker='h', linewidth=1.8,
            label='classified_fastpath')
    ax.plot(task_ids, [to_float(r['proc_other_sec']) for r in rows], marker='d', linewidth=1.8, label='other')
    ax.set_xlabel('Task ID')
    ax.set_ylabel('Time (s)')
    ax.set_title('Task vs Process Breakdown')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(task_ids)
    ax.legend(loc='best')

    ts = os.path.basename(csv_path).replace('benchmark_results_', '').replace('.csv', '')
    fig.suptitle(f'mark3 Sweep Dashboard (Replot {ts})', fontsize=13)
    fig.text(0.01, 0.01, f'csv: {csv_path}', fontsize=9, ha='left', va='bottom')
    fig.tight_layout(rect=[0, 0.06, 1, 0.94])
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(description='Replot mark3 dashboard from benchmark_results CSV')
    ap.add_argument('csv', help='path to benchmark_results_*.csv')
    ap.add_argument('-o', '--output', default='', help='output png path')
    args = ap.parse_args()

    csv_path = args.csv
    if not os.path.exists(csv_path):
        print(f'Error: csv not found: {csv_path}')
        return 1

    out_png = args.output
    if not out_png:
        d = os.path.dirname(csv_path) or '.'
        ts = os.path.basename(csv_path).replace('benchmark_results_', '').replace('.csv', '')
        out_png = os.path.join(d, f'benchmark_dashboard_{ts}_replot_custom.png')

    plot(csv_path, out_png)
    print(f'Saved: {out_png}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
