#!/usr/bin/env python3
"""Run mark7 evaluation matrices into evaluation/mark7/<timestamp>/raw."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from datetime import datetime
from pathlib import Path


DEFAULT_POLICIES = ["rss", "jsq", "static", "ours", "oracle"]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", default="mark7/build/ndpiBenchmarkMark7")
    ap.add_argument("--pcap", action="append", default=[], help="PCAP path; repeatable")
    ap.add_argument("--policy", action="append", default=[], help="Policy; repeatable")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--worker-cores", default="0,2,4,6,8,10,12,14,24,25,26,27,28,29,30,31")
    ap.add_argument("--dispatcher-cores", default="16,17,18,19,20,21,22,23")
    ap.add_argument("--oracle", default="", help="Oracle CSV used for oracle policy")
    ap.add_argument("--lookup", default="")
    ap.add_argument("--cost-profile", default="")
    ap.add_argument("--tag", default="overall", help="Experiment tag: overall/robustness/overload/etc.")
    ap.add_argument("--workload-label", default="", help="Label used by derived CSVs, e.g. CIC or 20%")
    ap.add_argument("--worker-count-label", default="", help="Overload x-axis label, e.g. 16")
    ap.add_argument("--extra-args", default="", help="Extra args passed to mark7")
    ap.add_argument("--eval-root", default="evaluation/mark7")
    ap.add_argument("--timeout", type=int, default=1800)
    return ap.parse_args()


def run_one(args: argparse.Namespace, pcap: str, policy: str, repeat: int, batch_dir: Path) -> None:
    label = args.workload_label or Path(pcap).stem
    run_id = f"{args.tag}_{label}_policy={policy}_rep={repeat}"
    out_dir = batch_dir / "raw" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    worker_cores = args.worker_cores
    worker_count = len([x for x in worker_cores.split(",") if x.strip()])
    cmd = [
        str(Path(args.binary)),
        "-i", pcap,
        "-P", policy,
        "-n", str(worker_count),
        "-c", worker_cores,
        "-d", args.dispatcher_cores,
        "-o", str(out_dir),
        "-q",
    ]
    if args.lookup:
        cmd.extend(["-m", args.lookup])
    if args.cost_profile:
        cmd.extend(["-C", args.cost_profile])
    if policy == "oracle":
        if not args.oracle:
            raise SystemExit("oracle policy requires --oracle")
        cmd.extend(["-O", args.oracle])
    if args.extra_args.strip():
        cmd.extend(shlex.split(args.extra_args))

    meta = {
        "run_id": run_id,
        "tag": args.tag,
        "workload_label": label,
        "worker_count_label": args.worker_count_label or str(worker_count),
        "pcap": pcap,
        "policy": policy,
        "repeat": repeat,
        "worker_cores": worker_cores,
        "dispatcher_cores": args.dispatcher_cores,
        "cmd": cmd,
    }
    (out_dir / "run_meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    cp = subprocess.run(cmd, text=True, capture_output=True, timeout=args.timeout)
    (out_dir / "stdout.log").write_text(cp.stdout)
    (out_dir / "stderr.log").write_text(cp.stderr)
    if cp.returncode != 0:
        raise SystemExit(f"run failed rc={cp.returncode}: {' '.join(cmd)}")


def main() -> None:
    args = parse_args()
    if not args.pcap:
        raise SystemExit("provide at least one --pcap")
    policies = args.policy or DEFAULT_POLICIES
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = Path(args.eval_root) / f"batch_{ts}"
    batch_dir.mkdir(parents=True, exist_ok=True)
    (batch_dir / "batch_config.json").write_text(json.dumps(vars(args), indent=2) + "\n")

    for pcap in args.pcap:
        for policy in policies:
            for repeat in range(1, args.repeats + 1):
                run_one(args, pcap, policy, repeat, batch_dir)

    print(batch_dir)


if __name__ == "__main__":
    main()
