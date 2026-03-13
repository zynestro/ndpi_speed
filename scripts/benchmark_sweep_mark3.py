#!/usr/bin/env python3
"""
mark3 benchmark sweep script.

Design:
- No explicit -n input from user. n is derived from worker set length.
- Sweep dimensions are worker_sets and reader_sets.
- Modes:
  - paired: pair worker_sets[i] with reader_sets[i]
  - cross: Cartesian product worker_sets x reader_sets
- Output:
  - output/<timestamp>/benchmark_results_<timestamp>.csv
  - output/run.log appended
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import List

MODE_PAIRED = "paired"
MODE_CROSS = "cross"


@dataclass
class Task:
    task_id: int
    worker_cores: List[int]
    reader_cores: List[int]


def parse_core_sets(raw: str, name: str) -> List[List[int]]:
    """
    Parse format like:
      "2,3,4;6,7;8"
    => [[2,3,4], [6,7], [8]]
    """
    if not raw or not raw.strip():
        raise ValueError(f"{name} is empty")

    groups = [g.strip() for g in raw.strip().split(";") if g.strip()]
    if not groups:
        raise ValueError(f"{name} has no valid groups")

    sets: List[List[int]] = []
    for gi, group in enumerate(groups, start=1):
        items = [x.strip() for x in group.split(",") if x.strip()]
        if not items:
            raise ValueError(f"{name} group #{gi} is empty")

        cores: List[int] = []
        seen = set()
        for item in items:
            if not re.fullmatch(r"\d+", item):
                raise ValueError(f"{name} group #{gi} contains non-integer core: {item}")
            core = int(item)
            if core < 0:
                raise ValueError(f"{name} group #{gi} contains negative core: {core}")
            if core in seen:
                raise ValueError(f"{name} group #{gi} has duplicate core: {core}")
            seen.add(core)
            cores.append(core)

        sets.append(cores)

    return sets


def normalize_core_sets(value, name: str) -> List[List[int]]:
    """
    Accept either:
    - string: "2,3,4;6,7"
    - list[list[int]]: [[2,3,4], [6,7]]
    - list[str]: ["2,3,4", "6,7"]
    """
    if isinstance(value, str):
        return parse_core_sets(value, name)

    if isinstance(value, list):
        out: List[List[int]] = []
        for gi, group in enumerate(value, start=1):
            if isinstance(group, str):
                parsed = parse_core_sets(group, f"{name}[{gi}]")
                if len(parsed) != 1:
                    raise ValueError(f"{name}[{gi}] string should describe one set")
                out.append(parsed[0])
                continue

            if not isinstance(group, list) or not group:
                raise ValueError(f"{name}[{gi}] must be a non-empty list")
            seen = set()
            cores: List[int] = []
            for item in group:
                if not isinstance(item, int):
                    raise ValueError(f"{name}[{gi}] contains non-int core: {item}")
                if item < 0:
                    raise ValueError(f"{name}[{gi}] contains negative core: {item}")
                if item in seen:
                    raise ValueError(f"{name}[{gi}] has duplicate core: {item}")
                seen.add(item)
                cores.append(item)
            out.append(cores)

        if not out:
            raise ValueError(f"{name} has no valid groups")
        return out

    raise ValueError(f"{name} must be string or list")


def load_config_file(path: str) -> dict:
    if not os.path.exists(path):
        raise ValueError(f"config file not found: {path}")

    _, ext = os.path.splitext(path.lower())
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    if ext == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON config: {e}") from e

    def parse_scalar(text: str):
        s = text.strip()
        if not s:
            return ""
        if s.startswith(("\"", "'")) and s.endswith(("\"", "'")) and len(s) >= 2:
            return s[1:-1]
        low = s.lower()
        if low == "true":
            return True
        if low == "false":
            return False
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        return s

    def parse_inline_list(text: str):
        s = text.strip()
        if not (s.startswith("[") and s.endswith("]")):
            raise ValueError(f"invalid inline list: {text}")
        inner = s[1:-1].strip()
        if not inner:
            return []
        parts = [p.strip() for p in inner.split(",")]
        out = []
        for p in parts:
            out.append(parse_scalar(p))
        return out

    def parse_simple_yaml(yaml_text: str) -> dict:
        # Minimal parser for root-level key/value and root-level list blocks:
        # key: value
        # key:
        #   - [1, 2]
        #   - [3, 4]
        obj: dict = {}
        raw_lines = yaml_text.splitlines()
        lines = []
        for raw in raw_lines:
            line = raw.split("#", 1)[0].rstrip()
            if line.strip():
                lines.append(line)

        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
            if not m:
                raise ValueError(f"cannot parse YAML line: {line}")
            key, rest = m.group(1), m.group(2)
            if rest:
                obj[key] = parse_scalar(rest)
                i += 1
                continue

            # block list
            arr = []
            i += 1
            while i < len(lines):
                sub = lines[i]
                if not sub.startswith("  "):
                    break
                sm = re.match(r"^\s*-\s*(.+)$", sub)
                if not sm:
                    raise ValueError(f"invalid YAML list item line: {sub}")
                item = sm.group(1).strip()
                if item.startswith("[") and item.endswith("]"):
                    arr.append(parse_inline_list(item))
                else:
                    arr.append(parse_scalar(item))
                i += 1
            obj[key] = arr
        return obj

    # yaml / yml / unknown -> try PyYAML first, then fallback parser
    try:
        import yaml  # type: ignore
    except ImportError as e:
        try:
            return parse_simple_yaml(text)
        except Exception as pe:
            raise ValueError(
                "YAML parse failed (PyYAML not installed and fallback parser failed): "
                f"{pe}"
            ) from e

    try:
        obj = yaml.safe_load(text)
    except Exception as e:
        try:
            obj = parse_simple_yaml(text)
        except Exception:
            raise ValueError(f"invalid YAML config: {e}") from e

    if not isinstance(obj, dict):
        raise ValueError("config root must be a mapping/object")
    return obj


def build_tasks(worker_sets: List[List[int]], reader_sets: List[List[int]], mode: str) -> List[Task]:
    tasks: List[Task] = []
    if mode == MODE_PAIRED:
        if len(worker_sets) != len(reader_sets):
            raise ValueError(
                f"paired mode requires equal set counts: worker_sets={len(worker_sets)}, "
                f"reader_sets={len(reader_sets)}"
            )
        for i, (w, r) in enumerate(zip(worker_sets, reader_sets), start=1):
            tasks.append(Task(task_id=i, worker_cores=w, reader_cores=r))
    else:
        tid = 1
        for w in worker_sets:
            for r in reader_sets:
                tasks.append(Task(task_id=tid, worker_cores=w, reader_cores=r))
                tid += 1
    return tasks


def validate_task(task: Task) -> None:
    if not task.worker_cores:
        raise ValueError(f"task#{task.task_id}: empty worker set")
    if not task.reader_cores:
        raise ValueError(f"task#{task.task_id}: empty reader set")


def core_list_to_arg(cores: List[int]) -> str:
    return ",".join(str(c) for c in cores)


def build_cmd(binary: str, pcap: str, task: Task, quiet: bool, extra_args: str) -> List[str]:
    cmd = [
        binary,
        "-i", pcap,
        "-n", str(len(task.worker_cores)),
        "-c", core_list_to_arg(task.worker_cores),
        "-d", core_list_to_arg(task.reader_cores),
    ]
    if quiet:
        cmd.append("-q")
    if extra_args.strip():
        cmd.extend(shlex.split(extra_args))
    return cmd


def parse_metrics(output: str) -> dict:
    patterns = {
        "total_elapsed_sec": r"Total Elapsed Time:\s+([\d.]+)\s+seconds",
        "preprocess_sec": r"Preprocess Time:\s+([\d.]+)\s+seconds",
        "elapsed_no_preprocess_sec": r"Elapsed Time \(No Preprocess\):\s+([\d.]+)\s+seconds",
        "dispatch_read_sec": r"Dispatch\(Read\) Time:\s+([\d.]+)\s+seconds",
        "dispatch_flow_to_worker_sec": r"Dispatch flow->worker map:\s+([\d.]+)\s+seconds",
        "dispatch_enqueue_sec": r"Dispatch enqueue:\s+([\d.]+)\s+seconds",
        "dispatch_other_sec": r"Dispatch other:\s+([\d.]+)\s+seconds",
        "process_time_sec": r"Process Time:\s+([\d.]+)\s+seconds",
        "throughput_mpps": r"Throughput:\s+([\d.]+)\s+Mpps",
        "bandwidth_gbps": r"Bandwidth:\s+([\d.]+)\s+Gbps",
        "cycles_per_pkt": r"Cycles per packet:\s+([\d.]+)",
        "total_packets": r"Total Packets:\s+(\d+)",
        "total_flows": r"Total flows created:\s+(\d+)",
        "detected_flows": r"Flows with detected protocol:\s+(\d+)",
        "scaling_efficiency": r"Scaling Efficiency:\s+([\d.]+)%",
    }

    out: dict = {}
    for k, p in patterns.items():
        m = re.search(p, output)
        if not m:
            continue
        if k in {"total_packets", "total_flows", "detected_flows"}:
            out[k] = int(m.group(1))
        else:
            out[k] = float(m.group(1))
    return out


def run_task(binary: str, pcap: str, task: Task, timeout_sec: int, quiet: bool, extra_args: str) -> tuple[int, str, dict]:
    cmd = build_cmd(binary, pcap, task, quiet=quiet, extra_args=extra_args)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        output = (cp.stdout or "") + (cp.stderr or "")
        metrics = parse_metrics(output)
        return cp.returncode, output, metrics
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or "") + (e.stderr or "")
        return 124, output, {}


def make_output_dir(base: str, now: datetime) -> str:
    ts = now.strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base, ts)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def append_run_log(log_path: str,
                   timestamp: str,
                   binary: str,
                   pcap: str,
                   mode: str,
                   worker_sets: List[List[int]],
                   reader_sets: List[List[int]],
                   quiet: bool,
                   timeout_sec: int,
                   extra_args: str) -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a") as f:
        f.write(f"\n[{timestamp}] mark3_sweep_start\n")
        f.write(f"binary: {binary}\n")
        f.write(f"input: {pcap}\n")
        f.write(f"mode: {mode}\n")
        f.write("worker_sets: " + ";".join(core_list_to_arg(s) for s in worker_sets) + "\n")
        f.write("reader_sets: " + ";".join(core_list_to_arg(s) for s in reader_sets) + "\n")
        f.write(f"quiet: {quiet}\n")
        f.write(f"timeout_sec: {timeout_sec}\n")
        f.write(f"extra_args: {extra_args}\n")


def save_csv(rows: List[dict], output_dir: str, timestamp: str) -> str:
    csv_path = os.path.join(output_dir, f"benchmark_results_{timestamp}.csv")
    headers = [
        "task_id",
        "worker_set",
        "reader_set",
        "n_workers",
        "return_code",
        "status",
        "total_elapsed_sec",
        "preprocess_sec",
        "elapsed_no_preprocess_sec",
        "dispatch_read_sec",
        "dispatch_flow_to_worker_sec",
        "dispatch_enqueue_sec",
        "dispatch_other_sec",
        "process_time_sec",
        "throughput_mpps",
        "bandwidth_gbps",
        "cycles_per_pkt",
        "total_packets",
        "total_flows",
        "detected_flows",
        "scaling_efficiency",
        "cmd",
    ]

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return csv_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="mark3 sweep: worker_sets + reader_sets, paired/cross modes"
    )
    parser.add_argument("--config", default="", help="YAML/JSON config file path")
    parser.add_argument("-i", "--input", default="", help="input pcap path")
    parser.add_argument("-b", "--binary", default="", help="mark3 binary path")
    parser.add_argument("--mode", choices=[MODE_PAIRED, MODE_CROSS], default=None,
                        help="paired: ith worker_set with ith reader_set; cross: Cartesian product")
    parser.add_argument("--worker-sets", default="",
                        help="semicolon separated core sets, e.g. '2,3,4,5;6,7,8,9'")
    parser.add_argument("--reader-sets", default="",
                        help="semicolon separated core sets, e.g. '1;1,6'")
    parser.add_argument("-o", "--output", default="", help="output root directory")
    parser.add_argument("--timeout", type=int, default=0, help="timeout per run in seconds")
    parser.add_argument("--no-quiet", action="store_true", help="disable -q")
    parser.add_argument("--extra-args", default="", help="extra args appended to binary command")
    args = parser.parse_args()

    try:
        cfg = {}
        if args.config:
            cfg = load_config_file(args.config)

        input_path = args.input if args.input else cfg.get("input", "")
        binary_path = args.binary if args.binary else cfg.get("binary", "mark3/build/ndpiBenchmarkMark3")
        mode = args.mode if args.mode else cfg.get("mode", MODE_PAIRED)
        output_dir = args.output if args.output else cfg.get("output", "output")
        timeout_sec = args.timeout if args.timeout > 0 else int(cfg.get("timeout", 900))
        extra_args = args.extra_args if args.extra_args else str(cfg.get("extra_args", ""))

        quiet = bool(cfg.get("quiet", True))
        if args.no_quiet:
            quiet = False

        worker_sets_raw = args.worker_sets if args.worker_sets else cfg.get("worker_sets", "")
        reader_sets_raw = args.reader_sets if args.reader_sets else cfg.get("reader_sets", "")

        worker_sets = normalize_core_sets(worker_sets_raw, "worker_sets")
        reader_sets = normalize_core_sets(reader_sets_raw, "reader_sets")
        if mode not in {MODE_PAIRED, MODE_CROSS}:
            raise ValueError(f"invalid mode: {mode}")
        tasks = build_tasks(worker_sets, reader_sets, mode)
        for t in tasks:
            validate_task(t)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    if not os.path.exists(input_path):
        print(f"Error: pcap not found: {input_path}")
        return 1
    if not os.path.exists(binary_path):
        print(f"Error: binary not found: {binary_path}")
        return 1

    now = datetime.now()
    ts = now.strftime("%Y%m%d_%H%M%S")
    run_output_dir = make_output_dir(output_dir, now)
    run_log_path = os.path.join(output_dir, "run.log")
    append_run_log(
        run_log_path,
        ts,
        binary_path,
        input_path,
        mode,
        worker_sets,
        reader_sets,
        quiet=quiet,
        timeout_sec=timeout_sec,
        extra_args=extra_args,
    )

    print(f"Output directory: {run_output_dir}")
    print(f"Run log appended: {run_log_path}")
    print(f"Mode: {mode}")
    print(f"Total tasks: {len(tasks)}")

    rows: List[dict] = []
    for i, task in enumerate(tasks, start=1):
        worker_arg = core_list_to_arg(task.worker_cores)
        reader_arg = core_list_to_arg(task.reader_cores)
        cmd = build_cmd(binary_path, input_path, task, quiet=quiet, extra_args=extra_args)
        cmd_text = " ".join(shlex.quote(x) for x in cmd)

        print(
            f"[{i}/{len(tasks)}] workers={worker_arg} (n={len(task.worker_cores)}), "
            f"readers={reader_arg} ...",
            end=" ",
            flush=True,
        )

        rc, output, metrics = run_task(
            binary_path,
            input_path,
            task,
            timeout_sec=timeout_sec,
            quiet=quiet,
            extra_args=extra_args,
        )

        status = "ok" if (rc == 0 and "throughput_mpps" in metrics) else "failed"
        if status == "ok":
            print(f"{metrics.get('bandwidth_gbps', 0.0):.2f} Gbps, {metrics.get('throughput_mpps', 0.0):.2f} Mpps")
        else:
            print(f"FAILED (rc={rc})")

        out_path = os.path.join(run_output_dir, f"task_{task.task_id:03d}.out.log")
        with open(out_path, "w") as f:
            f.write(output)

        row = {
            "task_id": task.task_id,
            "worker_set": worker_arg,
            "reader_set": reader_arg,
            "n_workers": len(task.worker_cores),
            "return_code": rc,
            "status": status,
            "total_elapsed_sec": metrics.get("total_elapsed_sec", ""),
            "preprocess_sec": metrics.get("preprocess_sec", ""),
            "elapsed_no_preprocess_sec": metrics.get("elapsed_no_preprocess_sec", ""),
            "dispatch_read_sec": metrics.get("dispatch_read_sec", ""),
            "dispatch_flow_to_worker_sec": metrics.get("dispatch_flow_to_worker_sec", ""),
            "dispatch_enqueue_sec": metrics.get("dispatch_enqueue_sec", ""),
            "dispatch_other_sec": metrics.get("dispatch_other_sec", ""),
            "process_time_sec": metrics.get("process_time_sec", ""),
            "throughput_mpps": metrics.get("throughput_mpps", ""),
            "bandwidth_gbps": metrics.get("bandwidth_gbps", ""),
            "cycles_per_pkt": metrics.get("cycles_per_pkt", ""),
            "total_packets": metrics.get("total_packets", ""),
            "total_flows": metrics.get("total_flows", ""),
            "detected_flows": metrics.get("detected_flows", ""),
            "scaling_efficiency": metrics.get("scaling_efficiency", ""),
            "cmd": cmd_text,
        }
        rows.append(row)

    csv_path = save_csv(rows, run_output_dir, ts)
    print(f"Saved: {csv_path}")

    ok_count = sum(1 for r in rows if r["status"] == "ok")
    print(f"Done. success={ok_count}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
