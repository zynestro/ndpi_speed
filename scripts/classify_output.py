#!/usr/bin/env python3
"""
Classify nDPI benchmark output folders by fingerprinting their contents.

Usage:
    # Scan for new outputs and print classification
    python3 scripts/classify_output.py

    # Scan and append new entries to EXPERIMENT_LOG.md
    python3 scripts/classify_output.py --update-log

    # Scan a specific directory
    python3 scripts/classify_output.py --dir output/mark5/
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# --- Fingerprint rules ---
# Each rule is (mark_name, binary_name, marker_files, subcategory)
# marker_files are checked with "all" (AND) or "any" (OR) logic
FINGERPRINTS = [
    # mark7 — must come before mark4 since proto_category_summary can co-exist
    {
        "mark": "mark7",
        "binary": "ndpiBenchmarkMark7",
        "markers_any": ["run_summary.csv", "policy_config.json", "worker_stats.csv"],
        "subcategory": None,
    },
    # mark5 hardware
    {
        "mark": "mark5",
        "binary": "ndpiBenchmarkMark5",
        "markers_any": ["hardware_flow_profile.csv", "hardware_protocol_summary.csv"],
        "subcategory": "hardware",
    },
    # mark5 time
    {
        "mark": "mark5",
        "binary": "ndpiBenchmarkMark5",
        "markers_all": ["time_flow_profile.csv", "time_protocol_summary.csv"],
        "subcategory": "time",
    },
    # mark5 early / lookup
    {
        "mark": "mark5",
        "binary": "ndpiBenchmarkMark5",
        "markers_any": ["flow_profile.csv", "first_packet_signature_summary.csv"],
        "markers_all": [],
        "subcategory": "time",  # lump with time for simplicity
    },
    # mark5 batch
    {
        "mark": "mark5",
        "binary": "run_mark5_batch.sh",
        "markers_any": ["batch.log", "manifest.json"],
        "subcategory": "batch",
    },
    # mark5 plots
    {
        "mark": "mark5",
        "binary": "mark5 plot scripts",
        "markers_any": ["plot_summary.json"],
        "subcategory": "plots",
    },
    # mark4 — must come after mark5 since some mark5 runs also have proto_category
    {
        "mark": "mark4",
        "binary": "ndpiBenchmarkMark4",
        "markers_all": ["proto_category_summary.csv"],
        "subcategory": None,
    },
    # mark8
    {
        "mark": "mark8",
        "binary": "ndpiBenchmarkMark8",
        "markers_any": ["run_summary.csv"],
        "markers_all": [],
        "subcategory": None,
        "extra_check": lambda p: _check_mark_version(p, "mark8"),
    },
    # mark9
    {
        "mark": "mark9",
        "binary": "ndpiBenchmarkMark9",
        "markers_any": ["run_summary.csv"],
        "markers_all": [],
        "subcategory": None,
        "extra_check": lambda p: _check_mark_version(p, "mark9"),
    },
]


def _check_mark_version(folder: Path, expected: str) -> bool:
    """Check if a policy_config.json or run_meta.json mentions the expected mark."""
    for meta_file in ["policy_config.json", "run_meta.json"]:
        meta_path = folder / meta_file
        if meta_path.exists():
            try:
                data = json.loads(meta_path.read_text())
                # Search recursively for mark version string
                text = json.dumps(data).lower()
                if expected in text:
                    return True
            except (json.JSONDecodeError, OSError):
                pass
    return False


def fingerprint_folder(folder: Path) -> Optional[dict]:
    """
    Classify a single output folder.
    Returns None if it can't be classified (empty, not an output folder, etc.).
    """
    if not folder.is_dir():
        return None

    # Skip known parent/category folders
    name = folder.name
    if name in ("legacy", "_test", "mark4", "mark5", "mark6", "mark7", "mark8", "mark9",
                "time", "hardware", "batch", "plots", "timeline"):
        return None

    # Check if empty
    try:
        contents = list(folder.iterdir())
    except PermissionError:
        return None
    if not contents:
        return {"mark": "?", "binary": "?", "subcategory": None,
                "note": "empty folder — likely failed/interrupted run"}

    # Try each fingerprint rule in order
    for rule in FINGERPRINTS:
        markers_all = rule.get("markers_all", [])
        markers_any = rule.get("markers_any", [])

        # AND check
        if markers_all:
            if not all((folder / m).exists() for m in markers_all):
                continue

        # OR check
        if markers_any:
            if not any((folder / m).exists() for m in markers_any):
                continue

        # Extra check (e.g., for disambiguating mark7/8/9)
        extra = rule.get("extra_check")
        if extra and not extra(folder):
            continue

        return {
            "mark": rule["mark"],
            "binary": rule["binary"],
            "subcategory": rule.get("subcategory"),
            "note": None,
        }

    # Unknown — list what files it has
    sample_files = [f.name for f in list(folder.iterdir())[:5]]
    return {
        "mark": "?",
        "binary": "?",
        "subcategory": None,
        "note": f"unrecognized — sample files: {', '.join(sample_files)}",
    }


def scan_output_dir(output_dir: Path) -> list[dict]:
    """Scan output/ and classify all timestamp-named folders."""
    results = []

    # Only scan top-level and immediate subdirs of known parent dirs
    # (not deeply nested children)
    scan_roots = [output_dir]

    # Also scan immediate children of mark4/, mark5/, etc.
    for parent in output_dir.iterdir():
        if parent.is_dir() and parent.name in ("mark4", "mark5", "mark6", "mark7", "mark8", "mark9"):
            scan_roots.append(parent)

    seen = set()
    for root in scan_roots:
        try:
            for entry in sorted(root.iterdir()):
                if entry.name.startswith(".") or entry.name.startswith("_"):
                    continue
                if entry.name == "EXPERIMENT_LOG.md":
                    continue
                abs_path = entry.resolve()
                if abs_path in seen:
                    continue
                seen.add(abs_path)

                result = fingerprint_folder(entry)
                if result:
                    result["path"] = str(entry.relative_to(output_dir))
                    result["name"] = entry.name
                    # Extract date from folder name
                    result["date"] = _extract_date(entry.name)
                    results.append(result)
        except PermissionError:
            pass

    return results


def _extract_date(name: str) -> str:
    """Extract YYYY-MM-DD from a folder name like 20260410_234655."""
    m = re.match(r"(\d{4})(\d{2})(\d{2})[_-]", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    return "unknown"


def format_markdown_table(results: list[dict]) -> str:
    """Format classification results as a markdown table."""
    if not results:
        return "_(no new outputs found)_\n"

    lines = []
    for r in results:
        path = r["path"]
        date = r["date"]
        mark = r["mark"]
        binary = r["binary"]
        note = r.get("note") or ""
        if note:
            note = f" ⚠ {note}"
        sub = f" ({r['subcategory']})" if r.get("subcategory") else ""
        lines.append(f"| `{path}` | {date} | {mark}{sub} | `{binary}` |{note} |")

    return "\n".join(lines) + "\n"


def update_experiment_log(output_dir: Path, results: list[dict]) -> bool:
    """Append new results to EXPERIMENT_LOG.md. Returns True if anything was added."""
    log_path = output_dir / "EXPERIMENT_LOG.md"
    if not log_path.exists():
        print(f"ERROR: {log_path} not found", file=sys.stderr)
        return False

    content = log_path.read_text()

    # Only add entries not already in the log
    new_entries = []
    for r in results:
        if r["name"] not in content:
            new_entries.append(r)

    if not new_entries:
        print("No new entries to add (all already in log).")
        return False

    # Build table rows
    rows = []
    for r in new_entries:
        path = r["path"]
        date = r["date"]
        mark = r["mark"]
        binary = r["binary"]
        note = r.get("note") or ""
        sub = f" ({r['subcategory']})" if r.get("subcategory") else ""
        rows.append(f"| `{path}` | {date} | {mark}{sub} | `{binary}` | {note} |")

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    header = f"\n<!-- Auto-classified {now} -->\n"
    table = header + "\n".join(rows) + "\n"

    # Append before the closing of the "新增记录" section
    # Find the last table separator line and append after it
    new_content = content.rstrip() + "\n" + table

    log_path.write_text(new_content)
    print(f"Added {len(new_entries)} new entries to {log_path}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Classify nDPI benchmark output folders")
    parser.add_argument("--dir", default="output",
                        help="Output directory to scan (default: output/)")
    parser.add_argument("--update-log", action="store_true",
                        help="Append new entries to EXPERIMENT_LOG.md")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON instead of table")
    args = parser.parse_args()

    output_dir = Path(args.dir)
    if not output_dir.exists():
        print(f"ERROR: {output_dir} does not exist", file=sys.stderr)
        sys.exit(1)

    results = scan_output_dir(output_dir)

    if not results:
        print("No classifiable output folders found.")
        return

    if args.json:
        print(json.dumps(results, indent=2, default=str))
        return

    # Group by mark
    by_mark = {}
    for r in results:
        key = r["mark"]
        by_mark.setdefault(key, []).append(r)

    print("=== Classification Results ===\n")
    for mark in sorted(by_mark.keys()):
        entries = by_mark[mark]
        print(f"## {mark} ({len(entries)} folders)")
        for r in entries:
            sub = f" [{r['subcategory']}]" if r.get("subcategory") else ""
            note = f" — {r['note']}" if r.get("note") else ""
            print(f"  {r['path']}{sub}{note}")
        print()

    if args.update_log:
        updated = update_experiment_log(output_dir, results)
        if not updated:
            print("(log already up to date)")


if __name__ == "__main__":
    main()
