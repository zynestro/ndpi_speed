#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SWEEP_SCRIPT="$ROOT_DIR/scripts/benchmark_sweep_mark1.py"
PCAP_FILE="$ROOT_DIR/input/seed_10G.pcap"
BUILD_DIR="$ROOT_DIR/mark1/build"
OUTPUT_DIR="$ROOT_DIR/output"
WORKERS="1-31"

BINARIES=(
  "ndpiBenchmark"
  # "ndpiBenchmarkClassified"
  # "ndpiBenchmarkBatch"
  # "ndpiBenchmarkMem"
  # "ndpiBenchmarkSingleHash"
  # "ndpiBenchmarkAggLB"
)

if [[ ! -x "$SWEEP_SCRIPT" ]]; then
  echo "Error: sweep script not executable: $SWEEP_SCRIPT"
  exit 1
fi

if [[ ! -f "$PCAP_FILE" ]]; then
  echo "Error: pcap file not found: $PCAP_FILE"
  exit 1
fi

for bin in "${BINARIES[@]}"; do
  bin_path="$BUILD_DIR/$bin"
  if [[ ! -x "$bin_path" ]]; then
    echo "Error: binary not found or not executable: $bin_path"
    exit 1
  fi

  echo
  echo "============================================================"
  echo "Running sweep for: $bin_path"
  echo "PCAP: $PCAP_FILE | workers: $WORKERS"
  echo "Start: $(date '+%F %T')"
  echo "============================================================"

  "$SWEEP_SCRIPT" \
    -i "$PCAP_FILE" \
    -b "$bin_path" \
    -w "$WORKERS" \
    -o "$OUTPUT_DIR"

  echo "Done: $bin_path at $(date '+%F %T')"
done

echo
echo "All sweeps finished at $(date '+%F %T')"
