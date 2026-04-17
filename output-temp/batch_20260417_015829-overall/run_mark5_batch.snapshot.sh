#!/usr/bin/env bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MARK5_REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
INPUT_DIR="${1:-${REPO_ROOT}/input}"
BATCH_TS="$(date +%Y%m%d_%H%M%S)"
BATCH_DIR="${REPO_ROOT}/output/batch_${BATCH_TS}"
LOG_FILE="${BATCH_DIR}/batch.log"
RUNS_TSV="${BATCH_DIR}/runs.tsv"
MANIFEST_JSON="${BATCH_DIR}/manifest.json"
TIME_EXE="${REPO_ROOT}/mark5/build/ndpiBenchmarkMark5Time"
HW_EXE="${REPO_ROOT}/mark5/build/ndpiBenchmarkMark5Hardware"
PLOT_MANIFEST_PY="${REPO_ROOT}/mark5/plot_protocol_manifest.py"
PLOT_OUTPUT_DIR="${BATCH_DIR}/plots"

mkdir -p "${BATCH_DIR}"

# Freeze the script body for this batch so later edits do not affect a running job.
if [[ "${MARK5_BATCH_SNAPSHOT:-0}" != "1" ]]; then
  SNAPSHOT_SH="${BATCH_DIR}/run_mark5_batch.snapshot.sh"
  cp "${BASH_SOURCE[0]}" "${SNAPSHOT_SH}"
  chmod +x "${SNAPSHOT_SH}"
  MARK5_BATCH_SNAPSHOT=1 MARK5_REPO_ROOT="${REPO_ROOT}" exec "${SNAPSHOT_SH}" "${INPUT_DIR}"
fi

log() {
  local ts
  ts="$(date '+%F %T')"
  printf '[%s] %s\n' "${ts}" "$*" | tee -a "${LOG_FILE}"
}

append_run_tsv() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" >> "${RUNS_TSV}"
}

build_manifest() {
  python3 - "${RUNS_TSV}" "${MANIFEST_JSON}" "${BATCH_TS}" <<'PY'
import csv
import json
import sys
from collections import OrderedDict
from pathlib import Path

runs_tsv = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
batch_ts = sys.argv[3]

pcaps = OrderedDict()
with runs_tsv.open("r", newline="") as f:
    reader = csv.DictReader(
        f,
        delimiter="\t",
        fieldnames=[
            "pcap",
            "pcap_name",
            "mode",
            "core",
            "core_label",
            "status",
            "start_ts",
            "end_ts",
            "output_dir",
            "command",
        ],
    )
    for row in reader:
        pcap = row["pcap"]
        entry = pcaps.setdefault(
            pcap,
            {
                "pcap": pcap,
                "name": row["pcap_name"],
                "runs": {},
            },
        )
        slot = f"{row['core_label'].lower()}_{'time' if row['mode'] == 'time' else 'hw'}"
        entry["runs"][slot] = {
            "mode": row["mode"],
            "core": int(row["core"]),
            "core_label": row["core_label"],
            "status": row["status"],
            "start_ts": row["start_ts"],
            "end_ts": row["end_ts"],
            "output_dir": row["output_dir"],
            "command": row["command"],
        }

manifest = {
    "batch_id": f"batch_{batch_ts}",
    "created_at": batch_ts,
    "batch_dir": str(manifest_path.parent),
    "pcaps": list(pcaps.values()),
}
manifest_path.write_text(json.dumps(manifest, indent=2))
PY
}

run_plot_manifest() {
  if [[ ! -f "${PLOT_MANIFEST_PY}" ]]; then
    log "Plot script not found, skipping auto-plot: ${PLOT_MANIFEST_PY}"
    return
  fi

  log "START auto-plot manifest=${MANIFEST_JSON}"
  local output
  output="$(python3 "${PLOT_MANIFEST_PY}" --manifest "${MANIFEST_JSON}" --output-dir "${PLOT_OUTPUT_DIR}" 2>&1)"
  local rc=$?
  printf '%s\n' "${output}" >> "${LOG_FILE}"
  if [[ ${rc} -ne 0 ]]; then
    log "ERROR auto-plot rc=${rc}"
    return
  fi
  log "DONE auto-plot output=${PLOT_OUTPUT_DIR}"
}

run_one() {
  local exe="$1"
  local mode="$2"
  local core="$3"
  local core_label="$4"
  local pcap="$5"
  local pcap_name="$6"

  local start_ts end_ts cmd status output output_dir
  start_ts="$(date -Iseconds)"
  cmd="${exe} -c ${core} -i ${pcap} -q"

  log "START pcap=${pcap_name} mode=${mode} core=${core} (${core_label})"
  output="$("${exe}" -c "${core}" -i "${pcap}" -q 2>&1)"
  local rc=$?
  printf '%s\n' "${output}" >> "${LOG_FILE}"

  end_ts="$(date -Iseconds)"
  output_dir="$(printf '%s\n' "${output}" | sed -n 's/^Output: //p' | tail -n 1)"
  status="success"
  if [[ ${rc} -ne 0 ]]; then
    status="error"
    log "ERROR pcap=${pcap_name} mode=${mode} core=${core} rc=${rc}"
  else
    log "DONE pcap=${pcap_name} mode=${mode} core=${core} output=${output_dir}"
  fi

  append_run_tsv "${pcap}" "${pcap_name}" "${mode}" "${core}" "${core_label}" "${status}" "${start_ts}" "${end_ts}" "${output_dir}" "${cmd}"
}

if [[ ! -x "${TIME_EXE}" ]]; then
  log "Missing executable: ${TIME_EXE}"
  exit 1
fi

if [[ ! -x "${HW_EXE}" ]]; then
  log "Missing executable: ${HW_EXE}"
  exit 1
fi

if [[ ! -d "${INPUT_DIR}" ]]; then
  log "Input directory not found: ${INPUT_DIR}"
  exit 1
fi

log "Batch directory: ${BATCH_DIR}"
log "Scanning input directory: ${INPUT_DIR}"

mapfile -d '' PCAPS < <(find "${INPUT_DIR}" -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) -print0 | sort -z)

if [[ ${#PCAPS[@]} -eq 0 ]]; then
  log "No pcap files found under ${INPUT_DIR}"
  exit 1
fi

for pcap in "${PCAPS[@]}"; do
  pcap_name="$(basename "${pcap}")"
  run_one "${TIME_EXE}" "time" 0 "P" "${pcap}" "${pcap_name}"
  run_one "${HW_EXE}" "hardware" 0 "P" "${pcap}" "${pcap_name}"
  run_one "${TIME_EXE}" "time" 19 "E" "${pcap}" "${pcap_name}"
  run_one "${HW_EXE}" "hardware" 19 "E" "${pcap}" "${pcap_name}"
done

build_manifest
log "Manifest saved: ${MANIFEST_JSON}"
run_plot_manifest
log "Batch finished"
