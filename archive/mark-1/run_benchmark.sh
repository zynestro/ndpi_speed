#!/bin/bash
# Wrapper script for ndpiBenchmark

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="${SCRIPT_DIR}/../src/lib:$LD_LIBRARY_PATH"

exec "${SCRIPT_DIR}/ndpiBenchmark" "$@"
