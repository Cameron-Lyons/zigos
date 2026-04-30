#!/usr/bin/env bash

set -euo pipefail

readonly default_threshold_file="benchmarks/kernel-thresholds.txt"

log_path="${1:?kernel benchmark log path required}"
threshold_file="${2:-$default_threshold_file}"

if ! grep -Eq '^[^#[:space:]]+[[:space:]]+[0-9]' "${threshold_file}"; then
    echo "No benchmark thresholds loaded from ${threshold_file}" >&2
    exit 1
fi

while read -r name max_cycles_per_op; do
    if [ -z "${name}" ] || [ "${name#\#}" != "${name}" ]; then
        continue
    fi
    if [ -z "${name}" ] || [ -z "${max_cycles_per_op:-}" ]; then
        echo "Invalid threshold entry in ${threshold_file}" >&2
        exit 1
    fi

    line="$(grep -F "BENCH:RESULT:${name}:" "${log_path}" | tail -n 1 || true)"
    if [ -z "${line}" ]; then
        echo "Kernel benchmark threshold failed: missing result for ${name}" >&2
        exit 1
    fi

    actual_cycles_per_op="$(printf '%s\n' "${line}" | awk -F: '{ for (i = 1; i <= NF; i += 1) if ($i ~ /^cycles_per_op=/) { sub(/^cycles_per_op=/, "", $i); print $i; exit } }')"
    if [ -z "${actual_cycles_per_op}" ]; then
        echo "Kernel benchmark threshold failed: malformed result for ${name}" >&2
        exit 1
    fi

    if ! awk -v actual="${actual_cycles_per_op}" -v max="${max_cycles_per_op}" 'BEGIN { exit (actual <= max) ? 0 : 1 }'; then
        echo "Kernel benchmark threshold failed for ${name}: ${actual_cycles_per_op} > ${max_cycles_per_op} cycles/op" >&2
        exit 1
    fi
done < "${threshold_file}"

while IFS= read -r line; do
    name="${line#BENCH:RESULT:}"
    name="${name%%:*}"
    if ! awk -v benchmark_name="${name}" '$1 == benchmark_name { found = 1 } END { exit found ? 0 : 1 }' "${threshold_file}"; then
        echo "Kernel benchmark threshold failed: untracked result for ${name}" >&2
        exit 1
    fi
done < <(grep -F 'BENCH:RESULT:' "${log_path}" || true)

echo "Kernel benchmark thresholds passed."
