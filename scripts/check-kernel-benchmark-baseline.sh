#!/usr/bin/env bash

set -euo pipefail

readonly default_baseline_file="benchmarks/kernel-baseline.txt"

log_path="${1:?kernel benchmark log path required}"
baseline_file="${2:-$default_baseline_file}"

if ! grep -Eq '^[^#[:space:]]+[[:space:]]+[0-9]+([.][0-9]+)?[[:space:]]+[0-9]+' "${baseline_file}"; then
    echo "No benchmark baselines loaded from ${baseline_file}" >&2
    exit 1
fi

while read -r name baseline_cycles_per_op allowed_regression_percent; do
    if [ -z "${name}" ] || [ "${name#\#}" != "${name}" ]; then
        continue
    fi
    if [ -z "${baseline_cycles_per_op:-}" ] || [ -z "${allowed_regression_percent:-}" ]; then
        echo "Invalid baseline entry in ${baseline_file}" >&2
        exit 1
    fi

    line="$(grep -F "BENCH:RESULT:${name}:" "${log_path}" | tail -n 1 || true)"
    if [ -z "${line}" ]; then
        echo "Kernel benchmark baseline check failed: missing result for ${name}" >&2
        exit 1
    fi

    actual_cycles_per_op="$(printf '%s\n' "${line}" | awk -F: '{ for (i = 1; i <= NF; i += 1) if ($i ~ /^cycles_per_op=/) { sub(/^cycles_per_op=/, "", $i); print $i; exit } }')"
    if [ -z "${actual_cycles_per_op}" ]; then
        echo "Kernel benchmark baseline check failed: malformed result for ${name}" >&2
        exit 1
    fi

    if ! awk -v actual="${actual_cycles_per_op}" -v baseline="${baseline_cycles_per_op}" -v allowed="${allowed_regression_percent}" 'BEGIN { max = baseline * (100 + allowed) / 100; exit (actual <= max) ? 0 : 1 }'; then
        echo "Kernel benchmark baseline regression for ${name}: ${actual_cycles_per_op} exceeded baseline ${baseline_cycles_per_op} with ${allowed_regression_percent}% allowance" >&2
        exit 1
    fi
done < "${baseline_file}"

echo "Kernel benchmark baseline comparison passed."
