#!/usr/bin/env bash

set -euo pipefail

readonly default_threshold_file="benchmarks/kernel-thresholds.txt"

log_path="${1:?kernel benchmark log path required}"
threshold_file="${2:-$default_threshold_file}"

declare -A thresholds=()
declare -A seen=()

while read -r name max_cycles_per_op; do
    if [ -z "${name}" ] || [ "${name#\#}" != "${name}" ]; then
        continue
    fi
    if [ -z "${name}" ] || [ -z "${max_cycles_per_op:-}" ]; then
        echo "Invalid threshold entry in ${threshold_file}" >&2
        exit 1
    fi
    thresholds["${name}"]="${max_cycles_per_op}"
done < "${threshold_file}"

if [ "${#thresholds[@]}" -eq 0 ]; then
    echo "No benchmark thresholds loaded from ${threshold_file}" >&2
    exit 1
fi

while IFS= read -r line; do
    case "${line}" in
        BENCH:RESULT:*)
            IFS=':' read -r _ _ name _ _ cycles_per_op_field _ <<< "${line}"
            if [ -z "${thresholds["${name}"]+x}" ]; then
                continue
            fi

            actual_cycles_per_op="${cycles_per_op_field#cycles_per_op=}"
            max_cycles_per_op="${thresholds["${name}"]}"
            if ! awk -v actual="${actual_cycles_per_op}" -v max="${max_cycles_per_op}" 'BEGIN { exit (actual <= max) ? 0 : 1 }'; then
                echo "Kernel benchmark threshold failed for ${name}: ${actual_cycles_per_op} > ${max_cycles_per_op} cycles/op" >&2
                exit 1
            fi
            seen["${name}"]=1
            ;;
    esac
done < "${log_path}"

for name in "${!thresholds[@]}"; do
    if [ -z "${seen["${name}"]+x}" ]; then
        echo "Kernel benchmark threshold failed: missing result for ${name}" >&2
        exit 1
    fi
done

echo "Kernel benchmark thresholds passed."
