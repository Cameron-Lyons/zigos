#!/usr/bin/env bash

set -euo pipefail

readonly default_baseline_file="benchmarks/kernel-baseline.txt"

log_path="${1:?kernel benchmark log path required}"
baseline_file="${2:-$default_baseline_file}"

declare -A baselines=()
declare -A allowances=()
declare -A seen=()

while read -r name baseline_cycles_per_op allowed_regression_percent; do
    if [ -z "${name}" ] || [ "${name#\#}" != "${name}" ]; then
        continue
    fi
    if [ -z "${baseline_cycles_per_op:-}" ] || [ -z "${allowed_regression_percent:-}" ]; then
        echo "Invalid baseline entry in ${baseline_file}" >&2
        exit 1
    fi
    baselines["${name}"]="${baseline_cycles_per_op}"
    allowances["${name}"]="${allowed_regression_percent}"
done < "${baseline_file}"

if [ "${#baselines[@]}" -eq 0 ]; then
    echo "No benchmark baselines loaded from ${baseline_file}" >&2
    exit 1
fi

while IFS= read -r line; do
    case "${line}" in
        BENCH:RESULT:*)
            IFS=':' read -r _ _ name _ _ cycles_per_op_field _ <<< "${line}"
            if [ -z "${baselines["${name}"]+x}" ]; then
                continue
            fi

            actual_cycles_per_op="${cycles_per_op_field#cycles_per_op=}"
            baseline_cycles_per_op="${baselines["${name}"]}"
            allowed_regression_percent="${allowances["${name}"]}"
            if ! awk -v actual="${actual_cycles_per_op}" -v baseline="${baseline_cycles_per_op}" -v allowed="${allowed_regression_percent}" 'BEGIN { max = baseline * (100 + allowed) / 100; exit (actual <= max) ? 0 : 1 }'; then
                echo "Kernel benchmark baseline regression for ${name}: ${actual_cycles_per_op} exceeded baseline ${baseline_cycles_per_op} with ${allowed_regression_percent}% allowance" >&2
                exit 1
            fi
            seen["${name}"]=1
            ;;
    esac
done < "${log_path}"

for name in "${!baselines[@]}"; do
    if [ -z "${seen["${name}"]+x}" ]; then
        echo "Kernel benchmark baseline check failed: missing result for ${name}" >&2
        exit 1
    fi
done

echo "Kernel benchmark baseline comparison passed."
