#!/usr/bin/env bash

set -euo pipefail

readonly default_threshold_file="benchmarks/kernel-thresholds.txt"
readonly default_baseline_file="benchmarks/kernel-baseline.txt"

log_path="${1:?kernel benchmark log path required}"
threshold_file="${2:-$default_threshold_file}"
baseline_file="${3:-$default_baseline_file}"

declare -A thresholds=()
declare -A baselines=()
declare -A allowances=()
declare -A seen=()

load_thresholds() {
    while read -r name max_cycles_per_op; do
        if [ -z "${name}" ] || [ "${name#\#}" != "${name}" ]; then
            continue
        fi
        if [ -z "${max_cycles_per_op:-}" ]; then
            echo "Invalid threshold entry in ${threshold_file}" >&2
            exit 1
        fi
        thresholds["${name}"]="${max_cycles_per_op}"
    done < "${threshold_file}"
}

load_baselines() {
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
}

percent_delta() {
    local actual="$1"
    local baseline="$2"
    awk -v actual="${actual}" -v baseline="${baseline}" 'BEGIN {
        if (baseline == 0) {
            print "n/a"
            exit 0
        }
        printf "%+.1f%%", ((actual - baseline) / baseline) * 100
    }'
}

passes_threshold() {
    local actual="$1"
    local max_cycles="$2"
    awk -v actual="${actual}" -v max_cycles="${max_cycles}" 'BEGIN { exit (actual <= max_cycles) ? 0 : 1 }'
}

passes_baseline() {
    local actual="$1"
    local baseline="$2"
    local allowed_percent="$3"
    awk -v actual="${actual}" -v baseline="${baseline}" -v allowed_percent="${allowed_percent}" 'BEGIN {
        max_allowed = baseline * (100 + allowed_percent) / 100
        exit (actual <= max_allowed) ? 0 : 1
    }'
}

load_thresholds
load_baselines

printf '## Kernel Benchmark Summary\n\n'

if [ ! -f "${log_path}" ]; then
    printf 'No benchmark log found at `%s`.\n' "${log_path}"
    exit 0
fi

if ! grep -Fq 'BENCH:RESULT:' "${log_path}"; then
    printf 'No benchmark results were found in `%s`.\n' "${log_path}"
    exit 0
fi

printf '| Benchmark | Iterations | Cycles/op | Threshold | Baseline | Delta | Status |\n'
printf '| --- | ---: | ---: | ---: | ---: | ---: | --- |\n'

overall_status="PASS"
summary_line=""

while IFS= read -r line; do
    case "${line}" in
        BENCH:RESULT:*)
            IFS=':' read -r _ _ name iterations_field _ cycles_per_op_field _ <<< "${line}"
            iterations="${iterations_field#iterations=}"
            actual_cycles_per_op="${cycles_per_op_field#cycles_per_op=}"

            threshold_display='--'
            baseline_display='--'
            delta_display='--'
            status='PASS'

            if [ -n "${thresholds["${name}"]+x}" ]; then
                threshold_display="<= ${thresholds["${name}"]}"
                if ! passes_threshold "${actual_cycles_per_op}" "${thresholds["${name}"]}"; then
                    status='FAIL'
                fi
            fi

            if [ -n "${baselines["${name}"]+x}" ]; then
                baseline_display="${baselines["${name}"]} (+${allowances["${name}"]}%)"
                delta_display="$(percent_delta "${actual_cycles_per_op}" "${baselines["${name}"]}")"
                if ! passes_baseline "${actual_cycles_per_op}" "${baselines["${name}"]}" "${allowances["${name}"]}"; then
                    status='FAIL'
                fi
            fi

            if [ "${status}" != 'PASS' ]; then
                overall_status='FAIL'
            fi

            seen["${name}"]=1
            printf '| `%s` | %s | %s | %s | %s | %s | %s |\n' \
                "${name}" \
                "${iterations}" \
                "${actual_cycles_per_op}" \
                "${threshold_display}" \
                "${baseline_display}" \
                "${delta_display}" \
                "${status}"
            ;;
        BENCH:SUMMARY:*)
            summary_line="${line}"
            ;;
    esac
done < "${log_path}"

missing_results=0
for name in "${!baselines[@]}"; do
    if [ -z "${seen["${name}"]+x}" ]; then
        missing_results=1
        overall_status='FAIL'
    fi
done

printf '\n'
printf -- '- Overall status: `%s`\n' "${overall_status}"

if [ -n "${summary_line}" ]; then
    total_benchmarks="${summary_line#BENCH:SUMMARY:benchmarks=}"
    total_benchmarks="${total_benchmarks%%:*}"
    total_cycles="${summary_line##*:total_cycles=}"
    printf -- '- Benchmarks reported: `%s`\n' "${total_benchmarks}"
    printf -- '- Total suite cycles: `%s`\n' "${total_cycles}"
fi

if [ "${missing_results}" -ne 0 ]; then
    printf -- '- Missing results for one or more baseline entries.\n'
fi

printf -- '- Source log: `%s`\n' "${log_path}"
