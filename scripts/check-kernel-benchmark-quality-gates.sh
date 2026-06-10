#!/usr/bin/env bash

set -euo pipefail

readonly default_quality_gate_file="benchmarks/kernel-quality-gates.txt"

log_path="${1:?kernel benchmark log path required}"
quality_gate_file="${2:-$default_quality_gate_file}"

if ! grep -Eq '^[^#[:space:]]+[[:space:]]+(-|[0-9]+)[[:space:]]+(-|[0-9]+)' "${quality_gate_file}"; then
    echo "No kernel benchmark quality gates loaded from ${quality_gate_file}" >&2
    exit 1
fi

while read -r name min_value max_value; do
    if [ -z "${name}" ] || [ "${name#\#}" != "${name}" ]; then
        continue
    fi
    if [ -z "${min_value:-}" ] || [ -z "${max_value:-}" ]; then
        echo "Invalid quality gate entry in ${quality_gate_file}" >&2
        exit 1
    fi

    line="$(grep -F "BENCH:QUALITY:${name}:" "${log_path}" | tail -n 1 || true)"
    if [ -z "${line}" ]; then
        echo "Kernel benchmark quality gate failed: missing result for ${name}" >&2
        exit 1
    fi

    actual_value="$(printf '%s\n' "${line}" | awk -F: '{ for (i = 1; i <= NF; i += 1) if ($i ~ /^value=/) { sub(/^value=/, "", $i); print $i; exit } }')"
    if [ -z "${actual_value}" ]; then
        echo "Kernel benchmark quality gate failed: malformed result for ${name}" >&2
        exit 1
    fi

    if [ "${min_value}" != "-" ] && ! awk -v actual="${actual_value}" -v min="${min_value}" 'BEGIN { exit (actual >= min) ? 0 : 1 }'; then
        echo "Kernel benchmark quality gate failed for ${name}: ${actual_value} < ${min_value}" >&2
        exit 1
    fi
    if [ "${max_value}" != "-" ] && ! awk -v actual="${actual_value}" -v max="${max_value}" 'BEGIN { exit (actual <= max) ? 0 : 1 }'; then
        echo "Kernel benchmark quality gate failed for ${name}: ${actual_value} > ${max_value}" >&2
        exit 1
    fi
done < "${quality_gate_file}"

while IFS= read -r line; do
    name="${line#BENCH:QUALITY:}"
    name="${name%%:*}"
    if ! awk -v gate_name="${name}" '$1 == gate_name { found = 1 } END { exit found ? 0 : 1 }' "${quality_gate_file}"; then
        echo "Kernel benchmark quality gate failed: untracked result for ${name}" >&2
        exit 1
    fi
done < <(grep -F 'BENCH:QUALITY:' "${log_path}" || true)

echo "Kernel benchmark quality gates passed."
