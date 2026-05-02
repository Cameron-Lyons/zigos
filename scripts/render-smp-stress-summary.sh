#!/usr/bin/env bash

set -euo pipefail

log_path="${1:?smp stress log path required}"

printf '## SMP Stress Summary\n\n'

if [ ! -f "${log_path}" ]; then
    printf "No SMP stress log found at \`%s\`.\n" "${log_path}"
    exit 0
fi

if ! grep -Fq 'SMP:' "${log_path}"; then
    printf "No SMP stress markers were found in \`%s\`.\n" "${log_path}"
    exit 0
fi

status='UNKNOWN'
if grep -Fq 'SMP:PASS' "${log_path}"; then
    status='PASS'
elif grep -Eq 'SMP:FAIL|SMP:TIMEOUT' "${log_path}"; then
    status='FAIL'
fi

active_cpus='--'
if grep -Fq 'SMP:ACTIVE_CPUS:' "${log_path}"; then
    active_cpus=$(grep -F 'SMP:ACTIVE_CPUS:' "${log_path}" | tail -n 1 | cut -d: -f3)
fi

tasks_created='no'
if grep -Fq 'SMP:TASKS_CREATED' "${log_path}"; then
    tasks_created='yes'
fi

tasks_done='no'
if grep -Fq 'SMP:TASKS_DONE' "${log_path}"; then
    tasks_done='yes'
fi

context_switches='--'
ready_processes='--'
blocked_processes='--'
cpu_usage='--'
stats_line=$(grep -F 'SMP:STATS:' "${log_path}" | tail -n 1 || true)
if [ -n "${stats_line}" ]; then
    context_switches=$(printf '%s\n' "${stats_line}" | sed -E 's/.*context_switches=([0-9]+).*/\1/')
    ready_processes=$(printf '%s\n' "${stats_line}" | sed -E 's/.*ready=([0-9]+).*/\1/')
    blocked_processes=$(printf '%s\n' "${stats_line}" | sed -E 's/.*blocked=([0-9]+).*/\1/')
    cpu_usage=$(printf '%s\n' "${stats_line}" | sed -E 's/.*cpu_usage=([0-9]+).*/\1/')
fi

printf '| Metric | Value |\n'
printf '| --- | --- |\n'
printf "| Status | \`%s\` |\n" "${status}"
printf "| Active CPUs | \`%s\` |\n" "${active_cpus}"
printf "| Tasks created marker | \`%s\` |\n" "${tasks_created}"
printf "| Tasks done marker | \`%s\` |\n" "${tasks_done}"
printf "| Context switches | \`%s\` |\n" "${context_switches}"
printf "| Ready processes | \`%s\` |\n" "${ready_processes}"
printf "| Blocked processes | \`%s\` |\n" "${blocked_processes}"
printf "| CPU usage | \`%s%%\` |\n" "${cpu_usage}"
printf '\n'
printf -- "- Source log: \`%s\`\n" "${log_path}"
