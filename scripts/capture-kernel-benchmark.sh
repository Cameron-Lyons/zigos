#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/qemu-harness.sh"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
SUMMARY_PATH="${3:-}"
BENCHMARK_SECONDS="${ZIGOS_BENCHMARK_SECONDS:-300}"

case "$BENCHMARK_SECONDS" in
  ''|*[!0-9]*|0*)
    echo "ZIGOS_BENCHMARK_SECONDS must be a positive integer" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"
if [ -n "$SUMMARY_PATH" ]; then
  rm -f "$SUMMARY_PATH"
fi

capture_status=0
QEMU_SERIAL_TARGET="file:$LOG_PATH" timeout --kill-after=5s "${BENCHMARK_SECONDS}s" \
  bash "$ROOT_DIR/scripts/run-headless-qemu.sh" "$KERNEL_PATH" || capture_status=$?
if [ "$capture_status" -ne 0 ]; then
  if [ "$capture_status" -eq 124 ] || [ "$capture_status" -eq 137 ]; then
    echo "Kernel benchmark capture failed: timed out after ${BENCHMARK_SECONDS}s" >&2
  else
    echo "Kernel benchmark capture failed: QEMU exited with status $capture_status" >&2
  fi
  if [ -s "$LOG_PATH" ]; then
    cat "$LOG_PATH" >&2
  fi
  exit 1
fi

if [ ! -s "$LOG_PATH" ]; then
  echo "Kernel benchmark capture failed: no serial output captured" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:benchmark" \
  "BOOT:ROLE:verification" \
  "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY" \
  "ZIGOS:CPU:NX:ENABLED" \
  "ZIGOS:CPU:PGE:ENABLED" \
  "ZIGOS:CPU:SYSCALL:ENABLED" \
  "ZIGOS:CPU:PCID:READY" \
  "ZIGOS:KERNEL:W_X:ENFORCED" \
  "BOOT:CORE_READY" \
  "BENCH:START" \
  "BENCH:QUALITY_SUMMARY" \
  "BENCH:SUMMARY" \
  "BENCH:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Kernel benchmark capture failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|BENCH:FAIL" "$LOG_PATH"; then
  echo "Kernel benchmark capture failed: panic or failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

if grep -Fq "BENCH:ENV:" "$LOG_PATH"; then
  echo "Kernel benchmark capture failed: guest output must not declare its host accelerator" >&2
  exit 1
fi

accelerator="$(qemu_harness_accelerator)"
case "$accelerator" in
  kvm|kvm,*)
    benchmark_accelerator="kvm"
    ;;
  ""|tcg|tcg,*)
    benchmark_accelerator="tcg"
    ;;
  *)
    echo "Kernel benchmark capture failed: unsupported accelerator '$accelerator'" >&2
    exit 1
    ;;
esac
printf 'BENCH:ENV:accelerator=%s\n' "$benchmark_accelerator" >> "$LOG_PATH"

echo "Kernel benchmark capture complete. Run the typed benchmark gate through './scripts/zig.sh build benchmark'. Log: $LOG_PATH"
