#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"

if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

QEMU_BIN="$QEMU_BIN" bash scripts/run-headless-qemu.sh "$KERNEL_PATH" "128M" "file:$LOG_PATH"

if [ ! -s "$LOG_PATH" ]; then
  echo "Kernel benchmark test failed: no serial output captured" >&2
  exit 1
fi

for marker in \
  "BOOT:START" \
  "BOOT:PROFILE:benchmark" \
  "BOOT:CORE_READY" \
  "BENCH:START" \
  "BENCH:RESULT:shell.tokenize.expansions" \
  "BENCH:RESULT:shell.pipeline.commandline" \
  "BENCH:RESULT:shell.glob.match_matrix" \
  "BENCH:RESULT:syscall.at.resolve_matrix" \
  "BENCH:RESULT:vfs.fd.freelist_churn" \
  "BENCH:RESULT:tcp.checksum.dual_stack" \
  "BENCH:RESULT:tcp.options.roundtrip" \
  "BENCH:RESULT:ipc.semops.batch" \
  "BENCH:SUMMARY" \
  "BENCH:PASS"
do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "Kernel benchmark test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|BENCH:FAIL" "$LOG_PATH"; then
  echo "Kernel benchmark test failed: panic or benchmark failure marker found" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

bash scripts/check-kernel-benchmark-thresholds.sh "$LOG_PATH"
bash scripts/check-kernel-benchmark-baseline.sh "$LOG_PATH"
echo "Kernel benchmark run passed. Log: $LOG_PATH"
