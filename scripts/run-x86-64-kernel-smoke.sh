#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=scripts/qemu-harness.sh
source "$ROOT_DIR/scripts/qemu-harness.sh"

ISO_PATH="${1:?x86-64 kernel ISO required}"
LOG_PATH="${2:?serial log path required}"
QEMU_LOG_PATH="${LOG_PATH%.log}.qemu.log"
READY_MARKER="ZIGOS:USERSPACE:RESUME:OK"
TIMEOUT_SECONDS="${ZIGOS_X86_64_KERNEL_SECONDS:-30}"

case "$TIMEOUT_SECONDS" in
  ''|*[!0-9]*|0)
    echo "ZIGOS_X86_64_KERNEL_SECONDS must be a positive integer" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH" "$QEMU_LOG_PATH"

qemu_harness_build_uefi_cdrom_command "$ISO_PATH" "128M" "file:$LOG_PATH"
"${QEMU_HARNESS_COMMAND[@]}" >"$QEMU_LOG_PATH" 2>&1 &
qemu_pid=$!
elapsed=0
while kill -0 "$qemu_pid" >/dev/null 2>&1; do
  if [ -s "$LOG_PATH" ] && grep -Fq "$READY_MARKER" "$LOG_PATH"; then
    qemu_harness_stop_qemu "$qemu_pid"
    break
  fi
  if [ "$elapsed" -ge "$TIMEOUT_SECONDS" ]; then
    qemu_harness_stop_qemu "$qemu_pid"
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
wait "$qemu_pid" >/dev/null 2>&1 || true

if ! grep -Fq "$READY_MARKER" "$LOG_PATH"; then
  echo "x86-64 kernel smoke test failed: missing '$READY_MARKER'" >&2
  cat "$LOG_PATH" >&2 || true
  qemu_harness_print_qemu_log "$QEMU_LOG_PATH"
  exit 1
fi

for required_marker in \
  "BOOT:START" \
  "BOOT:PROFILE:zigos_native" \
  "BOOT:ROLE:production" \
  "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY" \
  "ZIGOS:CPU:NX:ENABLED" \
  "ZIGOS:CPU:PGE:ENABLED" \
  "ZIGOS:CPU:PCID:READY" \
  "ZIGOS:ARCH:X86_64:PAGING:READY" \
  "ZIGOS:KERNEL:W_X:ENFORCED" \
  "BOOT:CORE_READY" \
  "ZIGOS:USERSPACE:ARTIFACTS:READY" \
  "ZIGOS:USERSPACE:EXEC_PROBE:OK"; do
  if ! grep -Fq "$required_marker" "$LOG_PATH"; then
    echo "x86-64 kernel smoke test failed: missing '$required_marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

echo "x86-64 kernel and userspace launch smoke test passed. Log: $LOG_PATH"
