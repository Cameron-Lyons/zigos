#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=scripts/qemu-harness.sh
source "$ROOT_DIR/scripts/qemu-harness.sh"

ISO_PATH="${1:?iso path required}"
LOG_PATH="${2:?serial log path required}"
EXPECTED_ROLE="${3:?expected kernel role required}"
UEFI_BOOT_TEST_SECONDS="${UEFI_BOOT_TEST_SECONDS:-20}"

case "$EXPECTED_ROLE" in
  production | verification)
    ;;
  *)
    echo "UEFI boot test failed: unsupported kernel role '$EXPECTED_ROLE'" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH"

qemu_harness_run_uefi_cdrom_for_seconds "$ISO_PATH" "$LOG_PATH" "$UEFI_BOOT_TEST_SECONDS"

if [ ! -s "$LOG_PATH" ]; then
  echo "UEFI boot test failed: no serial output at $LOG_PATH" >&2
  exit 1
fi

for marker in "BOOT:START" "BOOT:ROLE:${EXPECTED_ROLE}" "ZIGOS:CPU:BASELINE:MODERN_X86_64:READY" "ZIGOS:CPU:NX:ENABLED" "ZIGOS:CPU:PGE:ENABLED" "ZIGOS:CPU:SYSCALL:ENABLED" "ZIGOS:CPU:PCID:READY" "ZIGOS:KERNEL:W_X:ENFORCED" "Welcome to Zigos" "Initializing GDT" "BOOT:CORE_READY"; do
  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "UEFI boot test failed: missing marker '$marker'" >&2
    cat "$LOG_PATH" >&2
    exit 1
  fi
done

if grep -Eqi "panic|KERNEL PANIC|System Halted|FAIL" "$LOG_PATH"; then
  echo "UEFI boot test failed: panic or failure marker found in boot log" >&2
  cat "$LOG_PATH" >&2
  exit 1
fi

echo "UEFI boot test passed. Log: $LOG_PATH"
