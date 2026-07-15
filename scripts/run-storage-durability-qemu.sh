#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
ZIG="${ROOT_DIR}/scripts/zig.sh"
MARKER_TOOL="${ROOT_DIR}/src/print_native_smoke_markers.zig"

# shellcheck source=scripts/qemu-harness.sh
source "$ROOT_DIR/scripts/qemu-harness.sh"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
NATIVE_STORE_IMAGE="${3:?native store image path required}"
# Per-boot cap on waiting for each proof marker. Marker detection stops QEMU
# early, so this only bounds the failure path; keep it generous for slow
# shared runners.
ZIGOS_NATIVE_SECONDS="${ZIGOS_NATIVE_SECONDS:-420}"
NATIVE_STORE_SIZE_MIB="${NATIVE_STORE_SIZE_MIB:-8}"

# Drive the native store as a real NVMe controller so the kernel NVMe data-plane
# driver provides genuine persistence across the forced reboots in this proof.
# Keep both the block backend and controller cache write-back capable so the
# proof exercises the storage stack's explicit durability barriers.
export ZIGOS_NATIVE_STORE_BUS=nvme
export ZIGOS_NATIVE_STORE_CACHE=writeback
export ZIGOS_NVME_WRITE_CACHE=on

BASE_LOG_PATH="${LOG_PATH%.log}"
BOOT1_LOG="${BASE_LOG_PATH}.boot1.log"
BOOT2_LOG="${BASE_LOG_PATH}.boot2.log"
BOOT3_LOG="${BASE_LOG_PATH}.boot3.log"
BOOT4_LOG="${BASE_LOG_PATH}.boot4.log"

BASELINE_MARKER="ZIGOS:STORAGE:DURABILITY:BASELINE_CHECKPOINTED"
INTERRUPTED_WRITE_MARKER="ZIGOS:STORAGE:DURABILITY:INTERRUPTED_WRITE_STAGED"
FINAL_MARKER="ZIGOS:STORAGE:DURABILITY:FINAL_CHECKPOINTED"
BAD_ROOT_MARKER="ZIGOS:STORAGE:DURABILITY:BAD_ROOT_SLOT_FALLBACK_OK"
ROOT_SLOT_SECTOR_BYTES=512
LATEST_ROOT_SLOT_INDEX=1

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH" "$BOOT1_LOG" "$BOOT2_LOG" "$BOOT3_LOG" "$BOOT4_LOG"

run_boot_until_marker() {
  local log_path="$1"
  local reset_store="$2"
  local marker="$3"

  if [ "$reset_store" = "reset" ]; then
    bash "$ROOT_DIR/scripts/build-native-store.sh" "$NATIVE_STORE_IMAGE" "$NATIVE_STORE_SIZE_MIB" reset
  else
    bash "$ROOT_DIR/scripts/build-native-store.sh" "$NATIVE_STORE_IMAGE" "$NATIVE_STORE_SIZE_MIB" preserve
  fi

  if ! qemu_harness_run_native_store_until_marker \
    "$KERNEL_PATH" \
    "$NATIVE_STORE_IMAGE" \
    "$log_path" \
    "$marker" \
    "$ZIGOS_NATIVE_SECONDS"; then
    echo "Storage durability QEMU test failed during boot for $log_path" >&2
    exit 1
  fi

  if [ ! -s "$log_path" ]; then
    echo "Storage durability QEMU test failed: no serial output captured for $log_path" >&2
    exit 1
  fi

  if grep -Eqi "panic|KERNEL PANIC|System Halted|FAIL" "$log_path"; then
    echo "Storage durability QEMU test failed: panic or failure marker found in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi
}

assert_marker_group() {
  local log_path="$1"
  local needle

  while IFS= read -r needle; do
    [ -n "$needle" ] || continue
    if ! grep -Fq "$needle" "$log_path"; then
      echo "Storage durability QEMU test failed: missing '$needle' in $log_path" >&2
      cat "$log_path" >&2
      exit 1
    fi
  done < <("$ZIG" run "$MARKER_TOOL" -- storage_durability)
}

corrupt_latest_root_slot() {
  local root_slot_offset=$((LATEST_ROOT_SLOT_INDEX * ROOT_SLOT_SECTOR_BYTES))
  if ! printf '\377' | dd of="$NATIVE_STORE_IMAGE" bs=1 seek="$root_slot_offset" count=1 conv=notrunc >/dev/null 2>&1; then
    echo "Storage durability QEMU test failed: could not corrupt root slot $LATEST_ROOT_SLOT_INDEX in $NATIVE_STORE_IMAGE" >&2
    exit 1
  fi
}

run_boot_until_marker "$BOOT1_LOG" reset "$BASELINE_MARKER"
run_boot_until_marker "$BOOT2_LOG" preserve "$INTERRUPTED_WRITE_MARKER"
run_boot_until_marker "$BOOT3_LOG" preserve "$FINAL_MARKER"
corrupt_latest_root_slot
run_boot_until_marker "$BOOT4_LOG" preserve "$BAD_ROOT_MARKER"

{
  cat "$BOOT1_LOG"
  printf '\n=== FORCED REBOOT: INTERRUPTED WRITE ===\n'
  cat "$BOOT2_LOG"
  printf '\n=== FORCED REBOOT: RECOVERY AND FINAL CHECKPOINT ===\n'
  cat "$BOOT3_LOG"
  printf '\n=== HOST ROOT SLOT CORRUPTION ===\n'
  printf 'STORAGE_DURABILITY:CORRUPTED_ROOT_SLOT %d offset=%d\n' "$LATEST_ROOT_SLOT_INDEX" "$((LATEST_ROOT_SLOT_INDEX * ROOT_SLOT_SECTOR_BYTES))"
  printf '\n=== FORCED REBOOT: BAD ROOT SLOT RECOVERY ===\n'
  cat "$BOOT4_LOG"
} >"$LOG_PATH"

assert_marker_group "$LOG_PATH"
echo "Zigos storage durability QEMU test passed across forced reboots and one bad root slot. Logs: $LOG_PATH"
