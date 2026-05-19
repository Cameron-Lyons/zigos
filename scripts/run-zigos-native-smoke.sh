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
MODE="${4:-full}"
ZIGOS_NATIVE_SECONDS="${ZIGOS_NATIVE_SECONDS:-180}"
NATIVE_STORE_SIZE_MIB="${NATIVE_STORE_SIZE_MIB:-8}"
ZIGOS_READY_MARKER="$("$ZIG" run "$MARKER_TOOL" -- ready)"
DRIVER_RESTART_DONE_MARKER="ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_IO_AFTER_RESTART_OK"
ARTIFACT_MANIFEST_TAMPER_REJECTED_MARKER="ZIGOS:PLATFORM:ARTIFACT_MANIFEST:TAMPER_REJECTED"
ROLLBACK_SLOT_FAILURE_REJECTED_MARKER="ZIGOS:PLATFORM:BASE_SELECTOR:ROLLBACK_SLOT_REJECTED"
VALIDATION_MARKER="$ZIGOS_READY_MARKER"

if [ "$MODE" = "driver_restart" ]; then
  VALIDATION_MARKER="$DRIVER_RESTART_DONE_MARKER"
elif [ "$MODE" = "tampered_artifact_manifest" ]; then
  VALIDATION_MARKER="$ARTIFACT_MANIFEST_TAMPER_REJECTED_MARKER"
elif [ "$MODE" = "rollback_slot_failure" ]; then
  VALIDATION_MARKER="$ROLLBACK_SLOT_FAILURE_REJECTED_MARKER"
fi

BASE_LOG_PATH="${LOG_PATH%.log}"
BOOT1_LOG="${BASE_LOG_PATH}.boot1.log"
BOOT2_LOG="${BASE_LOG_PATH}.boot2.log"

mkdir -p "$(dirname "$LOG_PATH")"
rm -f "$LOG_PATH" "$BOOT1_LOG" "$BOOT2_LOG"

run_boot() {
  local log_path="$1"
  local reset_store="$2"

  if [ "$reset_store" = "reset" ]; then
    bash "$ROOT_DIR/scripts/build-native-store.sh" "$NATIVE_STORE_IMAGE" "$NATIVE_STORE_SIZE_MIB" reset
  else
    bash "$ROOT_DIR/scripts/build-native-store.sh" "$NATIVE_STORE_IMAGE" "$NATIVE_STORE_SIZE_MIB" preserve
  fi

  if ! qemu_harness_run_native_store_until_marker \
    "$KERNEL_PATH" \
    "$NATIVE_STORE_IMAGE" \
    "$log_path" \
    "$VALIDATION_MARKER" \
    "$ZIGOS_NATIVE_SECONDS"; then
    echo "Zigos native smoke test failed during QEMU boot for $log_path" >&2
    exit 1
  fi

  if [ ! -s "$log_path" ]; then
    echo "Zigos native smoke test failed: no serial output captured for $log_path" >&2
    exit 1
  fi

  if grep -Eqi "panic|KERNEL PANIC|System Halted|FAIL" "$log_path"; then
    echo "Zigos native smoke test failed: panic or failure marker found in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi
}

assert_marker_group() {
  local log_path="$1"
  local group="$2"
  local needle

  while IFS= read -r needle; do
    [ -n "$needle" ] || continue
    if ! grep -Fq "$needle" "$log_path"; then
      echo "Zigos native smoke test failed: missing '$needle' in $log_path" >&2
      cat "$log_path" >&2
      exit 1
    fi
  done < <("$ZIG" run "$MARKER_TOOL" -- "$group")
}

assert_boot_markers() {
  local log_path="$1"
  assert_marker_group "$log_path" cold_boot
}

assert_first_boot_markers() {
  local log_path="$1"
  assert_marker_group "$log_path" first_boot
}

assert_reboot_markers() {
  local log_path="$1"
  assert_marker_group "$log_path" cold_reboot
}

assert_ab_rollback_markers() {
  local log_path="$1"
  assert_marker_group "$log_path" ab_rollback
}

assert_base_selector_active_slot() {
  local log_path="$1"
  if ! grep -Fq "ZIGOS:PLATFORM:BASE_SELECTOR:ACTIVE_SLOT 0 " "$log_path"; then
    echo "Zigos native smoke test failed: base selector did not report active slot 0 in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi
}

assert_no_ready_marker() {
  local log_path="$1"
  if grep -Fq "$ZIGOS_READY_MARKER" "$log_path"; then
    echo "Zigos native smoke test failed: negative run reached ready marker in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi
}

assert_negative_boot_rejected() {
  local log_path="$1"
  local group="$2"
  assert_marker_group "$log_path" "$group"
  assert_no_ready_marker "$log_path"
}

line_number() {
  local log_path="$1"
  local marker="$2"
  grep -Fn "$marker" "$log_path" | head -n1 | cut -d: -f1
}

assert_driver_restart_without_reboot() {
  local log_path="$1"
  local boot_marker
  local crash_marker
  local rehost_marker
  local restart_marker
  local no_reboot_marker
  local storage_before_marker
  local storage_stale_marker
  local storage_after_marker
  local ready_marker
  local boot_count
  local boot_line
  local crash_line
  local rehost_line
  local restart_line
  local no_reboot_line
  local storage_before_line
  local storage_stale_line
  local storage_after_line
  local ready_line

  assert_marker_group "$log_path" driver_restart
  boot_marker="BOOT:START"
  crash_marker="ZIGOS:SERVICE_BOOT:SUPERVISOR:CRASH_RECORDED"
  rehost_marker="ZIGOS:SERVICE_BOOT:DRIVER:REHOST_OK"
  restart_marker="ZIGOS:SERVICE_BOOT:SUPERVISOR:RESTART_OK"
  no_reboot_marker="ZIGOS:SERVICE_BOOT:SUPERVISOR:RESTART_WITHOUT_REBOOT"
  storage_before_marker="ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_IO_BEFORE_RESTART_OK"
  storage_stale_marker="ZIGOS:SERVICE_BOOT:DRIVER:STALE_ACCESS_REJECTED"
  storage_after_marker="ZIGOS:SERVICE_BOOT:DRIVER:STORAGE_IO_AFTER_RESTART_OK"
  ready_marker="$VALIDATION_MARKER"

  boot_count="$(grep -Fc "$boot_marker" "$log_path")"
  if [ "$boot_count" -ne 1 ]; then
    echo "Zigos native smoke test failed: expected one boot start before driver restart proof in $log_path, found $boot_count" >&2
    cat "$log_path" >&2
    exit 1
  fi

  boot_line="$(line_number "$log_path" "$boot_marker")"
  crash_line="$(line_number "$log_path" "$crash_marker")"
  rehost_line="$(line_number "$log_path" "$rehost_marker")"
  restart_line="$(line_number "$log_path" "$restart_marker")"
  no_reboot_line="$(line_number "$log_path" "$no_reboot_marker")"
  storage_before_line="$(line_number "$log_path" "$storage_before_marker")"
  storage_stale_line="$(line_number "$log_path" "$storage_stale_marker")"
  storage_after_line="$(line_number "$log_path" "$storage_after_marker")"
  ready_line="$(line_number "$log_path" "$ready_marker")"

  if [ "$boot_line" -ge "$crash_line" ] ||
     [ "$crash_line" -ge "$rehost_line" ] ||
     [ "$rehost_line" -ge "$restart_line" ] ||
     [ "$restart_line" -ge "$no_reboot_line" ] ||
     [ "$no_reboot_line" -ge "$storage_before_line" ] ||
     [ "$storage_before_line" -ge "$storage_stale_line" ] ||
     [ "$storage_stale_line" -ge "$storage_after_line" ]; then
    echo "Zigos native smoke test failed: driver restart proof markers are out of order in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi

  if [ "$MODE" = "full" ] && [ "$storage_after_line" -ge "$ready_line" ]; then
    echo "Zigos native smoke test failed: driver restart proof markers are out of order in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

append_build_artifact_measurements() {
  local kernel_digest
  local artifact
  kernel_digest="$(sha256_file "$KERNEL_PATH")"
  printf '\n=== BUILD ARTIFACT MEASUREMENTS ===\n'
  printf 'MEASURED_BOOT:BUILD_ARTIFACT bootloader source=src/boot/boot64.S sha256=%s\n' "$(sha256_file "$ROOT_DIR/src/boot/boot64.S")"
  printf 'MEASURED_BOOT:BUILD_ARTIFACT kernel path=%s sha256=%s\n' "$KERNEL_PATH" "$kernel_digest"
  find "$ROOT_DIR/zig-out/bin" -maxdepth 1 -type f -name 'userspace-*.elf' | LC_ALL=C sort |
    while IFS= read -r artifact; do
      printf 'MEASURED_BOOT:BUILD_ARTIFACT userspace path=%s sha256=%s\n' "${artifact#"$ROOT_DIR"/}" "$(sha256_file "$artifact")"
    done
}

append_measured_boot_comparison() {
  local boot1_root
  local boot2_root
  boot1_root="$(awk '/^ZIGOS:PLATFORM:MEASURED_BOOT:ROOT / {print $2; exit}' "$BOOT1_LOG")"
  boot2_root="$(awk '/^ZIGOS:PLATFORM:MEASURED_BOOT:ROOT / {print $2; exit}' "$BOOT2_LOG")"
  printf '\n=== MEASURED BOOT COMPARISON ===\n'
  printf 'MEASURED_BOOT:BOOT1_ROOT %s\n' "$boot1_root"
  printf 'MEASURED_BOOT:BOOT2_ROOT %s\n' "$boot2_root"
  if [ -n "$boot1_root" ] && [ "$boot1_root" = "$boot2_root" ]; then
    printf 'MEASURED_BOOT:ROOT_COMPARE MATCH\n'
  elif grep -Fq "ZIGOS:PLATFORM:MEASURED_BOOT:COMPARE:SAME_ROOT" "$BOOT2_LOG" &&
       grep -Fq "ZIGOS:PLATFORM:MEASURED_BOOT:COMPARE:SAME_SHAPE" "$BOOT2_LOG"; then
    printf 'MEASURED_BOOT:ROOT_COMPARE MATCH_REPORTED_BY_BOOT_JOURNAL\n'
  else
    printf 'MEASURED_BOOT:ROOT_COMPARE MISMATCH\n'
    return 1
  fi
}

case "$MODE" in
  full)
    run_boot "$BOOT1_LOG" reset
    assert_boot_markers "$BOOT1_LOG"
    assert_first_boot_markers "$BOOT1_LOG"
    assert_ab_rollback_markers "$BOOT1_LOG"
    assert_base_selector_active_slot "$BOOT1_LOG"
    assert_driver_restart_without_reboot "$BOOT1_LOG"

    run_boot "$BOOT2_LOG" preserve
    assert_boot_markers "$BOOT2_LOG"
    assert_reboot_markers "$BOOT2_LOG"
    assert_ab_rollback_markers "$BOOT2_LOG"
    assert_base_selector_active_slot "$BOOT2_LOG"
    assert_driver_restart_without_reboot "$BOOT2_LOG"

    {
      cat "$BOOT1_LOG"
      printf '\n=== COLD REBOOT ===\n'
      cat "$BOOT2_LOG"
      append_measured_boot_comparison
      append_build_artifact_measurements
    } >"$LOG_PATH"

    echo "Zigos native smoke test passed across cold reboot. Logs: $LOG_PATH"
    ;;
  driver_restart)
    run_boot "$BOOT1_LOG" reset
    assert_driver_restart_without_reboot "$BOOT1_LOG"
    cat "$BOOT1_LOG" >"$LOG_PATH"
    echo "Zigos driver restart QEMU test passed. Logs: $LOG_PATH"
    ;;
  tampered_artifact_manifest)
    run_boot "$BOOT1_LOG" reset
    assert_negative_boot_rejected "$BOOT1_LOG" tampered_artifact_manifest
    cat "$BOOT1_LOG" >"$LOG_PATH"
    echo "Zigos tampered artifact manifest negative smoke test passed. Logs: $LOG_PATH"
    ;;
  rollback_slot_failure)
    run_boot "$BOOT1_LOG" reset
    assert_negative_boot_rejected "$BOOT1_LOG" rollback_slot_failure
    cat "$BOOT1_LOG" >"$LOG_PATH"
    echo "Zigos rollback-slot failure negative smoke test passed. Logs: $LOG_PATH"
    ;;
  *)
    echo "Unknown smoke mode '$MODE'" >&2
    exit 1
    ;;
esac
