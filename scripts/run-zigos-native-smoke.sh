#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
ZIG="${ROOT_DIR}/scripts/zig.sh"
MARKER_TOOL="${ROOT_DIR}/src/print_native_smoke_markers.zig"
PRODUCTION_BOOT_LOG_CHECKER="${ROOT_DIR}/scripts/check-production-boot-log.sh"

source "$ROOT_DIR/scripts/qemu-harness.sh"

KERNEL_PATH="${1:?kernel path required}"
LOG_PATH="${2:?serial log path required}"
NATIVE_STORE_IMAGE="${3:?native store image path required}"
MODE="${4:-full}"
USERSPACE_BIN_DIR="${5:-$ROOT_DIR/zig-out/bin}"
BOOTLOADER_SOURCE_PATH="${6:-src/boot/boot_x86_64.S}"
ZIGOS_NATIVE_SECONDS="${ZIGOS_NATIVE_SECONDS:-420}"
NATIVE_STORE_SIZE_MIB="${NATIVE_STORE_SIZE_MIB:-8}"
HIGH_MEMORY_MARKER="High-memory direct map: online"

last_marker_for_group() {
  local group="$1"
  "$ZIG" run "$MARKER_TOOL" -- "$group" | awk 'NF { marker = $0 } END { if (marker == "") exit 1; print marker }'
}

first_marker_for_group() {
  local group="$1"
  "$ZIG" run "$MARKER_TOOL" -- "$group" | awk 'NF && !found { marker = $0; found = 1 } END { if (!found) exit 1; print marker }'
}

validation_marker_for_mode() {
  local mode="$1"
  case "$mode" in
    production)
      last_marker_for_group production
      ;;
    full)
      last_marker_for_group ready
      ;;
    driver_restart | tampered_artifact_manifest | tampered_bootloader_measurement | tampered_kernel | tampered_userspace_image | tampered_policy | tampered_driver_set | rollback_slot_failure)
      last_marker_for_group "$mode"
      ;;
    *)
      echo "Unknown smoke mode '$mode'" >&2
      return 1
      ;;
  esac
}

BOOT_START_MARKER="$(first_marker_for_group cold_boot)"
ZIGOS_READY_MARKER="$(last_marker_for_group ready)"
VALIDATION_MARKER="$(validation_marker_for_mode "$MODE")"

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

  if [ "${ZIGOS_REQUIRE_HIGH_MEMORY:-0}" = 1 ] && ! grep -Fq "$HIGH_MEMORY_MARKER" "$log_path"; then
    echo "Zigos native smoke test failed: high-memory direct-map proof was not observed in $log_path" >&2
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

assert_marker_group_absent() {
  local log_path="$1"
  local group="$2"
  local needle

  while IFS= read -r needle; do
    [ -n "$needle" ] || continue
    if grep -Fq "$needle" "$log_path"; then
      echo "Zigos native smoke test failed: verification-only marker '$needle' found in production log $log_path" >&2
      cat "$log_path" >&2
      exit 1
    fi
  done < <("$ZIG" run "$MARKER_TOOL" -- "$group")
}

assert_production_boot_markers() {
  local log_path="$1"
  assert_marker_group "$log_path" production
  assert_marker_group_absent "$log_path" production_forbidden
  bash "$PRODUCTION_BOOT_LOG_CHECKER" "$log_path" >/dev/null
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

assert_stack_headroom() {
  local log_path="$1"
  local marker="$2"
  local metrics
  local used_bytes
  local capacity_bytes

  if ! metrics="$(awk -v marker="$marker" '
    index($0, marker) {
      used = ""
      capacity = ""
      for (field = 1; field <= NF; field += 1) {
        if ($field ~ /^used_bytes=/) {
          split($field, parts, "=")
          used = parts[2]
        } else if ($field ~ /^capacity_bytes=/) {
          split($field, parts, "=")
          capacity = parts[2]
        }
      }
    }
    END {
      if (used == "" || capacity == "") exit 1
      print used, capacity
    }
  ' "$log_path")"; then
    echo "Zigos native smoke test failed: missing stack watermark '$marker' in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi

  read -r used_bytes capacity_bytes <<<"$metrics"
  if [ "$used_bytes" -gt "$capacity_bytes" ] ||
     [ $((used_bytes * 4)) -gt $((capacity_bytes * 3)) ]; then
    echo "Zigos native smoke test failed: stack watermark '$marker' has less than 25% headroom in $log_path" >&2
    cat "$log_path" >&2
    exit 1
  fi
}

assert_stack_headroom_markers() {
  local log_path="$1"
  assert_stack_headroom "$log_path" "ZIGOS:PLATFORM:BOOT_STACK:PEAK"
  assert_stack_headroom "$log_path" "ZIGOS:PLATFORM:TRAP_STACK:PEAK"
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
  awk -v marker="$marker" 'index($0, marker) { print NR; exit }' "$log_path"
}

assert_driver_restart_without_reboot() {
  local log_path="$1"
  local boot_marker
  local ready_marker
  local boot_count
  local previous_line
  local marker
  local marker_line
  local storage_after_line
  local ready_line

  assert_marker_group "$log_path" driver_restart
  boot_marker="$BOOT_START_MARKER"
  ready_marker="$VALIDATION_MARKER"

  boot_count="$(grep -Fc "$boot_marker" "$log_path")"
  if [ "$boot_count" -ne 1 ]; then
    echo "Zigos native smoke test failed: expected one boot start before driver restart proof in $log_path, found $boot_count" >&2
    cat "$log_path" >&2
    exit 1
  fi

  previous_line="$(line_number "$log_path" "$boot_marker")"
  while IFS= read -r marker; do
    [ -n "$marker" ] || continue
    marker_line="$(line_number "$log_path" "$marker")"
    if [ "$previous_line" -ge "$marker_line" ]; then
      echo "Zigos native smoke test failed: driver restart proof markers are out of order in $log_path" >&2
      cat "$log_path" >&2
      exit 1
    fi
    previous_line="$marker_line"
  done < <("$ZIG" run "$MARKER_TOOL" -- driver_restart)
  storage_after_line="$previous_line"
  ready_line="$(line_number "$log_path" "$ready_marker")"

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
  local artifact_name
  if [ ! -d "$USERSPACE_BIN_DIR" ]; then
    echo "Zigos native smoke test failed: userspace artifact directory not found: $USERSPACE_BIN_DIR" >&2
    exit 1
  fi
  kernel_digest="$(sha256_file "$KERNEL_PATH")"
  printf '\n=== BUILD ARTIFACT MEASUREMENTS ===\n'
  printf 'MEASURED_BOOT:BUILD_ARTIFACT bootloader source=%s sha256=%s\n' "$BOOTLOADER_SOURCE_PATH" "$(sha256_file "$ROOT_DIR/$BOOTLOADER_SOURCE_PATH")"
  printf 'MEASURED_BOOT:BUILD_ARTIFACT kernel path=%s sha256=%s\n' "$KERNEL_PATH" "$kernel_digest"
  find "$USERSPACE_BIN_DIR" -maxdepth 1 -type f -name 'userspace-*.elf' | LC_ALL=C sort |
    while IFS= read -r artifact; do
      artifact_name="${artifact##*/}"
      if [ "$MODE" = "production" ]; then
        case "$artifact_name" in
          userspace-notes-daily.elf | \
            userspace-transport-probe.elf | \
            userspace-termination-probe.elf | \
            userspace-service-client.elf | \
            userspace-mmu-isolation-proof.elf)
            continue
            ;;
        esac
      fi
      printf 'MEASURED_BOOT:BUILD_ARTIFACT userspace path=%s sha256=%s\n' "${artifact#"$ROOT_DIR"/}" "$(sha256_file "$artifact")"
    done
}

assert_measured_userspace_count() {
  local log_path="$1"
  local expected="$2"
  local actual
  actual="$(grep -Fc 'MEASURED_BOOT:BUILD_ARTIFACT userspace path=' "$log_path" || true)"
  if [ "$actual" -ne "$expected" ]; then
    echo "Zigos native smoke test failed: expected $expected measured userspace artifacts, found $actual" >&2
    exit 1
  fi
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

smoke_mode_label() {
  local mode="$1"
  case "$mode" in
    tampered_artifact_manifest) printf 'tampered artifact manifest' ;;
    tampered_bootloader_measurement) printf 'tampered bootloader measurement' ;;
    tampered_kernel) printf 'tampered kernel' ;;
    tampered_userspace_image) printf 'tampered userspace image' ;;
    tampered_policy) printf 'tampered policy' ;;
    tampered_driver_set) printf 'tampered driver-set' ;;
    rollback_slot_failure) printf 'rollback-slot failure' ;;
    *) printf '%s' "$mode" ;;
  esac
}

run_negative_boot() {
  local group="$1"
  run_boot "$BOOT1_LOG" reset
  assert_negative_boot_rejected "$BOOT1_LOG" "$group"
  cat "$BOOT1_LOG" >"$LOG_PATH"
  echo "Zigos $(smoke_mode_label "$group") negative smoke test passed. Logs: $LOG_PATH"
}

case "$MODE" in
  production)
    run_boot "$BOOT1_LOG" reset
    assert_stack_headroom_markers "$BOOT1_LOG"
    assert_production_boot_markers "$BOOT1_LOG"
    assert_marker_group "$BOOT1_LOG" production_first_boot

    run_boot "$BOOT2_LOG" preserve
    assert_stack_headroom_markers "$BOOT2_LOG"
    assert_production_boot_markers "$BOOT2_LOG"
    assert_marker_group "$BOOT2_LOG" production_reboot

    {
      cat "$BOOT1_LOG"
      printf '\n=== COLD REBOOT ===\n'
      cat "$BOOT2_LOG"
      append_measured_boot_comparison
      append_build_artifact_measurements
    } >"$LOG_PATH"
    assert_marker_group_absent "$LOG_PATH" production_forbidden
    assert_measured_userspace_count "$LOG_PATH" 24

    echo "Zigos production smoke test passed across cold reboot. Logs: $LOG_PATH"
    ;;
  full)
    run_boot "$BOOT1_LOG" reset
    assert_stack_headroom_markers "$BOOT1_LOG"
    assert_boot_markers "$BOOT1_LOG"
    assert_first_boot_markers "$BOOT1_LOG"
    assert_ab_rollback_markers "$BOOT1_LOG"
    assert_base_selector_active_slot "$BOOT1_LOG"
    assert_driver_restart_without_reboot "$BOOT1_LOG"

    run_boot "$BOOT2_LOG" preserve
    assert_stack_headroom_markers "$BOOT2_LOG"
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
    assert_measured_userspace_count "$LOG_PATH" 29

    echo "Zigos native smoke test passed across cold reboot. Logs: $LOG_PATH"
    ;;
  driver_restart)
    run_boot "$BOOT1_LOG" reset
    assert_driver_restart_without_reboot "$BOOT1_LOG"
    cat "$BOOT1_LOG" >"$LOG_PATH"
    echo "Zigos driver restart QEMU test passed. Logs: $LOG_PATH"
    ;;
  tampered_artifact_manifest | tampered_bootloader_measurement | tampered_kernel | tampered_userspace_image | tampered_policy | tampered_driver_set | rollback_slot_failure)
    run_negative_boot "$MODE"
    ;;
  *)
    echo "Unknown smoke mode '$MODE'" >&2
    exit 1
    ;;
esac
