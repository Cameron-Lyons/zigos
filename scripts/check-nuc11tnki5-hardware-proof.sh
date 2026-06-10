#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

PROOF_PATH="${1:?hardware proof directory or serial log path required}"
MARKER_FILE="${2:-$ROOT_DIR/spec/hardware/nuc11tnki5-required-markers.txt}"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"

MIN_COLD_BOOTS=10
MIN_WARM_REBOOTS=10
MIN_STORAGE_WRITE_READ_CYCLES=100
MIN_NETWORK_FRAME_CYCLES=100
MIN_SUSPEND_RESUME_CYCLES=20
MIN_CRASH_RECOVERY_CYCLES=10

if [ -d "$PROOF_PATH" ]; then
  BUNDLE_DIR="$PROOF_PATH"
  LOG_PATH="$BUNDLE_DIR/serial.log"
else
  LOG_PATH="$PROOF_PATH"
  BUNDLE_DIR="$(dirname -- "$LOG_PATH")"
fi

FIRMWARE_SETTINGS_PATH="${FIRMWARE_SETTINGS_PATH:-$BUNDLE_DIR/firmware-settings.txt}"
POWER_CYCLE_NOTES_PATH="${POWER_CYCLE_NOTES_PATH:-$BUNDLE_DIR/power-cycle-notes.txt}"
ARTIFACT_DIGESTS_PATH="${ARTIFACT_DIGESTS_PATH:-$BUNDLE_DIR/artifact-digests.sha256}"
PROOF_MANIFEST_PATH="${PROOF_MANIFEST_PATH:-$BUNDLE_DIR/proof-manifest.txt}"

REQUIRED_ARTIFACT_DIGEST_PATHS=(
  "build/os.iso"
  "zig-out/bin/kernel-zigos-native.elf"
  "zig-out/bin/userspace-session-manager.elf"
  "zig-out/bin/userspace-policy-mediation.elf"
  "zig-out/bin/userspace-permission-review.elf"
  "zig-out/bin/userspace-network-stack.elf"
  "zig-out/bin/userspace-storage-driver.elf"
  "zig-out/bin/userspace-sync-service.elf"
  "spec/production_readiness.json"
  "spec/hardware/nuc11tnki5-required-markers.txt"
)

fail() {
  printf 'NUC11TNKi5 hardware proof failed: %s\n' "$*" >&2
  exit 1
}

require_non_empty_file() {
  local path="$1"
  local label="$2"
  if [ ! -s "$path" ]; then
    fail "$label is missing or empty: $path"
  fi
}

require_completed_text_file() {
  local path="$1"
  local label="$2"
  require_non_empty_file "$path" "$label"
  if grep -Eiq 'TODO|TBD|PLACEHOLDER|FILL_ME|<[^>]+>' "$path"; then
    fail "$label contains template placeholder text: $path"
  fi
}

require_exact_marker() {
  local marker="$1"
  if ! grep -Fxq "$marker" "$LOG_PATH"; then
    fail "missing marker '$marker' in $LOG_PATH"
  fi
}

require_key_value() {
  local path="$1"
  local label="$2"
  local key="$3"
  local expected="$4"
  local value
  if ! value="$(extract_key "$path" "$key")"; then
    fail "$label missing '${key}=${expected}' in $path"
  fi
  if [ "$value" != "$expected" ]; then
    fail "$label has '${key}=${value}', expected '${key}=${expected}' in $path"
  fi
}

require_key_present() {
  local path="$1"
  local label="$2"
  local key="$3"
  local value
  if ! value="$(extract_key "$path" "$key")" || [ -z "$value" ]; then
    fail "$label missing non-empty '${key}=...' in $path"
  fi
}

require_key_matches() {
  local path="$1"
  local label="$2"
  local key="$3"
  local pattern="$4"
  local value
  if ! value="$(extract_key "$path" "$key")"; then
    fail "$label missing '${key}=...' in $path"
  fi
  if ! [[ "$value" =~ $pattern ]]; then
    fail "$label key '${key}=${value}' does not match required format in $path"
  fi
}

extract_key() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '
    $1 == key {
      value = substr($0, length(key) + 2)
      found = 1
    }
    END {
      if (!found) exit 1
      print value
    }
  ' "$path"
}

extract_counter() {
  local counter_name="$1"
  awk -v prefix="${TARGET_PREFIX}:${counter_name}:" '
    index($0, prefix) == 1 {
      value = substr($0, length(prefix) + 1)
      if (value ~ /^[0-9]+$/) found = value
    }
    END {
      if (found == "") exit 1
      print found
    }
  ' "$LOG_PATH"
}

require_counter_at_least() {
  local counter_name="$1"
  local minimum="$2"
  local value
  if ! value="$(extract_counter "$counter_name")"; then
    fail "missing numeric counter '${TARGET_PREFIX}:${counter_name}:<count>' in $LOG_PATH"
  fi
  if [ "$value" -lt "$minimum" ]; then
    fail "counter ${TARGET_PREFIX}:${counter_name}:${value} is below required minimum $minimum"
  fi
}

require_sidecar_counter_at_least() {
  local path="$1"
  local label="$2"
  local counter_name="$3"
  local minimum="$4"
  local value
  if ! value="$(extract_key "$path" "$counter_name")"; then
    fail "$label missing '${counter_name}=<count>' in $path"
  fi
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    fail "$label counter '${counter_name}=${value}' is not numeric in $path"
  fi
  if [ "$value" -lt "$minimum" ]; then
    fail "$label counter '${counter_name}=${value}' is below required minimum $minimum"
  fi
}

require_digest_for_path() {
  local artifact_path="$1"
  if ! awk -v artifact_path="$artifact_path" '
    length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && $2 == artifact_path { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$ARTIFACT_DIGESTS_PATH"; then
    fail "artifact digest file missing sha256 line for ${artifact_path}: $ARTIFACT_DIGESTS_PATH"
  fi
}

require_completed_text_file "$LOG_PATH" "serial log"

if [ ! -f "$MARKER_FILE" ]; then
  fail "marker file is missing: $MARKER_FILE"
fi

require_completed_text_file "$PROOF_MANIFEST_PATH" "proof manifest"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "target_id" "intel-nuc11tnki5"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "board_sku" "NUC11TNKi5"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "evidence_source" "real_hardware"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "serial_log" "serial.log"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "firmware_settings" "firmware-settings.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "power_cycle_notes" "power-cycle-notes.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "artifact_digests" "artifact-digests.sha256"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "required_markers" "spec/hardware/nuc11tnki5-required-markers.txt"
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "prepared_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "captured_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_present "$PROOF_MANIFEST_PATH" "proof manifest" "operator"
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "repo_commit" '^[0-9a-fA-F]{40}$'

if grep -Eqi 'panic|KERNEL PANIC|System Halted|(^|:)FAIL($|:)|ZIGOS:.*:FAIL' "$LOG_PATH"; then
  fail "panic or failure text found in $LOG_PATH"
fi

if grep -Eqi 'QEMU|SeaBIOS|OVMF|TCG accelerator|KVM accelerator|Bochs|BHYVE|VMware|VirtualBox|Hypervisor' "$LOG_PATH"; then
  fail "emulator or virtual firmware text found in $LOG_PATH; NUC11TNKi5 proof must come from real hardware"
fi

require_exact_marker "${TARGET_PREFIX}:EVIDENCE_SOURCE:REAL_HARDWARE"
require_exact_marker "${TARGET_PREFIX}:BOARD_SKU:NUC11TNKi5"
require_exact_marker "${TARGET_PREFIX}:PROOF_MANIFEST:RECORDED"
require_exact_marker "${TARGET_PREFIX}:FIRMWARE_SETTINGS:RECORDED"
require_exact_marker "${TARGET_PREFIX}:POWER_CYCLE_NOTES:RECORDED"
require_exact_marker "${TARGET_PREFIX}:ARTIFACT_DIGESTS:RECORDED"

missing=0
while IFS= read -r marker; do
  case "$marker" in
    '' | \#*)
      continue
      ;;
  esac

  if ! grep -Fxq "$marker" "$LOG_PATH"; then
    printf "NUC11TNKi5 hardware proof failed: missing marker '%s' in %s\n" "$marker" "$LOG_PATH" >&2
    missing=1
  fi
done < "$MARKER_FILE"

if [ "$missing" -ne 0 ]; then
  exit 1
fi

require_counter_at_least "COLD_BOOTS" "$MIN_COLD_BOOTS"
require_counter_at_least "WARM_REBOOTS" "$MIN_WARM_REBOOTS"
require_counter_at_least "STORAGE_WRITE_READ_CYCLES" "$MIN_STORAGE_WRITE_READ_CYCLES"
require_counter_at_least "NETWORK_FRAME_CYCLES" "$MIN_NETWORK_FRAME_CYCLES"
require_counter_at_least "SUSPEND_RESUME_CYCLES" "$MIN_SUSPEND_RESUME_CYCLES"
require_counter_at_least "CRASH_RECOVERY_CYCLES" "$MIN_CRASH_RECOVERY_CYCLES"

require_completed_text_file "$FIRMWARE_SETTINGS_PATH" "firmware settings"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "target_id" "intel-nuc11tnki5"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "board_sku" "NUC11TNKi5"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "boot_mode" "UEFI"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "bios_version"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "secure_boot"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "storage_mode"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "wake_suspend"

require_completed_text_file "$POWER_CYCLE_NOTES_PATH" "power-cycle notes"
require_key_value "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "target_id" "intel-nuc11tnki5"
require_key_present "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "operator"
require_key_matches "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "started_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_matches "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "completed_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "cold_boots" "$MIN_COLD_BOOTS"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "warm_reboots" "$MIN_WARM_REBOOTS"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "storage_write_read_cycles" "$MIN_STORAGE_WRITE_READ_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "network_frame_cycles" "$MIN_NETWORK_FRAME_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "suspend_resume_cycles" "$MIN_SUSPEND_RESUME_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "crash_recovery_cycles" "$MIN_CRASH_RECOVERY_CYCLES"

require_completed_text_file "$ARTIFACT_DIGESTS_PATH" "artifact digests"

if ! awk '
  length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && NF >= 2 { found = 1 }
  END { exit found ? 0 : 1 }
' "$ARTIFACT_DIGESTS_PATH"; then
  fail "artifact digest file must include at least one sha256 digest line: $ARTIFACT_DIGESTS_PATH"
fi

for artifact_path in "${REQUIRED_ARTIFACT_DIGEST_PATHS[@]}"; do
  require_digest_for_path "$artifact_path"
done

printf 'NUC11TNKi5 hardware proof bundle OK: %s\n' "$BUNDLE_DIR"
