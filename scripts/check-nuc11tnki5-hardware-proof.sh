#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

PROOF_PATH="${1:?hardware proof directory or serial log path required}"
REQUIRED_MARKERS_PATH="spec/hardware/nuc11tnki5-required-markers.txt"
EXPECTED_MARKER_FILE="$ROOT_DIR/$REQUIRED_MARKERS_PATH"
MARKER_FILE="${2:-$EXPECTED_MARKER_FILE}"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"

MIN_COLD_BOOTS=10
MIN_WARM_REBOOTS=10
MIN_STORAGE_WRITE_READ_CYCLES=100
MIN_NETWORK_FRAME_CYCLES=100
MIN_SUSPEND_RESUME_CYCLES=20
MIN_CRASH_RECOVERY_CYCLES=10
MIN_CRASH_RECORD_PERSISTENCE_CYCLES=10
MIN_UPDATE_ROLLBACK_CYCLES=10

if [ -d "$PROOF_PATH" ]; then
  BUNDLE_DIR="$PROOF_PATH"
  LOG_PATH="$BUNDLE_DIR/serial.log"
else
  LOG_PATH="$PROOF_PATH"
  BUNDLE_DIR="$(dirname -- "$LOG_PATH")"
fi

EXPECTED_LOG_PATH="$BUNDLE_DIR/serial.log"
EXPECTED_FIRMWARE_SETTINGS_PATH="$BUNDLE_DIR/firmware-settings.txt"
EXPECTED_POWER_CYCLE_NOTES_PATH="$BUNDLE_DIR/power-cycle-notes.txt"
EXPECTED_ATTESTATION_LIFECYCLE_PATH="$BUNDLE_DIR/attestation-lifecycle.txt"
EXPECTED_ARTIFACT_DIGESTS_PATH="$BUNDLE_DIR/artifact-digests.sha256"
EXPECTED_PROOF_MANIFEST_PATH="$BUNDLE_DIR/proof-manifest.txt"

FIRMWARE_SETTINGS_PATH="${FIRMWARE_SETTINGS_PATH:-$EXPECTED_FIRMWARE_SETTINGS_PATH}"
POWER_CYCLE_NOTES_PATH="${POWER_CYCLE_NOTES_PATH:-$EXPECTED_POWER_CYCLE_NOTES_PATH}"
ATTESTATION_LIFECYCLE_PATH="${ATTESTATION_LIFECYCLE_PATH:-$EXPECTED_ATTESTATION_LIFECYCLE_PATH}"
ARTIFACT_DIGESTS_PATH="${ARTIFACT_DIGESTS_PATH:-$EXPECTED_ARTIFACT_DIGESTS_PATH}"
PROOF_MANIFEST_PATH="${PROOF_MANIFEST_PATH:-$EXPECTED_PROOF_MANIFEST_PATH}"
ARTIFACT_ROOT="${ZIGOS_ARTIFACT_ROOT:-$ROOT_DIR}"

REQUIRED_ARTIFACT_DIGEST_PATHS=(
  "build/os.iso"
  "zig-out/bin/kernel-zigos-native.elf"
  "zig-out/bin/userspace-session-manager.elf"
  "zig-out/bin/userspace-policy-mediation.elf"
  "zig-out/bin/userspace-permission-review.elf"
  "zig-out/bin/userspace-network-stack.elf"
  "zig-out/bin/userspace-storage-driver.elf"
  "zig-out/bin/userspace-sync-service.elf"
  "SECURITY.md"
  "spec/production_readiness.json"
  "spec/release_security/release_artifacts.json"
  "spec/release_security/release_keyring.json"
  "spec/release_security/revoked_release_keys.json"
  "spec/hardware/nuc11tnki5-required-markers.txt"
)

fail() {
  printf 'NUC11TNKi5 hardware proof failed: %s\n' "$*" >&2
  exit 1
}

absolute_path() {
  local path="$1"
  local dir
  local base
  local abs_dir
  dir="$(dirname -- "$path")"
  base="$(basename -- "$path")"
  if abs_dir="$(CDPATH='' cd -- "$dir" 2>/dev/null && pwd)"; then
    printf '%s/%s\n' "$abs_dir" "$base"
    return
  fi
  case "$path" in
    /*)
      printf '%s\n' "$path"
      ;;
    *)
      printf '%s/%s\n' "$(pwd)" "$path"
      ;;
  esac
}

require_non_empty_file() {
  local path="$1"
  local label="$2"
  if [ ! -s "$path" ]; then
    fail "$label is missing or empty: $path"
  fi
}

require_expected_bundle_path() {
  local path="$1"
  local expected_path="$2"
  local label="$3"
  if [ "$(absolute_path "$path")" != "$(absolute_path "$expected_path")" ]; then
    fail "$label path $path does not match proof bundle path $expected_path"
  fi
}

require_completed_text_file() {
  local path="$1"
  local label="$2"
  require_non_empty_file "$path" "$label"
  if grep -Eiq 'TODO|TBD|PLACEHOLDER|FILL_ME|<[^>]+>' "$path"; then
    fail "$label contains template placeholder text: $path"
  fi
  if grep -Eiq 'synthetic|simulated|mock|fake|fixture|test[-_ ]only|emulated' "$path"; then
    fail "$label contains non-real proof evidence text: $path"
  fi
}

require_exact_marker() {
  local marker="$1"
  local count
  count="$(grep -Fxc -- "$marker" "$LOG_PATH" || true)"
  if [ "$count" -eq 0 ]; then
    fail "missing marker '$marker' in $LOG_PATH"
  fi
  if [ "$count" -ne 1 ]; then
    fail "marker '$marker' appears $count times in $LOG_PATH"
  fi
}

marker_line_number() {
  local marker="$1"
  awk -v marker="$marker" '$0 == marker { print NR; exit }' "$LOG_PATH"
}

require_marker_before() {
  local earlier="$1"
  local later="$2"
  local earlier_line
  local later_line
  earlier_line="$(marker_line_number "$earlier")"
  later_line="$(marker_line_number "$later")"
  if [ -z "$earlier_line" ] || [ -z "$later_line" ]; then
    fail "cannot order missing markers '${earlier}' and '${later}' in $LOG_PATH"
  fi
  if [ "$earlier_line" -ge "$later_line" ]; then
    fail "marker '${earlier}' must appear before '${later}' in $LOG_PATH"
  fi
}

require_key_value() {
  local path="$1"
  local label="$2"
  local key="$3"
  local expected="$4"
  local value
  require_unique_key "$path" "$label" "$key"
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
  require_unique_key "$path" "$label" "$key"
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
  require_unique_key "$path" "$label" "$key"
  if ! value="$(extract_key "$path" "$key")"; then
    fail "$label missing '${key}=...' in $path"
  fi
  if ! [[ "$value" =~ $pattern ]]; then
    fail "$label key '${key}=${value}' does not match required format in $path"
  fi
}

require_timestamp_not_before() {
  local path="$1"
  local label="$2"
  local earlier_key="$3"
  local later_key="$4"
  local earlier_value
  local later_value
  earlier_value="$(extract_key "$path" "$earlier_key")"
  later_value="$(extract_key "$path" "$later_key")"
  if [[ "$later_value" < "$earlier_value" ]]; then
    fail "$label key '${later_key}=${later_value}' is before '${earlier_key}=${earlier_value}' in $path"
  fi
}

require_timestamp_value_not_before() {
  local label="$1"
  local checked_key="$2"
  local checked_value="$3"
  local floor_label="$4"
  local floor_value="$5"
  if [[ "$checked_value" < "$floor_value" ]]; then
    fail "$label ${checked_key}=${checked_value} is before ${floor_label}=${floor_value}"
  fi
}

require_timestamp_value_not_after() {
  local label="$1"
  local checked_key="$2"
  local checked_value="$3"
  local ceiling_label="$4"
  local ceiling_value="$5"
  if [[ "$checked_value" > "$ceiling_value" ]]; then
    fail "$label ${checked_key}=${checked_value} is after ${ceiling_label}=${ceiling_value}"
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

key_line_count() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '
    $1 == key { count += 1 }
    END { print count + 0 }
  ' "$path"
}

require_unique_key() {
  local path="$1"
  local label="$2"
  local key="$3"
  local count
  count="$(key_line_count "$path" "$key")"
  if [ "$count" -eq 0 ]; then
    fail "$label missing '${key}=...' in $path"
  fi
  if [ "$count" -ne 1 ]; then
    fail "$label key '${key}=...' appears $count times in $path"
  fi
}

extract_counter() {
  local counter_name="$1"
  awk -v prefix="${TARGET_PREFIX}:${counter_name}:" '
    index($0, prefix) == 1 {
      value = substr($0, length(prefix) + 1)
      if (value ~ /^[0-9]+$/) {
        print value
        found = 1
        exit
      }
    }
    END {
      if (!found) exit 1
    }
  ' "$LOG_PATH"
}

counter_line_count() {
  local counter_name="$1"
  awk -v prefix="${TARGET_PREFIX}:${counter_name}:" '
    index($0, prefix) == 1 { count += 1 }
    END { print count + 0 }
  ' "$LOG_PATH"
}

require_unique_counter() {
  local counter_name="$1"
  local count
  count="$(counter_line_count "$counter_name")"
  if [ "$count" -eq 0 ]; then
    fail "missing counter '${TARGET_PREFIX}:${counter_name}:<count>' in $LOG_PATH"
  fi
  if [ "$count" -ne 1 ]; then
    fail "counter '${TARGET_PREFIX}:${counter_name}:<count>' appears $count times in $LOG_PATH"
  fi
}

require_counter_at_least() {
  local counter_name="$1"
  local minimum="$2"
  local value
  require_unique_counter "$counter_name"
  if ! value="$(extract_counter "$counter_name")"; then
    fail "counter '${TARGET_PREFIX}:${counter_name}:<count>' is not numeric in $LOG_PATH"
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
  require_unique_key "$path" "$label" "$counter_name"
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

require_counter_matches_sidecar() {
  local sidecar_counter_name="$1"
  local serial_counter_name="$2"
  local sidecar_value
  local serial_value
  require_unique_key "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "$sidecar_counter_name"
  if ! sidecar_value="$(extract_key "$POWER_CYCLE_NOTES_PATH" "$sidecar_counter_name")"; then
    fail "power-cycle notes missing '${sidecar_counter_name}=<count>' in $POWER_CYCLE_NOTES_PATH"
  fi
  if ! [[ "$sidecar_value" =~ ^[0-9]+$ ]]; then
    fail "power-cycle notes counter '${sidecar_counter_name}=${sidecar_value}' is not numeric in $POWER_CYCLE_NOTES_PATH"
  fi
  require_unique_counter "$serial_counter_name"
  if ! serial_value="$(extract_counter "$serial_counter_name")"; then
    fail "counter '${TARGET_PREFIX}:${serial_counter_name}:<count>' is not numeric in $LOG_PATH"
  fi
  if [ "$sidecar_value" -ne "$serial_value" ]; then
    fail "power-cycle notes counter '${sidecar_counter_name}=${sidecar_value}' does not match serial counter '${serial_counter_name}=${serial_value}'"
  fi
}

sha256_file() {
  local file="${1:?file required}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

require_digest_manifest_format() {
  if ! awk '
    NF == 0 { next }
    length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && NF == 2 { next }
    {
      printf "malformed artifact digest line %d: %s\n", NR, $0 > "/dev/stderr"
      malformed = 1
    }
    END { exit malformed ? 1 : 0 }
  ' "$ARTIFACT_DIGESTS_PATH" >&2; then
    fail "artifact digest file contains malformed sha256 lines: $ARTIFACT_DIGESTS_PATH"
  fi
}

require_digest_for_path() {
  local artifact_path="$1"
  local digest_count
  digest_count="$(awk -v artifact_path="$artifact_path" '
    length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && $2 == artifact_path { count += 1 }
    END { print count + 0 }
  ' "$ARTIFACT_DIGESTS_PATH")"
  if [ "$digest_count" -eq 0 ]; then
    fail "artifact digest file missing sha256 line for ${artifact_path}: $ARTIFACT_DIGESTS_PATH"
  fi
  if [ "$digest_count" -ne 1 ]; then
    fail "artifact digest file has ${digest_count} sha256 lines for ${artifact_path}: $ARTIFACT_DIGESTS_PATH"
  fi

  local recorded_digest
  if ! recorded_digest="$(awk -v artifact_path="$artifact_path" '
    length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && $2 == artifact_path {
      print tolower($1)
      found = 1
      exit
    }
    END { exit found ? 0 : 1 }
  ' "$ARTIFACT_DIGESTS_PATH")"; then
    fail "artifact digest file has no readable sha256 line for ${artifact_path}: $ARTIFACT_DIGESTS_PATH"
  fi
  local actual_path="$ARTIFACT_ROOT/$artifact_path"
  if [ ! -f "$actual_path" ]; then
    fail "artifact digest file references missing artifact ${artifact_path} under $ARTIFACT_ROOT"
  fi
  local actual_digest
  actual_digest="$(sha256_file "$actual_path")"
  if [ "$recorded_digest" != "$actual_digest" ]; then
    fail "artifact digest mismatch for ${artifact_path}: recorded ${recorded_digest}, actual ${actual_digest}"
  fi
}

require_expected_bundle_path "$LOG_PATH" "$EXPECTED_LOG_PATH" "serial log"
require_completed_text_file "$LOG_PATH" "serial log"

if [ ! -f "$MARKER_FILE" ]; then
  fail "marker file is missing: $MARKER_FILE"
fi
if [ "$(absolute_path "$MARKER_FILE")" != "$EXPECTED_MARKER_FILE" ]; then
  fail "marker file $MARKER_FILE does not match proof manifest required_markers=${REQUIRED_MARKERS_PATH}"
fi

require_expected_bundle_path "$PROOF_MANIFEST_PATH" "$EXPECTED_PROOF_MANIFEST_PATH" "proof manifest"
require_completed_text_file "$PROOF_MANIFEST_PATH" "proof manifest"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "target_id" "intel-nuc11tnki5"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "board_sku" "NUC11TNKi5"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "evidence_source" "real_hardware"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "serial_log" "serial.log"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "firmware_settings" "firmware-settings.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "power_cycle_notes" "power-cycle-notes.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "attestation_lifecycle" "attestation-lifecycle.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "artifact_digests" "artifact-digests.sha256"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "required_markers" "$REQUIRED_MARKERS_PATH"
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "prepared_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "captured_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_timestamp_not_before "$PROOF_MANIFEST_PATH" "proof manifest" "prepared_at_utc" "captured_at_utc"
proof_prepared_at="$(extract_key "$PROOF_MANIFEST_PATH" "prepared_at_utc")"
proof_captured_at="$(extract_key "$PROOF_MANIFEST_PATH" "captured_at_utc")"
require_key_present "$PROOF_MANIFEST_PATH" "proof manifest" "operator"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_vcs" "jj"
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "repo_change_id" '^[a-z]{32}$'
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "repo_commit" '^[0-9a-fA-F]{40}$'
expected_repo_change_id="${ZIGOS_EXPECTED_REPO_CHANGE_ID:-$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"' 2>/dev/null || true)}"
if [ -n "$expected_repo_change_id" ]; then
  require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_change_id" "$expected_repo_change_id"
fi
expected_repo_commit="${ZIGOS_EXPECTED_REPO_COMMIT:-$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"' 2>/dev/null || true)}"
if [ -n "$expected_repo_commit" ]; then
  require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_commit" "$expected_repo_commit"
fi
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_dirty_files" "0"

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

  marker_count="$(grep -Fxc -- "$marker" "$LOG_PATH" || true)"
  if [ "$marker_count" -eq 0 ]; then
    printf "NUC11TNKi5 hardware proof failed: missing marker '%s' in %s\n" "$marker" "$LOG_PATH" >&2
    missing=1
  elif [ "$marker_count" -ne 1 ]; then
    printf "NUC11TNKi5 hardware proof failed: marker '%s' appears %s times in %s\n" "$marker" "$marker_count" "$LOG_PATH" >&2
    missing=1
  fi
done < "$MARKER_FILE"

if [ "$missing" -ne 0 ]; then
  exit 1
fi

require_marker_before "${TARGET_PREFIX}:SMBIOS_SKU:OBSERVED" "${TARGET_PREFIX}:UEFI_BOOT:PASS"
require_marker_before "${TARGET_PREFIX}:MULTIBOOT_MEMORY_MAP:OBSERVED" "${TARGET_PREFIX}:UEFI_BOOT:PASS"
require_marker_before "${TARGET_PREFIX}:ACPI_RSDP:OBSERVED" "${TARGET_PREFIX}:ACPI_TABLES:PASS"
require_marker_before "${TARGET_PREFIX}:ACPI_MADT:OBSERVED" "${TARGET_PREFIX}:ACPI_TABLES:PASS"
require_marker_before "${TARGET_PREFIX}:ACPI_FADT:OBSERVED" "${TARGET_PREFIX}:ACPI_TABLES:PASS"
require_marker_before "${TARGET_PREFIX}:APIC_TIMER_INTERRUPT:OBSERVED" "${TARGET_PREFIX}:APIC_TIMER:PASS"
require_marker_before "${TARGET_PREFIX}:FRAMEBUFFER_GOP_SCANOUT:OBSERVED" "${TARGET_PREFIX}:FRAMEBUFFER_GOP:PASS"
require_marker_before "${TARGET_PREFIX}:XHCI_BOOT_KEYBOARD_REPORT:OBSERVED" "${TARGET_PREFIX}:USB_INPUT_XHCI:PASS"
require_marker_before "${TARGET_PREFIX}:NVME_WRITE_READ_COMPLETION:OBSERVED" "${TARGET_PREFIX}:NVME_BLOCK:PASS"
require_marker_before "${TARGET_PREFIX}:I225_LM_FRAME_INTERRUPT:OBSERVED" "${TARGET_PREFIX}:NETWORK_I225_LM:PASS"
require_marker_before "${TARGET_PREFIX}:SUSPEND_RESUME_POWER:OBSERVED" "${TARGET_PREFIX}:SUSPEND_RESUME:PASS"
require_marker_before "${TARGET_PREFIX}:CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED" "${TARGET_PREFIX}:CRASH_RECOVERY:PASS"
require_marker_before "${TARGET_PREFIX}:UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED" "ZIGOS:PLATFORM:UPDATE_ROLLBACK:POWER_CYCLE_OK"
require_marker_before "${TARGET_PREFIX}:CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED" "ZIGOS:PLATFORM:CRASH_RECORD:PERSISTED"
require_marker_before "${TARGET_PREFIX}:XHCI_BOOT_KEYBOARD_REPORT:OBSERVED" "ZIGOS:PERMISSION:XHCI_KEYBOARD:REPORT"
require_marker_before "${TARGET_PREFIX}:I225_LM_FRAME_INTERRUPT:OBSERVED" "ZIGOS:SYNC:NATIVE_DRIVER:FRAME_SENT"

require_counter_at_least "COLD_BOOTS" "$MIN_COLD_BOOTS"
require_counter_at_least "WARM_REBOOTS" "$MIN_WARM_REBOOTS"
require_counter_at_least "STORAGE_WRITE_READ_CYCLES" "$MIN_STORAGE_WRITE_READ_CYCLES"
require_counter_at_least "NETWORK_FRAME_CYCLES" "$MIN_NETWORK_FRAME_CYCLES"
require_counter_at_least "SUSPEND_RESUME_CYCLES" "$MIN_SUSPEND_RESUME_CYCLES"
require_counter_at_least "CRASH_RECOVERY_CYCLES" "$MIN_CRASH_RECOVERY_CYCLES"
require_counter_at_least "CRASH_RECORD_PERSISTENCE_CYCLES" "$MIN_CRASH_RECORD_PERSISTENCE_CYCLES"
require_counter_at_least "UPDATE_ROLLBACK_CYCLES" "$MIN_UPDATE_ROLLBACK_CYCLES"

require_expected_bundle_path "$FIRMWARE_SETTINGS_PATH" "$EXPECTED_FIRMWARE_SETTINGS_PATH" "firmware settings"
require_completed_text_file "$FIRMWARE_SETTINGS_PATH" "firmware settings"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "target_id" "intel-nuc11tnki5"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "board_sku" "NUC11TNKi5"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "boot_mode" "UEFI"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "bios_version"
require_key_matches "$FIRMWARE_SETTINGS_PATH" "firmware settings" "secure_boot" '^(enabled|disabled|disabled-for-local-proof-media)$'
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "storage_mode" "nvme"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "wake_suspend"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "changed_options"

require_expected_bundle_path "$POWER_CYCLE_NOTES_PATH" "$EXPECTED_POWER_CYCLE_NOTES_PATH" "power-cycle notes"
require_completed_text_file "$POWER_CYCLE_NOTES_PATH" "power-cycle notes"
require_key_value "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "target_id" "intel-nuc11tnki5"
require_key_present "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "operator"
require_key_present "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "notes"
require_key_matches "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "started_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_matches "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "completed_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_timestamp_not_before "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "started_at_utc" "completed_at_utc"
power_started_at="$(extract_key "$POWER_CYCLE_NOTES_PATH" "started_at_utc")"
power_completed_at="$(extract_key "$POWER_CYCLE_NOTES_PATH" "completed_at_utc")"
require_timestamp_value_not_before "power-cycle notes" "started_at_utc" "$power_started_at" "proof manifest prepared_at_utc" "$proof_prepared_at"
require_timestamp_value_not_after "power-cycle notes" "completed_at_utc" "$power_completed_at" "proof manifest captured_at_utc" "$proof_captured_at"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "cold_boots" "$MIN_COLD_BOOTS"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "warm_reboots" "$MIN_WARM_REBOOTS"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "storage_write_read_cycles" "$MIN_STORAGE_WRITE_READ_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "network_frame_cycles" "$MIN_NETWORK_FRAME_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "suspend_resume_cycles" "$MIN_SUSPEND_RESUME_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "crash_recovery_cycles" "$MIN_CRASH_RECOVERY_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "crash_record_persistence_cycles" "$MIN_CRASH_RECORD_PERSISTENCE_CYCLES"
require_sidecar_counter_at_least "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "update_rollback_cycles" "$MIN_UPDATE_ROLLBACK_CYCLES"
require_counter_matches_sidecar "cold_boots" "COLD_BOOTS"
require_counter_matches_sidecar "warm_reboots" "WARM_REBOOTS"
require_counter_matches_sidecar "storage_write_read_cycles" "STORAGE_WRITE_READ_CYCLES"
require_counter_matches_sidecar "network_frame_cycles" "NETWORK_FRAME_CYCLES"
require_counter_matches_sidecar "suspend_resume_cycles" "SUSPEND_RESUME_CYCLES"
require_counter_matches_sidecar "crash_recovery_cycles" "CRASH_RECOVERY_CYCLES"
require_counter_matches_sidecar "crash_record_persistence_cycles" "CRASH_RECORD_PERSISTENCE_CYCLES"
require_counter_matches_sidecar "update_rollback_cycles" "UPDATE_ROLLBACK_CYCLES"

require_expected_bundle_path "$ATTESTATION_LIFECYCLE_PATH" "$EXPECTED_ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle"
require_completed_text_file "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "target_id" "intel-nuc11tnki5"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "evidence_source" "real_hardware"
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "operator"
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "captured_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "provider"
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "root_key_id"
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "initial_generation" '^[1-9][0-9]*$'
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "active_generation" '^[1-9][0-9]*$'
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "revoked_generation_count" '^[1-9][0-9]*$'
initial_generation="$(extract_key "$ATTESTATION_LIFECYCLE_PATH" "initial_generation")"
active_generation="$(extract_key "$ATTESTATION_LIFECYCLE_PATH" "active_generation")"
if [ "$active_generation" -le "$initial_generation" ]; then
  fail "attestation lifecycle active_generation=${active_generation} must be greater than initial_generation=${initial_generation}"
fi
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "stale_generation_rejected" "true"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "revoked_generation_rejected" "true"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "verifier_rejected_stale_attestation" "true"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "verifier_metadata_digest_bound" "true"
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "verifier_metadata_digest" '^[0-9a-fA-F]{64}$'
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "attestation_request_digest" '^[0-9a-fA-F]{64}$'
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "notes"
attestation_captured_at="$(extract_key "$ATTESTATION_LIFECYCLE_PATH" "captured_at_utc")"
require_timestamp_value_not_before "attestation lifecycle" "captured_at_utc" "$attestation_captured_at" "proof manifest prepared_at_utc" "$proof_prepared_at"
require_timestamp_value_not_after "attestation lifecycle" "captured_at_utc" "$attestation_captured_at" "proof manifest captured_at_utc" "$proof_captured_at"

require_expected_bundle_path "$ARTIFACT_DIGESTS_PATH" "$EXPECTED_ARTIFACT_DIGESTS_PATH" "artifact digests"
require_completed_text_file "$ARTIFACT_DIGESTS_PATH" "artifact digests"
require_digest_manifest_format

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
