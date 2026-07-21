#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

TARGET_ID="intel-nuc11tnki5"
BOARD_SKU="NUC11TNKi5"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"
PRODUCTION_REQUIRED_MARKERS_PATH="spec/hardware/nuc11tnki5-production-required-markers.txt"
VERIFICATION_REQUIRED_MARKERS_PATH="spec/hardware/nuc11tnki5-required-markers.txt"
PRODUCTION_MARKER_FILE="$ROOT_DIR/$PRODUCTION_REQUIRED_MARKERS_PATH"
VERIFICATION_MARKER_FILE="$ROOT_DIR/$VERIFICATION_REQUIRED_MARKERS_PATH"

MIN_COLD_BOOTS=10
MIN_WARM_REBOOTS=10
MIN_STORAGE_WRITE_READ_CYCLES=100
MIN_NETWORK_FRAME_CYCLES=100
MIN_SUSPEND_RESUME_CYCLES=20
MIN_CRASH_RECOVERY_CYCLES=10
MIN_CRASH_RECORD_PERSISTENCE_CYCLES=10
MIN_UPDATE_ROLLBACK_CYCLES=10

fail() {
  printf 'NUC11TNKi5 hardware proof failed: %s\n' "$*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then
  fail "usage: scripts/check-nuc11tnki5-hardware-proof.sh BUNDLE_DIRECTORY"
fi

PROOF_PATH="$1"
if [ ! -d "$PROOF_PATH" ]; then
  fail "proof path must be the complete bundle directory: $PROOF_PATH"
fi
BUNDLE_DIR="$(CDPATH='' cd -- "$PROOF_PATH" && pwd)"
ARTIFACT_ROOT="${ZIGOS_ARTIFACT_ROOT:-$ROOT_DIR}"

TRUSTED_VERIFIER="${ZIGOS_HARDWARE_PROOF_VERIFIER:-}"
EXPECTED_VERIFIER_SHA256="${ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256:-}"
EXPECTED_NONCE="${ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE:-}"

if [ -z "$TRUSTED_VERIFIER" ]; then
  fail "ZIGOS_HARDWARE_PROOF_VERIFIER must name an external trusted verifier executable"
fi
case "$TRUSTED_VERIFIER" in
  /*) ;;
  *) fail "ZIGOS_HARDWARE_PROOF_VERIFIER must be an absolute path" ;;
esac
if [ ! -f "$TRUSTED_VERIFIER" ] || [ ! -x "$TRUSTED_VERIFIER" ] || [ -L "$TRUSTED_VERIFIER" ]; then
  fail "trusted verifier must be an executable regular file, not a symlink: $TRUSTED_VERIFIER"
fi
case "$TRUSTED_VERIFIER" in
  "$BUNDLE_DIR"/*) fail "trusted verifier must be external to the proof bundle" ;;
esac
if ! [[ "$EXPECTED_VERIFIER_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  fail "ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256 must be an externally pinned lowercase SHA-256 digest"
fi
if ! [[ "$EXPECTED_NONCE" =~ ^[0-9a-f]{64}$ ]]; then
  fail "ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE must be the fresh externally issued 64-hex capture nonce"
fi

PROOF_MANIFEST_PATH="$BUNDLE_DIR/proof-manifest.txt"
DEVICE_IDENTITY_PATH="$BUNDLE_DIR/device-identity.txt"
PRODUCTION_LOG_PATH="$BUNDLE_DIR/production-serial.log"
VERIFICATION_LOG_PATH="$BUNDLE_DIR/verification-serial.log"
CYCLE_MANIFEST_PATH="$BUNDLE_DIR/cycle-manifest.txt"
FIRMWARE_SETTINGS_PATH="$BUNDLE_DIR/firmware-settings.txt"
POWER_CYCLE_NOTES_PATH="$BUNDLE_DIR/power-cycle-notes.txt"
ATTESTATION_LIFECYCLE_PATH="$BUNDLE_DIR/attestation-lifecycle.txt"
ARTIFACT_DIGESTS_PATH="$BUNDLE_DIR/artifact-digests.sha256"
OPERATOR_METADATA_PATH="$BUNDLE_DIR/operator-metadata-markers.txt"
PRODUCTION_QUOTE_PATH="$BUNDLE_DIR/production-attestation.quote"
PRODUCTION_SIGNATURE_PATH="$BUNDLE_DIR/production-attestation.sig"
VERIFICATION_QUOTE_PATH="$BUNDLE_DIR/verification-attestation.quote"
VERIFICATION_SIGNATURE_PATH="$BUNDLE_DIR/verification-attestation.sig"
CAPTURE_STATEMENT_PATH="$BUNDLE_DIR/capture-statement.txt"

REQUIRED_ARTIFACT_DIGEST_PATHS=(
  "build/os.iso"
  "zig-out/bin/kernel-zigos-native.elf"
  "build/os-verification.iso"
  "zig-out/bin/kernel-zigos-native-verification.elf"
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
  "$PRODUCTION_REQUIRED_MARKERS_PATH"
  "$VERIFICATION_REQUIRED_MARKERS_PATH"
)

PRODUCTION_FORBIDDEN_MARKERS=(
  "BOOT:ROLE:verification"
  "ZIGOS:RUNTIME_PROOF:PROCESS_ISOLATION:PASS"
  "ZIGOS:SERVICE_BOOT:IPC_CONNECT:ALL_OK"
  "ZIGOS:SERVICE_BOOT:SUPERVISOR:CRASH_RECORDED"
  "ZIGOS:SERVICE_BOOT:DRIVER:REHOST_OK"
  "ZIGOS:PLATFORM:ACTIVATION:ROLLBACK_OK"
  "ZIGOS:PLATFORM:HEALTH_CHECKS:BOOT_ROLLBACK"
  "ZIGOS:PERMISSION:REVIEW_PORT:READY"
  "ZIGOS:NOTES_DAILY:COMPLETE"
  "app.notes.daily"
  "userspace-notes-daily.elf"
  "zigos.system.transport-probe"
  "userspace-transport-probe.elf"
  "zigos.system.termination-probe"
  "userspace-termination-probe.elf"
  "zigos.system.service-client"
  "userspace-service-client.elf"
  "zigos.proof.mmu-isolation"
  "userspace-mmu-isolation-proof.elf"
)

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zigos-hardware-proof-check.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

sha256_file() {
  local file="${1:?file required}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  else
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  fi
}

require_regular_file() {
  local path="$1"
  local label="$2"
  if [ ! -f "$path" ] || [ ! -s "$path" ] || [ -L "$path" ]; then
    fail "$label must be a non-empty regular file, not a symlink: $path"
  fi
}

require_completed_text_file() {
  local path="$1"
  local label="$2"
  require_regular_file "$path" "$label"
  if grep -Eiq 'TODO|TBD|PLACEHOLDER|FILL_ME|<[^>]+>' "$path"; then
    fail "$label contains template placeholder text: $path"
  fi
  if grep -Eiq 'synthetic|simulated|mock|fake|fixture|test[-_ ]only|emulated' "$path"; then
    fail "$label contains non-real proof evidence text: $path"
  fi
}

extract_key() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); found = 1 } END { exit found ? 0 : 1 }' "$path"
}

key_line_count() {
  local path="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { count += 1 } END { print count + 0 }' "$path"
}

require_unique_key() {
  local path="$1"
  local label="$2"
  local key="$3"
  local count
  count="$(key_line_count "$path" "$key")"
  if [ "$count" -ne 1 ]; then
    fail "$label must contain exactly one '${key}=...' entry; found $count in $path"
  fi
}

require_key_value() {
  local path="$1"
  local label="$2"
  local key="$3"
  local expected="$4"
  local value
  require_unique_key "$path" "$label" "$key"
  value="$(extract_key "$path" "$key")"
  if [ "$value" != "$expected" ]; then
    fail "$label has '${key}=${value}', expected '${key}=${expected}' in $path"
  fi
}

require_key_present() {
  local path="$1"
  local label="$2"
  local key="$3"
  require_unique_key "$path" "$label" "$key"
  if [ -z "$(extract_key "$path" "$key")" ]; then
    fail "$label has an empty '${key}=...' entry in $path"
  fi
}

require_key_matches() {
  local path="$1"
  local label="$2"
  local key="$3"
  local pattern="$4"
  local value
  require_unique_key "$path" "$label" "$key"
  value="$(extract_key "$path" "$key")"
  if ! [[ "$value" =~ $pattern ]]; then
    fail "$label key '${key}=${value}' does not match its required format in $path"
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
    fail "$label key '${later_key}=${later_value}' is before '${earlier_key}=${earlier_value}'"
  fi
}

require_exact_marker_in_log() {
  local log_path="$1"
  local label="$2"
  local marker="$3"
  local count
  count="$(grep -Fxc -- "$marker" "$log_path" || true)"
  if [ "$count" -ne 1 ]; then
    fail "marker '$marker' must appear exactly once in $label; found $count"
  fi
}

marker_line_number() {
  local log_path="$1"
  local marker="$2"
  awk -v marker="$marker" '$0 == marker { print NR; exit }' "$log_path"
}

require_marker_before() {
  local log_path="$1"
  local label="$2"
  local earlier="$3"
  local later="$4"
  local earlier_line
  local later_line
  earlier_line="$(marker_line_number "$log_path" "$earlier")"
  later_line="$(marker_line_number "$log_path" "$later")"
  if [ -z "$earlier_line" ] || [ -z "$later_line" ] || [ "$earlier_line" -ge "$later_line" ]; then
    fail "marker '$earlier' must appear before '$later' in $label"
  fi
}

active_marker_lines() {
  awk '
    {
      line = $0
      sub(/\r$/, "", line)
      if (line ~ /^[[:space:]]*$/ || line ~ /^[[:space:]]*#/) next
      if (line ~ /^[[:space:]]/ || line ~ /[[:space:]]$/) exit 2
      print line
    }
  ' "$1"
}

require_marker_contract() {
  local marker_file="$1"
  local label="$2"
  require_completed_text_file "$marker_file" "$label"
  local active="$TMP_ROOT/${label// /-}.active"
  if ! active_marker_lines "$marker_file" > "$active"; then
    fail "$label contains a non-canonical active marker line"
  fi
  if [ ! -s "$active" ]; then
    fail "$label has no active marker lines"
  fi
  if [ -n "$(LC_ALL=C sort "$active" | uniq -d)" ]; then
    fail "$label contains duplicate active markers"
  fi
}

require_clean_log() {
  local log_path="$1"
  local label="$2"
  require_completed_text_file "$log_path" "$label"
  if grep -Eqi 'panic|KERNEL PANIC|System Halted|(^|:)FAIL($|:)|ZIGOS:.*:FAIL' "$log_path"; then
    fail "panic or failure text found in $label"
  fi
  if grep -Eqi 'QEMU|SeaBIOS|OVMF|TCG accelerator|KVM accelerator|Bochs|BHYVE|VMware|VirtualBox|Hypervisor' "$log_path"; then
    fail "emulator or virtual firmware text found in $label; proof must come from real hardware"
  fi
}

require_digest_manifest_format() {
  if ! awk '
    NF == 0 { next }
    length($1) == 64 && $1 ~ /^[0-9a-f]+$/ && NF == 2 && $2 ~ /^[A-Za-z0-9._\/-]+$/ && $2 !~ /^\// && $2 !~ /(^|\/)\.\.($|\/)/ { next }
    { malformed = 1 }
    END { exit malformed ? 1 : 0 }
  ' "$ARTIFACT_DIGESTS_PATH"; then
    fail "artifact digest file contains malformed or unsafe SHA-256 rows"
  fi
}

require_digest_for_path() {
  local artifact_path="$1"
  local count
  local recorded
  local actual_path="$ARTIFACT_ROOT/$artifact_path"
  count="$(awk -v path="$artifact_path" '$2 == path { count += 1 } END { print count + 0 }' "$ARTIFACT_DIGESTS_PATH")"
  if [ "$count" -ne 1 ]; then
    fail "artifact digest file must contain exactly one SHA-256 row for $artifact_path; found $count"
  fi
  require_regular_file "$actual_path" "artifact $artifact_path"
  recorded="$(awk -v path="$artifact_path" '$2 == path { print $1 }' "$ARTIFACT_DIGESTS_PATH")"
  if [ "$recorded" != "$(sha256_file "$actual_path")" ]; then
    fail "artifact digest mismatch for $artifact_path"
  fi
}

require_summary_counter() {
  local counter_name="$1"
  local expected="$2"
  local prefix="${TARGET_PREFIX}:${counter_name}:"
  local count
  local value
  count="$(awk -v prefix="$prefix" 'index($0, prefix) == 1 { count += 1 } END { print count + 0 }' "$VERIFICATION_LOG_PATH")"
  if [ "$count" -ne 1 ]; then
    fail "verification summary counter $counter_name must appear exactly once; found $count"
  fi
  value="$(awk -v prefix="$prefix" 'index($0, prefix) == 1 { print substr($0, length(prefix) + 1) }' "$VERIFICATION_LOG_PATH")"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -ne "$expected" ]; then
    fail "verification summary counter $counter_name=$value does not match $expected valid cycle entries"
  fi
}

validate_cycle_manifest() {
  require_completed_text_file "$CYCLE_MANIFEST_PATH" "cycle manifest"
  local parsed="$TMP_ROOT/cycles.parsed"
  if ! awk -F'|' '
    function rank(type) {
      if (type == "cold_boot") return 1
      if (type == "warm_reboot") return 2
      if (type == "storage_write_read") return 3
      if (type == "network_frame") return 4
      if (type == "suspend_resume") return 5
      if (type == "crash_recovery") return 6
      if (type == "crash_record_persistence") return 7
      if (type == "update_rollback") return 8
      return 0
    }
    NR == 1 {
      if ($0 != "format=zigos-nuc11tnki5-cycle-manifest-v1") bad = 1
      next
    }
    {
      if (NF != 4 || index($1, "cycle=") != 1) { bad = 1; next }
      type = substr($1, 7)
      index_text = $2
      digest = $3
      path = $4
      type_rank = rank(type)
      if (type_rank == 0 || type_rank < last_rank) bad = 1
      if (length(index_text) != 6 || index_text !~ /^[0-9]+$/) bad = 1
      if ((index_text + 0) != count[type] + 1) bad = 1
      if (length(digest) != 64 || digest !~ /^[0-9a-f]+$/) bad = 1
      expected_path = "cycles/" type "-" index_text ".log"
      if (path != expected_path) bad = 1
      if (seen_path[path] || seen_digest[digest]) bad = 1
      seen_path[path] = 1
      seen_digest[digest] = 1
      count[type] += 1
      last_rank = type_rank
      print type, index_text, digest, path
    }
    END {
      if (NR < 2) bad = 1
      exit bad ? 1 : 0
    }
  ' "$CYCLE_MANIFEST_PATH" > "$parsed"; then
    fail "cycle manifest is malformed, non-canonical, out of order, non-contiguous, or contains duplicate evidence"
  fi

  local listed_paths="$TMP_ROOT/cycle-paths.listed"
  local actual_paths="$TMP_ROOT/cycle-paths.actual"
  awk '{print $4}' "$parsed" | LC_ALL=C sort > "$listed_paths"
  (CDPATH='' cd -- "$BUNDLE_DIR" && find cycles -type f -name '*.log' -print | LC_ALL=C sort) > "$actual_paths"
  if ! cmp -s "$listed_paths" "$actual_paths"; then
    fail "cycles directory must contain exactly the logs named by cycle-manifest.txt"
  fi

  while read -r cycle_type cycle_index recorded_digest relative_path; do
    local cycle_path="$BUNDLE_DIR/$relative_path"
    require_completed_text_file "$cycle_path" "cycle log $relative_path"
    if [ "$(sha256_file "$cycle_path")" != "$recorded_digest" ]; then
      fail "cycle log digest mismatch for $relative_path"
    fi
    if ! awk -F= \
      -v nonce="$EXPECTED_NONCE" \
      -v target="$TARGET_ID" \
      -v device="$device_id" \
      -v type="$cycle_type" \
      -v cycle_index="$cycle_index" '
      BEGIN {
        expected["format"] = "zigos-nuc11tnki5-cycle-log-v1"
        expected["capture_nonce"] = nonce
        expected["target_id"] = target
        expected["device_id"] = device
        expected["cycle_type"] = type
        expected["cycle_index"] = cycle_index
        expected["result"] = "pass"
      }
      {
        upper = toupper($0)
        if (upper ~ /QEMU|SEABIOS|OVMF|VMWARE|VIRTUALBOX|HYPERVISOR/) bad = 1
        if ($1 in expected) {
          count[$1] += 1
          value[$1] = substr($0, length($1) + 2)
        }
      }
      END {
        for (key in expected) {
          if (count[key] != 1 || value[key] != expected[key]) bad = 1
        }
        exit bad ? 1 : 0
      }
    ' "$cycle_path"; then
      fail "cycle log has invalid, duplicate, mismatched, or emulator-sourced evidence: $relative_path"
    fi
  done < "$parsed"

  check_cycle_count() {
    local type="$1"
    local minimum="$2"
    local sidecar_key="$3"
    local serial_key="$4"
    local count
    local sidecar_value
    count="$(awk -v type="$type" '$1 == type { count += 1 } END { print count + 0 }' "$parsed")"
    if [ "$count" -lt "$minimum" ]; then
      fail "cycle manifest has $count valid unique $type entries; minimum is $minimum"
    fi
    require_unique_key "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "$sidecar_key"
    sidecar_value="$(extract_key "$POWER_CYCLE_NOTES_PATH" "$sidecar_key")"
    if ! [[ "$sidecar_value" =~ ^[0-9]+$ ]] || [ "$sidecar_value" -ne "$count" ]; then
      fail "power-cycle summary $sidecar_key=$sidecar_value does not match $count valid cycle entries"
    fi
    require_summary_counter "$serial_key" "$count"
  }

  check_cycle_count "cold_boot" "$MIN_COLD_BOOTS" "cold_boots" "COLD_BOOTS"
  check_cycle_count "warm_reboot" "$MIN_WARM_REBOOTS" "warm_reboots" "WARM_REBOOTS"
  check_cycle_count "storage_write_read" "$MIN_STORAGE_WRITE_READ_CYCLES" "storage_write_read_cycles" "STORAGE_WRITE_READ_CYCLES"
  check_cycle_count "network_frame" "$MIN_NETWORK_FRAME_CYCLES" "network_frame_cycles" "NETWORK_FRAME_CYCLES"
  check_cycle_count "suspend_resume" "$MIN_SUSPEND_RESUME_CYCLES" "suspend_resume_cycles" "SUSPEND_RESUME_CYCLES"
  check_cycle_count "crash_recovery" "$MIN_CRASH_RECOVERY_CYCLES" "crash_recovery_cycles" "CRASH_RECOVERY_CYCLES"
  check_cycle_count "crash_record_persistence" "$MIN_CRASH_RECORD_PERSISTENCE_CYCLES" "crash_record_persistence_cycles" "CRASH_RECORD_PERSISTENCE_CYCLES"
  check_cycle_count "update_rollback" "$MIN_UPDATE_ROLLBACK_CYCLES" "update_rollback_cycles" "UPDATE_ROLLBACK_CYCLES"
}

write_expected_statement() {
  local output="$1"
  cat > "$output" <<EOF
format=zigos-nuc11tnki5-capture-statement-v1
capture_nonce=$capture_nonce
target_id=$TARGET_ID
board_sku=$BOARD_SKU
device_id=$device_id
repo_vcs=jj
repo_change_id=$repo_change_id
repo_commit=$repo_commit
proof_manifest_sha256=$(sha256_file "$PROOF_MANIFEST_PATH")
device_identity_sha256=$(sha256_file "$DEVICE_IDENTITY_PATH")
production_serial_sha256=$(sha256_file "$PRODUCTION_LOG_PATH")
verification_serial_sha256=$(sha256_file "$VERIFICATION_LOG_PATH")
cycle_manifest_sha256=$(sha256_file "$CYCLE_MANIFEST_PATH")
production_iso_sha256=$(sha256_file "$ARTIFACT_ROOT/build/os.iso")
production_kernel_sha256=$(sha256_file "$ARTIFACT_ROOT/zig-out/bin/kernel-zigos-native.elf")
verification_iso_sha256=$(sha256_file "$ARTIFACT_ROOT/build/os-verification.iso")
verification_kernel_sha256=$(sha256_file "$ARTIFACT_ROOT/zig-out/bin/kernel-zigos-native-verification.elf")
production_marker_contract_sha256=$(sha256_file "$PRODUCTION_MARKER_FILE")
verification_marker_contract_sha256=$(sha256_file "$VERIFICATION_MARKER_FILE")
firmware_settings_sha256=$(sha256_file "$FIRMWARE_SETTINGS_PATH")
power_cycle_notes_sha256=$(sha256_file "$POWER_CYCLE_NOTES_PATH")
attestation_lifecycle_sha256=$(sha256_file "$ATTESTATION_LIFECYCLE_PATH")
artifact_digests_sha256=$(sha256_file "$ARTIFACT_DIGESTS_PATH")
operator_metadata_markers_sha256=$(sha256_file "$OPERATOR_METADATA_PATH")
production_quote_sha256=$(sha256_file "$PRODUCTION_QUOTE_PATH")
production_signature_sha256=$(sha256_file "$PRODUCTION_SIGNATURE_PATH")
verification_quote_sha256=$(sha256_file "$VERIFICATION_QUOTE_PATH")
verification_signature_sha256=$(sha256_file "$VERIFICATION_SIGNATURE_PATH")
EOF
}

actual_verifier_sha256="$(sha256_file "$TRUSTED_VERIFIER")"
if [ "$actual_verifier_sha256" != "$EXPECTED_VERIFIER_SHA256" ]; then
  fail "trusted verifier executable digest does not match the externally pinned SHA-256"
fi

require_completed_text_file "$PROOF_MANIFEST_PATH" "proof manifest"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "format" "zigos-nuc11tnki5-proof-v2"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "target_id" "$TARGET_ID"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "board_sku" "$BOARD_SKU"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "evidence_source" "real_hardware"
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "capture_nonce" '^[0-9a-f]{64}$'
capture_nonce="$(extract_key "$PROOF_MANIFEST_PATH" capture_nonce)"
if [ "$capture_nonce" != "$EXPECTED_NONCE" ]; then
  fail "proof manifest capture_nonce does not match the fresh externally issued nonce"
fi
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "device_id" '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'
device_id="$(extract_key "$PROOF_MANIFEST_PATH" device_id)"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "device_identity" "device-identity.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "production_serial_log" "production-serial.log"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "verification_serial_log" "verification-serial.log"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "cycle_manifest" "cycle-manifest.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "production_boot_medium" "build/os.iso"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "production_boot_kernel" "zig-out/bin/kernel-zigos-native.elf"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "production_required_markers" "$PRODUCTION_REQUIRED_MARKERS_PATH"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "verification_boot_medium" "build/os-verification.iso"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "verification_boot_kernel" "zig-out/bin/kernel-zigos-native-verification.elf"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "verification_required_markers" "$VERIFICATION_REQUIRED_MARKERS_PATH"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "firmware_settings" "firmware-settings.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "power_cycle_notes" "power-cycle-notes.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "attestation_lifecycle" "attestation-lifecycle.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "artifact_digests" "artifact-digests.sha256"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "operator_metadata_markers" "operator-metadata-markers.txt"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "production_quote" "production-attestation.quote"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "production_signature" "production-attestation.sig"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "verification_quote" "verification-attestation.quote"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "verification_signature" "verification-attestation.sig"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "capture_statement" "capture-statement.txt"
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "prepared_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "captured_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_timestamp_not_before "$PROOF_MANIFEST_PATH" "proof manifest" "prepared_at_utc" "captured_at_utc"
proof_prepared_at="$(extract_key "$PROOF_MANIFEST_PATH" prepared_at_utc)"
proof_captured_at="$(extract_key "$PROOF_MANIFEST_PATH" captured_at_utc)"
require_key_present "$PROOF_MANIFEST_PATH" "proof manifest" "operator"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_vcs" "jj"
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "repo_change_id" '^[a-z]{32}$'
require_key_matches "$PROOF_MANIFEST_PATH" "proof manifest" "repo_commit" '^[0-9a-f]{40}$'
repo_change_id="$(extract_key "$PROOF_MANIFEST_PATH" repo_change_id)"
repo_commit="$(extract_key "$PROOF_MANIFEST_PATH" repo_commit)"
expected_repo_change_id="${ZIGOS_EXPECTED_REPO_CHANGE_ID:-$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"' 2>/dev/null || true)}"
expected_repo_commit="${ZIGOS_EXPECTED_REPO_COMMIT:-$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"' 2>/dev/null || true)}"
if [ -z "$expected_repo_change_id" ] || [ -z "$expected_repo_commit" ]; then
  fail "current Jujutsu change and commit IDs could not be resolved"
fi
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_change_id" "$expected_repo_change_id"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_commit" "$expected_repo_commit"
require_key_value "$PROOF_MANIFEST_PATH" "proof manifest" "repo_dirty_files" "0"

require_completed_text_file "$DEVICE_IDENTITY_PATH" "device identity"
require_key_value "$DEVICE_IDENTITY_PATH" "device identity" "format" "zigos-nuc11tnki5-device-identity-v1"
require_key_value "$DEVICE_IDENTITY_PATH" "device identity" "target_id" "$TARGET_ID"
require_key_value "$DEVICE_IDENTITY_PATH" "device identity" "board_sku" "$BOARD_SKU"
require_key_value "$DEVICE_IDENTITY_PATH" "device identity" "device_id" "$device_id"
require_key_matches "$DEVICE_IDENTITY_PATH" "device identity" "smbios_system_uuid" '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
require_key_present "$DEVICE_IDENTITY_PATH" "device identity" "baseboard_serial"
require_key_matches "$DEVICE_IDENTITY_PATH" "device identity" "tpm_ek_public_sha256" '^[0-9a-f]{64}$'

for path_label in \
  "$PRODUCTION_LOG_PATH:production serial log" \
  "$VERIFICATION_LOG_PATH:verification serial log" \
  "$CYCLE_MANIFEST_PATH:cycle manifest" \
  "$FIRMWARE_SETTINGS_PATH:firmware settings" \
  "$POWER_CYCLE_NOTES_PATH:power-cycle notes" \
  "$ATTESTATION_LIFECYCLE_PATH:attestation lifecycle" \
  "$ARTIFACT_DIGESTS_PATH:artifact digests" \
  "$OPERATOR_METADATA_PATH:operator metadata markers" \
  "$PRODUCTION_QUOTE_PATH:production quote" \
  "$PRODUCTION_SIGNATURE_PATH:production signature" \
  "$VERIFICATION_QUOTE_PATH:verification quote" \
  "$VERIFICATION_SIGNATURE_PATH:verification signature" \
  "$CAPTURE_STATEMENT_PATH:capture statement" \
  "$ARTIFACT_ROOT/build/os.iso:production ISO" \
  "$ARTIFACT_ROOT/zig-out/bin/kernel-zigos-native.elf:production kernel" \
  "$ARTIFACT_ROOT/build/os-verification.iso:verification ISO" \
  "$ARTIFACT_ROOT/zig-out/bin/kernel-zigos-native-verification.elf:verification kernel"; do
  bound_path="${path_label%%:*}"
  bound_label="${path_label#*:}"
  require_regular_file "$bound_path" "$bound_label"
done

require_completed_text_file "$CAPTURE_STATEMENT_PATH" "capture statement"
expected_statement="$TMP_ROOT/capture-statement.expected"
write_expected_statement "$expected_statement"
if ! cmp -s "$expected_statement" "$CAPTURE_STATEMENT_PATH"; then
  fail "capture statement is not the canonical statement recomputed from current logs, cycle manifest, artifacts, contracts, quotes, signatures, and sidecars"
fi
statement_sha256="$(sha256_file "$CAPTURE_STATEMENT_PATH")"

require_marker_contract "$PRODUCTION_MARKER_FILE" "production marker contract"
require_marker_contract "$VERIFICATION_MARKER_FILE" "verification marker contract"
require_clean_log "$PRODUCTION_LOG_PATH" "production single-boot serial log"
require_clean_log "$VERIFICATION_LOG_PATH" "verification single-boot serial log"

production_role_count="$(grep -Ec '^BOOT:ROLE:' "$PRODUCTION_LOG_PATH" || true)"
verification_role_count="$(grep -Ec '^BOOT:ROLE:' "$VERIFICATION_LOG_PATH" || true)"
[ "$production_role_count" -eq 1 ] || fail "production single-boot log must contain exactly one BOOT:ROLE marker"
[ "$verification_role_count" -eq 1 ] || fail "verification single-boot log must contain exactly one BOOT:ROLE marker"
require_exact_marker_in_log "$PRODUCTION_LOG_PATH" "production single-boot log" "BOOT:ROLE:production"
require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "BOOT:ROLE:verification"
require_exact_marker_in_log "$PRODUCTION_LOG_PATH" "production single-boot log" "ZIGOS:NATIVE:READY"
require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "ZIGOS:NATIVE:READY"

for forbidden_marker in "${PRODUCTION_FORBIDDEN_MARKERS[@]}"; do
  if grep -Fq -- "$forbidden_marker" "$PRODUCTION_LOG_PATH"; then
    fail "production single-boot log contains verification-only evidence '$forbidden_marker'"
  fi
done
if grep -Eq "^${TARGET_PREFIX}:(COLD_BOOTS|WARM_REBOOTS|STORAGE_WRITE_READ_CYCLES|NETWORK_FRAME_CYCLES|SUSPEND_RESUME_CYCLES|CRASH_RECOVERY_CYCLES|CRASH_RECORD_PERSISTENCE_CYCLES|UPDATE_ROLLBACK_CYCLES):" "$PRODUCTION_LOG_PATH"; then
  fail "production single-boot log contains verification cycle summaries"
fi

production_active="$TMP_ROOT/production-markers.active"
verification_active="$TMP_ROOT/verification-markers.active"
active_marker_lines "$PRODUCTION_MARKER_FILE" > "$production_active"
active_marker_lines "$VERIFICATION_MARKER_FILE" > "$verification_active"
while IFS= read -r marker; do
  if [ "$marker" = "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false" ]; then
    continue
  fi
  require_exact_marker_in_log "$PRODUCTION_LOG_PATH" "production single-boot log" "$marker"
done < "$production_active"
while IFS= read -r marker; do
  require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "$marker"
done < "$verification_active"

checkpoint_count="$(grep -Ec '^ZIGOS:STORAGE:CHECKPOINT:FINAL([[:space:]]|$)' "$PRODUCTION_LOG_PATH" || true)"
[ "$checkpoint_count" -eq 1 ] || fail "production single-boot log must contain exactly one final checkpoint"
checkpoint_line="$(grep -E '^ZIGOS:STORAGE:CHECKPOINT:FINAL([[:space:]]|$)' "$PRODUCTION_LOG_PATH")"
if ! [[ "$checkpoint_line" =~ ^ZIGOS:STORAGE:CHECKPOINT:FINAL[[:space:]]enabled=true[[:space:]]dirty=false[[:space:]]generation=[0-9]+[[:space:]]error=none$ ]]; then
  fail "final checkpoint must be structured as enabled=true dirty=false generation=<n> error=none"
fi

require_marker_before "$PRODUCTION_LOG_PATH" "production single-boot log" "BOOT:START" "BOOT:PROFILE:zigos_native"
require_marker_before "$PRODUCTION_LOG_PATH" "production single-boot log" "BOOT:PROFILE:zigos_native" "BOOT:ROLE:production"
require_marker_before "$PRODUCTION_LOG_PATH" "production single-boot log" "BOOT:ROLE:production" "BOOT:CORE_READY"
require_marker_before "$PRODUCTION_LOG_PATH" "production single-boot log" "ZIGOS:PLATFORM:MEASURED_BOOT:VERIFIED_ROOT" "$checkpoint_line"
require_marker_before "$PRODUCTION_LOG_PATH" "production single-boot log" "$checkpoint_line" "ZIGOS:TASK:SESSION_READY"
require_marker_before "$PRODUCTION_LOG_PATH" "production single-boot log" "ZIGOS:TASK:SESSION_READY" "ZIGOS:NATIVE:READY"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "BOOT:ROLE:verification" "ZIGOS:NATIVE:READY"

require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:EVIDENCE_SOURCE:REAL_HARDWARE"
require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:BOARD_SKU:NUC11TNKi5"
require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:PROOF_MANIFEST:RECORDED"
require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:FIRMWARE_SETTINGS:RECORDED"
require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:POWER_CYCLE_NOTES:RECORDED"
require_exact_marker_in_log "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:ARTIFACT_DIGESTS:RECORDED"

require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:SMBIOS_SKU:OBSERVED" "${TARGET_PREFIX}:UEFI_BOOT:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:MULTIBOOT_MEMORY_MAP:OBSERVED" "${TARGET_PREFIX}:UEFI_BOOT:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:APIC_TIMER_INTERRUPT:OBSERVED" "${TARGET_PREFIX}:APIC_TIMER:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:FRAMEBUFFER_GOP_SCANOUT:OBSERVED" "${TARGET_PREFIX}:FRAMEBUFFER_GOP:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:XHCI_BOOT_KEYBOARD_REPORT:OBSERVED" "${TARGET_PREFIX}:USB_INPUT_XHCI:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:NVME_WRITE_READ_COMPLETION:OBSERVED" "${TARGET_PREFIX}:NVME_BLOCK:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:I225_LM_FRAME_INTERRUPT:OBSERVED" "${TARGET_PREFIX}:NETWORK_I225_LM:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:SUSPEND_RESUME_POWER:OBSERVED" "${TARGET_PREFIX}:SUSPEND_RESUME:PASS"
require_marker_before "$VERIFICATION_LOG_PATH" "verification single-boot log" "${TARGET_PREFIX}:CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED" "${TARGET_PREFIX}:CRASH_RECOVERY:PASS"

require_completed_text_file "$FIRMWARE_SETTINGS_PATH" "firmware settings"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "target_id" "$TARGET_ID"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "board_sku" "$BOARD_SKU"
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "boot_mode" "UEFI"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "bios_version"
require_key_matches "$FIRMWARE_SETTINGS_PATH" "firmware settings" "secure_boot" '^(enabled|disabled|disabled-for-local-proof-media)$'
require_key_value "$FIRMWARE_SETTINGS_PATH" "firmware settings" "storage_mode" "nvme"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "wake_suspend"
require_key_present "$FIRMWARE_SETTINGS_PATH" "firmware settings" "changed_options"

require_completed_text_file "$POWER_CYCLE_NOTES_PATH" "power-cycle notes"
require_key_value "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "target_id" "$TARGET_ID"
require_key_present "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "operator"
require_key_present "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "notes"
require_key_matches "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "started_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_matches "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "completed_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_timestamp_not_before "$POWER_CYCLE_NOTES_PATH" "power-cycle notes" "started_at_utc" "completed_at_utc"
power_started_at="$(extract_key "$POWER_CYCLE_NOTES_PATH" started_at_utc)"
power_completed_at="$(extract_key "$POWER_CYCLE_NOTES_PATH" completed_at_utc)"
if [[ "$power_started_at" < "$proof_prepared_at" ]] || [[ "$power_completed_at" > "$proof_captured_at" ]]; then
  fail "power-cycle notes timestamps must stay inside the proof capture window"
fi

require_completed_text_file "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "target_id" "$TARGET_ID"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "evidence_source" "real_hardware"
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "operator"
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "captured_at_utc" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "provider"
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "root_key_id"
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "initial_generation" '^[1-9][0-9]*$'
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "active_generation" '^[1-9][0-9]*$'
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "revoked_generation_count" '^[1-9][0-9]*$'
initial_generation="$(extract_key "$ATTESTATION_LIFECYCLE_PATH" initial_generation)"
active_generation="$(extract_key "$ATTESTATION_LIFECYCLE_PATH" active_generation)"
[ "$active_generation" -gt "$initial_generation" ] || fail "attestation active generation must exceed initial generation"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "stale_generation_rejected" "true"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "revoked_generation_rejected" "true"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "verifier_rejected_stale_attestation" "true"
require_key_value "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "verifier_metadata_digest_bound" "true"
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "verifier_metadata_digest" '^[0-9a-f]{64}$'
require_key_matches "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "attestation_request_digest" '^[0-9a-f]{64}$'
require_key_present "$ATTESTATION_LIFECYCLE_PATH" "attestation lifecycle" "notes"
attestation_captured_at="$(extract_key "$ATTESTATION_LIFECYCLE_PATH" captured_at_utc)"
if [[ "$attestation_captured_at" < "$proof_prepared_at" ]] || [[ "$attestation_captured_at" > "$proof_captured_at" ]]; then
  fail "attestation lifecycle timestamp must stay inside the proof capture window"
fi

require_completed_text_file "$OPERATOR_METADATA_PATH" "operator metadata markers"
for marker in \
  "${TARGET_PREFIX}:EVIDENCE_SOURCE:REAL_HARDWARE" \
  "${TARGET_PREFIX}:BOARD_SKU:NUC11TNKi5" \
  "${TARGET_PREFIX}:PROOF_MANIFEST:RECORDED" \
  "${TARGET_PREFIX}:FIRMWARE_SETTINGS:RECORDED" \
  "${TARGET_PREFIX}:POWER_CYCLE_NOTES:RECORDED" \
  "${TARGET_PREFIX}:ARTIFACT_DIGESTS:RECORDED"; do
  require_exact_marker_in_log "$OPERATOR_METADATA_PATH" "operator metadata markers" "$marker"
done

validate_cycle_manifest

require_completed_text_file "$ARTIFACT_DIGESTS_PATH" "artifact digests"
require_digest_manifest_format
for artifact_path in "${REQUIRED_ARTIFACT_DIGEST_PATHS[@]}"; do
  require_digest_for_path "$artifact_path"
done
if [ "$(sha256_file "$ARTIFACT_ROOT/$PRODUCTION_REQUIRED_MARKERS_PATH")" != "$(sha256_file "$PRODUCTION_MARKER_FILE")" ]; then
  fail "production marker contract under artifact root differs from the actively checked contract"
fi
if [ "$(sha256_file "$ARTIFACT_ROOT/$VERIFICATION_REQUIRED_MARKERS_PATH")" != "$(sha256_file "$VERIFICATION_MARKER_FILE")" ]; then
  fail "verification marker contract under artifact root differs from the actively checked contract"
fi

for path_label in \
  "$PRODUCTION_QUOTE_PATH:production quote" \
  "$PRODUCTION_SIGNATURE_PATH:production signature" \
  "$VERIFICATION_QUOTE_PATH:verification quote" \
  "$VERIFICATION_SIGNATURE_PATH:verification signature"; do
  quote_path="${path_label%%:*}"
  quote_label="${path_label#*:}"
  require_regular_file "$quote_path" "$quote_label"
done
if [ "$(sha256_file "$PRODUCTION_QUOTE_PATH")" = "$(sha256_file "$VERIFICATION_QUOTE_PATH")" ]; then
  fail "production and verification quotes must be role-specific and distinct"
fi
if [ "$(sha256_file "$PRODUCTION_SIGNATURE_PATH")" = "$(sha256_file "$VERIFICATION_SIGNATURE_PATH")" ]; then
  fail "production and verification signatures must be role-specific and distinct"
fi

verifier_response="$TMP_ROOT/verifier.response"
verifier_stderr="$TMP_ROOT/verifier.stderr"
if ! "$TRUSTED_VERIFIER" \
  --statement "$CAPTURE_STATEMENT_PATH" \
  --statement-sha256 "$statement_sha256" \
  --nonce "$capture_nonce" \
  --target-id "$TARGET_ID" \
  --device-id "$device_id" \
  --production-quote "$PRODUCTION_QUOTE_PATH" \
  --production-signature "$PRODUCTION_SIGNATURE_PATH" \
  --verification-quote "$VERIFICATION_QUOTE_PATH" \
  --verification-signature "$VERIFICATION_SIGNATURE_PATH" \
  > "$verifier_response" 2> "$verifier_stderr"; then
  fail "external trusted verifier rejected the capture statement or role-specific quote/signature inputs"
fi

expected_response="$TMP_ROOT/verifier.response.expected"
cat > "$expected_response" <<EOF
format=zigos-trusted-hardware-verifier-response-v1
result=verified
assertion=signed-response
statement_sha256=$statement_sha256
nonce=$capture_nonce
target_id=$TARGET_ID
device_id=$device_id
production_role=verified
verification_role=verified
EOF
if ! cmp -s "$expected_response" "$verifier_response"; then
  fail "external trusted verifier did not return the exact signed-response assertion for this statement digest and nonce"
fi

printf 'NUC11TNKi5 authenticated hardware proof bundle OK: %s\n' "$BUNDLE_DIR"
