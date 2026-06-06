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

require_exact_marker() {
  local marker="$1"
  if ! grep -Fxq "$marker" "$LOG_PATH"; then
    fail "missing marker '$marker' in $LOG_PATH"
  fi
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

require_non_empty_file "$LOG_PATH" "serial log"

if [ ! -f "$MARKER_FILE" ]; then
  fail "marker file is missing: $MARKER_FILE"
fi

if grep -Eqi 'panic|KERNEL PANIC|System Halted|(^|:)FAIL($|:)|ZIGOS:.*:FAIL' "$LOG_PATH"; then
  fail "panic or failure text found in $LOG_PATH"
fi

if grep -Eqi 'QEMU|SeaBIOS|OVMF|TCG accelerator|KVM accelerator|Bochs|BHYVE|VMware|VirtualBox|Hypervisor' "$LOG_PATH"; then
  fail "emulator or virtual firmware text found in $LOG_PATH; NUC11TNKi5 proof must come from real hardware"
fi

require_exact_marker "${TARGET_PREFIX}:EVIDENCE_SOURCE:REAL_HARDWARE"
require_exact_marker "${TARGET_PREFIX}:BOARD_SKU:NUC11TNKi5"
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

require_non_empty_file "$FIRMWARE_SETTINGS_PATH" "firmware settings"
require_non_empty_file "$POWER_CYCLE_NOTES_PATH" "power-cycle notes"
require_non_empty_file "$ARTIFACT_DIGESTS_PATH" "artifact digests"

if ! awk '
  length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && NF >= 2 { found = 1 }
  END { exit found ? 0 : 1 }
' "$ARTIFACT_DIGESTS_PATH"; then
  fail "artifact digest file must include at least one sha256 digest line: $ARTIFACT_DIGESTS_PATH"
fi

printf 'NUC11TNKi5 hardware proof bundle OK: %s\n' "$BUNDLE_DIR"
