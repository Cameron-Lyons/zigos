#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
CHECKER="$ROOT_DIR/scripts/check-nuc11tnki5-hardware-proof.sh"
MARKER_FILE="$ROOT_DIR/spec/hardware/nuc11tnki5-required-markers.txt"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zigos-nuc-proof-checker.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

write_manifest() {
  local dir="$1"
  cat > "$dir/proof-manifest.txt" <<'EOF'
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
evidence_source=real_hardware
serial_log=serial.log
firmware_settings=firmware-settings.txt
power_cycle_notes=power-cycle-notes.txt
artifact_digests=artifact-digests.sha256
required_markers=spec/hardware/nuc11tnki5-required-markers.txt
prepared_at_utc=2026-06-10T00:00:00Z
captured_at_utc=2026-06-10T01:00:00Z
operator=checker-self-test
repo_commit=0000000000000000000000000000000000000000
repo_dirty_files=0
EOF
}

write_firmware_settings() {
  local dir="$1"
  cat > "$dir/firmware-settings.txt" <<'EOF'
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
bios_version=TNTGL357.0071.2025.0123.1200
boot_mode=UEFI
secure_boot=disabled-for-local-proof-media
storage_mode=nvme
wake_suspend=S3 wake by keyboard and power button enabled
changed_options=boot order set to USB first
EOF
}

write_power_notes() {
  local dir="$1"
  cat > "$dir/power-cycle-notes.txt" <<'EOF'
target_id=intel-nuc11tnki5
operator=checker-self-test
started_at_utc=2026-06-10T00:00:00Z
completed_at_utc=2026-06-10T01:00:00Z
cold_boots=10
warm_reboots=10
storage_write_read_cycles=100
network_frame_cycles=100
suspend_resume_cycles=20
crash_recovery_cycles=10
notes=synthetic checker fixture only
EOF
}

write_artifact_digests() {
  local dir="$1"
  cat > "$dir/artifact-digests.sha256" <<'EOF'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  build/os.iso
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  zig-out/bin/kernel-zigos-native.elf
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  zig-out/bin/userspace-session-manager.elf
dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  zig-out/bin/userspace-policy-mediation.elf
eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  zig-out/bin/userspace-permission-review.elf
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  zig-out/bin/userspace-network-stack.elf
1111111111111111111111111111111111111111111111111111111111111111  zig-out/bin/userspace-storage-driver.elf
2222222222222222222222222222222222222222222222222222222222222222  zig-out/bin/userspace-sync-service.elf
3333333333333333333333333333333333333333333333333333333333333333  spec/production_readiness.json
4444444444444444444444444444444444444444444444444444444444444444  spec/hardware/nuc11tnki5-required-markers.txt
EOF
}

write_serial_log() {
  local dir="$1"
  {
    printf '%s:EVIDENCE_SOURCE:REAL_HARDWARE\n' "$TARGET_PREFIX"
    printf '%s:BOARD_SKU:NUC11TNKi5\n' "$TARGET_PREFIX"
    printf '%s:PROOF_MANIFEST:RECORDED\n' "$TARGET_PREFIX"
    printf '%s:FIRMWARE_SETTINGS:RECORDED\n' "$TARGET_PREFIX"
    printf '%s:POWER_CYCLE_NOTES:RECORDED\n' "$TARGET_PREFIX"
    printf '%s:ARTIFACT_DIGESTS:RECORDED\n' "$TARGET_PREFIX"
    grep -Ev '^[[:space:]]*(#|$)' "$MARKER_FILE"
    printf '%s:COLD_BOOTS:10\n' "$TARGET_PREFIX"
    printf '%s:WARM_REBOOTS:10\n' "$TARGET_PREFIX"
    printf '%s:STORAGE_WRITE_READ_CYCLES:100\n' "$TARGET_PREFIX"
    printf '%s:NETWORK_FRAME_CYCLES:100\n' "$TARGET_PREFIX"
    printf '%s:SUSPEND_RESUME_CYCLES:20\n' "$TARGET_PREFIX"
    printf '%s:CRASH_RECOVERY_CYCLES:10\n' "$TARGET_PREFIX"
  } > "$dir/serial.log"
}

make_valid_bundle() {
  local dir="$1"
  mkdir -p "$dir"
  write_manifest "$dir"
  write_firmware_settings "$dir"
  write_power_notes "$dir"
  write_artifact_digests "$dir"
  write_serial_log "$dir"
}

expect_pass() {
  local dir="$1"
  "$CHECKER" "$dir" >/dev/null
}

expect_fail() {
  local dir="$1"
  if "$CHECKER" "$dir" >/dev/null 2>"$dir/checker.err"; then
    printf 'expected checker failure for %s\n' "$dir" >&2
    exit 1
  fi
}

valid_bundle="$TMP_ROOT/valid"
make_valid_bundle "$valid_bundle"
expect_pass "$valid_bundle"

qemu_bundle="$TMP_ROOT/qemu"
make_valid_bundle "$qemu_bundle"
printf 'OVMF\n' >> "$qemu_bundle/serial.log"
expect_fail "$qemu_bundle"

placeholder_bundle="$TMP_ROOT/placeholder"
make_valid_bundle "$placeholder_bundle"
printf 'operator=TODO-fill\n' >> "$placeholder_bundle/proof-manifest.txt"
expect_fail "$placeholder_bundle"

low_counter_bundle="$TMP_ROOT/low-counter"
make_valid_bundle "$low_counter_bundle"
sed -i.bak 's/suspend_resume_cycles=20/suspend_resume_cycles=19/' "$low_counter_bundle/power-cycle-notes.txt"
expect_fail "$low_counter_bundle"

missing_digest_bundle="$TMP_ROOT/missing-digest"
make_valid_bundle "$missing_digest_bundle"
grep -v 'zig-out/bin/userspace-storage-driver.elf' "$missing_digest_bundle/artifact-digests.sha256" > "$missing_digest_bundle/artifact-digests.next"
mv "$missing_digest_bundle/artifact-digests.next" "$missing_digest_bundle/artifact-digests.sha256"
expect_fail "$missing_digest_bundle"

printf 'NUC11TNKi5 hardware proof checker self-test OK\n'
