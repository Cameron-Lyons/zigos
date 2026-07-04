#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
CHECKER="$ROOT_DIR/scripts/check-nuc11tnki5-hardware-proof.sh"
MARKER_FILE="$ROOT_DIR/spec/hardware/nuc11tnki5-required-markers.txt"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zigos-nuc-proof-checker.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT
ARTIFACT_ROOT="$TMP_ROOT/artifacts"

REQUIRED_ARTIFACTS=(
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

sha256_file() {
  local file="${1:?file required}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

write_required_artifacts() {
  local artifact
  for artifact in "${REQUIRED_ARTIFACTS[@]}"; do
    mkdir -p "$ARTIFACT_ROOT/$(dirname -- "$artifact")"
    printf 'checker fixture artifact: %s\n' "$artifact" > "$ARTIFACT_ROOT/$artifact"
  done
}

write_manifest() {
  local dir="$1"
  local repo_commit
  local repo_change_id
  if command -v jj >/dev/null 2>&1 &&
    repo_commit="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"' 2>/dev/null)" &&
    repo_change_id="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"' 2>/dev/null)" &&
    [ -n "$repo_commit" ] &&
    [ -n "$repo_change_id" ]; then
    :
  else
    repo_commit="1111111111111111111111111111111111111111"
    repo_change_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  fi
  export ZIGOS_EXPECTED_REPO_COMMIT="$repo_commit"
  export ZIGOS_EXPECTED_REPO_CHANGE_ID="$repo_change_id"
  cat > "$dir/proof-manifest.txt" <<EOF
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
evidence_source=real_hardware
serial_log=serial.log
firmware_settings=firmware-settings.txt
power_cycle_notes=power-cycle-notes.txt
attestation_lifecycle=attestation-lifecycle.txt
artifact_digests=artifact-digests.sha256
required_markers=spec/hardware/nuc11tnki5-required-markers.txt
prepared_at_utc=2026-06-10T00:00:00Z
captured_at_utc=2026-06-10T01:00:00Z
operator=checker-self-test
repo_vcs=jj
repo_change_id=$repo_change_id
repo_commit=$repo_commit
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
crash_record_persistence_cycles=10
update_rollback_cycles=10
notes=operator observed all required NUC11TNKi5 power cycles and reboot-persistence checks
EOF
}

write_attestation_lifecycle() {
  local dir="$1"
  cat > "$dir/attestation-lifecycle.txt" <<'EOF'
target_id=intel-nuc11tnki5
evidence_source=real_hardware
operator=checker-self-test
captured_at_utc=2026-06-10T00:30:00Z
provider=checker-tpm-root
root_key_id=checker-root-key
initial_generation=7
active_generation=9
revoked_generation_count=1
stale_generation_rejected=true
revoked_generation_rejected=true
verifier_rejected_stale_attestation=true
verifier_metadata_digest_bound=true
verifier_metadata_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
attestation_request_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
notes=operator captured root lifecycle rejection and metadata binding checks
EOF
}

write_artifact_digests() {
  local dir="$1"
  local artifact
  : > "$dir/artifact-digests.sha256"
  for artifact in "${REQUIRED_ARTIFACTS[@]}"; do
    printf '%s  %s\n' "$(sha256_file "$ARTIFACT_ROOT/$artifact")" "$artifact" >> "$dir/artifact-digests.sha256"
  done
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
	    grep -Ev '^[[:space:]]*(#|$)' "$MARKER_FILE" | grep -F "$TARGET_PREFIX:" | grep -F ':OBSERVED'
	    grep -Ev '^[[:space:]]*(#|$)' "$MARKER_FILE" | grep -F "$TARGET_PREFIX:" | grep -F ':PASS'
	    grep -Ev '^[[:space:]]*(#|$)' "$MARKER_FILE" | grep -Fv "$TARGET_PREFIX:"
	    printf '%s:COLD_BOOTS:10\n' "$TARGET_PREFIX"
    printf '%s:WARM_REBOOTS:10\n' "$TARGET_PREFIX"
    printf '%s:STORAGE_WRITE_READ_CYCLES:100\n' "$TARGET_PREFIX"
    printf '%s:NETWORK_FRAME_CYCLES:100\n' "$TARGET_PREFIX"
    printf '%s:SUSPEND_RESUME_CYCLES:20\n' "$TARGET_PREFIX"
    printf '%s:CRASH_RECOVERY_CYCLES:10\n' "$TARGET_PREFIX"
    printf '%s:CRASH_RECORD_PERSISTENCE_CYCLES:10\n' "$TARGET_PREFIX"
    printf '%s:UPDATE_ROLLBACK_CYCLES:10\n' "$TARGET_PREFIX"
  } > "$dir/serial.log"
}

make_valid_bundle() {
  local dir="$1"
  mkdir -p "$dir"
  write_manifest "$dir"
  write_firmware_settings "$dir"
  write_power_notes "$dir"
  write_attestation_lifecycle "$dir"
  write_artifact_digests "$dir"
  write_serial_log "$dir"
}

expect_pass() {
  local dir="$1"
  ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" "$CHECKER" "$dir" >/dev/null
}

expect_fail() {
  local dir="$1"
  if ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" "$CHECKER" "$dir" >/dev/null 2>"$dir/checker.err"; then
    printf 'expected checker failure for %s\n' "$dir" >&2
    exit 1
  fi
}

expect_fail_with_marker_file() {
  local dir="$1"
  local marker_file="$2"
  if ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" "$CHECKER" "$dir" "$marker_file" >/dev/null 2>"$dir/checker.err"; then
    printf 'expected checker failure for %s with marker file %s\n' "$dir" "$marker_file" >&2
    exit 1
  fi
}

expect_fail_with_proof_path() {
  local proof_path="$1"
  local err_path="$2"
  if ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" "$CHECKER" "$proof_path" >/dev/null 2>"$err_path"; then
    printf 'expected checker failure for proof path %s\n' "$proof_path" >&2
    exit 1
  fi
}

expect_fail_with_env_override() {
  local dir="$1"
  local env_name="$2"
  local env_value="$3"
  if env "$env_name=$env_value" ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" "$CHECKER" "$dir" >/dev/null 2>"$dir/checker.err"; then
    printf 'expected checker failure for %s with %s=%s\n' "$dir" "$env_name" "$env_value" >&2
    exit 1
  fi
}

write_required_artifacts

valid_bundle="$TMP_ROOT/valid"
make_valid_bundle "$valid_bundle"
expect_pass "$valid_bundle"

alternate_marker_bundle="$TMP_ROOT/alternate-marker-file"
alternate_marker_file="$TMP_ROOT/alternate-required-markers.txt"
make_valid_bundle "$alternate_marker_bundle"
cp "$MARKER_FILE" "$alternate_marker_file"
expect_fail_with_marker_file "$alternate_marker_bundle" "$alternate_marker_file"

alternate_serial_bundle="$TMP_ROOT/alternate-serial-log"
make_valid_bundle "$alternate_serial_bundle"
cp "$alternate_serial_bundle/serial.log" "$alternate_serial_bundle/alternate-serial.log"
expect_fail_with_proof_path "$alternate_serial_bundle/alternate-serial.log" "$alternate_serial_bundle/checker.err"

sidecar_override_bundle="$TMP_ROOT/sidecar-override"
sidecar_override_dir="$TMP_ROOT/sidecar-overrides"
make_valid_bundle "$sidecar_override_bundle"
mkdir -p "$sidecar_override_dir"
cp "$sidecar_override_bundle/proof-manifest.txt" "$sidecar_override_dir/proof-manifest.txt"
cp "$sidecar_override_bundle/firmware-settings.txt" "$sidecar_override_dir/firmware-settings.txt"
cp "$sidecar_override_bundle/power-cycle-notes.txt" "$sidecar_override_dir/power-cycle-notes.txt"
cp "$sidecar_override_bundle/attestation-lifecycle.txt" "$sidecar_override_dir/attestation-lifecycle.txt"
cp "$sidecar_override_bundle/artifact-digests.sha256" "$sidecar_override_dir/artifact-digests.sha256"
expect_fail_with_env_override "$sidecar_override_bundle" "PROOF_MANIFEST_PATH" "$sidecar_override_dir/proof-manifest.txt"
expect_fail_with_env_override "$sidecar_override_bundle" "FIRMWARE_SETTINGS_PATH" "$sidecar_override_dir/firmware-settings.txt"
expect_fail_with_env_override "$sidecar_override_bundle" "POWER_CYCLE_NOTES_PATH" "$sidecar_override_dir/power-cycle-notes.txt"
expect_fail_with_env_override "$sidecar_override_bundle" "ATTESTATION_LIFECYCLE_PATH" "$sidecar_override_dir/attestation-lifecycle.txt"
expect_fail_with_env_override "$sidecar_override_bundle" "ARTIFACT_DIGESTS_PATH" "$sidecar_override_dir/artifact-digests.sha256"

qemu_bundle="$TMP_ROOT/qemu"
make_valid_bundle "$qemu_bundle"
printf 'OVMF\n' >> "$qemu_bundle/serial.log"
expect_fail "$qemu_bundle"

placeholder_bundle="$TMP_ROOT/placeholder"
make_valid_bundle "$placeholder_bundle"
printf 'operator=TODO-fill\n' >> "$placeholder_bundle/proof-manifest.txt"
expect_fail "$placeholder_bundle"

synthetic_sidecar_bundle="$TMP_ROOT/synthetic-sidecar"
make_valid_bundle "$synthetic_sidecar_bundle"
printf 'notes=synthetic checker fixture only\n' >> "$synthetic_sidecar_bundle/power-cycle-notes.txt"
expect_fail "$synthetic_sidecar_bundle"

low_counter_bundle="$TMP_ROOT/low-counter"
make_valid_bundle "$low_counter_bundle"
sed -i.bak 's/suspend_resume_cycles=20/suspend_resume_cycles=19/' "$low_counter_bundle/power-cycle-notes.txt"
expect_fail "$low_counter_bundle"

counter_mismatch_bundle="$TMP_ROOT/counter-mismatch"
make_valid_bundle "$counter_mismatch_bundle"
sed -i.bak 's/^cold_boots=10/cold_boots=11/' "$counter_mismatch_bundle/power-cycle-notes.txt"
expect_fail "$counter_mismatch_bundle"

duplicate_marker_bundle="$TMP_ROOT/duplicate-marker"
make_valid_bundle "$duplicate_marker_bundle"
printf '%s:EVIDENCE_SOURCE:REAL_HARDWARE\n' "$TARGET_PREFIX" >> "$duplicate_marker_bundle/serial.log"
expect_fail "$duplicate_marker_bundle"

missing_hardware_fact_bundle="$TMP_ROOT/missing-hardware-fact"
make_valid_bundle "$missing_hardware_fact_bundle"
grep -v "${TARGET_PREFIX}:NVME_WRITE_READ_COMPLETION:OBSERVED" "$missing_hardware_fact_bundle/serial.log" > "$missing_hardware_fact_bundle/serial.next"
mv "$missing_hardware_fact_bundle/serial.next" "$missing_hardware_fact_bundle/serial.log"
expect_fail "$missing_hardware_fact_bundle"

out_of_order_pass_bundle="$TMP_ROOT/out-of-order-pass"
make_valid_bundle "$out_of_order_pass_bundle"
awk \
  -v pass="${TARGET_PREFIX}:APIC_TIMER:PASS" \
  -v observed="${TARGET_PREFIX}:APIC_TIMER_INTERRUPT:OBSERVED" \
  '$0 == pass { next } $0 == observed { print pass } { print }' \
  "$out_of_order_pass_bundle/serial.log" > "$out_of_order_pass_bundle/serial.next"
mv "$out_of_order_pass_bundle/serial.next" "$out_of_order_pass_bundle/serial.log"
expect_fail "$out_of_order_pass_bundle"

missing_attestation_lifecycle_bundle="$TMP_ROOT/missing-attestation-lifecycle"
make_valid_bundle "$missing_attestation_lifecycle_bundle"
grep -v "${TARGET_PREFIX}:ATTESTATION_ROOT_LIFECYCLE:OBSERVED" "$missing_attestation_lifecycle_bundle/serial.log" > "$missing_attestation_lifecycle_bundle/serial.next"
mv "$missing_attestation_lifecycle_bundle/serial.next" "$missing_attestation_lifecycle_bundle/serial.log"
expect_fail "$missing_attestation_lifecycle_bundle"

missing_attestation_lifecycle_sidecar_bundle="$TMP_ROOT/missing-attestation-lifecycle-sidecar"
make_valid_bundle "$missing_attestation_lifecycle_sidecar_bundle"
rm "$missing_attestation_lifecycle_sidecar_bundle/attestation-lifecycle.txt"
expect_fail "$missing_attestation_lifecycle_sidecar_bundle"

stale_attestation_generation_bundle="$TMP_ROOT/stale-attestation-generation"
make_valid_bundle "$stale_attestation_generation_bundle"
sed -i.bak 's/^active_generation=9/active_generation=7/' "$stale_attestation_generation_bundle/attestation-lifecycle.txt"
expect_fail "$stale_attestation_generation_bundle"

unbound_attestation_metadata_bundle="$TMP_ROOT/unbound-attestation-metadata"
make_valid_bundle "$unbound_attestation_metadata_bundle"
sed -i.bak 's/^verifier_metadata_digest_bound=true/verifier_metadata_digest_bound=false/' "$unbound_attestation_metadata_bundle/attestation-lifecycle.txt"
expect_fail "$unbound_attestation_metadata_bundle"

invalid_attestation_digest_bundle="$TMP_ROOT/invalid-attestation-digest"
make_valid_bundle "$invalid_attestation_digest_bundle"
sed -i.bak 's/^verifier_metadata_digest=.*/verifier_metadata_digest=not-a-digest/' "$invalid_attestation_digest_bundle/attestation-lifecycle.txt"
expect_fail "$invalid_attestation_digest_bundle"

duplicate_counter_bundle="$TMP_ROOT/duplicate-counter"
make_valid_bundle "$duplicate_counter_bundle"
printf '%s:COLD_BOOTS:10\n' "$TARGET_PREFIX" >> "$duplicate_counter_bundle/serial.log"
expect_fail "$duplicate_counter_bundle"

duplicate_manifest_key_bundle="$TMP_ROOT/duplicate-manifest-key"
make_valid_bundle "$duplicate_manifest_key_bundle"
printf 'repo_commit=0000000000000000000000000000000000000000\n' >> "$duplicate_manifest_key_bundle/proof-manifest.txt"
expect_fail "$duplicate_manifest_key_bundle"

duplicate_firmware_key_bundle="$TMP_ROOT/duplicate-firmware-key"
make_valid_bundle "$duplicate_firmware_key_bundle"
printf 'boot_mode=UEFI\n' >> "$duplicate_firmware_key_bundle/firmware-settings.txt"
expect_fail "$duplicate_firmware_key_bundle"

duplicate_power_key_bundle="$TMP_ROOT/duplicate-power-key"
make_valid_bundle "$duplicate_power_key_bundle"
printf 'cold_boots=10\n' >> "$duplicate_power_key_bundle/power-cycle-notes.txt"
expect_fail "$duplicate_power_key_bundle"

missing_changed_options_bundle="$TMP_ROOT/missing-changed-options"
make_valid_bundle "$missing_changed_options_bundle"
grep -v '^changed_options=' "$missing_changed_options_bundle/firmware-settings.txt" > "$missing_changed_options_bundle/firmware-settings.next"
mv "$missing_changed_options_bundle/firmware-settings.next" "$missing_changed_options_bundle/firmware-settings.txt"
expect_fail "$missing_changed_options_bundle"

invalid_secure_boot_bundle="$TMP_ROOT/invalid-secure-boot"
make_valid_bundle "$invalid_secure_boot_bundle"
sed -i.bak 's/^secure_boot=disabled-for-local-proof-media/secure_boot=maybe/' "$invalid_secure_boot_bundle/firmware-settings.txt"
expect_fail "$invalid_secure_boot_bundle"

invalid_storage_mode_bundle="$TMP_ROOT/invalid-storage-mode"
make_valid_bundle "$invalid_storage_mode_bundle"
sed -i.bak 's/^storage_mode=nvme/storage_mode=sata/' "$invalid_storage_mode_bundle/firmware-settings.txt"
expect_fail "$invalid_storage_mode_bundle"

missing_notes_bundle="$TMP_ROOT/missing-notes"
make_valid_bundle "$missing_notes_bundle"
grep -v '^notes=' "$missing_notes_bundle/power-cycle-notes.txt" > "$missing_notes_bundle/power-cycle-notes.next"
mv "$missing_notes_bundle/power-cycle-notes.next" "$missing_notes_bundle/power-cycle-notes.txt"
expect_fail "$missing_notes_bundle"

captured_before_prepared_bundle="$TMP_ROOT/captured-before-prepared"
make_valid_bundle "$captured_before_prepared_bundle"
sed -i.bak 's/^captured_at_utc=.*/captured_at_utc=2026-06-09T23:59:59Z/' "$captured_before_prepared_bundle/proof-manifest.txt"
expect_fail "$captured_before_prepared_bundle"

completed_before_started_bundle="$TMP_ROOT/completed-before-started"
make_valid_bundle "$completed_before_started_bundle"
sed -i.bak 's/^completed_at_utc=.*/completed_at_utc=2026-06-09T23:59:59Z/' "$completed_before_started_bundle/power-cycle-notes.txt"
expect_fail "$completed_before_started_bundle"

power_started_before_manifest_bundle="$TMP_ROOT/power-started-before-manifest"
make_valid_bundle "$power_started_before_manifest_bundle"
sed -i.bak 's/^started_at_utc=.*/started_at_utc=2026-06-09T23:59:59Z/' "$power_started_before_manifest_bundle/power-cycle-notes.txt"
expect_fail "$power_started_before_manifest_bundle"

power_completed_after_manifest_bundle="$TMP_ROOT/power-completed-after-manifest"
make_valid_bundle "$power_completed_after_manifest_bundle"
sed -i.bak 's/^completed_at_utc=.*/completed_at_utc=2026-06-10T01:00:01Z/' "$power_completed_after_manifest_bundle/power-cycle-notes.txt"
expect_fail "$power_completed_after_manifest_bundle"

attestation_after_manifest_bundle="$TMP_ROOT/attestation-after-manifest"
make_valid_bundle "$attestation_after_manifest_bundle"
sed -i.bak 's/^captured_at_utc=.*/captured_at_utc=2026-06-10T01:00:01Z/' "$attestation_after_manifest_bundle/attestation-lifecycle.txt"
expect_fail "$attestation_after_manifest_bundle"

missing_digest_bundle="$TMP_ROOT/missing-digest"
make_valid_bundle "$missing_digest_bundle"
grep -v 'zig-out/bin/userspace-storage-driver.elf' "$missing_digest_bundle/artifact-digests.sha256" > "$missing_digest_bundle/artifact-digests.next"
mv "$missing_digest_bundle/artifact-digests.next" "$missing_digest_bundle/artifact-digests.sha256"
expect_fail "$missing_digest_bundle"

missing_policy_digest_bundle="$TMP_ROOT/missing-policy-digest"
make_valid_bundle "$missing_policy_digest_bundle"
grep -v 'spec/release_security/release_keyring.json' "$missing_policy_digest_bundle/artifact-digests.sha256" > "$missing_policy_digest_bundle/artifact-digests.next"
mv "$missing_policy_digest_bundle/artifact-digests.next" "$missing_policy_digest_bundle/artifact-digests.sha256"
expect_fail "$missing_policy_digest_bundle"

corrupt_digest_bundle="$TMP_ROOT/corrupt-digest"
make_valid_bundle "$corrupt_digest_bundle"
sed -i.bak 's/^[0-9a-f][0-9a-f]*/0000000000000000000000000000000000000000000000000000000000000000/' "$corrupt_digest_bundle/artifact-digests.sha256"
expect_fail "$corrupt_digest_bundle"

malformed_digest_bundle="$TMP_ROOT/malformed-digest"
make_valid_bundle "$malformed_digest_bundle"
printf 'not-a-sha256  build/os.iso\n' >> "$malformed_digest_bundle/artifact-digests.sha256"
expect_fail "$malformed_digest_bundle"

duplicate_digest_bundle="$TMP_ROOT/duplicate-digest"
make_valid_bundle "$duplicate_digest_bundle"
printf '%s  build/os.iso\n' "$(sha256_file "$ARTIFACT_ROOT/build/os.iso")" >> "$duplicate_digest_bundle/artifact-digests.sha256"
expect_fail "$duplicate_digest_bundle"

stale_commit_bundle="$TMP_ROOT/stale-commit"
make_valid_bundle "$stale_commit_bundle"
sed -i.bak 's/^repo_commit=.*/repo_commit=0000000000000000000000000000000000000000/' "$stale_commit_bundle/proof-manifest.txt"
expect_fail "$stale_commit_bundle"

stale_change_bundle="$TMP_ROOT/stale-change"
make_valid_bundle "$stale_change_bundle"
sed -i.bak 's/^repo_change_id=.*/repo_change_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' "$stale_change_bundle/proof-manifest.txt"
expect_fail "$stale_change_bundle"

dirty_repo_bundle="$TMP_ROOT/dirty-repo"
make_valid_bundle "$dirty_repo_bundle"
sed -i.bak 's/^repo_dirty_files=0/repo_dirty_files=1/' "$dirty_repo_bundle/proof-manifest.txt"
expect_fail "$dirty_repo_bundle"

printf 'NUC11TNKi5 hardware proof checker self-test OK\n'
