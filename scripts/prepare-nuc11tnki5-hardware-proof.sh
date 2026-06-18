#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="build/hardware-proofs/nuc11tnki5"
RUN_BUILD=false

usage() {
  cat <<'EOF'
Usage: scripts/prepare-nuc11tnki5-hardware-proof.sh [--build] [--output DIR]

Creates the NUC11TNKi5 proof-bundle skeleton and artifact digest manifest.

  --build       Run the release artifact build before collecting digests.
  --output DIR  Write the bundle skeleton under DIR.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --build)
      RUN_BUILD=true
      shift
      ;;
    --output)
      if [ "$#" -lt 2 ]; then
        echo "--output requires a directory" >&2
        exit 1
      fi
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

OUTPUT_PATH="$ROOT_DIR/$OUTPUT_DIR"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"

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

jsonish_datetime() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

write_if_missing() {
  local path="$1"
  if [ -e "$path" ]; then
    return
  fi
  cat > "$path"
}

if [ "$RUN_BUILD" = true ]; then
  "$ROOT_DIR/scripts/zig.sh" build release-sbom-provenance
fi

missing=0
for artifact in "${REQUIRED_ARTIFACTS[@]}"; do
  if [ ! -f "$ROOT_DIR/$artifact" ]; then
    printf 'missing required artifact: %s\n' "$artifact" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  printf 'Build artifacts first, or rerun with --build.\n' >&2
  exit 1
fi

mkdir -p "$OUTPUT_PATH"

manifest_path="$OUTPUT_PATH/proof-manifest.txt"
firmware_path="$OUTPUT_PATH/firmware-settings.txt"
power_path="$OUTPUT_PATH/power-cycle-notes.txt"
attestation_path="$OUTPUT_PATH/attestation-lifecycle.txt"
metadata_markers_path="$OUTPUT_PATH/operator-metadata-markers.txt"
digests_path="$OUTPUT_PATH/artifact-digests.sha256"

prepared_at_utc="$(jsonish_datetime)"
if ! command -v jj >/dev/null 2>&1; then
  printf 'Jujutsu (jj) is required to prepare NUC11TNKi5 proof metadata.\n' >&2
  exit 1
fi
repo_commit="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"')"
repo_change_id="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"')"
repo_dirty_files="$(jj -R "$ROOT_DIR" diff -r @ --name-only | wc -l | tr -d ' ')"

write_if_missing "$manifest_path" <<EOF
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
evidence_source=real_hardware
serial_log=serial.log
firmware_settings=firmware-settings.txt
power_cycle_notes=power-cycle-notes.txt
attestation_lifecycle=attestation-lifecycle.txt
artifact_digests=artifact-digests.sha256
required_markers=spec/hardware/nuc11tnki5-required-markers.txt
prepared_at_utc=$prepared_at_utc
captured_at_utc=TODO-fill-after-run
operator=TODO-fill-operator
repo_vcs=jj
repo_change_id=$repo_change_id
repo_commit=$repo_commit
repo_dirty_files=$repo_dirty_files
EOF

write_if_missing "$firmware_path" <<'EOF'
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
bios_version=TODO-fill-from-NUC-setup
boot_mode=UEFI
secure_boot=TODO-enabled-disabled-or-disabled-for-local-proof-media
storage_mode=TODO-fill-nvme
wake_suspend=TODO-suspend-wake-settings
changed_options=TODO-list-any-changed-firmware-options
EOF

write_if_missing "$power_path" <<'EOF'
target_id=intel-nuc11tnki5
operator=TODO-fill-operator
started_at_utc=TODO-fill-start-time
completed_at_utc=TODO-fill-completion-time
cold_boots=0
warm_reboots=0
storage_write_read_cycles=0
network_frame_cycles=0
suspend_resume_cycles=0
crash_recovery_cycles=0
crash_record_persistence_cycles=0
update_rollback_cycles=0
notes=TODO-record-observed-hangs-panics-retries-and-recovery-behavior
EOF

write_if_missing "$attestation_path" <<'EOF'
target_id=intel-nuc11tnki5
evidence_source=real_hardware
operator=TODO-fill-operator
captured_at_utc=TODO-fill-attestation-capture-time
provider=TODO-fill-tpm-secure-enclave-hsm-or-kms-provider
root_key_id=TODO-fill-root-key-id
initial_generation=0
active_generation=0
revoked_generation_count=0
stale_generation_rejected=TODO-true-after-verifier-rejected-old-generation
revoked_generation_rejected=TODO-true-after-verifier-rejected-revoked-generation
verifier_rejected_stale_attestation=TODO-true-after-response-verification-failed
verifier_metadata_digest_bound=TODO-true-after-request-bound-metadata-digest
verifier_metadata_digest=TODO-fill-64-hex-digest
attestation_request_digest=TODO-fill-64-hex-request-digest
notes=TODO-record-root-rotation-revocation-and-verifier-rejection-evidence
EOF

cat > "$metadata_markers_path" <<EOF
$TARGET_PREFIX:EVIDENCE_SOURCE:REAL_HARDWARE
$TARGET_PREFIX:BOARD_SKU:NUC11TNKi5
$TARGET_PREFIX:PROOF_MANIFEST:RECORDED
$TARGET_PREFIX:FIRMWARE_SETTINGS:RECORDED
$TARGET_PREFIX:POWER_CYCLE_NOTES:RECORDED
$TARGET_PREFIX:ARTIFACT_DIGESTS:RECORDED
EOF

artifact_list="$(mktemp "${TMPDIR:-/tmp}/zigos-nuc-artifacts.XXXXXX")"
{
  printf '%s\n' "${REQUIRED_ARTIFACTS[@]}"
  if [ -d "$ROOT_DIR/zig-out/bin" ]; then
    find "$ROOT_DIR/zig-out/bin" -type f -print | sed "s#^$ROOT_DIR/##"
  fi
} | LC_ALL=C sort -u > "$artifact_list"

: > "$digests_path"
while IFS= read -r artifact; do
  [ -f "$ROOT_DIR/$artifact" ] || continue
  printf '%s  %s\n' "$(sha256_file "$ROOT_DIR/$artifact")" "$artifact" >> "$digests_path"
done < "$artifact_list"
rm -f -- "$artifact_list"

printf 'NUC11TNKi5 proof bundle skeleton prepared under %s\n' "$OUTPUT_DIR"
printf 'Capture real NUC output into %s/serial.log, fill TODO fields, then run:\n' "$OUTPUT_DIR"
printf '  scripts/check-nuc11tnki5-hardware-proof.sh %s\n' "$OUTPUT_DIR"
