#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="build/hardware-proofs/nuc11tnki5"
RUN_BUILD=false
CAPTURE_NONCE="${ZIGOS_HARDWARE_PROOF_NONCE:-}"

is_safe_proof_output_dir() {
  local candidate="${1:-}"
  local name="${candidate##*/}"
  [[ "$candidate" =~ ^build/hardware-proofs/[A-Za-z0-9._-]+$ ]] &&
    [ "$name" != "." ] && [ "$name" != ".." ]
}

usage() {
  cat <<'EOF'
Usage: scripts/prepare-nuc11tnki5-hardware-proof.sh --nonce HEX [--build] [--output DIR]

Creates the NUC11TNKi5 authenticated proof-bundle skeleton and exact 33-target
production digest manifest. The bundle requires a finalized authenticated release
manifest, separate production and verification single-boot captures, individually
hashed cycle logs, and two role-specific quotes/signatures from the same target.

  --build       One-shot phase-A alternative: build and verify the release
                candidate plus verification ISO before collecting digests.
                Do not regenerate the candidate after this command returns.
  --output DIR  Write into a fresh empty build/hardware-proofs/NAME directory.
  --nonce HEX   Fresh 32-byte verifier-issued challenge as 64 lowercase hex.
                ZIGOS_HARDWARE_PROOF_NONCE may provide the same value.
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
    --nonce)
      if [ "$#" -lt 2 ]; then
        echo "--nonce requires 64 lowercase hexadecimal characters" >&2
        exit 1
      fi
      CAPTURE_NONCE="$2"
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

if ! [[ "$CAPTURE_NONCE" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'A fresh verifier-issued nonce is required; use --nonce with 64 lowercase hexadecimal characters.\n' >&2
  exit 1
fi

is_safe_proof_output_dir "$OUTPUT_DIR" || {
  printf 'Proof output must be one direct child of build/hardware-proofs: %s\n' "$OUTPUT_DIR" >&2
  exit 1
}
OUTPUT_PATH="$ROOT_DIR/$OUTPUT_DIR"
OUTPUT_BASE="$ROOT_DIR/build/hardware-proofs"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"

REQUIRED_ARTIFACTS=(
  "build/os.iso"
  "spec/production_readiness.json"
  "spec/release_security/crash_dump_redaction.json"
  "spec/release_security/fuzz_corpus.json"
  "spec/release_security/memory_safety_inventory.json"
  "spec/release_security/release_artifacts.json"
  "spec/release_security/threat_model.json"
  "spec/release_security/vulnerability_disclosure.json"
  "zig-out/bin/kernel-zigos-native.elf"
  "zig-out/bin/userspace-attention-broker.elf"
  "zig-out/bin/userspace-capture.elf"
  "zig-out/bin/userspace-compositor.elf"
  "zig-out/bin/userspace-indexing-search.elf"
  "zig-out/bin/userspace-media-print.elf"
  "zig-out/bin/userspace-network-stack.elf"
  "zig-out/bin/userspace-notes.elf"
  "zig-out/bin/userspace-object-resilience.elf"
  "zig-out/bin/userspace-package-service.elf"
  "zig-out/bin/userspace-permission-review.elf"
  "zig-out/bin/userspace-personal-context.elf"
  "zig-out/bin/userspace-policy-mediation.elf"
  "zig-out/bin/userspace-secret-vault.elf"
  "zig-out/bin/userspace-secure-pasteboard.elf"
  "zig-out/bin/userspace-sensitive-capture.elf"
  "zig-out/bin/userspace-service-registry.elf"
  "zig-out/bin/userspace-session-manager.elf"
  "zig-out/bin/userspace-storage-driver.elf"
  "zig-out/bin/userspace-storage-object.elf"
  "zig-out/bin/userspace-sync-service.elf"
  "zig-out/bin/userspace-sync.elf"
  "zig-out/bin/userspace-task-lifecycle.elf"
  "zig-out/bin/userspace-viewer.elf"
  "zig-out/bin/userspace-workspace-storage.elf"
)

REQUIRED_CAPTURE_INPUTS=(
  "build/os-verification.iso"
  "zig-out/bin/kernel-zigos-native-verification.elf"
  "build/release-security/release-manifest.dsse.json"
  "build/release-security/release-trust-policy.dsse.json"
  "build/release-security/root-metadata.json"
  "spec/hardware/nuc11tnki5-production-required-markers.txt"
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

write_new_file() {
  local path="$1"
  [ ! -e "$path" ] || {
    printf 'Proof output changed during preparation; refusing to reuse %s.\n' "$path" >&2
    exit 1
  }
  (set -o noclobber; cat > "$path") || {
    printf 'Could not create proof output exclusively: %s\n' "$path" >&2
    exit 1
  }
}

prepare_fresh_output() {
  [ ! -L "$ROOT_DIR/build" ] || {
    printf 'Repository build directory must not be a symbolic link.\n' >&2
    exit 1
  }
  [ ! -L "$OUTPUT_BASE" ] || {
    printf 'Hardware-proof output base must not be a symbolic link.\n' >&2
    exit 1
  }
  mkdir -p "$OUTPUT_BASE"
  [ "$(realpath "$ROOT_DIR/build")" = "$ROOT_DIR/build" ] || {
    printf 'Repository build directory resolves outside the workspace.\n' >&2
    exit 1
  }
  [ "$(realpath "$OUTPUT_BASE")" = "$OUTPUT_BASE" ] || {
    printf 'Hardware-proof output base resolves outside the workspace.\n' >&2
    exit 1
  }
  if [ -e "$OUTPUT_PATH" ]; then
    if [ ! -d "$OUTPUT_PATH" ] || [ -L "$OUTPUT_PATH" ]; then
      printf 'Proof output must be a regular directory, not a symlink: %s\n' "$OUTPUT_DIR" >&2
      exit 1
    fi
    [ "$(realpath "$OUTPUT_PATH")" = "$OUTPUT_PATH" ] || {
      printf 'Proof output resolves outside the trusted output base: %s\n' "$OUTPUT_DIR" >&2
      exit 1
    }
    if [ -n "$(find "$OUTPUT_PATH" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
      printf 'Proof output is not empty; use a fresh --output directory: %s\n' "$OUTPUT_DIR" >&2
      exit 1
    fi
  else
    mkdir "$OUTPUT_PATH"
  fi
}

prepare_fresh_output

if [ "$RUN_BUILD" = true ]; then
  : "${ZIGOS_RELEASE_TRUST_ROOT:?--build requires an absolute ZIGOS_RELEASE_TRUST_ROOT}"
  : "${ZIGOS_RELEASE_TRUST_ROOT_SHA256:?--build requires ZIGOS_RELEASE_TRUST_ROOT_SHA256}"
  : "${ZIGOS_RELEASE_TRUST_POLICY:?--build requires an absolute ZIGOS_RELEASE_TRUST_POLICY}"
  : "${ZIGOS_RELEASE_TRUST_STATE:?--build requires an absolute external ZIGOS_RELEASE_TRUST_STATE}"
  : "${ZIGOS_RELEASE_VERIFIER:?--build requires an absolute independent ZIGOS_RELEASE_VERIFIER}"
  : "${ZIGOS_RELEASE_VERIFIER_SHA256:?--build requires ZIGOS_RELEASE_VERIFIER_SHA256}"
  : "${ZIGOS_RELEASE_DSSE_SIGN_COMMAND:?--build requires ZIGOS_RELEASE_DSSE_SIGN_COMMAND}"
  : "${ZIGOS_RELEASE_SIGNING_KEY_ID:?--build requires ZIGOS_RELEASE_SIGNING_KEY_ID}"
  : "${ZIGOS_RELEASE_HARDWARE_BACKED:?--build requires ZIGOS_RELEASE_HARDWARE_BACKED=true}"
  : "${ZIGOS_RELEASE_SEQUENCE:?--build requires a strictly increasing ZIGOS_RELEASE_SEQUENCE for the new candidate}"
  : "${ZIGOS_RELEASE_EXPIRES_AT:?--build requires a future ZIGOS_RELEASE_EXPIRES_AT}"
  "$ROOT_DIR/scripts/zig.sh" build -Doptimize=ReleaseFast \
    -Drelease-trust-root="$ZIGOS_RELEASE_TRUST_ROOT" \
    -Drelease-trust-root-sha256="$ZIGOS_RELEASE_TRUST_ROOT_SHA256" \
    -Drelease-trust-policy="$ZIGOS_RELEASE_TRUST_POLICY" \
    -Drelease-trust-state="$ZIGOS_RELEASE_TRUST_STATE" \
    -Drelease-verifier="$ZIGOS_RELEASE_VERIFIER" \
    -Drelease-verifier-sha256="$ZIGOS_RELEASE_VERIFIER_SHA256" \
    release-bundle-check
fi

missing=0
for artifact in "${REQUIRED_ARTIFACTS[@]}" "${REQUIRED_CAPTURE_INPUTS[@]}"; do
  if [ ! -f "$ROOT_DIR/$artifact" ]; then
    printf 'missing required artifact: %s\n' "$artifact" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  printf 'Build artifacts first, or rerun with --build.\n' >&2
  exit 1
fi

manifest_path="$OUTPUT_PATH/proof-manifest.txt"
firmware_path="$OUTPUT_PATH/firmware-settings.txt"
power_path="$OUTPUT_PATH/power-cycle-notes.txt"
attestation_path="$OUTPUT_PATH/attestation-lifecycle.txt"
device_identity_path="$OUTPUT_PATH/device-identity.txt"
metadata_markers_path="$OUTPUT_PATH/operator-metadata-markers.txt"
digests_path="$OUTPUT_PATH/artifact-digests.sha256"
cycle_manifest_path="$OUTPUT_PATH/cycle-manifest.txt"
production_quote_path="$OUTPUT_PATH/production-attestation.quote"
production_signature_path="$OUTPUT_PATH/production-attestation.sig"
verification_quote_path="$OUTPUT_PATH/verification-attestation.quote"
verification_signature_path="$OUTPUT_PATH/verification-attestation.sig"
release_manifest_path="$ROOT_DIR/build/release-security/release-manifest.dsse.json"
release_root_metadata_path="$ROOT_DIR/build/release-security/root-metadata.json"
release_trust_policy_path="$ROOT_DIR/build/release-security/release-trust-policy.dsse.json"

prepared_at_utc="$(jsonish_datetime)"
if ! command -v jj >/dev/null 2>&1; then
  printf 'Jujutsu (jj) is required to prepare NUC11TNKi5 proof metadata.\n' >&2
  exit 1
fi
repo_commit="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"')"
repo_change_id="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"')"
repo_dirty_files="$(jj -R "$ROOT_DIR" diff -r @ --name-only | wc -l | tr -d ' ')"

write_new_file "$manifest_path" <<EOF
format=zigos-nuc11tnki5-proof-v2
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
evidence_source=real_hardware
capture_nonce=$CAPTURE_NONCE
device_id=TODO-fill-stable-device-id
device_identity=device-identity.txt
production_serial_log=production-serial.log
production_boot_medium=build/os.iso
production_boot_kernel=zig-out/bin/kernel-zigos-native.elf
production_required_markers=spec/hardware/nuc11tnki5-production-required-markers.txt
verification_serial_log=verification-serial.log
verification_boot_medium=build/os-verification.iso
verification_boot_kernel=zig-out/bin/kernel-zigos-native-verification.elf
verification_required_markers=spec/hardware/nuc11tnki5-required-markers.txt
cycle_manifest=cycle-manifest.txt
firmware_settings=firmware-settings.txt
power_cycle_notes=power-cycle-notes.txt
attestation_lifecycle=attestation-lifecycle.txt
artifact_digests=artifact-digests.sha256
release_bundle=build/release-security
release_manifest=build/release-security/release-manifest.dsse.json
release_manifest_sha256=$(sha256_file "$release_manifest_path")
release_root_metadata=build/release-security/root-metadata.json
release_root_metadata_sha256=$(sha256_file "$release_root_metadata_path")
release_trust_policy=build/release-security/release-trust-policy.dsse.json
release_trust_policy_sha256=$(sha256_file "$release_trust_policy_path")
operator_metadata_markers=operator-metadata-markers.txt
production_quote=production-attestation.quote
production_signature=production-attestation.sig
verification_quote=verification-attestation.quote
verification_signature=verification-attestation.sig
capture_statement=capture-statement.txt
prepared_at_utc=$prepared_at_utc
captured_at_utc=TODO-fill-after-run
operator=TODO-fill-operator
repo_vcs=jj
repo_change_id=$repo_change_id
repo_commit=$repo_commit
repo_dirty_files=$repo_dirty_files
EOF

write_new_file "$device_identity_path" <<'EOF'
format=zigos-nuc11tnki5-device-identity-v1
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
device_id=TODO-fill-same-stable-device-id-as-proof-manifest
smbios_system_uuid=TODO-fill-canonical-SMBIOS-UUID
baseboard_serial=TODO-fill-baseboard-serial
tpm_ek_public_sha256=TODO-fill-64-lowercase-hex-EK-public-key-digest
EOF

write_new_file "$firmware_path" <<'EOF'
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
bios_version=TODO-fill-from-NUC-setup
boot_mode=UEFI
secure_boot=TODO-enabled-disabled-or-disabled-for-local-proof-media
storage_mode=TODO-fill-nvme
wake_suspend=TODO-suspend-wake-settings
changed_options=TODO-list-any-changed-firmware-options
EOF

write_new_file "$power_path" <<'EOF'
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

write_new_file "$attestation_path" <<'EOF'
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

write_new_file "$metadata_markers_path" <<EOF
$TARGET_PREFIX:EVIDENCE_SOURCE:REAL_HARDWARE
$TARGET_PREFIX:BOARD_SKU:NUC11TNKi5
$TARGET_PREFIX:PROOF_MANIFEST:RECORDED
$TARGET_PREFIX:FIRMWARE_SETTINGS:RECORDED
$TARGET_PREFIX:POWER_CYCLE_NOTES:RECORDED
$TARGET_PREFIX:ARTIFACT_DIGESTS:RECORDED
EOF

write_new_file "$cycle_manifest_path" <<'EOF'
format=zigos-nuc11tnki5-cycle-manifest-v1
EOF

write_new_file "$production_quote_path" <<'EOF'
TODO-replace-with-production-role-hardware-quote-bound-to-capture-nonce
EOF
write_new_file "$production_signature_path" <<'EOF'
TODO-replace-with-production-role-quote-signature
EOF
write_new_file "$verification_quote_path" <<'EOF'
TODO-replace-with-verification-role-hardware-quote-bound-to-capture-nonce
EOF
write_new_file "$verification_signature_path" <<'EOF'
TODO-replace-with-verification-role-quote-signature
EOF

mkdir "$OUTPUT_PATH/cycles"

{
  for artifact in "${REQUIRED_ARTIFACTS[@]}"; do
    printf '%s  %s\n' "$(sha256_file "$ROOT_DIR/$artifact")" "$artifact"
  done
} | write_new_file "$digests_path"

printf 'NUC11TNKi5 authenticated proof bundle skeleton prepared under %s\n' "$OUTPUT_DIR"
printf 'The bundle is bound to verifier-issued nonce %s.\n' "$CAPTURE_NONCE"
printf 'Perform two separate single-boot captures on the same NUC11TNKi5:\n'
printf '  1. Boot build/os.iso and capture the production kernel output into %s/production-serial.log.\n' "$OUTPUT_DIR"
printf '  2. Boot build/os-verification.iso and capture one verification boot into %s/verification-serial.log.\n' "$OUTPUT_DIR"
printf 'Do not concatenate boots. Record every repeated hardware cycle as an individually hashed cycles/*.log entry in cycle-manifest.txt.\n'
printf 'Fill TODO fields and role-specific quote/signature files, then write the canonical statement:\n'
printf '  scripts/write-nuc11tnki5-capture-statement.sh %s\n' "$OUTPUT_DIR"
printf 'Validate with separately installed hardware/release verifiers, an externally pinned root, and external rollback state:\n'
printf '  ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE=%s ZIGOS_HARDWARE_PROOF_VERIFIER=/absolute/hardware-verifier ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256=<64-hex> ZIGOS_RELEASE_VERIFIER=/absolute/zigos-verify-release ZIGOS_RELEASE_VERIFIER_SHA256=<64-hex> ZIGOS_RELEASE_TRUST_ROOT=/absolute/root-metadata.json ZIGOS_RELEASE_TRUST_ROOT_SHA256=<64-hex> ZIGOS_RELEASE_TRUST_STATE=/absolute/persistent-state.json scripts/check-nuc11tnki5-hardware-proof.sh %s\n' "$CAPTURE_NONCE" "$OUTPUT_DIR"
