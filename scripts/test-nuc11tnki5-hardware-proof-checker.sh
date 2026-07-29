#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
CHECKER="$ROOT_DIR/scripts/check-nuc11tnki5-hardware-proof.sh"
STATEMENT_WRITER="$ROOT_DIR/scripts/write-nuc11tnki5-capture-statement.sh"
PRODUCTION_MARKERS="$ROOT_DIR/spec/hardware/nuc11tnki5-production-required-markers.txt"
VERIFICATION_MARKERS="$ROOT_DIR/spec/hardware/nuc11tnki5-required-markers.txt"
TARGET_PREFIX="ZIGOS:HW_TARGET:INTEL_NUC11TNKI5"
NONCE="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
DEVICE_ID="nuc11tnki5-system-00112233"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zigos-nuc-proof-checker.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT
ARTIFACT_ROOT="$TMP_ROOT/artifacts"
VERIFIER="$TMP_ROOT/trusted-fixture-verifier"
RELEASE_VERIFIER="$TMP_ROOT/trusted-release-verifier"
TRUSTED_ROOT="$TMP_ROOT/trusted-root-metadata.json"
TRUST_STATE="$TMP_ROOT/persistent-release-trust-state.json"

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
  "spec/hardware/nuc11tnki5-production-required-markers.txt"
  "spec/hardware/nuc11tnki5-required-markers.txt"
)

RELEASE_EVIDENCE_NAMES=(
  "artifact-digests.sha256"
  "artifact-measurements.json"
  "customer-verification-policy.json"
  "provenance.dsse.intoto.jsonl"
  "provenance.intoto.jsonl"
  "release-trust-policy.dsse.json"
  "reproducible-artifact-digests.sha256"
  "reproducible-build.json"
  "root-metadata.json"
  "sbom.spdx.json"
)

sha256_file() {
  local file="${1:?file required}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  else
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  fi
}

write_required_artifacts() {
  local artifact
  for artifact in "${REQUIRED_ARTIFACTS[@]}" "${REQUIRED_CAPTURE_INPUTS[@]}"; do
    mkdir -p "$ARTIFACT_ROOT/$(dirname -- "$artifact")"
    case "$artifact" in
      spec/hardware/nuc11tnki5-production-required-markers.txt)
        cp "$PRODUCTION_MARKERS" "$ARTIFACT_ROOT/$artifact"
        ;;
      spec/hardware/nuc11tnki5-required-markers.txt)
        cp "$VERIFICATION_MARKERS" "$ARTIFACT_ROOT/$artifact"
        ;;
      *)
        printf 'hardware checker artifact %s\n' "$artifact" > "$ARTIFACT_ROOT/$artifact"
        ;;
    esac
  done

  mkdir -p "$ARTIFACT_ROOT/build/release-security"
  printf '{"schemaVersion":1,"fixture":"trusted-root"}\n' > "$TRUSTED_ROOT"
  cp "$TRUSTED_ROOT" "$ARTIFACT_ROOT/build/release-security/root-metadata.json"
  for evidence_name in "${RELEASE_EVIDENCE_NAMES[@]}"; do
    if [ "$evidence_name" = "root-metadata.json" ]; then
      continue
    fi
    printf 'authenticated release evidence fixture: %s\n' "$evidence_name" > "$ARTIFACT_ROOT/build/release-security/$evidence_name"
  done
  printf 'authenticated exact release manifest fixture\n' > "$ARTIFACT_ROOT/build/release-security/release-manifest.dsse.json"
}

write_fixture_verifier() {
  cat > "$VERIFIER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  else
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  fi
}

key() {
  local path="$1"
  local name="$2"
  awk -F= -v name="$name" '$1 == name { print substr($0, length(name) + 2); found = 1 } END { exit found ? 0 : 1 }' "$path"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --statement) statement="$2" ;;
    --statement-sha256) statement_sha256="$2" ;;
    --nonce) nonce="$2" ;;
    --target-id) target_id="$2" ;;
    --device-id) device_id="$2" ;;
    --production-quote) production_quote="$2" ;;
    --production-signature) production_signature="$2" ;;
    --verification-quote) verification_quote="$2" ;;
    --verification-signature) verification_signature="$2" ;;
    *) exit 64 ;;
  esac
  shift 2
done

[ "$(sha256_file "$statement")" = "$statement_sha256" ]
[ "$target_id" = "intel-nuc11tnki5" ]

verify_role() {
  local role="$1"
  local quote="$2"
  local signature="$3"
  [ "$(key "$quote" format)" = "zigos-fixture-hardware-quote-v1" ]
  [ "$(key "$quote" role)" = "$role" ]
  [ "$(key "$quote" nonce)" = "$nonce" ]
  [ "$(key "$quote" device_id)" = "$device_id" ]
  [ "$(key "$signature" format)" = "zigos-fixture-hardware-signature-v1" ]
  [ "$(key "$signature" role)" = "$role" ]
  [ "$(key "$signature" nonce)" = "$nonce" ]
  [ "$(key "$signature" quote_sha256)" = "$(sha256_file "$quote")" ]
}

verify_role production "$production_quote" "$production_signature"
verify_role verification "$verification_quote" "$verification_signature"

cat <<EOF_RESPONSE
format=zigos-trusted-hardware-verifier-response-v1
result=verified
assertion=signed-response
statement_sha256=$statement_sha256
nonce=$nonce
target_id=$target_id
device_id=$device_id
production_role=verified
verification_role=verified
EOF_RESPONSE
EOF
  chmod 0700 "$VERIFIER"
}

write_fixture_release_verifier() {
  cat > "$RELEASE_VERIFIER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  else
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  fi
}

[ "${1:-}" = "verify" ]
shift
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) bundle="$2" ;;
    --artifacts) artifacts="$2" ;;
    --trusted-root) trusted_root="$2" ;;
    --trusted-root-sha256) trusted_root_sha256="$2" ;;
    --trust-state) trust_state="$2" ;;
    *) exit 64 ;;
  esac
  shift 2
done

[ "$bundle" = "$artifacts/build/release-security" ]
[ "$(sha256_file "$trusted_root")" = "$trusted_root_sha256" ]
cmp -s "$trusted_root" "$bundle/root-metadata.json"
[ -s "$bundle/release-trust-policy.dsse.json" ]
[ -s "$bundle/release-manifest.dsse.json" ]
printf '{"fixture":"authenticated-release-state"}\n' > "$trust_state"
printf 'release bundle verified\n'
EOF
  chmod 0700 "$RELEASE_VERIFIER"
}

write_manifest() {
  local dir="$1"
  local repo_commit
  local repo_change_id
  if command -v jj >/dev/null 2>&1 &&
    repo_commit="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'commit_id ++ "\n"' 2>/dev/null)" &&
    repo_change_id="$(jj -R "$ROOT_DIR" log -r @ --no-graph -T 'change_id ++ "\n"' 2>/dev/null)" &&
    [ -n "$repo_commit" ] && [ -n "$repo_change_id" ]; then
    :
  else
    repo_commit="1111111111111111111111111111111111111111"
    repo_change_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  fi
  export ZIGOS_EXPECTED_REPO_COMMIT="$repo_commit"
  export ZIGOS_EXPECTED_REPO_CHANGE_ID="$repo_change_id"
  cat > "$dir/proof-manifest.txt" <<EOF
format=zigos-nuc11tnki5-proof-v2
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
evidence_source=real_hardware
capture_nonce=$NONCE
device_id=$DEVICE_ID
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
release_manifest_sha256=$(sha256_file "$ARTIFACT_ROOT/build/release-security/release-manifest.dsse.json")
release_root_metadata=build/release-security/root-metadata.json
release_root_metadata_sha256=$(sha256_file "$ARTIFACT_ROOT/build/release-security/root-metadata.json")
release_trust_policy=build/release-security/release-trust-policy.dsse.json
release_trust_policy_sha256=$(sha256_file "$ARTIFACT_ROOT/build/release-security/release-trust-policy.dsse.json")
operator_metadata_markers=operator-metadata-markers.txt
production_quote=production-attestation.quote
production_signature=production-attestation.sig
verification_quote=verification-attestation.quote
verification_signature=verification-attestation.sig
capture_statement=capture-statement.txt
prepared_at_utc=2026-06-10T00:00:00Z
captured_at_utc=2026-06-10T01:00:00Z
operator=hardware-operator
repo_vcs=jj
repo_change_id=$repo_change_id
repo_commit=$repo_commit
repo_dirty_files=0
EOF
}

write_device_identity() {
  local dir="$1"
  cat > "$dir/device-identity.txt" <<EOF
format=zigos-nuc11tnki5-device-identity-v1
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
device_id=$DEVICE_ID
smbios_system_uuid=00112233-4455-6677-8899-aabbccddeeff
baseboard_serial=BTNUC11SERIAL001
tpm_ek_public_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
}

write_sidecars() {
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
  cat > "$dir/power-cycle-notes.txt" <<'EOF'
target_id=intel-nuc11tnki5
operator=hardware-operator
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
notes=operator observed all required physical power and device cycles
EOF
  cat > "$dir/attestation-lifecycle.txt" <<'EOF'
target_id=intel-nuc11tnki5
evidence_source=real_hardware
operator=hardware-operator
captured_at_utc=2026-06-10T00:30:00Z
provider=hardware-tpm-root
root_key_id=hardware-root-key
initial_generation=7
active_generation=9
revoked_generation_count=1
stale_generation_rejected=true
revoked_generation_rejected=true
verifier_rejected_stale_attestation=true
verifier_metadata_digest_bound=true
verifier_metadata_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
attestation_request_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
notes=operator captured root lifecycle rejection and request binding
EOF
  cat > "$dir/operator-metadata-markers.txt" <<EOF
$TARGET_PREFIX:EVIDENCE_SOURCE:REAL_HARDWARE
$TARGET_PREFIX:BOARD_SKU:NUC11TNKi5
$TARGET_PREFIX:PROOF_MANIFEST:RECORDED
$TARGET_PREFIX:FIRMWARE_SETTINGS:RECORDED
$TARGET_PREFIX:POWER_CYCLE_NOTES:RECORDED
$TARGET_PREFIX:ARTIFACT_DIGESTS:RECORDED
EOF
}

write_production_log() {
  local dir="$1"
  local marker
  : > "$dir/production-serial.log"
  while IFS= read -r marker; do
    case "$marker" in
      '' | \#*) continue ;;
    esac
    if [ "$marker" = "ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false" ]; then
      printf '%s generation=42 error=none\n' "$marker" >> "$dir/production-serial.log"
    else
      printf '%s\n' "$marker" >> "$dir/production-serial.log"
    fi
  done < "$PRODUCTION_MARKERS"
}

write_verification_log() {
  local dir="$1"
  {
    printf '%s:EVIDENCE_SOURCE:REAL_HARDWARE\n' "$TARGET_PREFIX"
    printf '%s:BOARD_SKU:NUC11TNKi5\n' "$TARGET_PREFIX"
    printf '%s:PROOF_MANIFEST:RECORDED\n' "$TARGET_PREFIX"
    printf '%s:FIRMWARE_SETTINGS:RECORDED\n' "$TARGET_PREFIX"
    printf '%s:POWER_CYCLE_NOTES:RECORDED\n' "$TARGET_PREFIX"
    printf '%s:ARTIFACT_DIGESTS:RECORDED\n' "$TARGET_PREFIX"
    grep -Ev '^[[:space:]]*(#|$)' "$VERIFICATION_MARKERS" | grep -F "$TARGET_PREFIX:" | grep -F ':OBSERVED'
    grep -Ev '^[[:space:]]*(#|$)' "$VERIFICATION_MARKERS" | grep -F "$TARGET_PREFIX:" | grep -E ':(PASS|ENFORCED)$'
    grep -Ev '^[[:space:]]*(#|$)' "$VERIFICATION_MARKERS" | grep -Fv "$TARGET_PREFIX:"
    printf '%s:COLD_BOOTS:10\n' "$TARGET_PREFIX"
    printf '%s:WARM_REBOOTS:10\n' "$TARGET_PREFIX"
    printf '%s:STORAGE_WRITE_READ_CYCLES:100\n' "$TARGET_PREFIX"
    printf '%s:NETWORK_FRAME_CYCLES:100\n' "$TARGET_PREFIX"
    printf '%s:SUSPEND_RESUME_CYCLES:20\n' "$TARGET_PREFIX"
    printf '%s:CRASH_RECOVERY_CYCLES:10\n' "$TARGET_PREFIX"
    printf '%s:CRASH_RECORD_PERSISTENCE_CYCLES:10\n' "$TARGET_PREFIX"
    printf '%s:UPDATE_ROLLBACK_CYCLES:10\n' "$TARGET_PREFIX"
  } > "$dir/verification-serial.log"
}

write_cycles() {
  local dir="$1"
  mkdir -p "$dir/cycles"
  printf 'format=zigos-nuc11tnki5-cycle-manifest-v1\n' > "$dir/cycle-manifest.txt"
  add_cycles() {
    local type="$1"
    local count="$2"
    local index=1
    while [ "$index" -le "$count" ]; do
      local padded
      local path
      local digest
      padded="$(printf '%06d' "$index")"
      path="cycles/${type}-${padded}.log"
      cat > "$dir/$path" <<EOF
format=zigos-nuc11tnki5-cycle-log-v1
capture_nonce=$NONCE
target_id=intel-nuc11tnki5
device_id=$DEVICE_ID
cycle_type=$type
cycle_index=$padded
result=pass
observation=physical target cycle completed
EOF
      digest="$(sha256_file "$dir/$path")"
      printf 'cycle=%s|%s|%s|%s\n' "$type" "$padded" "$digest" "$path" >> "$dir/cycle-manifest.txt"
      index=$((index + 1))
    done
  }
  add_cycles cold_boot 10
  add_cycles warm_reboot 10
  add_cycles storage_write_read 100
  add_cycles network_frame 100
  add_cycles suspend_resume 20
  add_cycles crash_recovery 10
  add_cycles crash_record_persistence 10
  add_cycles update_rollback 10
}

write_role_quote() {
  local dir="$1"
  local role="$2"
  local quote="$dir/${role}-attestation.quote"
  local signature="$dir/${role}-attestation.sig"
  cat > "$quote" <<EOF
format=zigos-fixture-hardware-quote-v1
role=$role
nonce=$NONCE
device_id=$DEVICE_ID
measurement=${role}-hardware-capture
EOF
  cat > "$signature" <<EOF
format=zigos-fixture-hardware-signature-v1
role=$role
nonce=$NONCE
quote_sha256=$(sha256_file "$quote")
EOF
}

rewrite_role_signature() {
  local dir="$1"
  local role="$2"
  local quote="$dir/${role}-attestation.quote"
  cat > "$dir/${role}-attestation.sig" <<EOF
format=zigos-fixture-hardware-signature-v1
role=$role
nonce=$NONCE
quote_sha256=$(sha256_file "$quote")
EOF
}

write_artifact_digests() {
  local dir="$1"
  local artifact
  : > "$dir/artifact-digests.sha256"
  for artifact in "${REQUIRED_ARTIFACTS[@]}"; do
    printf '%s  %s\n' "$(sha256_file "$ARTIFACT_ROOT/$artifact")" "$artifact" >> "$dir/artifact-digests.sha256"
  done
  cp "$dir/artifact-digests.sha256" "$ARTIFACT_ROOT/build/release-security/artifact-digests.sha256"
}

write_statement() {
  local dir="$1"
  ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" "$STATEMENT_WRITER" "$dir" >/dev/null
}

make_valid_bundle() {
  local dir="$1"
  mkdir -p "$dir"
  write_manifest "$dir"
  write_device_identity "$dir"
  write_sidecars "$dir"
  write_production_log "$dir"
  write_verification_log "$dir"
  write_cycles "$dir"
  write_role_quote "$dir" production
  write_role_quote "$dir" verification
  write_artifact_digests "$dir"
  write_statement "$dir"
}

checker_env() {
  env \
    ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
    ZIGOS_EXPECTED_REPO_COMMIT="$ZIGOS_EXPECTED_REPO_COMMIT" \
    ZIGOS_EXPECTED_REPO_CHANGE_ID="$ZIGOS_EXPECTED_REPO_CHANGE_ID" \
    ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE="$NONCE" \
    ZIGOS_HARDWARE_PROOF_VERIFIER="$VERIFIER" \
    ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256="$VERIFIER_SHA256" \
    ZIGOS_RELEASE_VERIFIER="$RELEASE_VERIFIER" \
    ZIGOS_RELEASE_VERIFIER_SHA256="$RELEASE_VERIFIER_SHA256" \
    ZIGOS_RELEASE_TRUST_ROOT="$TRUSTED_ROOT" \
    ZIGOS_RELEASE_TRUST_ROOT_SHA256="$TRUSTED_ROOT_SHA256" \
    ZIGOS_RELEASE_TRUST_STATE="$TRUST_STATE" \
    "$@"
}

expect_pass() {
  local dir="$1"
  checker_env "$CHECKER" "$dir" >/dev/null
}

expect_fail() {
  local dir="$1"
  if checker_env "$CHECKER" "$dir" >/dev/null 2> "$dir/checker.err"; then
    printf 'expected checker failure for %s\n' "$dir" >&2
    exit 1
  fi
}

copy_valid() {
  local name="$1"
  local target="$TMP_ROOT/$name"
  cp -R "$VALID_BUNDLE" "$target"
  printf '%s\n' "$target"
}

write_required_artifacts
write_fixture_verifier
write_fixture_release_verifier
VERIFIER_SHA256="$(sha256_file "$VERIFIER")"
RELEASE_VERIFIER_SHA256="$(sha256_file "$RELEASE_VERIFIER")"
TRUSTED_ROOT_SHA256="$(sha256_file "$TRUSTED_ROOT")"
export ZIGOS_RELEASE_VERIFIER="$RELEASE_VERIFIER"
export ZIGOS_RELEASE_VERIFIER_SHA256="$RELEASE_VERIFIER_SHA256"
export ZIGOS_RELEASE_TRUST_ROOT="$TRUSTED_ROOT"
export ZIGOS_RELEASE_TRUST_ROOT_SHA256="$TRUSTED_ROOT_SHA256"
export ZIGOS_RELEASE_TRUST_STATE="$TRUST_STATE"
VALID_BUNDLE="$TMP_ROOT/valid"
make_valid_bundle "$VALID_BUNDLE"
expect_pass "$VALID_BUNDLE"

missing_verifier="$(copy_valid missing-verifier)"
if env -u ZIGOS_HARDWARE_PROOF_VERIFIER \
  ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
  ZIGOS_EXPECTED_REPO_COMMIT="$ZIGOS_EXPECTED_REPO_COMMIT" \
  ZIGOS_EXPECTED_REPO_CHANGE_ID="$ZIGOS_EXPECTED_REPO_CHANGE_ID" \
  ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE="$NONCE" \
  ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256="$VERIFIER_SHA256" \
  "$CHECKER" "$missing_verifier" >/dev/null 2> "$missing_verifier/checker.err"; then
  printf 'expected checker failure without trusted verifier\n' >&2
  exit 1
fi

spoof_verifier="$TMP_ROOT/exit-zero-verifier"
printf '#!/usr/bin/env bash\nexit 0\n' > "$spoof_verifier"
chmod 0700 "$spoof_verifier"
spoof_bundle="$(copy_valid spoof-verifier)"
if env \
  ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
  ZIGOS_EXPECTED_REPO_COMMIT="$ZIGOS_EXPECTED_REPO_COMMIT" \
  ZIGOS_EXPECTED_REPO_CHANGE_ID="$ZIGOS_EXPECTED_REPO_CHANGE_ID" \
  ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE="$NONCE" \
  ZIGOS_HARDWARE_PROOF_VERIFIER="$spoof_verifier" \
  ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256="$(sha256_file "$spoof_verifier")" \
  "$CHECKER" "$spoof_bundle" >/dev/null 2> "$spoof_bundle/checker.err"; then
  printf 'expected exact-response failure for exit-zero verifier\n' >&2
  exit 1
fi

wrong_verifier_digest="$(copy_valid wrong-verifier-digest)"
if env \
  ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
  ZIGOS_EXPECTED_REPO_COMMIT="$ZIGOS_EXPECTED_REPO_COMMIT" \
  ZIGOS_EXPECTED_REPO_CHANGE_ID="$ZIGOS_EXPECTED_REPO_CHANGE_ID" \
  ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE="$NONCE" \
  ZIGOS_HARDWARE_PROOF_VERIFIER="$VERIFIER" \
  ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
  "$CHECKER" "$wrong_verifier_digest" >/dev/null 2> "$wrong_verifier_digest/checker.err"; then
  printf 'expected externally pinned verifier digest failure\n' >&2
  exit 1
fi

stale_nonce="$(copy_valid stale-nonce)"
if env \
  ZIGOS_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
  ZIGOS_EXPECTED_REPO_COMMIT="$ZIGOS_EXPECTED_REPO_COMMIT" \
  ZIGOS_EXPECTED_REPO_CHANGE_ID="$ZIGOS_EXPECTED_REPO_CHANGE_ID" \
  ZIGOS_HARDWARE_PROOF_EXPECTED_NONCE="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
  ZIGOS_HARDWARE_PROOF_VERIFIER="$VERIFIER" \
  ZIGOS_HARDWARE_PROOF_VERIFIER_SHA256="$VERIFIER_SHA256" \
  "$CHECKER" "$stale_nonce" >/dev/null 2> "$stale_nonce/checker.err"; then
  printf 'expected stale nonce failure\n' >&2
  exit 1
fi

stale_production_log="$(copy_valid stale-production-log)"
printf 'late unbound production bytes\n' >> "$stale_production_log/production-serial.log"
expect_fail "$stale_production_log"

stale_verification_log="$(copy_valid stale-verification-log)"
printf 'late unbound verification bytes\n' >> "$stale_verification_log/verification-serial.log"
expect_fail "$stale_verification_log"

production_notes_fixture="$(copy_valid production-notes-fixture)"
printf 'app.notes.daily\nuserspace-notes-daily.elf\n' >> "$production_notes_fixture/production-serial.log"
write_statement "$production_notes_fixture"
expect_fail "$production_notes_fixture"

tampered_statement="$(copy_valid tampered-statement)"
sed 's/^production_iso_sha256=./production_iso_sha256=f/' "$tampered_statement/capture-statement.txt" > "$tampered_statement/capture-statement.next"
mv "$tampered_statement/capture-statement.next" "$tampered_statement/capture-statement.txt"
expect_fail "$tampered_statement"

spoofed_scalar_counts="$(copy_valid spoofed-scalar-counts)"
sed 's/^cold_boots=10$/cold_boots=11/' "$spoofed_scalar_counts/power-cycle-notes.txt" > "$spoofed_scalar_counts/power-cycle-notes.next"
mv "$spoofed_scalar_counts/power-cycle-notes.next" "$spoofed_scalar_counts/power-cycle-notes.txt"
sed "s/${TARGET_PREFIX}:COLD_BOOTS:10/${TARGET_PREFIX}:COLD_BOOTS:11/" "$spoofed_scalar_counts/verification-serial.log" > "$spoofed_scalar_counts/verification-serial.next"
mv "$spoofed_scalar_counts/verification-serial.next" "$spoofed_scalar_counts/verification-serial.log"
write_statement "$spoofed_scalar_counts"
expect_fail "$spoofed_scalar_counts"

stale_cycle_log="$(copy_valid stale-cycle-log)"
printf 'late unbound cycle bytes\n' >> "$stale_cycle_log/cycles/cold_boot-000001.log"
expect_fail "$stale_cycle_log"

missing_cycle_log="$(copy_valid missing-cycle-log)"
rm "$missing_cycle_log/cycles/warm_reboot-000010.log"
expect_fail "$missing_cycle_log"

duplicate_cycle="$(copy_valid duplicate-cycle)"
duplicate_entry="$(tail -n 1 "$duplicate_cycle/cycle-manifest.txt")"
printf '%s\n' "$duplicate_entry" >> "$duplicate_cycle/cycle-manifest.txt"
expect_fail "$duplicate_cycle"

stale_quote="$(copy_valid stale-quote)"
printf 'unbound quote bytes\n' >> "$stale_quote/production-attestation.quote"
expect_fail "$stale_quote"

invalid_quote="$(copy_valid invalid-quote)"
sed 's/^role=production$/role=verification/' "$invalid_quote/production-attestation.quote" > "$invalid_quote/production-attestation.next"
mv "$invalid_quote/production-attestation.next" "$invalid_quote/production-attestation.quote"
rewrite_role_signature "$invalid_quote" production
write_statement "$invalid_quote"
expect_fail "$invalid_quote"

invalid_signature="$(copy_valid invalid-signature)"
sed 's/^quote_sha256=./quote_sha256=f/' "$invalid_signature/verification-attestation.sig" > "$invalid_signature/verification-attestation.next"
mv "$invalid_signature/verification-attestation.next" "$invalid_signature/verification-attestation.sig"
write_statement "$invalid_signature"
expect_fail "$invalid_signature"

missing_quote="$(copy_valid missing-quote)"
rm "$missing_quote/verification-attestation.quote"
expect_fail "$missing_quote"

checkpoint_error="$(copy_valid checkpoint-error)"
sed 's/error=none/error=write_failed/' "$checkpoint_error/production-serial.log" > "$checkpoint_error/production-serial.next"
mv "$checkpoint_error/production-serial.next" "$checkpoint_error/production-serial.log"
write_statement "$checkpoint_error"
expect_fail "$checkpoint_error"

checkpoint_after_ready="$(copy_valid checkpoint-after-ready)"
checkpoint="$(grep '^ZIGOS:STORAGE:CHECKPOINT:FINAL' "$checkpoint_after_ready/production-serial.log")"
grep -v '^ZIGOS:STORAGE:CHECKPOINT:FINAL' "$checkpoint_after_ready/production-serial.log" > "$checkpoint_after_ready/production-serial.next"
printf '%s\n' "$checkpoint" >> "$checkpoint_after_ready/production-serial.next"
mv "$checkpoint_after_ready/production-serial.next" "$checkpoint_after_ready/production-serial.log"
write_statement "$checkpoint_after_ready"
expect_fail "$checkpoint_after_ready"

missing_verification_ready="$(copy_valid missing-verification-ready)"
grep -v '^ZIGOS:NATIVE:READY$' "$missing_verification_ready/verification-serial.log" > "$missing_verification_ready/verification-serial.next"
mv "$missing_verification_ready/verification-serial.next" "$missing_verification_ready/verification-serial.log"
write_statement "$missing_verification_ready"
expect_fail "$missing_verification_ready"

device_mismatch="$(copy_valid device-mismatch)"
sed 's/^device_id=.*/device_id=nuc11tnki5-different-device/' "$device_mismatch/device-identity.txt" > "$device_mismatch/device-identity.next"
mv "$device_mismatch/device-identity.next" "$device_mismatch/device-identity.txt"
write_statement "$device_mismatch"
expect_fail "$device_mismatch"

legacy_digest_entry="$(copy_valid legacy-digest-entry)"
printf '%064d  spec/release_security/release_keyring.json\n' 0 >> "$legacy_digest_entry/artifact-digests.sha256"
write_statement "$legacy_digest_entry"
expect_fail "$legacy_digest_entry"

tampered_release_manifest="$(copy_valid tampered-release-manifest)"
printf 'unbound replacement release bytes\n' >> "$ARTIFACT_ROOT/build/release-security/release-manifest.dsse.json"
expect_fail "$tampered_release_manifest"
printf 'authenticated exact release manifest fixture\n' > "$ARTIFACT_ROOT/build/release-security/release-manifest.dsse.json"

tampered_root_evidence="$(copy_valid tampered-root-evidence)"
printf 'untrusted bundled root bytes\n' >> "$ARTIFACT_ROOT/build/release-security/root-metadata.json"
expect_fail "$tampered_root_evidence"
cp "$TRUSTED_ROOT" "$ARTIFACT_ROOT/build/release-security/root-metadata.json"

artifact_hash="$(copy_valid artifact-hash)"
printf 'changed production ISO\n' >> "$ARTIFACT_ROOT/build/os.iso"
expect_fail "$artifact_hash"
printf 'hardware checker artifact %s\n' "build/os.iso" > "$ARTIFACT_ROOT/build/os.iso"

printf 'NUC11TNKi5 hardware proof checker self-test: PASS\n'
