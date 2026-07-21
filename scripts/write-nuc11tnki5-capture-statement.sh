#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

BUNDLE_DIR="${1:?hardware proof bundle directory required}"
ARTIFACT_ROOT="${ZIGOS_ARTIFACT_ROOT:-$ROOT_DIR}"

fail() {
  printf 'NUC11TNKi5 capture statement failed: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  local file="${1:?file required}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  else
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  fi
}

extract_unique_key() {
  local path="$1"
  local key="$2"
  local count
  count="$(awk -F= -v key="$key" '$1 == key { count += 1 } END { print count + 0 }' "$path")"
  if [ "$count" -ne 1 ]; then
    fail "$path must contain exactly one ${key}= entry"
  fi
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2) }' "$path"
}

require_file() {
  local path="$1"
  local label="$2"
  if [ ! -f "$path" ] || [ ! -s "$path" ] || [ -L "$path" ]; then
    fail "$label must be a non-empty regular file, not a symlink: $path"
  fi
}

if [ ! -d "$BUNDLE_DIR" ]; then
  fail "bundle directory is missing: $BUNDLE_DIR"
fi
BUNDLE_DIR="$(CDPATH='' cd -- "$BUNDLE_DIR" && pwd)"

manifest="$BUNDLE_DIR/proof-manifest.txt"
require_file "$manifest" "proof manifest"

format="$(extract_unique_key "$manifest" format)"
nonce="$(extract_unique_key "$manifest" capture_nonce)"
target_id="$(extract_unique_key "$manifest" target_id)"
board_sku="$(extract_unique_key "$manifest" board_sku)"
device_id="$(extract_unique_key "$manifest" device_id)"
repo_vcs="$(extract_unique_key "$manifest" repo_vcs)"
repo_change_id="$(extract_unique_key "$manifest" repo_change_id)"
repo_commit="$(extract_unique_key "$manifest" repo_commit)"

[ "$format" = "zigos-nuc11tnki5-proof-v2" ] || fail "unsupported proof manifest format: $format"
[[ "$nonce" =~ ^[0-9a-f]{64}$ ]] || fail "capture_nonce must be 64 lowercase hexadecimal characters"
[ "$target_id" = "intel-nuc11tnki5" ] || fail "unexpected target_id: $target_id"
[ "$board_sku" = "NUC11TNKi5" ] || fail "unexpected board_sku: $board_sku"
[ "$repo_vcs" = "jj" ] || fail "unexpected repo_vcs: $repo_vcs"

device_identity="$BUNDLE_DIR/device-identity.txt"
production_log="$BUNDLE_DIR/production-serial.log"
verification_log="$BUNDLE_DIR/verification-serial.log"
cycle_manifest="$BUNDLE_DIR/cycle-manifest.txt"
firmware_settings="$BUNDLE_DIR/firmware-settings.txt"
power_cycle_notes="$BUNDLE_DIR/power-cycle-notes.txt"
attestation_lifecycle="$BUNDLE_DIR/attestation-lifecycle.txt"
artifact_digests="$BUNDLE_DIR/artifact-digests.sha256"
operator_metadata="$BUNDLE_DIR/operator-metadata-markers.txt"
production_quote="$BUNDLE_DIR/production-attestation.quote"
production_signature="$BUNDLE_DIR/production-attestation.sig"
verification_quote="$BUNDLE_DIR/verification-attestation.quote"
verification_signature="$BUNDLE_DIR/verification-attestation.sig"
statement="$BUNDLE_DIR/capture-statement.txt"

for entry in \
  "$device_identity:device identity" \
  "$production_log:production serial log" \
  "$verification_log:verification serial log" \
  "$cycle_manifest:cycle manifest" \
  "$firmware_settings:firmware settings" \
  "$power_cycle_notes:power-cycle notes" \
  "$attestation_lifecycle:attestation lifecycle" \
  "$artifact_digests:artifact digests" \
  "$operator_metadata:operator metadata markers" \
  "$production_quote:production attestation quote" \
  "$production_signature:production attestation signature" \
  "$verification_quote:verification attestation quote" \
  "$verification_signature:verification attestation signature"; do
  path="${entry%%:*}"
  label="${entry#*:}"
  require_file "$path" "$label"
done

production_iso="$ARTIFACT_ROOT/build/os.iso"
production_kernel="$ARTIFACT_ROOT/zig-out/bin/kernel-zigos-native.elf"
verification_iso="$ARTIFACT_ROOT/build/os-verification.iso"
verification_kernel="$ARTIFACT_ROOT/zig-out/bin/kernel-zigos-native-verification.elf"
production_markers="$ARTIFACT_ROOT/spec/hardware/nuc11tnki5-production-required-markers.txt"
verification_markers="$ARTIFACT_ROOT/spec/hardware/nuc11tnki5-required-markers.txt"

for entry in \
  "$production_iso:production ISO" \
  "$production_kernel:production kernel" \
  "$verification_iso:verification ISO" \
  "$verification_kernel:verification kernel" \
  "$production_markers:production marker contract" \
  "$verification_markers:verification marker contract"; do
  path="${entry%%:*}"
  label="${entry#*:}"
  require_file "$path" "$label"
done

tmp_statement="$(mktemp "$BUNDLE_DIR/.capture-statement.XXXXXX")"
trap 'rm -f -- "$tmp_statement"' EXIT
cat > "$tmp_statement" <<EOF
format=zigos-nuc11tnki5-capture-statement-v1
capture_nonce=$nonce
target_id=$target_id
board_sku=$board_sku
device_id=$device_id
repo_vcs=$repo_vcs
repo_change_id=$repo_change_id
repo_commit=$repo_commit
proof_manifest_sha256=$(sha256_file "$manifest")
device_identity_sha256=$(sha256_file "$device_identity")
production_serial_sha256=$(sha256_file "$production_log")
verification_serial_sha256=$(sha256_file "$verification_log")
cycle_manifest_sha256=$(sha256_file "$cycle_manifest")
production_iso_sha256=$(sha256_file "$production_iso")
production_kernel_sha256=$(sha256_file "$production_kernel")
verification_iso_sha256=$(sha256_file "$verification_iso")
verification_kernel_sha256=$(sha256_file "$verification_kernel")
production_marker_contract_sha256=$(sha256_file "$production_markers")
verification_marker_contract_sha256=$(sha256_file "$verification_markers")
firmware_settings_sha256=$(sha256_file "$firmware_settings")
power_cycle_notes_sha256=$(sha256_file "$power_cycle_notes")
attestation_lifecycle_sha256=$(sha256_file "$attestation_lifecycle")
artifact_digests_sha256=$(sha256_file "$artifact_digests")
operator_metadata_markers_sha256=$(sha256_file "$operator_metadata")
production_quote_sha256=$(sha256_file "$production_quote")
production_signature_sha256=$(sha256_file "$production_signature")
verification_quote_sha256=$(sha256_file "$verification_quote")
verification_signature_sha256=$(sha256_file "$verification_signature")
EOF

chmod 0600 "$tmp_statement"
mv -f -- "$tmp_statement" "$statement"
trap - EXIT
printf 'NUC11TNKi5 canonical capture statement written: %s\n' "$statement"
