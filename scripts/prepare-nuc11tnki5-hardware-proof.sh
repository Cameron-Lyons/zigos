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
  "spec/production_readiness.json"
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
metadata_markers_path="$OUTPUT_PATH/operator-metadata-markers.txt"
digests_path="$OUTPUT_PATH/artifact-digests.sha256"

prepared_at_utc="$(jsonish_datetime)"
repo_commit="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || printf 'unknown')"
repo_dirty_files="$(git -C "$ROOT_DIR" status --short 2>/dev/null | wc -l | tr -d ' ')"

write_if_missing "$manifest_path" <<EOF
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
evidence_source=real_hardware
serial_log=serial.log
firmware_settings=firmware-settings.txt
power_cycle_notes=power-cycle-notes.txt
artifact_digests=artifact-digests.sha256
required_markers=spec/hardware/nuc11tnki5-required-markers.txt
prepared_at_utc=$prepared_at_utc
captured_at_utc=TODO-fill-after-run
operator=TODO-fill-operator
repo_commit=$repo_commit
repo_dirty_files=$repo_dirty_files
EOF

write_if_missing "$firmware_path" <<'EOF'
target_id=intel-nuc11tnki5
board_sku=NUC11TNKi5
bios_version=TODO-fill-from-NUC-setup
boot_mode=UEFI
secure_boot=TODO-enabled-or-disabled
storage_mode=TODO-nvme-mode
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
notes=TODO-record-observed-hangs-panics-retries-and-recovery-behavior
EOF

cat > "$metadata_markers_path" <<EOF
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
