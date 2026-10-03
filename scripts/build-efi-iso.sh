#!/usr/bin/env bash
set -euo pipefail
umask 022

UNIFIED_EFI_PATH="${1:?unified EFI image path required}"
OUTPUT_ISO="${2:?output iso path required}"
STAGING_DIR="${3:?staging directory required}"

# Use SOURCE_DATE_EPOCH, defaulting to 1980-01-01 UTC. Accept nonnegative
# seconds through 2107 and clamp all media dates before FAT's 1980 epoch.
# The optional fourth argument makes this input explicit in cached build steps.
SOURCE_DATE_EPOCH="${4-${SOURCE_DATE_EPOCH:-315532800}}"
case "$SOURCE_DATE_EPOCH" in
  ''|*[!0-9]*)
    echo "SOURCE_DATE_EPOCH must contain nonnegative decimal seconds" >&2
    exit 2
    ;;
esac
if [ "${#SOURCE_DATE_EPOCH}" -gt 10 ]; then
  echo "SOURCE_DATE_EPOCH exceeds FAT's maximum year 2107" >&2
  exit 2
fi
SOURCE_DATE_EPOCH="$((10#$SOURCE_DATE_EPOCH))"
if [ "$SOURCE_DATE_EPOCH" -gt 4354819199 ]; then
  echo "SOURCE_DATE_EPOCH exceeds FAT's maximum year 2107" >&2
  exit 2
fi
if [ "$SOURCE_DATE_EPOCH" -lt 315532800 ]; then
  SOURCE_DATE_EPOCH=315532800
fi
export SOURCE_DATE_EPOCH TZ=UTC

if [ ! -f "$UNIFIED_EFI_PATH" ]; then
  echo "Unified EFI image not found: $UNIFIED_EFI_PATH" >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
bash "$SCRIPT_DIR/check-efi-image.sh" "$UNIFIED_EFI_PATH"

if ! command -v xorriso >/dev/null 2>&1; then
  echo "xorriso not found. Install xorriso." >&2
  exit 1
fi
if ! command -v mformat >/dev/null 2>&1; then
  echo "mformat not found. Install mtools." >&2
  exit 1
fi
if ! command -v mcopy >/dev/null 2>&1; then
  echo "mcopy not found. Install mtools." >&2
  exit 1
fi

rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/EFI/BOOT" "$(dirname "$OUTPUT_ISO")"

ESP_IMAGE="$STAGING_DIR/esp.img"
STAGED_EFI="$STAGING_DIR/EFI/BOOT/BOOTX64.EFI"
cp "$UNIFIED_EFI_PATH" "$STAGED_EFI"
chmod 644 "$STAGED_EFI"
dd if=/dev/zero of="$ESP_IMAGE" bs=1M count=40 status=none
mformat -i "$ESP_IMAGE" -N 0 -v ZIGOS ::
mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP_IMAGE" "$STAGED_EFI" ::/EFI/BOOT/BOOTX64.EFI

xorriso -as mkisofs \
  -R -J \
  -uid 0 -gid 0 \
  -e esp.img \
  -no-emul-boot \
  --set_all_file_dates "=$SOURCE_DATE_EPOCH" \
  -o "$OUTPUT_ISO" \
  "$STAGING_DIR"

if ! EL_TORITO_REPORT="$(xorriso -indev "$OUTPUT_ISO" -report_el_torito plain 2>&1)"; then
  echo "Could not inspect EFI ISO boot metadata: $OUTPUT_ISO" >&2
  printf '%s\n' "$EL_TORITO_REPORT" >&2
  exit 1
fi

BOOTABLE_PLATFORMS="$(awk '
  $1 == "El" && $2 == "Torito" && $3 == "boot" && $4 == "img" && $5 == ":" && $8 == "y" { print $7 }
' <<<"$EL_TORITO_REPORT")"
if [ -z "$BOOTABLE_PLATFORMS" ] || grep -Fvxq 'UEFI' <<<"$BOOTABLE_PLATFORMS"; then
  echo "EFI ISO must contain only bootable UEFI El Torito images: $OUTPUT_ISO" >&2
  printf '%s\n' "$EL_TORITO_REPORT" >&2
  exit 1
fi

echo "Validated x86-64 UEFI native boot media: $OUTPUT_ISO"
