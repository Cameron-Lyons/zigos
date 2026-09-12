#!/usr/bin/env bash
set -euo pipefail

KERNEL_PATH="${1:?kernel path required}"
EFI_STUB_PATH="${2:?EFI stub path required}"
OUTPUT_ISO="${3:?output iso path required}"
STAGING_DIR="${4:?staging directory required}"
CMDLINE_PATH="${5:-src/boot/cmdline.txt}"

if [ ! -f "$KERNEL_PATH" ]; then
  echo "Kernel image not found: $KERNEL_PATH" >&2
  exit 1
fi
if [ ! -f "$EFI_STUB_PATH" ]; then
  echo "EFI stub not found: $EFI_STUB_PATH" >&2
  exit 1
fi
if [ ! -f "$CMDLINE_PATH" ]; then
  echo "EFI command line not found: $CMDLINE_PATH" >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
bash "$SCRIPT_DIR/check-efi-image.sh" "$EFI_STUB_PATH"

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
mkdir -p "$STAGING_DIR" "$(dirname "$OUTPUT_ISO")"

ESP_IMAGE="$STAGING_DIR/esp.img"
dd if=/dev/zero of="$ESP_IMAGE" bs=1M count=40 status=none
mformat -i "$ESP_IMAGE" -v ZIGOS ::
mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/BOOT ::/boot
mcopy -i "$ESP_IMAGE" "$EFI_STUB_PATH" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$ESP_IMAGE" "$KERNEL_PATH" ::/boot/kernel.elf
mcopy -i "$ESP_IMAGE" "$CMDLINE_PATH" ::/boot/cmdline.txt

xorriso -as mkisofs \
  -R -J \
  -e esp.img \
  -no-emul-boot \
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
