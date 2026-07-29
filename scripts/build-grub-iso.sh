#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
OUTPUT_ISO="${2:?output iso path required}"
STAGING_DIR="${3:?staging directory required}"
GRUB_CONFIG_PATH="${4:-src/boot/grub-x86_64-kernel.cfg}"
GRUB_MKRESCUE="${GRUB_MKRESCUE:-}"
GRUB_MODULE_DIR="${GRUB_MODULE_DIR:-}"

if [ ! -f "$GRUB_CONFIG_PATH" ]; then
  echo "GRUB configuration not found: $GRUB_CONFIG_PATH" >&2
  exit 1
fi

if [ -z "$GRUB_MKRESCUE" ]; then
  for cmd in x86_64-elf-grub-mkrescue grub-mkrescue; do
    if command -v "$cmd" >/dev/null 2>&1; then
      GRUB_MKRESCUE="$cmd"
      break
    fi
  done
fi

if [ -z "$GRUB_MKRESCUE" ]; then
  echo "No GRUB mkrescue command found. Set GRUB_MKRESCUE or install GRUB tools." >&2
  exit 1
fi

if [ -z "$GRUB_MODULE_DIR" ]; then
  GRUB_MKRESCUE_PATH="$(command -v "$GRUB_MKRESCUE")"
  GRUB_PREFIX="${GRUB_MKRESCUE_PATH%/bin/*}"
  for dir in \
    "$GRUB_PREFIX/lib/x86_64-elf/grub/x86_64-efi" \
    /usr/lib/grub/x86_64-efi \
    /usr/lib64/grub/x86_64-efi \
    /usr/share/grub/x86_64-efi; do
    if [ -f "$dir/modinfo.sh" ]; then
      GRUB_MODULE_DIR="$dir"
      break
    fi
  done
fi

if [ ! -f "$GRUB_MODULE_DIR/modinfo.sh" ]; then
  echo "No x86-64 EFI GRUB module directory found. Set GRUB_MODULE_DIR explicitly." >&2
  exit 1
fi

if ! command -v xorriso >/dev/null 2>&1; then
  echo "xorriso not found. Install xorriso." >&2
  exit 1
fi

if ! command -v mformat >/dev/null 2>&1; then
  echo "mformat not found. Install mtools." >&2
  exit 1
fi

rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/boot/grub" "$(dirname "$OUTPUT_ISO")"
cp "$KERNEL_PATH" "$STAGING_DIR/boot/kernel.elf"
cp "$GRUB_CONFIG_PATH" "$STAGING_DIR/boot/grub/grub.cfg"
"$GRUB_MKRESCUE" --directory "$GRUB_MODULE_DIR" -o "$OUTPUT_ISO" "$STAGING_DIR"

if ! EL_TORITO_REPORT="$(xorriso -indev "$OUTPUT_ISO" -report_el_torito plain 2>&1)"; then
  echo "Could not inspect GRUB ISO boot metadata: $OUTPUT_ISO" >&2
  printf '%s\n' "$EL_TORITO_REPORT" >&2
  exit 1
fi

BOOTABLE_PLATFORMS="$(awk '
  $1 == "El" && $2 == "Torito" && $3 == "boot" && $4 == "img" && $5 == ":" && $8 == "y" { print $7 }
' <<<"$EL_TORITO_REPORT")"
if [ -z "$BOOTABLE_PLATFORMS" ] || grep -Fvxq 'UEFI' <<<"$BOOTABLE_PLATFORMS"; then
  echo "GRUB ISO must contain only bootable UEFI El Torito images: $OUTPUT_ISO" >&2
  printf '%s\n' "$EL_TORITO_REPORT" >&2
  exit 1
fi

if ! X86_64_EFI_REPORT="$(xorriso -report_about SORRY -indev "$OUTPUT_ISO" -find /boot/grub/x86_64-efi -type d -exec echo -- 2>&1)" ||
   ! grep -Fq "'/boot/grub/x86_64-efi'" <<<"$X86_64_EFI_REPORT"; then
  echo "GRUB ISO is missing x86-64 EFI modules: $OUTPUT_ISO" >&2
  printf '%s\n' "$X86_64_EFI_REPORT" >&2
  exit 1
fi

echo "Validated x86-64 UEFI boot media: $OUTPUT_ISO"
