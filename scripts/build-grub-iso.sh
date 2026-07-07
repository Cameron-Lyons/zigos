#!/usr/bin/env bash
set -eu

KERNEL_PATH="${1:?kernel path required}"
OUTPUT_ISO="${2:?output iso path required}"
STAGING_DIR="${3:?staging directory required}"
GRUB_MKRESCUE="${GRUB_MKRESCUE:-}"

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
cp src/boot/grub.cfg "$STAGING_DIR/boot/grub/"
"$GRUB_MKRESCUE" -o "$OUTPUT_ISO" "$STAGING_DIR"
