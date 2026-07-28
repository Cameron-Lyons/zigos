#!/usr/bin/env bash
set -euo pipefail

IMAGE_PATH="${1:?ELF image path required}"
GRUB_FILE="${GRUB_FILE:-}"

if [ -z "$GRUB_FILE" ]; then
  for candidate in grub-file i686-elf-grub-file x86_64-elf-grub-file; do
    if command -v "$candidate" >/dev/null 2>&1; then
      GRUB_FILE="$candidate"
      break
    fi
  done
fi

if [ -z "$GRUB_FILE" ]; then
  echo "No GRUB image checker found. Set GRUB_FILE or install GRUB tools." >&2
  exit 1
fi

if ! "$GRUB_FILE" --is-x86-multiboot2 "$IMAGE_PATH"; then
  echo "ELF64 entry probe does not contain a discoverable Multiboot2 header: $IMAGE_PATH" >&2
  exit 1
fi

echo "Multiboot2 image header validated: $IMAGE_PATH"
