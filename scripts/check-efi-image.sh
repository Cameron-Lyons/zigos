#!/usr/bin/env bash
set -euo pipefail

IMAGE_PATH="${1:?EFI image path required}"

if [ ! -f "$IMAGE_PATH" ]; then
  echo "EFI image is missing: $IMAGE_PATH" >&2
  exit 1
fi

if [ ! -s "$IMAGE_PATH" ]; then
  echo "EFI image is empty: $IMAGE_PATH" >&2
  exit 1
fi

header="$(dd if="$IMAGE_PATH" bs=2 count=1 status=none | od -An -tx1)"
if ! grep -Fq "4d 5a" <<<"$header"; then
  echo "EFI image is missing an MZ header: $IMAGE_PATH" >&2
  exit 1
fi

pe_offset_hex="$(dd if="$IMAGE_PATH" bs=1 skip=60 count=4 status=none | od -An -tx1)"
pe_offset=0
index=0
for byte in $pe_offset_hex; do
  value=$((16#$byte))
  pe_offset=$((pe_offset | (value << (8 * index))))
  index=$((index + 1))
done

pe_magic="$(dd if="$IMAGE_PATH" bs=1 skip="$pe_offset" count=4 status=none | od -An -tx1)"
if ! grep -Fq "50 45 00 00" <<<"$pe_magic"; then
  echo "EFI image is missing a PE/COFF header: $IMAGE_PATH" >&2
  exit 1
fi

echo "EFI PE/COFF image header validated: $IMAGE_PATH"
