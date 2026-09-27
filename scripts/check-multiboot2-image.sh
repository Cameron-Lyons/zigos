#!/usr/bin/env bash
set -euo pipefail

IMAGE_PATH="${1:?ELF image path required}"

if ! command -v readelf >/dev/null 2>&1 && ! command -v llvm-readelf >/dev/null 2>&1; then
  echo "No readelf found to validate the 64-bit kernel image: $IMAGE_PATH" >&2
  exit 1
fi

READELF="readelf"
if ! command -v readelf >/dev/null 2>&1; then
  READELF="llvm-readelf"
fi

HEADER="$("$READELF" -h "$IMAGE_PATH")"
echo "$HEADER" | grep -Fq "ELF64" || {
  echo "Kernel image must be ELF64: $IMAGE_PATH" >&2
  exit 1
}
echo "$HEADER" | grep -Eq "Machine:[[:space:]]+Advanced Micro Devices X86-64|Machine:[[:space:]]+X86-64" || {
  echo "Kernel image must target x86-64: $IMAGE_PATH" >&2
  exit 1
}

echo "ELF64 long-mode kernel image validated: $IMAGE_PATH"
