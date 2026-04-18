#!/usr/bin/env bash
set -eu

IMAGE_PATH="${1:-build/native-store.img}"
SIZE_MIB="${2:-8}"
MODE="${3:-preserve}"

mkdir -p "$(dirname "$IMAGE_PATH")"

bytes=$((SIZE_MIB * 1024 * 1024))

file_size_bytes() {
  stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1"
}

case "$MODE" in
  preserve)
    if [ ! -f "$IMAGE_PATH" ]; then
      truncate -s "$bytes" "$IMAGE_PATH"
      exit 0
    fi
    current_size=$(file_size_bytes "$IMAGE_PATH")
    if [ "$current_size" -lt "$bytes" ]; then
      truncate -s "$bytes" "$IMAGE_PATH"
    fi
    ;;
  reset)
    rm -f "$IMAGE_PATH"
    truncate -s "$bytes" "$IMAGE_PATH"
    ;;
  *)
    echo "Unknown mode '$MODE' for native store image" >&2
    exit 1
    ;;
esac
