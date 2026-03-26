#!/usr/bin/env bash
set -eu

IMAGE_PATH="${1:-build/ext2.img}"
IMAGE_SIZE="${2:-32M}"

if ! command -v mke2fs >/dev/null 2>&1; then
  echo "mke2fs not found. Install e2fsprogs." >&2
  exit 1
fi

mkdir -p "$(dirname "$IMAGE_PATH")"
rm -f "$IMAGE_PATH"
truncate -s "$IMAGE_SIZE" "$IMAGE_PATH"
mke2fs -q -t ext2 -F "$IMAGE_PATH"
