#!/usr/bin/env bash
set -eu

IMAGE_PATH="${1:-build/disk.img}"
USER_BIN_DIR="${2:-zig-out/user/bin}"
ETC_DIR="${3:-zig-out/user/rootfs/etc}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$2" >&2
    exit 1
  fi
}

require_cmd mkfs.fat "mkfs.fat not found. Install dosfstools."
require_cmd mmd "mmd not found. Install mtools."
require_cmd mcopy "mcopy not found. Install mtools."

mkdir -p "$(dirname "$IMAGE_PATH")"
rm -f "$IMAGE_PATH"
truncate -s 64M "$IMAGE_PATH"
mkfs.fat -F 32 "$IMAGE_PATH" >/dev/null

for dir in etc bin tmp dev home home/user proc root sys usr usr/bin; do
  mmd -i "$IMAGE_PATH" "::/$dir"
done

for program_path in "$USER_BIN_DIR"/*; do
  [ -f "$program_path" ] || continue
  mcopy -i "$IMAGE_PATH" "$program_path" "::/bin/$(basename "$program_path")"
done

for etc_name in motd passwd; do
  etc_path="$ETC_DIR/$etc_name"
  if [ ! -f "$etc_path" ]; then
    echo "Missing rootfs asset: $etc_path" >&2
    exit 1
  fi
  mcopy -i "$IMAGE_PATH" "$etc_path" "::/etc/$etc_name"
done
