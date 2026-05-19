#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/clean-build.sh [--dry-run]

Remove local generated build outputs and Zig caches:
  build/
  zig-out/
  .zig-cache/
  zig-cache/
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -n|--dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

remove_generated_path() {
  local relative_path="${1:?generated path required}"
  local absolute_path="$ROOT_DIR/$relative_path"

  case "$relative_path" in
    ""|"."|".."|/*|../*|*/../*)
      echo "Refusing unsafe cleanup path: $relative_path" >&2
      return 1
      ;;
  esac

  if [ ! -e "$absolute_path" ] && [ ! -L "$absolute_path" ]; then
    printf 'Already clean: %s\n' "$relative_path"
    return 0
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'Would remove: %s\n' "$relative_path"
    return 0
  fi

  rm -rf -- "$absolute_path"
  printf 'Removed: %s\n' "$relative_path"
}

remove_generated_path "build"
remove_generated_path "zig-out"
remove_generated_path ".zig-cache"
remove_generated_path "zig-cache"
