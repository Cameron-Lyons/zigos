#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"

LOG_PATH="${1:?serial log path required}"
MARKER_FILE="${2:-$ROOT_DIR/spec/hardware/nuc11tnki5-required-markers.txt}"

if [ ! -s "$LOG_PATH" ]; then
  echo "NUC11TNKi5 hardware proof failed: serial log is missing or empty: $LOG_PATH" >&2
  exit 1
fi

if [ ! -f "$MARKER_FILE" ]; then
  echo "NUC11TNKi5 hardware proof failed: marker file is missing: $MARKER_FILE" >&2
  exit 1
fi

if grep -Eqi 'panic|KERNEL PANIC|System Halted|FAIL' "$LOG_PATH"; then
  echo "NUC11TNKi5 hardware proof failed: panic or failure text found in $LOG_PATH" >&2
  exit 1
fi

missing=0
while IFS= read -r marker; do
  case "$marker" in
    '' | \#*)
      continue
      ;;
  esac

  if ! grep -Fq "$marker" "$LOG_PATH"; then
    echo "NUC11TNKi5 hardware proof failed: missing marker '$marker' in $LOG_PATH" >&2
    missing=1
  fi
done < "$MARKER_FILE"

if [ "$missing" -ne 0 ]; then
  exit 1
fi

printf 'NUC11TNKi5 hardware proof log OK: %s\n' "$LOG_PATH"
