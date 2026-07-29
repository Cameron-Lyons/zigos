#!/usr/bin/env bash
set -euo pipefail

BOOT_ISO_PATH="${1:?QEMU boot ISO required}"
SCRIPT_PATH="${2:?QEMU harness script required}"
shift 2

QEMU_BOOT_ISO="$BOOT_ISO_PATH" exec bash "$SCRIPT_PATH" "$@"
