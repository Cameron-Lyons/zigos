#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
CHECKER="$SCRIPT_DIR/check-production-boot-log.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zigos-production-log-check.XXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

write_log() {
  local name="$1"
  shift
  printf '%s\n' "$@" >"$TMP_ROOT/$name.log"
}

expect_pass() {
  local name="$1"
  if ! bash "$CHECKER" "$TMP_ROOT/$name.log" >/dev/null; then
    printf 'Expected production log fixture to pass: %s\n' "$name" >&2
    exit 1
  fi
}

expect_fail() {
  local name="$1"
  if bash "$CHECKER" "$TMP_ROOT/$name.log" >/dev/null 2>&1; then
    printf 'Expected production log fixture to fail: %s\n' "$name" >&2
    exit 1
  fi
}

write_log valid \
  'BOOT:ROLE:production' \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none' \
  'ZIGOS:TASK:SESSION_READY' \
  'ZIGOS:NATIVE:READY'
expect_pass valid

write_log zero-generation \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=0 error=none' \
  'ZIGOS:TASK:SESSION_READY' \
  'ZIGOS:NATIVE:READY'
expect_fail zero-generation

write_log checkpoint-error \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=DiskFault' \
  'ZIGOS:TASK:SESSION_READY' \
  'ZIGOS:NATIVE:READY'
expect_fail checkpoint-error

write_log suffixed-checkpoint \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none forged' \
  'ZIGOS:TASK:SESSION_READY' \
  'ZIGOS:NATIVE:READY'
expect_fail suffixed-checkpoint

write_log reordered \
  'ZIGOS:TASK:SESSION_READY' \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none' \
  'ZIGOS:NATIVE:READY'
expect_fail reordered

write_log suffixed-ready \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none' \
  'ZIGOS:TASK:SESSION_READY forged' \
  'ZIGOS:NATIVE:READY'
expect_fail suffixed-ready

write_log duplicated \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none' \
  'ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=4 error=none' \
  'ZIGOS:TASK:SESSION_READY' \
  'ZIGOS:NATIVE:READY'
expect_fail duplicated

write_log comments-only \
  '# ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=3 error=none' \
  '# ZIGOS:TASK:SESSION_READY' \
  '# ZIGOS:NATIVE:READY'
expect_fail comments-only

printf 'Production boot log checker self-test: PASS\n'
