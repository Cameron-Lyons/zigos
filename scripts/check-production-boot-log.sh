#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'Production boot log check failed: %s\n' "$*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then
  fail "usage: scripts/check-production-boot-log.sh SERIAL_LOG"
fi

LOG_PATH="$1"
if [ ! -f "$LOG_PATH" ] || [ ! -s "$LOG_PATH" ]; then
  fail "serial log must be a non-empty regular file: $LOG_PATH"
fi

if ! awk '
  BEGIN {
    checkpoint_prefix = "ZIGOS:STORAGE:CHECKPOINT:FINAL"
    checkpoint_pattern = "^ZIGOS:STORAGE:CHECKPOINT:FINAL enabled=true dirty=false generation=[1-9][0-9]* error=none$"
    task_ready = "ZIGOS:TASK:SESSION_READY"
    native_ready = "ZIGOS:NATIVE:READY"
  }
  index($0, checkpoint_prefix) == 1 {
    checkpoint_like += 1
    if ($0 ~ checkpoint_pattern) {
      checkpoint_valid += 1
      checkpoint_line = NR
    } else {
      invalid = 1
    }
  }
  index($0, task_ready) == 1 {
    task_like += 1
    if ($0 == task_ready) {
      task_valid += 1
      task_line = NR
    } else {
      invalid = 1
    }
  }
  index($0, native_ready) == 1 {
    native_like += 1
    if ($0 == native_ready) {
      native_valid += 1
      native_line = NR
    } else {
      invalid = 1
    }
  }
  END {
    if (checkpoint_like != 1 || checkpoint_valid != 1) invalid = 1
    if (task_like != 1 || task_valid != 1) invalid = 1
    if (native_like != 1 || native_valid != 1) invalid = 1
    if (!(checkpoint_line < task_line && task_line < native_line)) invalid = 1
    exit invalid ? 1 : 0
  }
' "$LOG_PATH"; then
  fail "expected one exact clean checkpoint with positive generation, followed by exact TASK_READY and NATIVE_READY markers: $LOG_PATH"
fi

printf 'Production boot log ordering OK: %s\n' "$LOG_PATH"
