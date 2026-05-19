#!/usr/bin/env bash
set -euo pipefail

readonly qemu_harness_debug_exit_device="isa-debug-exit,iobase=0xf4,iosize=0x04"
readonly qemu_harness_success_status=0x10
readonly qemu_harness_success_exit=$(((qemu_harness_success_status << 1) | 1))

QEMU_HARNESS_EXTRA_ARGS=()
QEMU_HARNESS_COMMAND=()

qemu_harness_binary() {
  printf '%s\n' "${QEMU_BIN:-qemu-system-x86_64}"
}

qemu_harness_default_memory() {
  printf '%s\n' "${QEMU_MEMORY:-256M}"
}

qemu_harness_profile_memory() {
  printf '%s\n' "${QEMU_PROFILE_MEMORY:-${QEMU_MEMORY:-128M}}"
}

qemu_harness_native_smoke_memory() {
  local profile_memory
  profile_memory="$(qemu_harness_profile_memory)"
  printf '%s\n' "${QEMU_NATIVE_SMOKE_MEMORY:-$profile_memory}"
}

qemu_harness_require_binary() {
  local qemu_binary
  qemu_binary="$(qemu_harness_binary)"
  if ! command -v "$qemu_binary" >/dev/null 2>&1; then
    echo "QEMU binary '$qemu_binary' not found. Set QEMU_BIN or install QEMU." >&2
    return 1
  fi
}

qemu_harness_load_extra_args() {
  QEMU_HARNESS_EXTRA_ARGS=()
  if [ -n "${QEMU_EXTRA_ARGS:-}" ]; then
    read -r -a QEMU_HARNESS_EXTRA_ARGS <<< "${QEMU_EXTRA_ARGS}"
  fi
}

qemu_harness_drive_arg() {
  local image_path="${1:?drive image path required}"
  printf 'file=%s,if=ide,format=raw,index=0,id=disk0\n' "$image_path"
}

qemu_harness_build_kernel_command() {
  local kernel_path="${1:?kernel path required}"
  local memory_size="${2:?QEMU memory size required}"
  local serial_target="${3:?serial target required}"
  local include_debug_exit="${4:?debug-exit flag required}"
  local include_no_shutdown="${5:?no-shutdown flag required}"
  shift 5

  qemu_harness_require_binary
  qemu_harness_load_extra_args

  QEMU_HARNESS_COMMAND=(
    "$(qemu_harness_binary)"
    -kernel "$kernel_path"
    -m "$memory_size"
    -display none
    -serial "$serial_target"
    -monitor none
    -no-reboot
  )

  if [ "$include_no_shutdown" = "yes" ]; then
    QEMU_HARNESS_COMMAND+=(-no-shutdown)
  fi
  if [ "$include_debug_exit" = "yes" ]; then
    QEMU_HARNESS_COMMAND+=(-device "$qemu_harness_debug_exit_device")
  fi

  if [ "${#QEMU_HARNESS_EXTRA_ARGS[@]}" -gt 0 ]; then
    QEMU_HARNESS_COMMAND+=("${QEMU_HARNESS_EXTRA_ARGS[@]}")
  fi
  QEMU_HARNESS_COMMAND+=("$@")
}

qemu_harness_build_cdrom_command() {
  local iso_path="${1:?ISO path required}"
  local memory_size="${2:?QEMU memory size required}"
  local serial_target="${3:?serial target required}"

  qemu_harness_require_binary
  qemu_harness_load_extra_args

  QEMU_HARNESS_COMMAND=(
    "$(qemu_harness_binary)"
    -cdrom "$iso_path"
    -boot d
    -m "$memory_size"
    -display none
    -serial "$serial_target"
    -monitor none
    -no-reboot
    -no-shutdown
  )
  if [ "${#QEMU_HARNESS_EXTRA_ARGS[@]}" -gt 0 ]; then
    QEMU_HARNESS_COMMAND+=("${QEMU_HARNESS_EXTRA_ARGS[@]}")
  fi
}

qemu_harness_normalize_exit() {
  local qemu_exit_code="${1:?QEMU exit code required}"
  case "$qemu_exit_code" in
    0|"$qemu_harness_success_exit")
      return 0
      ;;
    *)
      return "$qemu_exit_code"
      ;;
  esac
}

qemu_harness_run_command() {
  local qemu_log_path="${1:-}"
  local qemu_exit_code

  set +e
  if [ -n "$qemu_log_path" ]; then
    "${QEMU_HARNESS_COMMAND[@]}" >"$qemu_log_path" 2>&1
  else
    "${QEMU_HARNESS_COMMAND[@]}"
  fi
  qemu_exit_code=$?
  set -e

  qemu_harness_normalize_exit "$qemu_exit_code"
}

qemu_harness_run_kernel() {
  local kernel_path="${1:?kernel path required}"
  local serial_target="${2:-stdio}"
  local memory_size="${3:-$(qemu_harness_profile_memory)}"
  local qemu_log_path="${4:-}"
  if [ "$#" -ge 4 ]; then
    shift 4
  else
    set --
  fi

  qemu_harness_build_kernel_command "$kernel_path" "$memory_size" "$serial_target" yes no "$@"
  qemu_harness_run_command "$qemu_log_path"
}

qemu_harness_run_native_store() {
  local kernel_path="${1:?kernel path required}"
  local store_image="${2:?native store image required}"
  local serial_target="${3:-stdio}"
  local memory_size="${4:-$(qemu_harness_default_memory)}"
  local qemu_log_path="${5:-}"
  if [ "$#" -ge 5 ]; then
    shift 5
  else
    set --
  fi

  qemu_harness_build_kernel_command \
    "$kernel_path" \
    "$memory_size" \
    "$serial_target" \
    no \
    yes \
    -drive "$(qemu_harness_drive_arg "$store_image")" \
    "$@"
  qemu_harness_run_command "$qemu_log_path"
}

qemu_harness_print_qemu_log() {
  local qemu_log_path="${1:?QEMU log path required}"
  if [ -s "$qemu_log_path" ]; then
    cat "$qemu_log_path" >&2
  fi
}

qemu_harness_stop_qemu() {
  local qemu_pid="${1:?QEMU pid required}"
  kill -TERM "$qemu_pid" >/dev/null 2>&1 || true
  sleep 1
  kill -KILL "$qemu_pid" >/dev/null 2>&1 || true
}

qemu_harness_run_native_store_until_marker() {
  local kernel_path="${1:?kernel path required}"
  local store_image="${2:?native store image required}"
  local serial_log_path="${3:?serial log path required}"
  local validation_marker="${4:?validation marker required}"
  local timeout_seconds="${5:?timeout seconds required}"
  local memory_size="${6:-$(qemu_harness_native_smoke_memory)}"
  local qemu_log_path
  local qemu_pid
  local elapsed=0
  local marker_seen=0

  mkdir -p "$(dirname "$serial_log_path")"
  rm -f "$serial_log_path"
  qemu_log_path="${serial_log_path%.log}.qemu.log"
  rm -f "$qemu_log_path"

  qemu_harness_build_kernel_command \
    "$kernel_path" \
    "$memory_size" \
    "file:$serial_log_path" \
    yes \
    no \
    -drive "$(qemu_harness_drive_arg "$store_image")"

  "${QEMU_HARNESS_COMMAND[@]}" >"$qemu_log_path" 2>&1 &
  qemu_pid=$!

  while kill -0 "$qemu_pid" >/dev/null 2>&1; do
    if [ -s "$serial_log_path" ] && grep -Fq "$validation_marker" "$serial_log_path"; then
      marker_seen=1
      sleep 1
      qemu_harness_stop_qemu "$qemu_pid"
      break
    fi
    if [ "$elapsed" -ge "$timeout_seconds" ]; then
      qemu_harness_stop_qemu "$qemu_pid"
      break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  wait "$qemu_pid" >/dev/null 2>&1 || true

  if [ ! -s "$serial_log_path" ]; then
    echo "QEMU run failed: no serial output captured for $serial_log_path" >&2
    qemu_harness_print_qemu_log "$qemu_log_path"
    return 1
  fi

  if [ "$marker_seen" -eq 0 ] && ! grep -Fq "$validation_marker" "$serial_log_path"; then
    echo "QEMU run failed: validation marker '$validation_marker' not observed in $serial_log_path" >&2
    cat "$serial_log_path" >&2
    qemu_harness_print_qemu_log "$qemu_log_path"
    return 1
  fi
}

qemu_harness_run_cdrom_for_seconds() {
  local iso_path="${1:?ISO path required}"
  local serial_log_path="${2:?serial log path required}"
  local timeout_seconds="${3:?timeout seconds required}"
  local memory_size="${4:-$(qemu_harness_default_memory)}"
  local qemu_log_path
  local qemu_pid

  mkdir -p "$(dirname "$serial_log_path")"
  rm -f "$serial_log_path"
  qemu_log_path="${serial_log_path%.log}.qemu.log"
  rm -f "$qemu_log_path"

  qemu_harness_build_cdrom_command "$iso_path" "$memory_size" "file:$serial_log_path"
  "${QEMU_HARNESS_COMMAND[@]}" >"$qemu_log_path" 2>&1 &
  qemu_pid=$!

  sleep "$timeout_seconds"
  if kill -0 "$qemu_pid" >/dev/null 2>&1; then
    qemu_harness_stop_qemu "$qemu_pid"
  fi
  wait "$qemu_pid" >/dev/null 2>&1 || true
}

qemu_harness_main() {
  local command="${1:-}"
  case "$command" in
    kernel)
      shift
      qemu_harness_run_kernel "$@"
      ;;
    native-store)
      shift
      qemu_harness_run_native_store "$@"
      ;;
    *)
      echo "usage: $0 {kernel|native-store} ..." >&2
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  qemu_harness_main "$@"
fi
