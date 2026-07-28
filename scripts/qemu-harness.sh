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

qemu_harness_cpu_model() {
  # 'max' satisfies the mandatory long-mode, NX, SMEP, SMAP, and UMIP contract;
  # the legacy qemu64 model does not advertise the complete baseline.
  printf '%s\n' "${QEMU_CPU_MODEL:-max}"
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
  printf 'file=%s,if=ide,format=raw,index=0,id=disk0,cache=writethrough\n' "$image_path"
}

qemu_harness_append_native_store_drive() {
  local image_path="${1:?drive image path required}"
  local default_bus="${2:-ide}"
  local native_store_bus="${ZIGOS_NATIVE_STORE_BUS:-$default_bus}"
  local native_store_cache="${ZIGOS_NATIVE_STORE_CACHE:-writethrough}"

  case "$native_store_cache" in
    writeback|writethrough)
      ;;
    *)
      echo "Unsupported ZIGOS_NATIVE_STORE_CACHE '$native_store_cache'; expected 'writeback' or 'writethrough'." >&2
      return 2
      ;;
  esac

  QEMU_HARNESS_COMMAND+=(
    -drive "file=$image_path,if=none,format=raw,id=disk0,cache=$native_store_cache"
  )
  case "$native_store_bus" in
    nvme)
      local nvme_write_cache="${ZIGOS_NVME_WRITE_CACHE:-auto}"
      case "$nvme_write_cache" in
        on|off|auto)
          ;;
        *)
          echo "Unsupported ZIGOS_NVME_WRITE_CACHE '$nvme_write_cache'; expected 'on', 'off', or 'auto'." >&2
          return 2
          ;;
      esac
      QEMU_HARNESS_COMMAND+=(
        -device "nvme,drive=disk0,serial=zigosnvme0,write-cache=$nvme_write_cache"
      )
      ;;
    ide)
      QEMU_HARNESS_COMMAND+=(
        -device "ide-hd,drive=disk0,bus=ide.0,unit=0"
      )
      ;;
    *)
      echo "Unsupported ZIGOS_NATIVE_STORE_BUS '$native_store_bus'; expected 'nvme' or 'ide'." >&2
      return 2
      ;;
  esac
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
    -cpu "$(qemu_harness_cpu_model)"
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
  if [ -n "${QEMU_KERNEL_APPEND:-}" ]; then
    QEMU_HARNESS_COMMAND+=(-append "$QEMU_KERNEL_APPEND")
  fi

  if [ "${#QEMU_HARNESS_EXTRA_ARGS[@]}" -gt 0 ]; then
    QEMU_HARNESS_COMMAND+=("${QEMU_HARNESS_EXTRA_ARGS[@]}")
  fi
  QEMU_HARNESS_COMMAND+=("$@")
}

qemu_harness_find_ovmf_code() {
  local path

  if [ -n "${OVMF_CODE:-}" ]; then
    if [ -f "$OVMF_CODE" ]; then
      printf '%s\n' "$OVMF_CODE"
      return 0
    fi
    echo "OVMF_CODE is set but does not exist: $OVMF_CODE" >&2
    return 1
  fi

  for path in \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.fd \
    /usr/share/edk2/ovmf/OVMF_CODE_4M.fd \
    /usr/share/edk2/x64/OVMF_CODE.fd \
    /usr/share/qemu/edk2-x86_64-code.fd \
    /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
    /usr/local/share/qemu/edk2-x86_64-code.fd; do
    if [ -f "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done

  echo "No OVMF firmware found. Set OVMF_CODE or install OVMF/edk2-ovmf." >&2
  return 1
}

qemu_harness_find_ovmf_vars() {
  local path

  if [ -n "${OVMF_VARS:-}" ]; then
    if [ -f "$OVMF_VARS" ]; then
      printf '%s\n' "$OVMF_VARS"
      return 0
    fi
    echo "OVMF_VARS is set but does not exist: $OVMF_VARS" >&2
    return 1
  fi

  for path in \
    /usr/share/OVMF/OVMF_VARS.fd \
    /usr/share/OVMF/OVMF_VARS_4M.fd \
    /usr/share/edk2/ovmf/OVMF_VARS.fd \
    /usr/share/edk2/ovmf/OVMF_VARS_4M.fd \
    /usr/share/edk2/x64/OVMF_VARS.fd \
    /usr/share/qemu/edk2-x86_64-vars.fd \
    /opt/homebrew/share/qemu/edk2-x86_64-vars.fd \
    /usr/local/share/qemu/edk2-x86_64-vars.fd; do
    if [ -f "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done

  return 1
}

qemu_harness_build_uefi_cdrom_command() {
  local iso_path="${1:?ISO path required}"
  local memory_size="${2:?QEMU memory size required}"
  local serial_target="${3:?serial target required}"
  local ovmf_code
  local ovmf_vars
  local ovmf_vars_copy

  qemu_harness_require_binary
  qemu_harness_load_extra_args
  ovmf_code="$(qemu_harness_find_ovmf_code)"

  QEMU_HARNESS_COMMAND=(
    "$(qemu_harness_binary)"
    -machine q35
    -cpu "$(qemu_harness_cpu_model)"
    -m "$memory_size"
    -display none
    -serial "$serial_target"
    -monitor none
    -no-reboot
    -no-shutdown
  )

  if ovmf_vars="$(qemu_harness_find_ovmf_vars)"; then
    ovmf_vars_copy="${QEMU_OVMF_VARS_COPY:-build/ovmf-vars.fd}"
    mkdir -p "$(dirname "$ovmf_vars_copy")"
    cp "$ovmf_vars" "$ovmf_vars_copy"
    QEMU_HARNESS_COMMAND+=(
      -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code"
      -drive "if=pflash,format=raw,file=$ovmf_vars_copy"
    )
  else
    QEMU_HARNESS_COMMAND+=(-bios "$ovmf_code")
  fi

  QEMU_HARNESS_COMMAND+=(-cdrom "$iso_path" -boot d)
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
  # Modeled device inventory for QEMU smoke/sync boots that use the production
  # .none kernel on emulators without first-target PCI hardware.
  QEMU_KERNEL_APPEND="${QEMU_KERNEL_APPEND:-model_inventory}"

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
    "$@"
  qemu_harness_append_native_store_drive "$store_image"
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
  local remaining="${QEMU_STOP_GRACE_SECONDS:-10}"
  kill -TERM "$qemu_pid" >/dev/null 2>&1 || true
  while [ "$remaining" -gt 0 ]; do
    if ! kill -0 "$qemu_pid" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    remaining=$((remaining - 1))
  done
  kill -KILL "$qemu_pid" >/dev/null 2>&1 || true
}

qemu_harness_run_native_store_until_marker() {
  # Marker-driven QEMU boots need modeled inventory for production driver
  # binding unless a caller supplied a stricter kernel command line.
  QEMU_KERNEL_APPEND="${QEMU_KERNEL_APPEND:-model_inventory}"

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
  local marker_stop_delay="${QEMU_MARKER_STOP_DELAY:-1}"

  mkdir -p "$(dirname "$serial_log_path")"
  rm -f "$serial_log_path"
  qemu_log_path="${serial_log_path%.log}.qemu.log"
  rm -f "$qemu_log_path"

  qemu_harness_build_kernel_command \
    "$kernel_path" \
    "$memory_size" \
    "file:$serial_log_path" \
    yes \
    no
  qemu_harness_append_native_store_drive "$store_image"

  "${QEMU_HARNESS_COMMAND[@]}" >"$qemu_log_path" 2>&1 &
  qemu_pid=$!

  while kill -0 "$qemu_pid" >/dev/null 2>&1; do
    if [ -s "$serial_log_path" ] && grep -Fq "$validation_marker" "$serial_log_path"; then
      marker_seen=1
      sleep "$marker_stop_delay"
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

qemu_harness_run_uefi_cdrom_for_seconds() {
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

  qemu_harness_build_uefi_cdrom_command "$iso_path" "$memory_size" "file:$serial_log_path"
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
    uefi-cdrom)
      shift
      qemu_harness_run_uefi_cdrom_for_seconds "$@"
      ;;
    *)
      echo "usage: $0 {kernel|native-store|uefi-cdrom} ..." >&2
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  qemu_harness_main "$@"
fi
