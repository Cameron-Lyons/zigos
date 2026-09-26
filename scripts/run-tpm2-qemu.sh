#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/qemu-harness.sh"

KERNEL_PATH="${1:?kernel path required}"
SWTPM_BIN="${SWTPM_BIN:-swtpm}"
if ! command -v "$SWTPM_BIN" >/dev/null 2>&1; then
  echo "swtpm is required for TPM2 device validation; set SWTPM_BIN or install swtpm." >&2
  exit 1
fi
qemu_harness_require_binary
TPM_WORK="$(mktemp -d /tmp/zigos-tpm2.XXXXXXXX)"
TPM_PID=""
BASE_EXTRA_ARGS="${QEMU_EXTRA_ARGS:-}"
LOG_DIR="$ROOT_DIR/build/tpm2-qemu"
STORE_IMAGE="$LOG_DIR/native-store.img"
mkdir -p "$TPM_WORK/state" "$LOG_DIR"

stop_tpm() {
  if [ -n "$TPM_PID" ]; then
    kill "$TPM_PID" 2>/dev/null || true
    wait "$TPM_PID" 2>/dev/null || true
    TPM_PID=""
  fi
}
cleanup() {
  stop_tpm
  rm -rf "$TPM_WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_tpm() {
  local name="$1"
  local attempt
  rm -f "$TPM_WORK/control.sock"
  "$SWTPM_BIN" socket --tpm2 --tpmstate "dir=$TPM_WORK/state" \
    --ctrl "type=unixio,path=$TPM_WORK/control.sock" >"$LOG_DIR/$name.swtpm.log" 2>&1 &
  TPM_PID=$!
  for attempt in {1..50}; do
    if [ -S "$TPM_WORK/control.sock" ] && kill -0 "$TPM_PID" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$TPM_PID" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  cat "$LOG_DIR/$name.swtpm.log" >&2
  echo "swtpm did not become ready" >&2
  return 1
}

run_boot() {
  local name="$1"
  local device="$2"
  local expected="$3"
  local log="$LOG_DIR/$name.log"
  export QEMU_EXTRA_ARGS="$BASE_EXTRA_ARGS"
  if [ "$device" != none ]; then
    start_tpm "$name"
    QEMU_EXTRA_ARGS+=" -chardev socket,id=zigos_tpm_socket,path=$TPM_WORK/control.sock -tpmdev emulator,id=zigos_tpm,chardev=zigos_tpm_socket -device $device,tpmdev=zigos_tpm"
  fi
  qemu_harness_run_native_store_until_marker "$KERNEL_PATH" "$STORE_IMAGE" "$log" \
    'ZIGOS:NATIVE:READY' "${TPM2_QEMU_SECONDS:-90}"
  stop_tpm
  if [ "$(grep -c '^ZIGOS:TPM2:' "$log")" -ne 1 ] || ! grep -Fxq "$expected" "$log"; then
    cat "$log" >&2
    echo "TPM2 device result mismatch for $name" >&2
    return 1
  fi
  bash "$SCRIPT_DIR/check-production-boot-log.sh" "$log"
  echo "TPM2 QEMU $name: PASS"
}

bash "$SCRIPT_DIR/build-native-store.sh" "$STORE_IMAGE" 8 reset
run_boot cold tpm-crb 'ZIGOS:TPM2:CRB_READY'
# Restart both the VM and emulator with the same TPM persistent state.
run_boot reboot tpm-crb 'ZIGOS:TPM2:CRB_READY'
run_boot unsupported-fifo tpm-tis 'ZIGOS:TPM2:UNAVAILABLE NoSupportedDevice'
run_boot absent none 'ZIGOS:TPM2:UNAVAILABLE NoSupportedDevice'
