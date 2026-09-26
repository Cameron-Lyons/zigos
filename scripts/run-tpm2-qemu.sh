#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/qemu-harness.sh"

KERNEL_PATH="${1:?kernel path required}"
MODE="${2:-transport}"
case "$MODE" in transport|sealing) ;; *) echo "Unknown TPM test mode: $MODE" >&2; exit 2 ;; esac
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
if [ "$MODE" = sealing ]; then LOG_DIR="$ROOT_DIR/build/tpm2-sealing-qemu"; fi
STORE_IMAGE="$LOG_DIR/native-store.img"
mkdir -p "$TPM_WORK/state" "$LOG_DIR"

stop_tpm() {
  if [ -n "$TPM_PID" ]; then
    qemu_harness_stop_qemu "$TPM_PID"
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
  local sealing_marker="${4:-}"
  local log="$LOG_DIR/$name.log"
  export QEMU_EXTRA_ARGS="$BASE_EXTRA_ARGS"
  if [ "$device" != none ]; then
    start_tpm "$name"
    QEMU_EXTRA_ARGS+=" -chardev socket,id=zigos_tpm_socket,path=$TPM_WORK/control.sock -tpmdev emulator,id=zigos_tpm,chardev=zigos_tpm_socket -device $device,tpmdev=zigos_tpm"
  fi
  qemu_harness_run_native_store_until_marker "$KERNEL_PATH" "$STORE_IMAGE" "$log" \
    'ZIGOS:NATIVE:READY' "${TPM2_QEMU_SECONDS:-90}"
  stop_tpm
  if [ "$(grep -Ec '^ZIGOS:TPM2:(CRB_READY|UNAVAILABLE)' "$log")" -ne 1 ] || ! grep -Fxq "$expected" "$log"; then
    cat "$log" >&2
    echo "TPM2 device result mismatch for $name" >&2
    return 1
  fi
  if [ -n "$sealing_marker" ]; then
    if [ "$(grep -c '^ZIGOS:TPM2:SEAL:' "$log")" -ne 1 ] || ! grep -Fxq "$sealing_marker" "$log"; then
      cat "$log" >&2
      echo "TPM2 sealing result mismatch for $name" >&2
      return 1
    fi
    local vault_marker="${sealing_marker/:SEAL:/:VAULT:}"
    if [ "$(grep -c '^ZIGOS:TPM2:VAULT:' "$log")" -ne 1 ] || ! grep -Fxq "$vault_marker" "$log"; then
      cat "$log" >&2
      echo "TPM2 vault result mismatch for $name" >&2
      return 1
    fi
  else
    bash "$SCRIPT_DIR/check-production-boot-log.sh" "$log"
  fi
  echo "TPM2 QEMU $name: PASS"
}

bash "$SCRIPT_DIR/build-native-store.sh" "$STORE_IMAGE" 8 reset
if [ "$MODE" = sealing ]; then
  run_boot cold tpm-crb 'ZIGOS:TPM2:CRB_READY' 'ZIGOS:TPM2:SEAL:CREATED'
  # Give both restart cases the same persisted sealed object. Verification
  # fixtures mutate other records on each boot and are not a soak workload.
  cp --sparse=always "$STORE_IMAGE" "$TPM_WORK/sealed-store.img"
  run_boot reboot tpm-crb 'ZIGOS:TPM2:CRB_READY' 'ZIGOS:TPM2:SEAL:RECOVERED'
  # Restore that disk snapshot and replace the TPM, including its owner seed.
  cp --sparse=always "$TPM_WORK/sealed-store.img" "$STORE_IMAGE"
  mv "$TPM_WORK/state" "$TPM_WORK/original-state"
  mkdir "$TPM_WORK/state"
  run_boot different-tpm tpm-crb 'ZIGOS:TPM2:CRB_READY' 'ZIGOS:TPM2:SEAL:WRONG_DEVICE'
else
  run_boot cold tpm-crb 'ZIGOS:TPM2:CRB_READY'
  # Restart both the VM and emulator with the same TPM persistent state.
  run_boot reboot tpm-crb 'ZIGOS:TPM2:CRB_READY'
  run_boot unsupported-fifo tpm-tis 'ZIGOS:TPM2:UNAVAILABLE NoSupportedDevice'
  run_boot absent none 'ZIGOS:TPM2:UNAVAILABLE NoSupportedDevice'
fi
