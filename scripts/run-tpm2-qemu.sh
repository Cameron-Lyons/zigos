#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/qemu-harness.sh
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
  for ((attempt = 0; attempt < 50; attempt++)); do
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

check_transport_proof() {
  local log="$1"
  if [ "$(grep -c '^ZIGOS:TPM2:ASYNC_TRANSPORT:' "$log" || true)" -ne 1 ] ||
    ! grep -Fxq 'ZIGOS:TPM2:ASYNC_TRANSPORT:VERIFIED' "$log"; then
    cat "$log" >&2
    echo 'TPM2 asynchronous transport proof mismatch' >&2
    return 1
  fi
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
    check_transport_proof "$log"
    local pin_marker='ZIGOS:TPM2:PIN:VERIFIED'
    local session_proofs=1
    if [ "$name" = different-tpm ]; then session_proofs=0; fi
    if [ "$(grep -c '^ZIGOS:TPM2:SESSION:' "$log" || true)" -ne "$session_proofs" ] ||
      [ "$(grep -c '^ZIGOS:TPM2:PIN_INPUT:' "$log" || true)" -ne "$session_proofs" ] ||
      { [ "$session_proofs" -eq 1 ] && ! grep -Fxq 'ZIGOS:TPM2:PIN_INPUT:VERIFIED' "$log"; } ||
      { [ "$session_proofs" -eq 1 ] && ! grep -Fxq 'ZIGOS:TPM2:SESSION:VERIFIED' "$log"; }; then
      cat "$log" >&2
      echo "TPM2 identity session mismatch for $name" >&2
      return 1
    fi
    if [ "$name" = different-tpm ]; then pin_marker='ZIGOS:TPM2:PIN:WRONG_DEVICE'; fi
    if [ "$(grep -c '^ZIGOS:TPM2:PIN:' "$log" || true)" -ne 1 ] || ! grep -Fxq "$pin_marker" "$log"; then
      cat "$log" >&2
      echo "TPM2 PIN verification mismatch for $name" >&2
      return 1
    fi
    local enrollment_marker='ZIGOS:TPM2:ENROLLMENT_RECOVERY:VERIFIED'
    if [ "$name" = cold ]; then enrollment_marker='ZIGOS:TPM2:ENROLLMENT_RECOVERY:COMMITTED'; fi
    if [ "$name" = different-tpm ]; then enrollment_marker='ZIGOS:TPM2:ENROLLMENT_RECOVERY:MISSING'; fi
    if [ "$(grep -c '^ZIGOS:TPM2:ENROLLMENT_RECOVERY:' "$log" || true)" -ne 1 ] || ! grep -Fxq "$enrollment_marker" "$log"; then
      cat "$log" >&2
      echo "TPM2 initial enrollment recovery mismatch for $name" >&2
      return 1
    fi
    if [ "$(grep -c '^ZIGOS:TPM2:SEAL:' "$log")" -ne 1 ] || ! grep -Fxq "$sealing_marker" "$log"; then
      cat "$log" >&2
      echo "TPM2 sealing result mismatch for $name" >&2
      return 1
    fi
    local vault_marker="${5:-${sealing_marker/:SEAL:/:VAULT:}}"
    if [ "$(grep -c '^ZIGOS:TPM2:VAULT:' "$log")" -ne 1 ] || ! grep -Fxq "$vault_marker" "$log"; then
      cat "$log" >&2
      echo "TPM2 vault result mismatch for $name" >&2
      return 1
    fi
    local expected_proofs=1 proof
    if [[ "$vault_marker" == *:WRONG_DEVICE || "$vault_marker" == *:ROLLBACK_REJECTED ]]; then expected_proofs=0; fi
    for proof in IDENTITY:SIGNED KEYGEN:DISTINCT DOCUMENT:SIGNING PEER:AUTHENTICATED; do
      if [ "$(grep -c "^ZIGOS:TPM2:${proof%%:*}:" "$log" || true)" -ne "$expected_proofs" ] ||
        { [ "$expected_proofs" -eq 1 ] && ! grep -Fxq "ZIGOS:TPM2:$proof" "$log"; }; then
        cat "$log" >&2
        echo "TPM2 $proof result mismatch for $name" >&2
        return 1
      fi
    done
    local durable_kind durable_marker
    for durable_kind in CATALOG CREDENTIALS ENROLLMENT PUBLIC_ENROLLMENT PUBLIC_ROTATION KEY_RETIREMENT; do
      durable_marker="ZIGOS:TPM2:$durable_kind:COMMITTED"
      if [ "$name" = reboot ]; then durable_marker="ZIGOS:TPM2:$durable_kind:RESTORED"; fi
      if [ "$(grep -c "^ZIGOS:TPM2:$durable_kind:" "$log" || true)" -ne "$expected_proofs" ] ||
        { [ "$expected_proofs" -eq 1 ] && ! grep -Fxq "$durable_marker" "$log"; }; then
        cat "$log" >&2
        echo "TPM2 $durable_kind durability result mismatch for $name" >&2
        return 1
      fi
    done
    local unlock_marker="ZIGOS:TPM2:UNLOCK:BOUND"
    if [ "$name" = reboot ]; then unlock_marker="ZIGOS:TPM2:UNLOCK:REPLAY_REJECTED"; fi
    if [ "$(grep -c '^ZIGOS:TPM2:UNLOCK:' "$log" || true)" -ne "$expected_proofs" ] ||
      { [ "$expected_proofs" -eq 1 ] && ! grep -Fxq "$unlock_marker" "$log"; }; then
      cat "$log" >&2
      echo "TPM2 unlock replay result mismatch for $name" >&2
      return 1
    fi
    local anchor_marker="ZIGOS:TPM2:ANCHOR:PROVISIONED" anchor_count=1 nv_count=0 retry_count=0
    case "$name" in
      cold) nv_count=1 ;;
      reboot) anchor_marker='ZIGOS:TPM2:ANCHOR:ADVANCED'; retry_count=1 ;;
      rollback) anchor_marker='ZIGOS:TPM2:ANCHOR:ROLLBACK_REJECTED' ;;
      different-tpm) anchor_count=0 ;;
    esac
    if [ "$(grep -c '^ZIGOS:TPM2:ANCHOR:' "$log" || true)" -ne "$anchor_count" ] ||
      { [ "$anchor_count" -eq 1 ] && ! grep -Fxq "$anchor_marker" "$log"; } ||
      [ "$(grep -c '^ZIGOS:TPM2:NV:' "$log" || true)" -ne "$nv_count" ] ||
      { [ "$nv_count" -eq 1 ] && ! grep -Fxq 'ZIGOS:TPM2:NV:AUTHENTICATED' "$log"; }; then
      cat "$log" >&2
      echo "TPM2 vault anchor result mismatch for $name" >&2
      return 1
    fi
    if [ "$(grep -c '^ZIGOS:TPM2:ANCHOR_RETRY:' "$log" || true)" -ne "$retry_count" ] ||
      { [ "$retry_count" -eq 1 ] && ! grep -Fxq 'ZIGOS:TPM2:ANCHOR_RETRY:RECONCILED' "$log"; }; then
      cat "$log" >&2
      echo "TPM2 ambiguous anchor write mismatch for $name" >&2
      return 1
    fi
    if [ "$(grep -c '^ZIGOS:TPM2:ANCHOR_RECOVERY:' "$log" || true)" -ne "$retry_count" ] ||
      { [ "$retry_count" -eq 1 ] && ! grep -Fxq 'ZIGOS:TPM2:ANCHOR_RECOVERY:COMMITTED' "$log"; }; then
      cat "$log" >&2
      echo "TPM2 interrupted checkpoint recovery mismatch for $name" >&2
      return 1
    fi
  else
    bash "$SCRIPT_DIR/check-production-boot-log.sh" "$log"
  fi
  echo "TPM2 QEMU $name: PASS"
}

run_interrupted_checkpoint() {
  local log="$LOG_DIR/interrupted-checkpoint.log"
  start_tpm interrupted-checkpoint
  export QEMU_EXTRA_ARGS="$BASE_EXTRA_ARGS -chardev socket,id=zigos_tpm_socket,path=$TPM_WORK/control.sock -tpmdev emulator,id=zigos_tpm,chardev=zigos_tpm_socket -device tpm-crb,tpmdev=zigos_tpm"
  # The proof disables interrupts and halts at this boundary, so stopping the
  # guest cannot race a successful NV write or an acknowledged assertion.
  qemu_harness_run_native_store_until_marker "$KERNEL_PATH" "$STORE_IMAGE" "$log" \
    'ZIGOS:TPM2:ANCHOR_RECOVERY:INTERRUPTED' "${TPM2_QEMU_SECONDS:-90}"
  stop_tpm
  check_transport_proof "$log"
  if ! grep -Fxq 'ZIGOS:TPM2:CRB_READY' "$log" ||
    ! grep -Fxq 'ZIGOS:TPM2:SEAL:RECOVERED' "$log" ||
    [ "$(grep -c '^ZIGOS:TPM2:ANCHOR_RECOVERY:' "$log" || true)" -ne 1 ] ||
    grep -Eq '^ZIGOS:TPM2:(IDENTITY|VAULT):|FAIL' "$log"; then
    cat "$log" >&2
    echo 'TPM2 interrupted checkpoint did not stop before acknowledgement' >&2
    return 1
  fi
  echo 'TPM2 QEMU interrupted checkpoint: PASS'
}

run_interrupted_enrollment() {
  local log="$LOG_DIR/interrupted-enrollment.log"
  start_tpm interrupted-enrollment
  export QEMU_EXTRA_ARGS="$BASE_EXTRA_ARGS -chardev socket,id=zigos_tpm_socket,path=$TPM_WORK/control.sock -tpmdev emulator,id=zigos_tpm,chardev=zigos_tpm_socket -device tpm-crb,tpmdev=zigos_tpm"
  qemu_harness_run_native_store_until_marker "$KERNEL_PATH" "$STORE_IMAGE" "$log" \
    'ZIGOS:TPM2:ENROLLMENT_RECOVERY:INTERRUPTED' "${TPM2_QEMU_SECONDS:-90}"
  stop_tpm
  check_transport_proof "$log"
  if ! grep -Fxq 'ZIGOS:TPM2:CRB_READY' "$log" ||
    ! grep -Fxq 'ZIGOS:TPM2:PIN:RECOVERED' "$log" ||
    ! grep -Fxq 'ZIGOS:TPM2:SESSION:VERIFIED' "$log" ||
    ! grep -Fxq 'ZIGOS:TPM2:PIN_INPUT:VERIFIED' "$log" ||
    [ "$(grep -c '^ZIGOS:TPM2:PIN:' "$log" || true)" -ne 1 ] ||
    [ "$(grep -c '^ZIGOS:TPM2:ENROLLMENT_RECOVERY:' "$log" || true)" -ne 1 ] ||
    grep -Eq '^ZIGOS:TPM2:(SEAL|IDENTITY|VAULT):|FAIL' "$log"; then
    cat "$log" >&2
    echo 'TPM2 interrupted enrollment did not stop before its first NV write' >&2
    return 1
  fi
  echo 'TPM2 QEMU interrupted enrollment: PASS'
}

run_pin_lockout() {
  local log="$LOG_DIR/pin-lockout.log"
  start_tpm pin-lockout
  export QEMU_EXTRA_ARGS="$BASE_EXTRA_ARGS -chardev socket,id=zigos_tpm_socket,path=$TPM_WORK/control.sock -tpmdev emulator,id=zigos_tpm,chardev=zigos_tpm_socket -device tpm-crb,tpmdev=zigos_tpm"
  qemu_harness_run_native_store_until_marker "$KERNEL_PATH" "$STORE_IMAGE" "$log" \
    'ZIGOS:TPM2:PIN:LOCKED' "${TPM2_QEMU_SECONDS:-90}"
  stop_tpm
  check_transport_proof "$log"
  if ! grep -Fxq 'ZIGOS:TPM2:CRB_READY' "$log" ||
    [ "$(grep -c '^ZIGOS:TPM2:PIN:' "$log" || true)" -ne 1 ] ||
    grep -Eq '^ZIGOS:TPM2:(SEAL|IDENTITY|VAULT|ENROLLMENT_RECOVERY):|FAIL' "$log"; then
    cat "$log" >&2
    echo 'TPM2 PIN proof did not stop at persistent lockout' >&2
    return 1
  fi
  echo 'TPM2 QEMU PIN lockout: PASS'
}

bash "$SCRIPT_DIR/build-native-store.sh" "$STORE_IMAGE" 8 reset
if [ "$MODE" = sealing ]; then
  run_pin_lockout
  run_interrupted_enrollment
  run_boot cold tpm-crb 'ZIGOS:TPM2:CRB_READY' 'ZIGOS:TPM2:SEAL:CREATED'
  # Give each restart case the same persisted sealed object. Verification
  # fixtures mutate other records on each boot and are not a soak workload.
  cp --sparse=always "$STORE_IMAGE" "$TPM_WORK/sealed-store.img"
  run_interrupted_checkpoint
  run_boot reboot tpm-crb 'ZIGOS:TPM2:CRB_READY' 'ZIGOS:TPM2:SEAL:RECOVERED'
  # Keep the advanced TPM state while rolling the disk back to its old catalog.
  # The sealed key remains valid; the independent NV anchor must reject restore.
  cp --sparse=always "$TPM_WORK/sealed-store.img" "$STORE_IMAGE"
  run_boot rollback tpm-crb 'ZIGOS:TPM2:CRB_READY' 'ZIGOS:TPM2:SEAL:RECOVERED' 'ZIGOS:TPM2:VAULT:ROLLBACK_REJECTED'
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
