#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=scripts/qemu-harness.sh
source "$SCRIPT_DIR/qemu-harness.sh"

IMAGE_PATH="${1:?unified EFI image required}"
KERNEL_PATH="${2:?embedded kernel ELF required}"
CMDLINE_PATH="${3:?embedded command line required}"
TEST_DIR="${4:?test output directory required}"
TEST_PYTHON="${EFI_TEST_PYTHON:-python3}"
VARS_TOOL="${EFI_VARS_TOOL:-virt-fw-vars}"
OVMF_CODE="${OVMF_SECURE_BOOT_CODE:?set OVMF_SECURE_BOOT_CODE to a Secure Boot capable OVMF image}"
VARS_TEMPLATE="${OVMF_SECURE_BOOT_VARS:-$(qemu_harness_find_ovmf_vars)}"
BOOT_SECONDS="${EFI_TEST_SECONDS:-20}"
SWTPM_BIN="${SWTPM_BIN:-swtpm}"
SWTPM_SETUP_BIN="${SWTPM_SETUP_BIN:-swtpm_setup}"
TPM_WORK="$(mktemp -d /tmp/zigos-efi-tpm.XXXXXXXX)"
TPM_PID=""
stop_tpm() {
  if [ -n "$TPM_PID" ]; then
    qemu_harness_stop_qemu "$TPM_PID"
    wait "$TPM_PID" 2>/dev/null || true
    TPM_PID=""
  fi
}
cleanup() { stop_tpm; rm -rf -- "$TPM_WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$TEST_DIR"
"$TEST_PYTHON" "$SCRIPT_DIR/prepare-unified-efi-test.py" "$IMAGE_PATH" "$KERNEL_PATH" "$CMDLINE_PATH" "$TEST_DIR"
# These keys and variable stores exist only in this test's VM. Authorize the
# complete PE Authenticode digest; no host firmware or release key is involved.
"$VARS_TOOL" --input "$VARS_TEMPLATE" --output "$TEST_DIR/authorized-vars.fd" \
  --enroll-generate "Zigos disposable firmware test" --no-microsoft --microsoft-kek none \
  --add-db-hash 4ea05883-5aa1-4b23-a876-0e36079efa1d "$(cat "$TEST_DIR/image.sha256")" --secure-boot

run_case() {
  local name="$1" vars="$2" expected="$3" banks="${4:-}"
  local log="$TEST_DIR/$name.log" status attempt
  OVMF_VARS="$vars"
  bash "$SCRIPT_DIR/build-native-store.sh" "$TEST_DIR/$name.store" 8 reset
  rm -f "$log"
  mkdir "$TPM_WORK/$name"
  if [ -n "$banks" ]; then
    "$SWTPM_SETUP_BIN" --tpm2 --tpm "$(command -v "$SWTPM_BIN") socket" --tpmstate "$TPM_WORK/$name" \
      --config /dev/null --pcr-banks "$banks" >"$TEST_DIR/$name.setup.log" 2>&1
  fi
  "$SWTPM_BIN" socket --tpm2 --tpmstate "dir=$TPM_WORK/$name" \
    --ctrl "type=unixio,path=$TPM_WORK/control.sock" >"$TEST_DIR/$name.swtpm.log" 2>&1 &
  TPM_PID=$!
  for ((attempt = 0; attempt < 50; attempt++)); do
    if [ -S "$TPM_WORK/control.sock" ] && kill -0 "$TPM_PID" 2>/dev/null; then break; fi
    if ! kill -0 "$TPM_PID" 2>/dev/null; then cat "$TEST_DIR/$name.swtpm.log" >&2; return 1; fi
    sleep 0.1
  done
  test -S "$TPM_WORK/control.sock"
  qemu_harness_build_uefi_cdrom_command "$TEST_DIR/$name.iso" "$(qemu_harness_default_memory)" "file:$log"
  QEMU_HARNESS_COMMAND+=(-machine smm=on -global "driver=cfi.pflash01,property=secure,value=on")
  QEMU_HARNESS_COMMAND+=(-chardev "socket,id=zigos_tpm_socket,path=$TPM_WORK/control.sock" \
    -tpmdev "emulator,id=zigos_tpm,chardev=zigos_tpm_socket" -device "tpm-crb,tpmdev=zigos_tpm")
  qemu_harness_append_native_store_drive "$TEST_DIR/$name.store"
  status=0
  timeout --kill-after=5s "${BOOT_SECONDS}s" "${QEMU_HARNESS_COMMAND[@]}" >"$TEST_DIR/$name.qemu.log" 2>&1 || status=$?
  stop_tpm
  rm -f "$TPM_WORK/control.sock"
  if [[ "$status" != 0 && "$status" != 124 && "$status" != "$qemu_harness_success_exit" ]]; then
    cat "$TEST_DIR/$name.qemu.log" >&2
    return 1
  fi
  if [[ "$expected" == measurement-rejected ]]; then
    if grep -Fq 'BOOT:START' "$log" || ! grep -Fq 'EFI:FAIL:tpm-measurement' "$log"; then
      echo "Loader did not reject unsupported TPM banks before kernel entry" >&2
      cat "$log" >&2
      return 1
    fi
  elif [[ "$expected" == rejected ]]; then
    if grep -Fq 'BOOT:START' "$log" || ! grep -Eq 'Security Violation|Access Denied' "$log"; then
      echo "Firmware did not reject $name before kernel entry" >&2
      cat "$log" >&2
      return 1
    fi
  else
    grep -Fqx 'ZIGOS:NATIVE:READY' "$log"
    grep -Fqx 'ZIGOS:TPM2:BOOT_MEASUREMENT:VERIFIED' "$log"
    grep -Fqx "ZIGOS:PLATFORM:BOOT_IMAGE:$expected" "$log"
    if grep -Eq 'PANIC|:FAIL|System Halted' "$log"; then return 1; fi
    if [[ "$expected" == UNVERIFIED ]]; then
      if grep -Eq 'BOOT_IMAGE:FIRMWARE_AUTHENTICATED|MEASURED_BOOT:VERIFIED_ROOT' "$log"; then return 1; fi
    else
      grep -Fqx 'ZIGOS:PLATFORM:MEASURED_BOOT:VERIFIED_ROOT' "$log"
    fi
  fi
  echo "Unified EFI firmware case passed: $name"
}

for name in original tampered-kernel tampered-cmdline; do
  bash "$SCRIPT_DIR/build-efi-iso.sh" "$TEST_DIR/$name.efi" "$TEST_DIR/$name.iso" "$TEST_DIR/$name.staging" >"$TEST_DIR/$name.media.log" 2>&1
done
cp "$TEST_DIR/original.iso" "$TEST_DIR/unverified.iso"
run_case unverified "$VARS_TEMPLATE" UNVERIFIED
run_case original "$TEST_DIR/authorized-vars.fd" FIRMWARE_AUTHENTICATED
run_case tampered-kernel "$TEST_DIR/authorized-vars.fd" rejected
run_case tampered-cmdline "$TEST_DIR/authorized-vars.fd" rejected

# Unauthenticated sidecar files cannot override bytes embedded in the EFI image.
rm -rf -- "$TEST_DIR/sidecars.staging"
cp -a "$TEST_DIR/original.staging" "$TEST_DIR/sidecars.staging"
printf 'invalid ELF\n' >"$TEST_DIR/kernel.elf"
printf 'untrusted_external_options\n' >"$TEST_DIR/cmdline.txt"
mmd -i "$TEST_DIR/sidecars.staging/esp.img" ::/boot
mcopy -i "$TEST_DIR/sidecars.staging/esp.img" "$TEST_DIR/kernel.elf" "$TEST_DIR/cmdline.txt" ::/boot/
xorriso -as mkisofs -R -J -e esp.img -no-emul-boot -o "$TEST_DIR/sidecars.iso" "$TEST_DIR/sidecars.staging" >"$TEST_DIR/sidecars.media.log" 2>&1
run_case sidecars "$TEST_DIR/authorized-vars.fd" FIRMWARE_AUTHENTICATED
cp "$TEST_DIR/original.iso" "$TEST_DIR/no-sha256.iso"
run_case no-sha256 "$TEST_DIR/authorized-vars.fd" measurement-rejected sha1
echo "Unified EFI authentication, TPM measurement, payload tampering, and external override checks passed. Logs: $TEST_DIR"
