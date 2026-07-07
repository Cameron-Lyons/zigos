#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
ZIG="${ROOT_DIR}/scripts/zig.sh"

log() {
  printf '%s\n' "$*"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

find_ovmf_code() {
  local path

  for path in \
    "${OVMF_CODE:-}" \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.fd \
    /usr/share/edk2/ovmf/OVMF_CODE_4M.fd \
    /usr/share/edk2/x64/OVMF_CODE.fd \
    /usr/share/qemu/edk2-x86_64-code.fd \
    /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
    /usr/local/share/qemu/edk2-x86_64-code.fd; do
    [ -n "$path" ] || continue
    if [ -f "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done

  return 1
}

sudo_cmd() {
  if [ "${EUID}" -eq 0 ]; then
    printf ''
    return
  fi

  if have_cmd sudo; then
    printf 'sudo'
    return
  fi

  log "sudo is required when not running as root."
  exit 1
}

install_macos() {
  if ! have_cmd brew; then
    log "Homebrew is required on macOS. Install from https://brew.sh"
    exit 1
  fi

  log "Installing dependencies with Homebrew..."
  brew install zig nasm qemu dosfstools xorriso mtools x86_64-elf-grub
}

install_apt() {
  local s
  s="$(sudo_cmd)"

  log "Installing dependencies with apt..."
  ${s} apt-get update
  ${s} apt-get install -y nasm qemu-system-x86 ovmf grub-common grub-pc-bin dosfstools xorriso mtools

  if ! have_cmd zig; then
    if ! ${s} apt-get install -y zig; then
      log "Could not install Zig from apt on this distro. Install Zig 0.16.0 exactly from https://ziglang.org/download/ or use mise."
    fi
  fi
}

install_dnf() {
  local s
  s="$(sudo_cmd)"

  log "Installing dependencies with dnf..."
  ${s} dnf install -y zig nasm qemu-system-x86 edk2-ovmf grub2-tools grub2-tools-extra dosfstools xorriso mtools
}

install_pacman() {
  local s
  s="$(sudo_cmd)"

  log "Installing dependencies with pacman..."
  ${s} pacman -Sy --noconfirm zig nasm grub edk2-ovmf dosfstools xorriso mtools

  if ! ${s} pacman -S --noconfirm qemu-full; then
    if ! ${s} pacman -S --noconfirm qemu-desktop; then
      ${s} pacman -S --noconfirm qemu
    fi
  fi
}

verify_tools() {
  log "Verifying toolchain..."

  local missing=0
  for cmd in nasm qemu-system-x86_64 xorriso mformat mcopy mmd mkfs.fat; do
    if ! have_cmd "${cmd}"; then
      log "Missing command: ${cmd}"
      missing=1
    fi
  done

  if ! "${ZIG}" version >/dev/null 2>&1; then
    log "Missing Zig 0.16.0. Install it exactly, use mise, or set ZIG_BIN."
    missing=1
  fi

  local grub_cmd=""
  for cmd in x86_64-elf-grub-mkrescue grub-mkrescue; do
    if have_cmd "${cmd}"; then
      grub_cmd="${cmd}"
      break
    fi
  done
  if [ -z "${grub_cmd}" ]; then
    log "Missing GRUB mkrescue command."
    missing=1
  fi

  local ovmf_code=""
  if ovmf_code="$(find_ovmf_code)"; then
    log "Using OVMF firmware: ${ovmf_code}"
  else
    log "Missing OVMF firmware. Install OVMF/edk2-ovmf or set OVMF_CODE for uefi-qemu-test."
    missing=1
  fi

  if [ "${missing}" -ne 0 ]; then
    log "Dependency setup completed with missing tools."
    exit 1
  fi

  log "Using Zig: $("${ZIG}" version)"
  log "Using GRUB mkrescue: ${grub_cmd}"
  log "Dependency verification passed."
}

case "$(uname -s)" in
  Darwin)
    install_macos
    ;;
  Linux)
    if have_cmd apt-get; then
      install_apt
    elif have_cmd dnf; then
      install_dnf
    elif have_cmd pacman; then
      install_pacman
    else
      log "Unsupported Linux package manager. Supported: apt, dnf, pacman."
      exit 1
    fi
    ;;
  *)
    log "Unsupported OS: $(uname -s)"
    exit 1
    ;;
esac

verify_tools
log "Dependency setup complete."
