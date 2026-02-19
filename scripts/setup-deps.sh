#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s\n' "$*"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_macos() {
  if ! have_cmd brew; then
    log "Homebrew is required on macOS. Install from https://brew.sh"
    exit 1
  fi

  log "Installing dependencies with Homebrew..."
  brew install zig nasm qemu xorriso mtools i686-elf-grub
}

install_ubuntu() {
  if ! have_cmd apt-get; then
    log "apt-get is required for Ubuntu setup."
    exit 1
  fi

  local sudo_cmd=""
  if [ "${EUID}" -ne 0 ]; then
    if have_cmd sudo; then
      sudo_cmd="sudo"
    else
      log "sudo is required when not running as root."
      exit 1
    fi
  fi

  log "Installing dependencies with apt..."
  ${sudo_cmd} apt-get update
  ${sudo_cmd} apt-get install -y nasm qemu-system-x86 qemu-system-i386 grub-common grub-pc-bin xorriso mtools

  if ! have_cmd zig; then
    if ! ${sudo_cmd} apt-get install -y zig; then
      log "Could not install Zig from apt on this distro. Install Zig 0.15.2+ from https://ziglang.org/download/"
    fi
  fi
}

case "$(uname -s)" in
  Darwin)
    install_macos
    ;;
  Linux)
    install_ubuntu
    ;;
  *)
    log "Unsupported OS: $(uname -s)"
    exit 1
    ;;
esac

log "Dependency setup complete."
