#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s\n' "$*"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
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
  brew install zig nasm qemu dosfstools e2fsprogs xorriso mtools i686-elf-grub
}

install_apt() {
  local s
  s="$(sudo_cmd)"

  log "Installing dependencies with apt..."
  ${s} apt-get update
  ${s} apt-get install -y nasm qemu-system-x86 qemu-system-i386 grub-common grub-pc-bin dosfstools e2fsprogs xorriso mtools

  if ! have_cmd zig; then
    if ! ${s} apt-get install -y zig; then
      log "Could not install Zig from apt on this distro. Install Zig 0.15.2+ from https://ziglang.org/download/"
    fi
  fi
}

install_dnf() {
  local s
  s="$(sudo_cmd)"

  log "Installing dependencies with dnf..."
  ${s} dnf install -y zig nasm qemu-system-x86 grub2-tools grub2-tools-extra dosfstools e2fsprogs xorriso mtools
}

install_pacman() {
  local s
  s="$(sudo_cmd)"

  log "Installing dependencies with pacman..."
  ${s} pacman -Sy --noconfirm zig nasm grub dosfstools e2fsprogs xorriso mtools

  if ! ${s} pacman -S --noconfirm qemu-full; then
    if ! ${s} pacman -S --noconfirm qemu-desktop; then
      ${s} pacman -S --noconfirm qemu
    fi
  fi
}

verify_tools() {
  log "Verifying toolchain..."

  local missing=0
  for cmd in zig nasm qemu-system-x86_64 xorriso mformat mcopy mmd mkfs.fat mke2fs; do
    if ! have_cmd "${cmd}"; then
      log "Missing command: ${cmd}"
      missing=1
    fi
  done

  local grub_cmd=""
  for cmd in grub-mkrescue i686-elf-grub-mkrescue x86_64-elf-grub-mkrescue; do
    if have_cmd "${cmd}"; then
      grub_cmd="${cmd}"
      break
    fi
  done
  if [ -z "${grub_cmd}" ]; then
    log "Missing GRUB mkrescue command."
    missing=1
  fi

  if [ "${missing}" -ne 0 ]; then
    log "Dependency setup completed with missing tools."
    exit 1
  fi

  log "Using Zig: $(zig version)"
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
