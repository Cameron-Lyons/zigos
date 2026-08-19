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

find_grub_module_dir() {
  local grub_cmd="$1"
  local grub_path prefix path

  grub_path="$(command -v "${grub_cmd}")"
  prefix="${grub_path%/bin/*}"
  for path in \
    "${GRUB_MODULE_DIR:-}" \
    "${prefix}/lib/x86_64-elf/grub/x86_64-efi" \
    /usr/lib/grub/x86_64-efi \
    /usr/lib64/grub/x86_64-efi \
    /usr/share/grub/x86_64-efi; do
    [ -n "${path}" ] || continue
    if [ -f "${path}/modinfo.sh" ]; then
      printf '%s\n' "${path}"
      return 0
    fi
  done

  return 1
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
  local s source
  local -a apt_options=(
    -o Acquire::Retries=4
    -o Acquire::http::Timeout=30
    -o Acquire::https::Timeout=30
    -o Acquire::ForceIPv4=true
  )
  s="$(sudo_cmd)"

  log "Installing dependencies with apt..."
  if [ -f /etc/apt/apt-mirrors.txt ]; then
    ${s} sed -i '\|azure.archive.ubuntu.com|d' /etc/apt/apt-mirrors.txt
  fi
  for source in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do
    [ -f "${source}" ] || continue
    ${s} sed -i 's|http://azure.archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' "${source}"
  done
  ${s} apt-get "${apt_options[@]}" update
  ${s} apt-get "${apt_options[@]}" install -y nasm qemu-system-x86 ovmf grub-common grub-efi-amd64-bin dosfstools xorriso mtools

  if ! have_cmd zig; then
    if ! ${s} apt-get "${apt_options[@]}" install -y zig; then
      log "Could not install Zig from apt on this distro. Install Zig 0.16.0 exactly from https://ziglang.org/download/ or use mise."
    fi
  fi
}

install_dnf() {
  local s
  s="$(sudo_cmd)"

  log "Installing dependencies with dnf..."
  ${s} dnf install -y zig nasm qemu-system-x86 edk2-ovmf grub2-tools grub2-tools-extra grub2-efi-x64-modules dosfstools xorriso mtools
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
    log "Missing x86-64 EFI-capable GRUB mkrescue command."
    missing=1
  fi

  local grub_module_dir=""
  if [ -n "${grub_cmd}" ] && grub_module_dir="$(find_grub_module_dir "${grub_cmd}")"; then
    log "Using x86-64 EFI GRUB modules: ${grub_module_dir}"
  else
    log "Missing x86-64 EFI GRUB modules. Install them or set GRUB_MODULE_DIR."
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
