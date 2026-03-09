# ZigOS

A minimal operating system written in Zig with networking capabilities. ZigOS is a hobby operating system that implements core kernel functionality including process management, memory management, filesystem support, and a complete networking stack.

The kernel supports multitasking with preemptive scheduling, virtual memory management with paging, and system calls for user programs. It includes drivers for common hardware including VGA text mode, keyboard, ATA disks, and multiple network cards (RTL8139, E1000, and VirtIO). The networking stack implements Ethernet, ARP, IPv4, ICMP, TCP, UDP, DHCP, DNS, and HTTP protocols, allowing the system to connect to networks and make HTTP requests.

Filesystem support includes both FAT32 and ext2 filesystems through a virtual filesystem layer. The system includes a built-in shell with text editing capabilities and supports loading and running ELF executables in user mode. SMP support enables the kernel to utilize multiple CPU cores.

## Requirements

- Zig compiler (0.15.2 or later)
- NASM assembler
- QEMU for testing
- For ISO builds: GRUB `mkrescue`, `xorriso`, and `mtools`

### macOS (Homebrew)

```bash
brew install zig nasm qemu xorriso mtools i686-elf-grub
```

### Linux Packages

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y zig nasm qemu-system-x86 qemu-system-i386 grub-common grub-pc-bin xorriso mtools
```

Fedora:

```bash
sudo dnf install -y zig nasm qemu-system-x86 grub2-tools grub2-tools-extra xorriso mtools
```

Arch Linux:

```bash
sudo pacman -Sy --noconfirm zig nasm grub xorriso mtools qemu-full
```

### One-Command Setup

```bash
./scripts/setup-deps.sh
```

The script supports macOS (Homebrew) and Linux systems with `apt`, `dnf`, or `pacman`.

## Building and Running

```bash
# Build the development kernel
zig build kernel

# Run the development profile in QEMU
zig build run

# Build the CI smoke-test profile
zig build kernel-ci-smoke

# Build the VM-test profile
zig build kernel-test-vm

# Build a bootable ISO from the development profile
zig build iso

# Run the ISO boot smoke test
zig build boot-test

# Run the CI smoke profile directly in QEMU
zig build run-ci-smoke

# Run the VM test profile directly in QEMU
zig build run-test-vm
```

`zig build iso` auto-detects `grub-mkrescue`, `i686-elf-grub-mkrescue`, or `x86_64-elf-grub-mkrescue`. You can override detection with:

```bash
GRUB_MKRESCUE=/path/to/grub-mkrescue zig build iso
```

`zig build boot-test` builds the ISO, boots it headlessly in QEMU, and verifies required boot markers. Optional overrides:

```bash
QEMU_BIN=qemu-system-x86_64 BOOT_TEST_SECONDS=15 zig build boot-test
```

## Boot Profiles

- `dev`: starts the interactive shell and demo processes
- `ci_smoke`: boots core services, initializes the shell, emits serial markers, and exits through QEMU debug-exit
- `test_vm`: runs the virtual memory test suite and exits through QEMU debug-exit

## Smoke Boot Verification

Use the smoke-test wrapper to build the `ci_smoke` profile, run QEMU headlessly, and verify the expected serial markers.

```bash
./test_kernel.sh
```

Successful smoke boots emit these serial markers:

- `BOOT:START`
- `BOOT:PROFILE:ci_smoke`
- `BOOT:CORE_READY`
- `BOOT:SHELL_READY`
- `BOOT:PASS`
