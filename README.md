# ZigOS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A minimal operating system written in Zig with networking capabilities. ZigOS is a hobby operating system that implements core kernel functionality including process management, memory management, filesystem support, and a complete networking stack.

The kernel supports multitasking with preemptive scheduling, virtual memory management with paging, and system calls for user programs. It includes drivers for common hardware including VGA text mode, keyboard, ATA disks, and multiple network cards (RTL8139, E1000, and VirtIO). The networking stack implements Ethernet, ARP, IPv4, ICMP, TCP, UDP, DHCP, DNS, and HTTP protocols, allowing the system to connect to networks and make HTTP requests.

Filesystem support includes both FAT32 and ext2 filesystems through a virtual filesystem layer. The system includes a built-in shell with text editing capabilities and supports loading and running ELF executables in user mode. SMP support enables the kernel to utilize multiple CPU cores.

## Requirements

- Zig compiler (0.15.2 or later)
- NASM assembler
- QEMU for testing
- For disk-backed rootfs and ext2 test images: `dosfstools`, `e2fsprogs`, and `mtools`
- For ISO builds: GRUB `mkrescue`, `xorriso`, and `mtools`

### macOS (Homebrew)

```bash
brew install zig nasm qemu dosfstools e2fsprogs xorriso mtools i686-elf-grub
```

### Linux Packages

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y zig nasm qemu-system-x86 qemu-system-i386 grub-common grub-pc-bin dosfstools e2fsprogs xorriso mtools
```

Fedora:

```bash
sudo dnf install -y zig nasm qemu-system-x86 grub2-tools grub2-tools-extra dosfstools e2fsprogs xorriso mtools
```

Arch Linux:

```bash
sudo pacman -Sy --noconfirm zig nasm grub dosfstools e2fsprogs xorriso mtools qemu-full
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

# Build the initial userland programs
zig build userland

# Build the FAT disk image with staged user programs
zig build rootfs

# Run host-side unit tests for extracted shell/TCP/IPC logic
zig build host-tests

# Run host-side benchmarks for extracted shell/TCP/IPC logic
zig build bench

# Build the kernel benchmark profile
zig build kernel-bench

# Build the scheduler stress profile
zig build kernel-smp-stress

# Build the SMP regression profile
zig build kernel-smp-regression

# Build the manual regression profile
zig build kernel-manual-regression

# Build the ext2 regression profile
zig build kernel-ext2-regression

# Build the service regression profile
zig build kernel-service-regression

# Build the scheduler regression profile
zig build kernel-scheduler-regression

# Build the NIC ingress regression profile
zig build kernel-nic-ingress

# Build the E1000 ingress regression profile
zig build kernel-e1000-ingress

# Build the VirtIO ingress regression profile
zig build kernel-virtio-ingress

# Run the kernel benchmark profile in headless QEMU
zig build run-kernel-bench

# Run the scheduler stress profile in headless QEMU
zig build run-smp-stress

# Capture and verify kernel benchmark markers/results/thresholds
zig build kernel-bench-test

# Run the scheduler stress smoke/regression profile
zig build smp-stress-test

# Run the SMP regression profile
zig build smp-regression-test

# Run the manual regression profile for file I/O, TCP, sync, and IPC suites
zig build manual-regression-test

# Run the ext2 regression profile against a dedicated ext2 disk image
zig build ext2-regression-test

# Run the service regression profile for memory, syscall, network, and driver RX self-tests
zig build service-regression-test

# Run the scheduler/process-monitoring regression profile
zig build scheduler-regression-test

# Run the true QEMU NIC ingress regression profile
zig build nic-ingress-test

# Run the true QEMU E1000 ingress regression profile
zig build e1000-ingress-test

# Run the true QEMU VirtIO ingress regression profile
zig build virtio-ingress-test

# Run the development profile in QEMU
zig build run

# Build the CI smoke-test profile
zig build kernel-ci-smoke

# Build the userland smoke-test profile
zig build kernel-userland-smoke

# Build the VM-test profile
zig build kernel-test-vm

# Build the VM core regression profile
zig build kernel-vm-core-regression

# Build the VM readiness regression profile
zig build kernel-vm-readiness-regression

# Build the VM memory, state, and tty regression profiles
zig build kernel-vm-memory-regression
zig build kernel-vm-state-regression
zig build kernel-vm-tty-regression

# Build the VM socket, event, and inotify regression profiles
zig build kernel-vm-socket-regression
zig build kernel-vm-event-regression
zig build kernel-vm-inotify-regression

# Build a bootable ISO from the development profile
zig build iso

# Run the ISO boot smoke test
zig build boot-test

# Run the CI smoke profile directly in QEMU
zig build run-ci-smoke

# Run the VM test profile directly in QEMU
zig build run-test-vm

# Run the smaller VM regression profiles
zig build vm-core-regression-test
zig build vm-readiness-regression-test
zig build vm-memory-regression-test
zig build vm-state-regression-test
zig build vm-tty-regression-test
zig build vm-socket-regression-test
zig build vm-event-regression-test
zig build vm-inotify-regression-test

# Run the automated userland smoke test
zig build userland-smoke-test
```

The VM regression logs emit per-case serial markers such as `VMMEM:CASE:PASS:page_mapping`, `VMSTATE:CASE:PASS:file_backed_mmap`, `VMSOCK:CASE:PASS:tcp_select_readiness`, and `VMINOTIFY:CASE:PASS:inotify_internal_vnode_dispatch`, so CI failures point to the exact subtest path. The aggregate `run-test-vm`, `vm-core-regression-test`, and `vm-readiness-regression-test` commands remain available for local use, but CI now relies on the split subgroup profiles and runs them directly without a separate aggregate pre-build job.

`zig build iso` auto-detects `grub-mkrescue`, `i686-elf-grub-mkrescue`, or `x86_64-elf-grub-mkrescue`. You can override detection with:

```bash
GRUB_MKRESCUE=/path/to/grub-mkrescue zig build iso
```

`zig build boot-test` builds the ISO, boots it headlessly in QEMU, and verifies required boot markers. Optional overrides:

```bash
QEMU_BIN=qemu-system-x86_64 BOOT_TEST_SECONDS=15 zig build boot-test
```

## Benchmarking

The benchmark runner exercises host-safe subsystems such as shell parsing, glob expansion, TCP helpers, and semaphore semantics without booting QEMU.

```bash
# List benchmark cases
zig build bench -- --list

# Run only TCP benchmarks for longer samples
zig build bench -- --filter tcp --duration-ms 1000 --warmup-ms 100
```

For freestanding measurements inside QEMU, use the kernel benchmark profile. It emits `BENCH:*` markers over serial and reports cycles per operation for representative shell, TCP, and IPC workloads.

```bash
# Stream kernel benchmark output to the terminal
zig build run-kernel-bench

# Capture output to build/kernel-benchmark.log and verify markers, thresholds, and baseline regressions
zig build kernel-bench-test

# Capture output to build/smp-stress.log and verify scheduler stress markers
zig build smp-stress-test

# Run the SMP regression suite with serial pass/fail markers
zig build smp-regression-test

# Run the broader kernel regression suite for file I/O, TCP, sync, and IPC
zig build manual-regression-test

# Run ext2 write coverage against a dedicated ext2 image attached beside the rootfs disk
zig build ext2-regression-test

# Run memory allocator, syscall, and network stack smoke/regression coverage
zig build service-regression-test

# Run scheduler and process-monitoring smoke/regression coverage
zig build scheduler-regression-test

# Run a real QEMU NIC ingress smoke/regression path with injected Ethernet frames
zig build nic-ingress-test

# Run a real QEMU E1000 ingress smoke/regression path with UDP host forwarding
zig build e1000-ingress-test

# Run a real QEMU VirtIO ingress smoke/regression path with injected Ethernet frames
zig build virtio-ingress-test
```

## Boot Profiles

- `dev`: starts the interactive shell and demo processes
- `ci_smoke`: boots core services, initializes the shell, emits serial markers, and exits through QEMU debug-exit
- `test_vm`: runs the virtual memory test suite and exits through QEMU debug-exit
- `vm_core_regression`: runs the VM memory, process-state, mmap, and tty subset with dedicated serial pass/fail markers
- `vm_readiness_regression`: runs the VM readiness, poll/select, eventfd, timerfd, signalfd, and inotify subset with dedicated serial pass/fail markers
- `vm_memory_regression`: runs the VM allocation, mapping, stats, flags, and range-operation subset with dedicated serial pass/fail markers
- `vm_state_regression`: runs the VM process-local-state and file-backed-mmap subset with dedicated serial pass/fail markers
- `vm_tty_regression`: runs the VM tty surface subset with dedicated serial pass/fail markers
- `vm_socket_regression`: runs the TCP, UDP, and Unix socket readiness subset with dedicated serial pass/fail markers
- `vm_event_regression`: runs the eventfd, timerfd, and signalfd subset with dedicated serial pass/fail markers
- `vm_inotify_regression`: runs the inotify readiness and dispatch subset with dedicated serial pass/fail markers
- `benchmark`: boots the kernel, runs serial-reported microbenchmarks in QEMU, and exits through QEMU debug-exit
- `smp_stress`: boots the kernel, runs a headless scheduler stress workload, emits serial markers and scheduler stats, and exits through QEMU debug-exit
- `smp_regression`: boots the kernel with SMP startup enabled, runs the SMP validation suite, emits serial pass/fail markers, and exits through QEMU debug-exit
- `manual_regression`: boots the kernel from the disk-backed rootfs, runs automated file I/O, TCP, synchronization, and IPC suites, emits serial pass/fail markers, and exits through QEMU debug-exit
- `ext2_regression`: boots the kernel from the disk-backed rootfs, mounts a dedicated ext2 disk on `/mnt`, runs ext2 write coverage, emits serial pass/fail markers, and exits through QEMU debug-exit
- `service_regression`: boots the kernel with the network stack enabled, runs memory allocator, syscall, deeper network packet-path smoke suites, plus RTL8139, E1000, and VirtIO interrupt/RX self-tests, emits serial pass/fail markers, and exits through QEMU debug-exit
- `scheduler_regression`: boots the kernel, runs scheduler/demo and process-monitoring smoke suites, emits serial pass/fail markers, and exits through QEMU debug-exit
- `nic_ingress`: boots the kernel with the network stack enabled, initializes a real QEMU NIC, accepts injected Ethernet ingress frames through the emulated device, and exits through QEMU debug-exit once the ARP path succeeds
- `e1000_ingress`: boots the kernel with the network stack enabled, initializes a real QEMU e1000 NIC, observes a live host-forwarded packet reaching the guest network stack, and exits through QEMU debug-exit once ingress succeeds
- `virtio_ingress`: boots the kernel with the network stack enabled, initializes a real QEMU VirtIO NIC, accepts injected Ethernet ingress frames through the emulated device, and exits through QEMU debug-exit once the ARP path succeeds
- `userland_smoke`: boots from the disk-backed rootfs when available, falls back to the embedded rootfs otherwise, runs the external userland smoke commands (`hello`, `echo`, `uname`, `ls`, `cat`), and exits through QEMU debug-exit

The current bootstrap prefers the staged FAT disk image as `/`, with the embedded root filesystem kept as a fallback. The staged image still mirrors the bootstrap `/bin` and `/etc` content for disk-based workflows.

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

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
