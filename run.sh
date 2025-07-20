#!/bin/bash

# Build the kernel first
zig build

# Run with QEMU using multiboot
qemu-system-i386 \
    -kernel zig-out/bin/kernel.elf \
    -m 128M \
    -cpu max \
    -enable-kvm 2>/dev/null || \
qemu-system-i386 \
    -kernel zig-out/bin/kernel.elf \
    -m 128M \
    -cpu max