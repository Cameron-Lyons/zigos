#!/bin/bash

echo "Building kernel..."
zig build kernel || exit 1

echo "Running ZigOS in QEMU..."
echo "Press Ctrl+A then X to exit"
echo ""

# Run with basic hardware support
qemu-system-x86_64 \
    -kernel zig-out/bin/kernel.elf \
    -m 256M \
    -cpu qemu64 \
    -smp 2 \
    -device e1000,netdev=net0 \
    -netdev user,id=net0,dhcpstart=10.0.2.15 \
    -device AC97 \
    -drive file=disk.img,if=ide,format=raw,id=disk0 \
    -monitor stdio \
    -d int,cpu_reset 2>/dev/null || \
qemu-system-x86_64 \
    -kernel zig-out/bin/kernel.elf \
    -m 128M \
    -nographic