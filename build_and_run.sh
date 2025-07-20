#!/bin/bash

# Create build directory
mkdir -p build

# Assemble the boot code
echo "Assembling boot code..."
nasm -f elf64 src/boot/boot.asm -o build/boot.o

# Build the kernel
echo "Building kernel..."
zig build

# Link everything together
echo "Linking kernel..."
ld -n -T src/arch/x86_64/linker.ld -o build/kernel.elf build/boot.o zig-out/bin/kernel.elf

# Run with QEMU
echo "Running OS in QEMU..."
qemu-system-x86_64 -kernel build/kernel.elf -m 128M -no-reboot -no-shutdown