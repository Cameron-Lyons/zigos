#!/bin/bash

echo "Building ZigOS kernel..."

# Create build directory
mkdir -p build

# Assemble the assembly files
echo "Assembling boot and kernel assembly files..."
as -32 src/kernel/context_switch.S -o build/context_switch.o || exit 1
as -32 src/kernel/gdt_flush.S -o build/gdt_flush.o || exit 1
as -32 src/kernel/interrupt32.S -o build/interrupt32.o || exit 1

echo "Assembly files compiled successfully"

# Build the kernel with Zig
echo "Building kernel with Zig..."
zig build-exe src/main.zig \
    build/context_switch.o \
    build/gdt_flush.o \
    build/interrupt32.o \
    --script src/arch/x86_64/linker.ld \
    -target x86-freestanding-none \
    -femit-bin=kernel.elf || exit 1

echo "Kernel built successfully!"
echo "Output: kernel.elf"

# Show kernel info
echo ""
echo "Kernel information:"
file kernel.elf
ls -lh kernel.elf

echo ""
echo "To run the kernel, you need QEMU installed:"
echo "  qemu-system-x86_64 -kernel kernel.elf -m 128M -no-reboot -no-shutdown"