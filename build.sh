#!/bin/bash

# Compile boot assembly
nasm -f elf64 src/boot/boot.asm -o build/boot.o

# Build kernel with zig
zig build kernel

# Link boot.o with kernel
ld -n -T src/arch/x86_64/linker.ld -o zig-out/bin/kernel.elf build/boot.o zig-out/bin/kernel.elf.o