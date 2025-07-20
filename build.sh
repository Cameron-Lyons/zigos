#!/bin/bash

nasm -f elf64 src/boot/boot.asm -o build/boot.o

zig build kernel

ld -n -T src/arch/x86_64/linker.ld -o zig-out/bin/kernel.elf build/boot.o zig-out/bin/kernel.elf.o

