#!/bin/bash

zig build kernel

qemu-system-i386 \
  -kernel zig-out/bin/kernel.elf \
  -m 128M \
  -cpu max \
  -enable-kvm 2>/dev/null ||
  qemu-system-i386 \
    -kernel zig-out/bin/kernel.elf \
    -m 128M \
    -cpu max

