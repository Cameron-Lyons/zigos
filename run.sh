#!/bin/bash

zig build kernel

qemu-system-x86_64 \
  -kernel zig-out/bin/kernel.elf \
  -m 128M \
  -cpu max \
  -enable-kvm 2>/dev/null ||
  qemu-system-x86_64 \
    -kernel zig-out/bin/kernel.elf \
    -m 128M \
    -cpu max

