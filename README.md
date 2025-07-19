# ZigOS

A minimal operating system written in Zig.

## Requirements

- Zig compiler (0.11.0 or later)
- NASM assembler
- GRUB tools (grub-mkrescue)
- QEMU for testing
- xorriso (required by grub-mkrescue)

## Building

```bash
# Build the kernel
zig build kernel

# Create bootable ISO
zig build iso

# Run in QEMU
zig build run
```

## Project Structure

```
zigos/
├── src/
│   ├── boot/          # Bootloader and GRUB configuration
│   ├── kernel/        # Kernel source code
│   └── arch/          # Architecture-specific code
│       └── x86_64/    # x86_64 specific files
├── build.zig          # Zig build configuration
└── README.md          # This file
```

## Current Features

- Multiboot-compliant bootloader
- Basic VGA text mode driver
- Simple "Hello World" kernel

## Next Steps

- Memory management (paging, allocation)
- Interrupt handling
- Keyboard driver
- Basic shell