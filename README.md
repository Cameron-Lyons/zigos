# ZigOS

A minimal operating system written in Zig with networking capabilities.

## Requirements

- Zig compiler (0.11.0 or later)
- NASM assembler
- QEMU for testing

## Building and Running

```bash
# Quick build and run
./build_and_run.sh

# Or use Zig build system
zig build kernel
zig build iso
zig build run
```

## Project Structure

```
zigos/
├── src/
│   ├── boot/          # Bootloader (multiboot-compliant)
│   ├── kernel/        # Kernel source code
│   │   ├── main.zig          # Kernel entry point
│   │   ├── memory.zig        # Memory management
│   │   ├── paging.zig        # Virtual memory paging
│   │   ├── gdt.zig           # Global Descriptor Table
│   │   ├── idt.zig           # Interrupt Descriptor Table
│   │   ├── isr.zig           # Interrupt Service Routines
│   │   ├── keyboard.zig      # Keyboard driver
│   │   ├── timer.zig         # System timer
│   │   ├── vga.zig           # VGA text mode driver
│   │   ├── pci.zig           # PCI bus enumeration
│   │   ├── rtl8139.zig       # RTL8139 network driver
│   │   ├── network.zig       # Network stack core
│   │   ├── ethernet.zig      # Ethernet layer
│   │   ├── arp.zig           # ARP protocol
│   │   ├── ipv4.zig          # IPv4 implementation
│   │   ├── icmp.zig          # ICMP protocol
│   │   ├── tcp.zig           # TCP protocol
│   │   ├── udp.zig           # UDP protocol
│   │   ├── dhcp.zig          # DHCP client
│   │   ├── dns.zig           # DNS resolver
│   │   ├── http.zig          # HTTP client
│   │   ├── socket.zig        # Socket API
│   │   ├── posix.zig         # POSIX compatibility layer
│   │   ├── process.zig       # Process management
│   │   ├── syscall.zig       # System calls
│   │   ├── ring3.zig         # User mode support
│   │   ├── userspace.zig     # Userspace utilities
│   │   ├── elf.zig           # ELF executable loading
│   │   ├── vfs.zig           # Virtual File System
│   │   ├── fat32.zig         # FAT32 filesystem
│   │   ├── ata.zig           # ATA disk driver
│   │   ├── device.zig        # Device management
│   │   ├── e1000.zig         # E1000 network driver
│   │   ├── virtio.zig        # VirtIO network driver
│   │   ├── smp.zig           # SMP (multicore) support
│   │   ├── framebuffer.zig   # Graphics/framebuffer support
│   │   ├── memory_pool.zig   # Advanced memory management
│   │   └── user_programs.zig # User program utilities
│   └── arch/          # Architecture-specific code
│       └── x86_64/    # x86_64 specific files
├── build.zig          # Zig build configuration
├── build_and_run.sh   # Quick build and run script
└── README.md          # This file
```

## Current Features

### Core System
- ✅ Multiboot-compliant bootloader
- ✅ x86_64 long mode support
- ✅ Global Descriptor Table (GDT)
- ✅ Interrupt Descriptor Table (IDT)
- ✅ Interrupt handling and ISRs
- ✅ Memory management with paging
- ✅ Virtual memory management
- ✅ Advanced memory management (memory pools, slab allocator)
- ✅ VGA text mode driver
- ✅ Framebuffer/graphics mode support
- ✅ Keyboard driver
- ✅ System timer
- ✅ Console device support
- ✅ SMP (multicore) support with APIC

### Process Management
- ✅ Multitasking and scheduling
- ✅ Context switching
- ✅ Process creation and management
- ✅ Inter-process communication (IPC)
- ✅ Process monitoring
- ✅ Synchronization primitives
- ✅ System call interface
- ✅ Ring 3 (user mode) support
- ✅ ELF executable loading
- ✅ Userspace/kernel separation
- ✅ Built-in shell
- ✅ User program framework and utilities

### Networking Stack
- ✅ PCI bus enumeration
- ✅ RTL8139 network card driver
- ✅ E1000 network driver (Intel Gigabit Ethernet)
- ✅ VirtIO network driver
- ✅ Ethernet layer
- ✅ ARP (Address Resolution Protocol)
- ✅ IPv4 protocol with routing
- ✅ ICMP (ping support)
- ✅ TCP protocol
- ✅ UDP protocol
- ✅ DHCP client
- ✅ DNS resolver
- ✅ HTTP client
- ✅ Socket API with POSIX compatibility

### File Systems
- ✅ Virtual File System (VFS) layer
- ✅ FAT32 filesystem support
- ✅ File write support
- ✅ Symlink support (extended operations)
- ✅ Hardlink support (extended operations)
- ✅ ATA disk driver
- ✅ Device management framework

## Roadmap

- [x] More network drivers (e1000, virtio-net) - ✅ Implemented
- [x] Extended file system operations - ✅ Symlink and hardlink support added
- [x] Advanced memory management features - ✅ Memory pools and slab allocator implemented
- [x] More user programs and utilities - ✅ User program framework and utilities added
- [x] SMP (multicore) support - ✅ SMP initialization and APIC support implemented
- [x] Graphics mode support - ✅ Framebuffer driver implemented (requires multiboot framebuffer info)
