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
│   ├── boot/              # Bootloader (multiboot-compliant)
│   ├── kernel/            # Kernel source code
│   │   ├── main.zig       # Kernel entry point
│   │   ├── drivers/       # Hardware drivers
│   │   │   ├── ac97.zig       # AC97 audio driver
│   │   │   ├── ata.zig        # ATA disk driver
│   │   │   ├── e1000.zig      # E1000 network driver
│   │   │   ├── keyboard.zig   # Keyboard driver
│   │   │   ├── pci.zig        # PCI bus enumeration
│   │   │   ├── rtl8139.zig    # RTL8139 network driver
│   │   │   ├── usb.zig        # USB driver
│   │   │   ├── vga.zig        # VGA text mode driver
│   │   │   └── virtio.zig     # VirtIO network driver
│   │   ├── net/            # Network stack
│   │   │   ├── arp.zig        # ARP protocol
│   │   │   ├── dhcp.zig       # DHCP client
│   │   │   ├── dns.zig        # DNS resolver
│   │   │   ├── ethernet.zig   # Ethernet layer
│   │   │   ├── http.zig       # HTTP client
│   │   │   ├── icmp.zig       # ICMP protocol
│   │   │   ├── ipv4.zig       # IPv4 implementation
│   │   │   ├── network.zig    # Network stack core
│   │   │   ├── routing.zig    # IP routing
│   │   │   ├── socket.zig     # Socket API
│   │   │   ├── tcp.zig        # TCP protocol
│   │   │   └── udp.zig        # UDP protocol
│   │   ├── fs/             # File systems
│   │   │   ├── ext2.zig       # ext2 filesystem
│   │   │   ├── fat32.zig      # FAT32 filesystem
│   │   │   ├── file_ops.zig   # File operations
│   │   │   ├── fs_utils.zig   # Filesystem utilities
│   │   │   └── vfs.zig        # Virtual File System
│   │   ├── memory/         # Memory management
│   │   │   ├── memory.zig     # Memory allocator
│   │   │   ├── memory_pool.zig # Memory pools
│   │   │   ├── mmap.zig       # Memory mapping
│   │   │   ├── paging.zig     # Virtual memory paging
│   │   │   └── protection.zig # Memory protection
│   │   ├── process/        # Process management
│   │   │   ├── context_switch.S # Context switching (assembly)
│   │   │   ├── ipc.zig         # Inter-process communication
│   │   │   ├── process.zig     # Process management
│   │   │   ├── ring3.zig       # User mode support
│   │   │   ├── scheduler.zig   # Process scheduler
│   │   │   ├── signal.zig      # Signal handling
│   │   │   ├── syscall.zig     # System calls
│   │   │   ├── user_programs.zig # User program utilities
│   │   │   └── userspace.zig   # Userspace utilities
│   │   ├── interrupts/     # Interrupt handling
│   │   │   ├── gdt.zig         # Global Descriptor Table
│   │   │   ├── gdt_flush.S     # GDT flush (assembly)
│   │   │   ├── idt.zig         # Interrupt Descriptor Table
│   │   │   ├── interrupt.S     # Interrupt handlers (assembly)
│   │   │   ├── interrupt32.S   # 32-bit interrupt handlers
│   │   │   ├── interrupts.s    # Interrupt handlers (assembly)
│   │   │   └── isr.zig         # Interrupt Service Routines
│   │   ├── devices/         # Device management
│   │   │   ├── console_device.zig # Console device
│   │   │   ├── device.zig       # Device management
│   │   │   ├── framebuffer.zig  # Graphics/framebuffer support
│   │   │   └── vt.zig           # Virtual terminals
│   │   ├── utils/          # Utilities
│   │   │   ├── builtin.zig     # Built-in utilities
│   │   │   ├── environ.zig     # Environment variables
│   │   │   ├── error.zig       # Error handling
│   │   │   ├── io.zig          # I/O utilities
│   │   │   ├── panic.zig       # Panic handler
│   │   │   ├── posix.zig       # POSIX compatibility layer
│   │   │   └── sync.zig        # Synchronization primitives
│   │   ├── tests/          # Test files
│   │   │   ├── multitask_demo.zig # Multitasking demo
│   │   │   ├── net_test.zig    # Network tests
│   │   │   ├── procmon.zig      # Process monitor
│   │   │   ├── test_fs.zig      # Filesystem tests
│   │   │   ├── test_memory.zig  # Memory tests
│   │   │   ├── test_syscall.zig # Syscall tests
│   │   │   └── vm_test.zig     # Virtual memory tests
│   │   ├── shell/          # Shell and editor
│   │   │   ├── editor.zig      # Text editor
│   │   │   └── shell.zig       # Shell implementation
│   │   ├── elf/            # ELF loading
│   │   │   └── elf.zig         # ELF executable loading
│   │   ├── acpi/           # ACPI
│   │   │   └── acpi.zig        # ACPI support
│   │   ├── timer/          # Timer
│   │   │   └── timer.zig       # System timer
│   │   └── smp/            # SMP (multicore)
│   │       └── smp.zig         # SMP support
│   └── arch/              # Architecture-specific code
│       └── x86_64/        # x86_64 specific files
├── build.zig              # Zig build configuration
├── build_and_run.sh       # Quick build and run script
└── README.md              # This file
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
