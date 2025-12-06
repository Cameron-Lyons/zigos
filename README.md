# ZigOS

A minimal operating system written in Zig with networking capabilities. ZigOS is a hobby operating system that implements core kernel functionality including process management, memory management, filesystem support, and a complete networking stack.

The kernel supports multitasking with preemptive scheduling, virtual memory management with paging, and system calls for user programs. It includes drivers for common hardware including VGA text mode, keyboard, ATA disks, and multiple network cards (RTL8139, E1000, and VirtIO). The networking stack implements Ethernet, ARP, IPv4, ICMP, TCP, UDP, DHCP, DNS, and HTTP protocols, allowing the system to connect to networks and make HTTP requests.

Filesystem support includes both FAT32 and ext2 filesystems through a virtual filesystem layer. The system includes a built-in shell with text editing capabilities and supports loading and running ELF executables in user mode. SMP support enables the kernel to utilize multiple CPU cores.

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
