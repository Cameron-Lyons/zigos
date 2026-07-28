const std = @import("std");
const x86 = @import("x86");

const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D7_6289;
const SERIAL_BASE: u16 = 0x3F8;
const SERIAL_LINE_STATUS: u16 = SERIAL_BASE + 5;
const SERIAL_TRANSMIT_EMPTY: u8 = 1 << 5;
const QEMU_EXIT_PORT: u16 = 0xF4;
const QEMU_SUCCESS: u32 = 0x10;
const QEMU_FAILURE: u32 = 0x11;

pub fn panic(_: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    serialWrite("ZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:FAIL panic\n");
    exitQemu(QEMU_FAILURE);
}

pub export fn long_mode_probe_main(multiboot_magic: u32, multiboot_info: u32) callconv(.c) noreturn {
    serialInit();
    if (multiboot_magic != MULTIBOOT2_BOOTLOADER_MAGIC or multiboot_info == 0) {
        serialWrite("ZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:FAIL handoff\n");
        exitQemu(QEMU_FAILURE);
    }

    serialWrite("ZIGOS:ARCH:X86_64:LONG_MODE_ENTRY:READY\n");
    exitQemu(QEMU_SUCCESS);
}

fn serialInit() void {
    x86.outb(SERIAL_BASE + 1, 0x00);
    x86.outb(SERIAL_BASE + 3, 0x80);
    x86.outb(SERIAL_BASE, 0x03);
    x86.outb(SERIAL_BASE + 1, 0x00);
    x86.outb(SERIAL_BASE + 3, 0x03);
    x86.outb(SERIAL_BASE + 2, 0xC7);
    x86.outb(SERIAL_BASE + 4, 0x0B);
}

fn serialWrite(bytes: []const u8) void {
    for (bytes) |byte| {
        while ((x86.inb(SERIAL_LINE_STATUS) & SERIAL_TRANSMIT_EMPTY) == 0) {
            asm volatile ("pause");
        }
        x86.outb(SERIAL_BASE, byte);
    }
}

fn exitQemu(status: u32) noreturn {
    x86.outl(QEMU_EXIT_PORT, status);
    while (true) x86.hlt();
}
