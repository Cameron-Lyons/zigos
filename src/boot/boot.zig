const std = @import("std");
const kernel = @import("../kernel/main.zig");
const vga = @import("../kernel/vga.zig");
const isr = @import("../kernel/isr.zig");
const idt = @import("../kernel/idt.zig");

pub usingnamespace kernel;
pub usingnamespace isr;

export fn _start() callconv(.Naked) noreturn {
    asm volatile (
        \\    lea stack_top, %%rsp
        \\    cli
        \\    call kernel_main
        \\.hang:
        \\    cli
        \\    hlt
        \\    jmp .hang
    );
}

// Multiboot header
export var multiboot_header align(4) linksection(".multiboot") = [_]u32{
    0x1BADB002, // magic
    0x00,       // flags
    @as(u32, @bitCast(@as(i32, -(0x1BADB002 + 0x00)))), // checksum
};

// Stack
var stack_bytes: [16384]u8 align(16) = undefined;
export const stack_top = @as([*]u8, &stack_bytes) + stack_bytes.len;