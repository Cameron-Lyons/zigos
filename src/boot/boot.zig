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

export var multiboot_header align(4) linksection(".multiboot") = [_]u32{
    0x1BADB002,
    0x00,
    @as(u32, @bitCast(@as(i32, -(0x1BADB002 + 0x00)))),
};

// SAFETY: used as the kernel stack; stack_top points to the end of this array
var stack_bytes: [16384]u8 align(16) = undefined;
// zlint-disable unused-decls

