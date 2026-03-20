// Keep the trap entrypoints in assembly so this ABI boundary does not depend on Zig inline-asm codegen.
extern fn syscall0_asm(number: u32) callconv(.c) i32;
extern fn syscall1_asm(number: u32, arg1: usize) callconv(.c) i32;
extern fn syscall2_asm(number: u32, arg1: usize, arg2: usize) callconv(.c) i32;
extern fn syscall3_asm(number: u32, arg1: usize, arg2: usize, arg3: usize) callconv(.c) i32;
extern fn syscall4_asm(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) callconv(.c) i32;
extern fn syscall5_asm(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) callconv(.c) i32;
extern fn syscall6_asm(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) callconv(.c) i32;

pub const kernel = struct {
    // The kernel path calls a custom register ABI entrypoint in assembly so the
    // ring-0 test harness keeps the same register semantics as the original
    // inline `int $0x80` wrappers.
    pub fn syscall0(number: u32) i32 {
        var result: i32 = undefined;
        asm volatile (
            \\call syscall_regcall_asm
            : [result] "={eax}" (result),
            : [num] "{eax}" (number),
            : .{ .memory = true });
        return result;
    }

    pub fn syscall1(number: u32, arg1: usize) i32 {
        var result: i32 = undefined;
        asm volatile (
            \\call syscall_regcall_asm
            : [result] "={eax}" (result),
            : [num] "{eax}" (number),
              [arg1] "{ebx}" (arg1),
            : .{ .memory = true });
        return result;
    }

    pub fn syscall2(number: u32, arg1: usize, arg2: usize) i32 {
        var result: i32 = undefined;
        asm volatile (
            \\call syscall_regcall_asm
            : [result] "={eax}" (result),
            : [num] "{eax}" (number),
              [arg1] "{ebx}" (arg1),
              [arg2] "{ecx}" (arg2),
            : .{ .memory = true });
        return result;
    }

    pub fn syscall3(number: u32, arg1: usize, arg2: usize, arg3: usize) i32 {
        var result: i32 = undefined;
        asm volatile (
            \\call syscall_regcall_asm
            : [result] "={eax}" (result),
            : [num] "{eax}" (number),
              [arg1] "{ebx}" (arg1),
              [arg2] "{ecx}" (arg2),
              [arg3] "{edx}" (arg3),
            : .{ .memory = true });
        return result;
    }

    pub fn syscall4(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) i32 {
        var result: i32 = undefined;
        asm volatile (
            \\call syscall_regcall_asm
            : [result] "={eax}" (result),
            : [num] "{eax}" (number),
              [arg1] "{ebx}" (arg1),
              [arg2] "{ecx}" (arg2),
              [arg3] "{edx}" (arg3),
              [arg4] "{esi}" (arg4),
            : .{ .memory = true });
        return result;
    }

    pub fn syscall5(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
        var result: i32 = undefined;
        asm volatile (
            \\call syscall_regcall_asm
            : [result] "={eax}" (result),
            : [num] "{eax}" (number),
              [arg1] "{ebx}" (arg1),
              [arg2] "{ecx}" (arg2),
              [arg3] "{edx}" (arg3),
              [arg4] "{esi}" (arg4),
              [arg5] "{edi}" (arg5),
            : .{ .memory = true });
        return result;
    }

    pub fn syscall6(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) i32 {
        return syscall6_asm(number, arg1, arg2, arg3, arg4, arg5, arg6);
    }
};

pub const user = struct {
    pub inline fn syscall0(number: u32) i32 {
        return syscall0_asm(number);
    }

    pub inline fn syscall1(number: u32, arg1: usize) i32 {
        return syscall1_asm(number, @as(usize, @as(u32, @intCast(arg1))));
    }

    pub inline fn syscall2(number: u32, arg1: usize, arg2: usize) i32 {
        return syscall2_asm(
            number,
            @as(usize, @as(u32, @intCast(arg1))),
            @as(usize, @as(u32, @intCast(arg2))),
        );
    }

    pub inline fn syscall3(number: u32, arg1: usize, arg2: usize, arg3: usize) i32 {
        return syscall3_asm(
            number,
            @as(usize, @as(u32, @intCast(arg1))),
            @as(usize, @as(u32, @intCast(arg2))),
            @as(usize, @as(u32, @intCast(arg3))),
        );
    }

    pub inline fn syscall4(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) i32 {
        return syscall4_asm(
            number,
            @as(usize, @as(u32, @intCast(arg1))),
            @as(usize, @as(u32, @intCast(arg2))),
            @as(usize, @as(u32, @intCast(arg3))),
            @as(usize, @as(u32, @intCast(arg4))),
        );
    }

    pub inline fn syscall5(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
        return syscall5_asm(
            number,
            @as(usize, @as(u32, @intCast(arg1))),
            @as(usize, @as(u32, @intCast(arg2))),
            @as(usize, @as(u32, @intCast(arg3))),
            @as(usize, @as(u32, @intCast(arg4))),
            @as(usize, @as(u32, @intCast(arg5))),
        );
    }

    pub inline fn syscall6(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) i32 {
        return syscall6_asm(
            number,
            @as(usize, @as(u32, @intCast(arg1))),
            @as(usize, @as(u32, @intCast(arg2))),
            @as(usize, @as(u32, @intCast(arg3))),
            @as(usize, @as(u32, @intCast(arg4))),
            @as(usize, @as(u32, @intCast(arg5))),
            @as(usize, @as(u32, @intCast(arg6))),
        );
    }
};
