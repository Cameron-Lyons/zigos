pub fn syscall0(num: u32) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
        : .{ .memory = true });
    return result;
}

pub fn syscall1(num: u32, arg1: usize) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
        : .{ .memory = true });
    return result;
}

pub fn syscall2(num: u32, arg1: usize, arg2: usize) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
        : .{ .memory = true });
    return result;
}

pub fn syscall3(num: u32, arg1: usize, arg2: usize, arg3: usize) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
        : .{ .memory = true });
    return result;
}

pub fn syscall4(num: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4),
        : .{ .memory = true });
    return result;
}

pub fn syscall5(num: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4),
          [arg5] "{edi}" (arg5),
        : .{ .memory = true });
    return result;
}

extern fn syscall6_asm(num: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) callconv(.c) i32;

pub fn syscall6(num: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) i32 {
    return syscall6_asm(num, arg1, arg2, arg3, arg4, arg5, arg6);
}
