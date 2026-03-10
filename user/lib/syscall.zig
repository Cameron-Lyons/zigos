const abi = @import("abi");

pub const STDIN = abi.STDIN;
pub const STDOUT = abi.STDOUT;
pub const STDERR = abi.STDERR;
pub const O_RDONLY: u32 = 0;
pub const DT_REG: u8 = 1;
pub const DT_DIR: u8 = 2;

pub const LinuxDirent = extern struct {
    d_ino: u32,
    d_off: u32,
    d_reclen: u16,
    d_type: u8,
};

pub inline fn syscall0(number: u32) i32 {
    const raw: u32 = asm volatile ("int $0x80"
        : [ret] "={eax}" (-> u32),
        : [num] "{eax}" (number),
        : .{ .memory = true });
    return @bitCast(raw);
}

pub inline fn syscall1(number: u32, arg1: usize) i32 {
    const raw: u32 = asm volatile ("int $0x80"
        : [ret] "={eax}" (-> u32),
        : [num] "{eax}" (number),
          [arg1] "{ebx}" (@as(u32, @intCast(arg1))),
        : .{ .memory = true });
    return @bitCast(raw);
}

pub inline fn syscall2(number: u32, arg1: usize, arg2: usize) i32 {
    const raw: u32 = asm volatile ("int $0x80"
        : [ret] "={eax}" (-> u32),
        : [num] "{eax}" (number),
          [arg1] "{ebx}" (@as(u32, @intCast(arg1))),
          [arg2] "{ecx}" (@as(u32, @intCast(arg2))),
        : .{ .memory = true });
    return @bitCast(raw);
}

pub inline fn syscall3(number: u32, arg1: usize, arg2: usize, arg3: usize) i32 {
    const raw: u32 = asm volatile ("int $0x80"
        : [ret] "={eax}" (-> u32),
        : [num] "{eax}" (number),
          [arg1] "{ebx}" (@as(u32, @intCast(arg1))),
          [arg2] "{ecx}" (@as(u32, @intCast(arg2))),
          [arg3] "{edx}" (@as(u32, @intCast(arg3))),
        : .{ .memory = true });
    return @bitCast(raw);
}

pub inline fn syscall4(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) i32 {
    const raw: u32 = asm volatile ("int $0x80"
        : [ret] "={eax}" (-> u32),
        : [num] "{eax}" (number),
          [arg1] "{ebx}" (@as(u32, @intCast(arg1))),
          [arg2] "{ecx}" (@as(u32, @intCast(arg2))),
          [arg3] "{edx}" (@as(u32, @intCast(arg3))),
          [arg4] "{esi}" (@as(u32, @intCast(arg4))),
        : .{ .memory = true });
    return @bitCast(raw);
}

pub fn read(fd: i32, buffer: []u8) i32 {
    return syscall3(abi.SYS_READ, @bitCast(@as(u32, @bitCast(fd))), @intFromPtr(buffer.ptr), buffer.len);
}

pub fn write(fd: i32, buffer: []const u8) i32 {
    return syscall3(abi.SYS_WRITE, @bitCast(@as(u32, @bitCast(fd))), @intFromPtr(buffer.ptr), buffer.len);
}

pub fn open(path: [*:0]const u8, flags: u32) i32 {
    return syscall2(abi.SYS_OPEN, @intFromPtr(path), flags);
}

pub fn close(fd: i32) i32 {
    return syscall1(abi.SYS_CLOSE, @bitCast(@as(u32, @bitCast(fd))));
}

pub fn getpid() i32 {
    return syscall0(abi.SYS_GETPID);
}

pub fn fork() i32 {
    return syscall0(abi.SYS_FORK);
}

pub fn execve(path: [*:0]const u8, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) i32 {
    return syscall3(abi.SYS_EXECVE, @intFromPtr(path), @intFromPtr(argv), @intFromPtr(envp));
}

pub fn wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) i32 {
    return syscall4(
        abi.SYS_WAIT4,
        @bitCast(@as(u32, @bitCast(pid))),
        if (status) |value| @intFromPtr(value) else 0,
        @bitCast(@as(u32, @bitCast(options))),
        if (rusage) |value| @intFromPtr(value) else 0,
    );
}

pub fn getdents(fd: i32, buffer: []u8) i32 {
    return syscall3(abi.SYS_GETDENTS, @bitCast(@as(u32, @bitCast(fd))), @intFromPtr(buffer.ptr), buffer.len);
}

pub fn exit(status: i32) noreturn {
    _ = syscall1(abi.SYS_EXIT, @bitCast(@as(u32, @bitCast(status))));
    while (true) {
        asm volatile ("hlt");
    }
}

pub export fn __zigos_exit(status: i32) callconv(.c) noreturn {
    exit(status);
}

pub fn isError(result: i32) bool {
    return result < 0;
}
