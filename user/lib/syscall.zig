const abi = @import("abi");

pub const STDIN = abi.STDIN;
pub const STDOUT = abi.STDOUT;
pub const STDERR = abi.STDERR;
pub const O_RDONLY = abi.O_RDONLY;
pub const O_WRONLY = abi.O_WRONLY;
pub const O_RDWR = abi.O_RDWR;
pub const O_CREAT = abi.O_CREAT;
pub const O_TRUNC = abi.O_TRUNC;
pub const DT_REG = abi.DT_REG;
pub const DT_DIR = abi.DT_DIR;
pub const SIGINT = abi.SIGINT;
pub const SIGKILL = abi.SIGKILL;
pub const SIGTERM = abi.SIGTERM;
pub const SIGCONT = abi.SIGCONT;
pub const SIGSTOP = abi.SIGSTOP;
pub const SIGTSTP = abi.SIGTSTP;
pub const CLOCK_REALTIME = abi.CLOCK_REALTIME;
pub const CLOCK_MONOTONIC = abi.CLOCK_MONOTONIC;
pub const PROT_NONE = abi.PROT_NONE;
pub const PROT_READ = abi.PROT_READ;
pub const PROT_WRITE = abi.PROT_WRITE;
pub const PROT_EXEC = abi.PROT_EXEC;
pub const MAP_SHARED = abi.MAP_SHARED;
pub const MAP_PRIVATE = abi.MAP_PRIVATE;
pub const MAP_FIXED = abi.MAP_FIXED;
pub const MAP_ANONYMOUS = abi.MAP_ANONYMOUS;
pub const TCGETS = abi.TCGETS;
pub const TCSETS = abi.TCSETS;
pub const TCSETSW = abi.TCSETSW;
pub const TCSETSF = abi.TCSETSF;
pub const TIOCGWINSZ = abi.TIOCGWINSZ;
pub const TTY_LFLAG_ISIG = abi.TTY_LFLAG_ISIG;
pub const TTY_LFLAG_ICANON = abi.TTY_LFLAG_ICANON;
pub const TTY_LFLAG_ECHO = abi.TTY_LFLAG_ECHO;
pub const AT_FDCWD = abi.AT_FDCWD;

pub const LinuxDirent = extern struct {
    d_ino: u32,
    d_off: u32,
    d_reclen: u16,
    d_type: u8,
};

pub const TimeSpec = extern struct {
    tv_sec: i32,
    tv_nsec: i32,
};

pub const ProcInfo = abi.ProcInfo;

pub const Termios = extern struct {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [19]u8,
};

pub const WinSize = extern struct {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
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

pub inline fn syscall5(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
    const raw: u32 = asm volatile ("int $0x80"
        : [ret] "={eax}" (-> u32),
        : [num] "{eax}" (number),
          [arg1] "{ebx}" (@as(u32, @intCast(arg1))),
          [arg2] "{ecx}" (@as(u32, @intCast(arg2))),
          [arg3] "{edx}" (@as(u32, @intCast(arg3))),
          [arg4] "{esi}" (@as(u32, @intCast(arg4))),
          [arg5] "{edi}" (@as(u32, @intCast(arg5))),
        : .{ .memory = true });
    return @bitCast(raw);
}

extern fn syscall6_asm(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) callconv(.c) i32;

pub inline fn syscall6(number: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) i32 {
    return syscall6_asm(number, arg1, arg2, arg3, arg4, arg5, arg6);
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

pub fn getuid() i32 {
    return syscall0(abi.SYS_GETUID);
}

pub fn getgid() i32 {
    return syscall0(abi.SYS_GETGID);
}

pub fn setuid(uid: u16) i32 {
    return syscall1(abi.SYS_SETUID, uid);
}

pub fn setgid(gid: u16) i32 {
    return syscall1(abi.SYS_SETGID, gid);
}

pub fn geteuid() i32 {
    return syscall0(abi.SYS_GETEUID);
}

pub fn getegid() i32 {
    return syscall0(abi.SYS_GETEGID);
}

pub fn fork() i32 {
    return syscall0(abi.SYS_FORK);
}

pub fn execve(path: [*:0]const u8, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) i32 {
    return syscall3(abi.SYS_EXECVE, @intFromPtr(path), @intFromPtr(argv), @intFromPtr(envp));
}

pub fn spawnve(path: [*:0]const u8, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) i32 {
    return syscall3(abi.SYS_SPAWN, @intFromPtr(path), @intFromPtr(argv), @intFromPtr(envp));
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

pub fn mkdir(path: [*:0]const u8, mode: u32) i32 {
    return syscall2(abi.SYS_MKDIR, @intFromPtr(path), mode);
}

pub fn chmod(path: [*:0]const u8, mode: u32) i32 {
    return syscall2(abi.SYS_CHMOD, @intFromPtr(path), mode);
}

pub fn chown(path: [*:0]const u8, uid: u16, gid: u16) i32 {
    return syscall3(abi.SYS_CHOWN, @intFromPtr(path), uid, gid);
}

pub fn fchownat(dirfd: i32, pathname: [*:0]const u8, owner: i32, group: i32) i32 {
    return syscall4(
        abi.SYS_FCHOWNAT,
        @bitCast(@as(u32, @bitCast(dirfd))),
        @intFromPtr(pathname),
        @bitCast(@as(u32, @bitCast(owner))),
        @bitCast(@as(u32, @bitCast(group))),
    );
}

pub fn symlink(target: [*:0]const u8, linkpath: [*:0]const u8) i32 {
    return syscall2(abi.SYS_SYMLINK, @intFromPtr(target), @intFromPtr(linkpath));
}

pub fn link(oldpath: [*:0]const u8, newpath: [*:0]const u8) i32 {
    return syscall2(abi.SYS_LINK, @intFromPtr(oldpath), @intFromPtr(newpath));
}

pub fn unlink(path: [*:0]const u8) i32 {
    return syscall1(abi.SYS_UNLINK, @intFromPtr(path));
}

pub fn rename(old_path: [*:0]const u8, new_path: [*:0]const u8) i32 {
    return syscall2(abi.SYS_RENAME, @intFromPtr(old_path), @intFromPtr(new_path));
}

pub fn kill(pid: i32, signum: i32) i32 {
    return syscall2(
        abi.SYS_KILL,
        @bitCast(@as(u32, @bitCast(pid))),
        @bitCast(@as(u32, @bitCast(signum))),
    );
}

pub fn getprocs(buffer: []ProcInfo) i32 {
    return syscall2(abi.SYS_GETPROCS, @intFromPtr(buffer.ptr), buffer.len);
}

pub fn ping(ipv4_addr: u32) i32 {
    return syscall1(abi.SYS_PING, ipv4_addr);
}

pub fn gethostname(buffer: []u8) i32 {
    return syscall2(abi.SYS_GETHOSTNAME, @intFromPtr(buffer.ptr), buffer.len);
}

pub fn sethostname(name: []const u8) i32 {
    return syscall2(abi.SYS_SETHOSTNAME, @intFromPtr(name.ptr), name.len);
}

pub fn getcwd(buffer: []u8) i32 {
    return syscall2(abi.SYS_GETCWD, @intFromPtr(buffer.ptr), buffer.len);
}

pub fn chdir(path: [*:0]const u8) i32 {
    return syscall1(abi.SYS_CHDIR, @intFromPtr(path));
}

pub fn mount(source: [*:0]const u8, target: [*:0]const u8, fstype: [*:0]const u8, flags: u32) i32 {
    return syscall5(abi.SYS_MOUNT, @intFromPtr(source), @intFromPtr(target), @intFromPtr(fstype), flags, 0);
}

pub fn umount2(target: [*:0]const u8, flags: u32) i32 {
    return syscall2(abi.SYS_UMOUNT2, @intFromPtr(target), flags);
}

pub fn umount(target: [*:0]const u8) i32 {
    return umount2(target, 0);
}

pub fn munmap(addr: usize, length: usize) i32 {
    return syscall2(abi.SYS_MUNMAP, addr, length);
}

pub fn ioctl(fd: i32, request: u32, arg: usize) i32 {
    return syscall3(abi.SYS_IOCTL, @bitCast(@as(u32, @bitCast(fd))), request, arg);
}

pub fn isatty(fd: i32) i32 {
    return syscall1(abi.SYS_ISATTY, @bitCast(@as(u32, @bitCast(fd))));
}

pub fn mprotect(addr: usize, length: usize, prot: u32) i32 {
    return syscall3(abi.SYS_MPROTECT, addr, length, prot);
}

pub fn mmap(addr: usize, length: usize, prot: u32, flags: u32, fd: i32, offset: usize) i32 {
    return syscall6(
        abi.SYS_MMAP,
        addr,
        length,
        prot,
        flags,
        @bitCast(@as(u32, @bitCast(fd))),
        offset,
    );
}

pub fn nanosleep(req: *const TimeSpec, rem: ?*TimeSpec) i32 {
    return syscall2(abi.SYS_NANOSLEEP, @intFromPtr(req), if (rem) |value| @intFromPtr(value) else 0);
}

pub fn clock_gettime(clock_id: i32, tp: *TimeSpec) i32 {
    return syscall2(abi.SYS_CLOCK_GETTIME, @bitCast(@as(u32, @bitCast(clock_id))), @intFromPtr(tp));
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
