const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const idt = @import("../interrupts/idt.zig");
const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");
const keyboard = @import("../drivers/keyboard.zig");
const protection = @import("../memory/protection.zig");
const posix = @import("../utils/posix.zig");
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const vfs = @import("../fs/vfs.zig");
const credentials = @import("credentials.zig");
const signal = @import("signal.zig");
const socket = @import("../net/socket.zig");
const ipc = @import("ipc.zig");

pub const SYS_EXIT = 1;
pub const SYS_WRITE = 2;
pub const SYS_READ = 3;
pub const SYS_OPEN = 4;
pub const SYS_CLOSE = 5;
pub const SYS_GETPID = 6;
pub const SYS_YIELD = 7;
pub const SYS_FORK = 8;
pub const SYS_EXECVE = 9;
pub const SYS_WAIT4 = 10;
pub const SYS_BRK = 11;
pub const SYS_MMAP = 12;
pub const SYS_MKDIR = 13;
pub const SYS_RMDIR = 14;
pub const SYS_UNLINK = 15;
pub const SYS_RENAME = 16;
pub const SYS_LSEEK = 17;
pub const SYS_STAT = 18;
pub const SYS_FSTAT = 19;
pub const SYS_GETUID = 20;
pub const SYS_GETGID = 21;
pub const SYS_SETUID = 22;
pub const SYS_SETGID = 23;
pub const SYS_CHOWN = 24;
pub const SYS_PIPE = 25;
pub const SYS_DUP2 = 26;
pub const SYS_SOCKET = 27;
pub const SYS_BIND = 28;
pub const SYS_CONNECT = 29;
pub const SYS_LISTEN = 30;
pub const SYS_ACCEPT = 31;
pub const SYS_SEND = 32;
pub const SYS_RECV = 33;
pub const SYS_SHUTDOWN = 34;
pub const SYS_KILL = 35;
pub const SYS_SIGACTION = 36;
pub const SYS_GETCWD = 37;
pub const SYS_CHDIR = 38;
pub const SYS_MSGGET = 39;
pub const SYS_MSGSND = 40;
pub const SYS_MSGRCV = 41;
pub const SYS_MUNMAP = 42;
pub const SYS_IOCTL = 43;
pub const SYS_GETPPID = 44;
pub const SYS_GETPGID = 45;
pub const SYS_SETPGID = 46;
pub const SYS_SETSID = 47;
pub const SYS_NANOSLEEP = 48;
pub const SYS_CLOCK_GETTIME = 49;
pub const SYS_ACCESS = 50;
pub const SYS_CHMOD = 51;
pub const SYS_FCHMOD = 52;
pub const SYS_FTRUNCATE = 53;
pub const SYS_GETDENTS = 54;
pub const SYS_SYMLINK = 55;
pub const SYS_LINK = 56;
pub const SYS_READLINK = 57;
pub const SYS_SIGPROCMASK = 58;
pub const SYS_SIGPENDING = 59;
pub const SYS_SIGSUSPEND = 60;
pub const SYS_DUP = 61;
pub const SYS_FCNTL = 62;
pub const SYS_SELECT = 63;
pub const SYS_UMASK = 64;
pub const SYS_UNAME = 65;
pub const SYS_TRUNCATE = 66;
pub const SYS_PREAD = 67;
pub const SYS_PWRITE = 68;
pub const SYS_SENDTO = 69;
pub const SYS_RECVFROM = 70;
pub const SYS_GETSOCKNAME = 71;
pub const SYS_GETPEERNAME = 72;
pub const SYS_FCHOWN = 73;
pub const SYS_FSYNC = 74;
pub const SYS_FDATASYNC = 75;
pub const SYS_POLL = 76;
pub const SYS_LSTAT = 77;
pub const SYS_GETSOCKOPT = 78;
pub const SYS_SETSOCKOPT = 79;
pub const SYS_READV = 80;
pub const SYS_WRITEV = 81;
pub const SYS_GETEUID = 82;
pub const SYS_GETEGID = 83;
pub const SYS_ISATTY = 84;
pub const SYS_STATFS = 85;
pub const SYS_FSTATFS = 86;
pub const SYS_GETHOSTNAME = 87;
pub const SYS_SETHOSTNAME = 88;
pub const SYS_OPENAT = 89;
pub const SYS_MKDIRAT = 90;
pub const SYS_UNLINKAT = 91;
pub const SYS_LINKAT = 92;
pub const SYS_FCHMODAT = 93;
pub const SYS_FCHOWNAT = 94;
pub const SYS_RENAMEAT = 95;
pub const SYS_GETGROUPS = 96;
pub const SYS_SETGROUPS = 97;
pub const SYS_GETITIMER = 98;
pub const SYS_SETITIMER = 99;
pub const SYS_MKFIFO = 100;
pub const SYS_EPOLL_CREATE = 101;
pub const SYS_EPOLL_CTL = 102;
pub const SYS_EPOLL_WAIT = 103;
pub const SYS_TIMERFD_CREATE = 104;
pub const SYS_TIMERFD_SETTIME = 105;
pub const SYS_TIMERFD_GETTIME = 106;
pub const SYS_SHMGET = 107;
pub const SYS_SHMAT = 108;
pub const SYS_SHMDT = 109;
pub const SYS_SHMCTL = 110;
pub const SYS_SEMGET = 111;
pub const SYS_SEMOP = 112;
pub const SYS_SEMCTL = 113;
pub const SYS_TIMES = 114;
pub const SYS_GETRUSAGE = 115;
pub const SYS_MKNOD = 116;
pub const SYS_GETRANDOM = 117;
pub const SYS_PIPE2 = 118;
pub const SYS_DUP3 = 119;
pub const SYS_ACCEPT4 = 120;
pub const SYS_EVENTFD = 121;
pub const SYS_EVENTFD2 = 122;
pub const SYS_PRCTL = 123;
pub const SYS_SIGNALFD = 124;
pub const SYS_SIGNALFD4 = 125;
pub const SYS_PPOLL = 126;
pub const SYS_PSELECT6 = 127;
pub const SYS_FACCESSAT = 128;
pub const SYS_FACCESSAT2 = 129;
pub const SYS_STATX = 130;
pub const SYS_MEMBARRIER = 131;
pub const SYS_COPY_FILE_RANGE = 132;
pub const SYS_FADVISE64 = 133;
pub const SYS_READAHEAD = 134;
pub const SYS_SYNC_FILE_RANGE = 135;
pub const SYS_SYNCFS = 136;
pub const SYS_GETPRIORITY = 137;
pub const SYS_SETPRIORITY = 138;
pub const SYS_SCHED_GETAFFINITY = 139;
pub const SYS_SCHED_SETAFFINITY = 140;
pub const SYS_UTIMENSAT = 141;
pub const SYS_FUTIMESAT = 142;
pub const SYS_FSTATAT = 143;
pub const SYS_SYMLINKAT = 144;
pub const SYS_READLINKAT = 145;
pub const SYS_WAITID = 146;
pub const SYS_SET_TID_ADDRESS = 147;
pub const SYS_GET_ROBUST_LIST = 148;
pub const SYS_SET_ROBUST_LIST = 149;
pub const SYS_TGKILL = 150;
pub const SYS_TKILL = 151;
pub const SYS_INOTIFY_INIT = 152;
pub const SYS_INOTIFY_INIT1 = 153;
pub const SYS_INOTIFY_ADD_WATCH = 154;
pub const SYS_INOTIFY_RM_WATCH = 155;
pub const SYS_MLOCK = 156;
pub const SYS_MUNLOCK = 157;
pub const SYS_MLOCKALL = 158;
pub const SYS_MUNLOCKALL = 159;
pub const SYS_MADVISE = 160;
pub const SYS_MINCORE = 161;
pub const SYS_GETRLIMIT = 162;
pub const SYS_SETRLIMIT = 163;
pub const SYS_PRLIMIT64 = 164;
pub const SYS_MPROTECT = 165;
pub const SYS_SOCKETPAIR = 166;
pub const SYS_SYSINFO = 167;
pub const SYS_CLOCK_SETTIME = 168;
pub const SYS_CLOCK_GETRES = 169;
pub const SYS_CLOCK_NANOSLEEP = 170;
pub const SYS_TIMER_CREATE = 171;
pub const SYS_TIMER_DELETE = 172;
pub const SYS_TIMER_SETTIME = 173;
pub const SYS_TIMER_GETTIME = 174;
pub const SYS_TIMER_GETOVERRUN = 175;
pub const SYS_CHROOT = 176;
pub const SYS_MOUNT = 177;
pub const SYS_UMOUNT2 = 178;
pub const SYS_SWAPON = 179;
pub const SYS_SWAPOFF = 180;
pub const SYS_REBOOT = 181;

pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;
const FD_OFFSET = 3;

pub const EPERM = -1;
pub const ENOENT = -2;
pub const ESRCH = -3;
pub const EINTR = -4;
pub const EIO = -5;
pub const E2BIG = -7;
pub const EBADF = -9;
pub const EAGAIN = -11;
pub const EWOULDBLOCK = EAGAIN;
pub const ENOMEM = -12;
pub const EACCES = -13;
pub const EFAULT = -14;
pub const ENOTDIR = -20;
pub const EINVAL = -22;
pub const EBUSY = -16;
pub const EEXIST = -17;
pub const EISDIR = -21;
pub const ENFILE = -23;
pub const EMFILE = -24;
pub const ENOSPC = -28;
pub const EROFS = -30;
pub const EPIPE = -32;
pub const ENAMETOOLONG = -36;
pub const ENOSYS = -38;
pub const EOVERFLOW = -75;
pub const ENODEV = -19;
pub const EOPNOTSUPP = -95;
pub const EAFNOSUPPORT = -97;
pub const EADDRINUSE = -98;
pub const EADDRNOTAVAIL = -99;
pub const ENETDOWN = -100;
pub const ENETUNREACH = -101;
pub const ECONNABORTED = -103;
pub const ECONNRESET = -104;
pub const ENOBUFS = -105;
pub const EISCONN = -106;
pub const ENOTCONN = -107;
pub const ETIMEDOUT = -110;
pub const ECONNREFUSED = -111;
pub const EHOSTUNREACH = -113;
pub const ENXIO = -6;
pub const ENOEXEC = -8;
pub const EXDEV = -18;
pub const ENOTTY = -25;
pub const ETXTBSY = -26;
pub const ELOOP = -40;
pub const EMSGSIZE = -90;
pub const ENOPROTOOPT = -92;

pub const AT_FDCWD: i32 = -100;
pub const AT_REMOVEDIR: u32 = 0x200;

pub const ITIMER_REAL: u32 = 0;
pub const ITIMER_VIRTUAL: u32 = 1;
pub const ITIMER_PROF: u32 = 2;

pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLET: u32 = 0x80000000;

pub const TFD_CLOEXEC: u32 = 0x80000;
pub const TFD_NONBLOCK: u32 = 0x800;

pub const IPC_CREAT: u32 = 0o1000;
pub const IPC_EXCL: u32 = 0o2000;
pub const IPC_NOWAIT: u32 = 0o4000;
pub const IPC_RMID: u32 = 0;
pub const IPC_SET: u32 = 1;
pub const IPC_STAT: u32 = 2;

pub const SHM_RDONLY: u32 = 0o10000;
pub const SHM_RND: u32 = 0o20000;

pub const GETVAL: u32 = 12;
pub const SETVAL: u32 = 16;
pub const GETALL: u32 = 13;
pub const SETALL: u32 = 17;

pub const F_GETLK: u32 = 5;
pub const F_SETLK: u32 = 6;
pub const F_SETLKW: u32 = 7;

pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFSOCK: u32 = 0o140000;

pub const RUSAGE_SELF: i32 = 0;
pub const RUSAGE_CHILDREN: i32 = -1;

pub const EIDRM = -43;
pub const ENOMSG = -42;
pub const EDEADLK = -35;
pub const ENOLCK = -37;

pub const O_CLOEXEC: u32 = 0x80000;

pub const GRND_NONBLOCK: u32 = 0x0001;
pub const GRND_RANDOM: u32 = 0x0002;

pub const EFD_SEMAPHORE: u32 = 0x00001;
pub const EFD_CLOEXEC: u32 = 0x80000;
pub const EFD_NONBLOCK: u32 = 0x00800;

pub const SOCK_CLOEXEC: u32 = 0x80000;
pub const SOCK_NONBLOCK: u32 = 0x800;

pub const PR_SET_NAME: u32 = 15;
pub const PR_GET_NAME: u32 = 16;
pub const PR_SET_DUMPABLE: u32 = 4;
pub const PR_GET_DUMPABLE: u32 = 3;
pub const PR_SET_KEEPCAPS: u32 = 8;
pub const PR_GET_KEEPCAPS: u32 = 7;
pub const PR_SET_PDEATHSIG: u32 = 1;
pub const PR_GET_PDEATHSIG: u32 = 2;

pub const SFD_CLOEXEC: u32 = 0x80000;
pub const SFD_NONBLOCK: u32 = 0x800;

pub const AT_EACCESS: u32 = 0x200;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

pub const STATX_TYPE: u32 = 0x0001;
pub const STATX_MODE: u32 = 0x0002;
pub const STATX_NLINK: u32 = 0x0004;
pub const STATX_UID: u32 = 0x0008;
pub const STATX_GID: u32 = 0x0010;
pub const STATX_ATIME: u32 = 0x0020;
pub const STATX_MTIME: u32 = 0x0040;
pub const STATX_CTIME: u32 = 0x0080;
pub const STATX_INO: u32 = 0x0100;
pub const STATX_SIZE: u32 = 0x0200;
pub const STATX_BLOCKS: u32 = 0x0400;
pub const STATX_BASIC_STATS: u32 = 0x07ff;

pub const MEMBARRIER_CMD_QUERY: u32 = 0;
pub const MEMBARRIER_CMD_GLOBAL: u32 = 1;
pub const MEMBARRIER_CMD_GLOBAL_EXPEDITED: u32 = 2;
pub const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: u32 = 4;
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u32 = 8;
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u32 = 16;

pub const POSIX_FADV_NORMAL: u32 = 0;
pub const POSIX_FADV_RANDOM: u32 = 1;
pub const POSIX_FADV_SEQUENTIAL: u32 = 2;
pub const POSIX_FADV_WILLNEED: u32 = 3;
pub const POSIX_FADV_DONTNEED: u32 = 4;
pub const POSIX_FADV_NOREUSE: u32 = 5;

pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = 1;
pub const SYNC_FILE_RANGE_WRITE: u32 = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = 4;

pub const PRIO_PROCESS: u32 = 0;
pub const PRIO_PGRP: u32 = 1;
pub const PRIO_USER: u32 = 2;

pub const UTIME_NOW: i32 = 0x3fffffff;
pub const UTIME_OMIT: i32 = 0x3ffffffe;

pub const P_ALL: u32 = 0;
pub const P_PID: u32 = 1;
pub const P_PGID: u32 = 2;

pub const WEXITED: u32 = 0x04;
pub const WSTOPPED: u32 = 0x02;
pub const WCONTINUED: u32 = 0x08;
pub const WNOWAIT: u32 = 0x01000000;

pub const ECHILD = -10;

pub const IN_ACCESS: u32 = 0x00000001;
pub const IN_MODIFY: u32 = 0x00000002;
pub const IN_ATTRIB: u32 = 0x00000004;
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
pub const IN_OPEN: u32 = 0x00000020;
pub const IN_MOVED_FROM: u32 = 0x00000040;
pub const IN_MOVED_TO: u32 = 0x00000080;
pub const IN_CREATE: u32 = 0x00000100;
pub const IN_DELETE: u32 = 0x00000200;
pub const IN_DELETE_SELF: u32 = 0x00000400;
pub const IN_MOVE_SELF: u32 = 0x00000800;
pub const IN_NONBLOCK: u32 = 0x00000800;
pub const IN_CLOEXEC: u32 = 0x00080000;

pub const MCL_CURRENT: u32 = 1;
pub const MCL_FUTURE: u32 = 2;

pub const MADV_NORMAL: u32 = 0;
pub const MADV_RANDOM: u32 = 1;
pub const MADV_SEQUENTIAL: u32 = 2;
pub const MADV_WILLNEED: u32 = 3;
pub const MADV_DONTNEED: u32 = 4;

pub const RLIMIT_CPU: u32 = 0;
pub const RLIMIT_FSIZE: u32 = 1;
pub const RLIMIT_DATA: u32 = 2;
pub const RLIMIT_STACK: u32 = 3;
pub const RLIMIT_CORE: u32 = 4;
pub const RLIMIT_RSS: u32 = 5;
pub const RLIMIT_NPROC: u32 = 6;
pub const RLIMIT_NOFILE: u32 = 7;
pub const RLIMIT_MEMLOCK: u32 = 8;
pub const RLIMIT_AS: u32 = 9;
pub const RLIM_INFINITY: u64 = 0xffffffffffffffff;

pub const PROT_NONE: u32 = 0x0;
pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;

pub const CLOCK_MONOTONIC_RAW: u32 = 4;
pub const CLOCK_REALTIME_COARSE: u32 = 5;
pub const CLOCK_MONOTONIC_COARSE: u32 = 6;
pub const CLOCK_BOOTTIME: u32 = 7;

pub const TIMER_ABSTIME: u32 = 1;

pub const MNT_FORCE: u32 = 1;
pub const MNT_DETACH: u32 = 2;
pub const MNT_EXPIRE: u32 = 4;
pub const UMOUNT_NOFOLLOW: u32 = 8;

pub const LINUX_REBOOT_MAGIC1: u32 = 0xfee1dead;
pub const LINUX_REBOOT_MAGIC2: u32 = 0x28121969;
pub const LINUX_REBOOT_CMD_RESTART: u32 = 0x01234567;
pub const LINUX_REBOOT_CMD_HALT: u32 = 0xcdef0123;
pub const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321fedc;

fn vfsErrno(err: vfs.VFSError) i32 {
    return switch (err) {
        vfs.VFSError.NotFound => ENOENT,
        vfs.VFSError.PermissionDenied => EACCES,
        vfs.VFSError.IsDirectory => EISDIR,
        vfs.VFSError.NotDirectory => ENOTDIR,
        vfs.VFSError.AlreadyExists => EEXIST,
        vfs.VFSError.NoSpace => ENOSPC,
        vfs.VFSError.ReadOnly => EROFS,
        vfs.VFSError.OutOfMemory => ENOMEM,
        vfs.VFSError.InvalidPath => EINVAL,
        vfs.VFSError.InvalidOperation => EINVAL,
        vfs.VFSError.DeviceError => EINVAL,
        vfs.VFSError.BrokenPipe => EPIPE,
        vfs.VFSError.TooManyOpenFiles => EMFILE,
    };
}

fn socketErrno(err: anyerror) i32 {
    if (err == socket.SocketError.InvalidSocket) return EBADF;
    if (err == socket.SocketError.InvalidAddress) return EINVAL;
    if (err == socket.SocketError.AlreadyConnected) return EISCONN;
    if (err == socket.SocketError.NotConnected) return ENOTCONN;
    if (err == socket.SocketError.ConnectionRefused) return ECONNREFUSED;
    if (err == socket.SocketError.ConnectionReset) return ECONNRESET;
    if (err == socket.SocketError.NoBufferSpace) return ENOBUFS;
    if (err == socket.SocketError.Timeout) return ETIMEDOUT;
    if (err == socket.SocketError.AddressInUse) return EADDRINUSE;
    if (err == socket.SocketError.NotListening) return EINVAL;
    if (err == error.OutOfMemory) return ENOMEM;
    return EINVAL;
}

export fn syscall_handler(regs: *idt.InterruptRegisters) callconv(.c) void {
    const syscall_num = regs.eax;

    const arg1 = regs.ebx;
    const arg2 = regs.ecx;
    const arg3 = regs.edx;
    const arg4 = regs.esi;
    const arg5 = regs.edi;

    const result = switch (syscall_num) {
        SYS_EXIT => sys_exit(@intCast(arg1)),
        SYS_WRITE => sys_write(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_READ => sys_read(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3),
        SYS_OPEN => sys_open(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_CLOSE => sys_close(@intCast(arg1)),
        SYS_GETPID => sys_getpid(),
        SYS_YIELD => sys_yield(),
        SYS_FORK => sys_fork(),
        SYS_EXECVE => sys_execve(@as([*]const u8, @ptrFromInt(arg1)), arg2, arg3),
        SYS_WAIT4 => sys_wait4(@intCast(arg1), @as(?*i32, @ptrFromInt(arg2)), @intCast(arg3), @as(?*anyopaque, @ptrFromInt(arg4))),
        SYS_BRK => sys_brk(arg1),
        SYS_MMAP => sys_mmap(arg1, arg2, @intCast(arg3), @intCast(arg4), @intCast(arg5), @intCast(@as(i32, @intCast(regs.ebp)))),
        SYS_MKDIR => sys_mkdir(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_RMDIR => sys_rmdir(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_UNLINK => sys_unlink(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_RENAME => sys_rename(@as([*]const u8, @ptrFromInt(arg1)), @as([*]const u8, @ptrFromInt(arg2))),
        SYS_LSEEK => sys_lseek(@intCast(arg1), @as(i64, @bitCast(@as(u64, arg2) | (@as(u64, arg3) << 32))), @intCast(arg4)),
        SYS_STAT => sys_stat(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_GETUID => sys_getuid(),
        SYS_GETGID => sys_getgid(),
        SYS_SETUID => sys_setuid(@intCast(arg1)),
        SYS_SETGID => sys_setgid(@intCast(arg1)),
        SYS_CHOWN => sys_chown(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2), @intCast(arg3)),
        SYS_FSTAT => sys_fstat(@intCast(arg1), arg2),
        SYS_PIPE => sys_pipe(@as(?*[2]i32, @ptrFromInt(arg1))),
        SYS_DUP2 => sys_dup2(@intCast(arg1), @intCast(arg2)),
        SYS_SOCKET => sys_socket(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_BIND => sys_bind(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_CONNECT => sys_connect(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_LISTEN => sys_listen(@intCast(arg1), @intCast(arg2)),
        SYS_ACCEPT => sys_accept(@intCast(arg1)),
        SYS_SEND => sys_send(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_RECV => sys_recv(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3),
        SYS_SHUTDOWN => sys_shutdown(@intCast(arg1)),
        SYS_KILL => sys_kill(@intCast(arg1), @intCast(arg2)),
        SYS_SIGACTION => sys_sigaction(@intCast(arg1), arg2, arg3),
        SYS_GETCWD => sys_getcwd(@as([*]u8, @ptrFromInt(arg1)), arg2),
        SYS_CHDIR => sys_chdir(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_MSGGET => sys_msgget(@intCast(arg1)),
        SYS_MSGSND => sys_msgsnd(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_MSGRCV => sys_msgrcv(@as([*]u8, @ptrFromInt(arg1)), arg2, @intCast(arg3)),
        SYS_MUNMAP => sys_munmap(arg1, arg2),
        SYS_IOCTL => sys_ioctl(@intCast(arg1), @intCast(arg2), arg3),
        SYS_GETPPID => sys_getppid_syscall(),
        SYS_GETPGID => sys_getpgid(@intCast(arg1)),
        SYS_SETPGID => sys_setpgid(@intCast(arg1), @intCast(arg2)),
        SYS_SETSID => sys_setsid(),
        SYS_NANOSLEEP => sys_nanosleep(arg1, arg2),
        SYS_CLOCK_GETTIME => sys_clock_gettime(@intCast(arg1), arg2),
        SYS_ACCESS => sys_access(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_CHMOD => sys_chmod_syscall(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_FCHMOD => sys_fchmod(@intCast(arg1), arg2),
        SYS_FTRUNCATE => sys_ftruncate(@intCast(arg1), arg2),
        SYS_GETDENTS => sys_getdents(@intCast(arg1), arg2, arg3),
        SYS_SYMLINK => sys_symlink(@as([*]const u8, @ptrFromInt(arg1)), @as([*]const u8, @ptrFromInt(arg2))),
        SYS_LINK => sys_link(@as([*]const u8, @ptrFromInt(arg1)), @as([*]const u8, @ptrFromInt(arg2))),
        SYS_READLINK => sys_readlink(@as([*]const u8, @ptrFromInt(arg1)), @as([*]u8, @ptrFromInt(arg2)), arg3),
        SYS_SIGPROCMASK => sys_sigprocmask(@intCast(arg1), arg2, arg3),
        SYS_SIGPENDING => sys_sigpending(arg1),
        SYS_SIGSUSPEND => sys_sigsuspend(arg1),
        SYS_DUP => sys_dup(@intCast(arg1)),
        SYS_FCNTL => sys_fcntl(@intCast(arg1), @intCast(arg2), arg3),
        SYS_SELECT => sys_select(@intCast(arg1), arg2, arg3, arg4, arg5),
        SYS_UMASK => sys_umask(@intCast(arg1)),
        SYS_UNAME => sys_uname(arg1),
        SYS_TRUNCATE => sys_truncate(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_PREAD => sys_pread(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3, @as(u64, arg4) | (@as(u64, arg5) << 32)),
        SYS_PWRITE => sys_pwrite(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, @as(u64, arg4) | (@as(u64, arg5) << 32)),
        SYS_SENDTO => sys_sendto(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, arg4, @intCast(arg5)),
        SYS_RECVFROM => sys_recvfrom(@intCast(arg1), @as([*]u8, @ptrFromInt(arg2)), arg3, arg4, arg5),
        SYS_GETSOCKNAME => sys_getsockname(@intCast(arg1), arg2, arg3),
        SYS_GETPEERNAME => sys_getpeername(@intCast(arg1), arg2, arg3),
        SYS_FCHOWN => sys_fchown(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_FSYNC => sys_fsync(@intCast(arg1)),
        SYS_FDATASYNC => sys_fsync(@intCast(arg1)),
        SYS_POLL => sys_poll(arg1, @intCast(arg2), @intCast(@as(i32, @bitCast(arg3)))),
        SYS_LSTAT => sys_lstat(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_GETSOCKOPT => sys_getsockopt(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4, arg5),
        SYS_SETSOCKOPT => sys_setsockopt(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4, arg5),
        SYS_READV => sys_readv(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_WRITEV => sys_writev(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_GETEUID => sys_geteuid(),
        SYS_GETEGID => sys_getegid(),
        SYS_ISATTY => sys_isatty(@intCast(arg1)),
        SYS_STATFS => sys_statfs(@as([*]const u8, @ptrFromInt(arg1)), arg2),
        SYS_FSTATFS => sys_fstatfs(@intCast(arg1), arg2),
        SYS_GETHOSTNAME => sys_gethostname(arg1, arg2),
        SYS_SETHOSTNAME => sys_sethostname(arg1, arg2),
        SYS_OPENAT => sys_openat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_MKDIRAT => sys_mkdirat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_UNLINKAT => sys_unlinkat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_LINKAT => sys_linkat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), @as([*]const u8, @ptrFromInt(arg4)), @intCast(arg5)),
        SYS_FCHMODAT => sys_fchmodat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_FCHOWNAT => sys_fchownat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), @intCast(arg4)),
        SYS_RENAMEAT => sys_renameat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), @as([*]const u8, @ptrFromInt(arg4))),
        SYS_GETGROUPS => sys_getgroups(@intCast(arg1), arg2),
        SYS_SETGROUPS => sys_setgroups(@intCast(arg1), arg2),
        SYS_GETITIMER => sys_getitimer(@intCast(arg1), arg2),
        SYS_SETITIMER => sys_setitimer(@intCast(arg1), arg2, arg3),
        SYS_MKFIFO => sys_mkfifo(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_EPOLL_CREATE => sys_epoll_create(@intCast(arg1)),
        SYS_EPOLL_CTL => sys_epoll_ctl(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4),
        SYS_EPOLL_WAIT => sys_epoll_wait(@intCast(arg1), arg2, @intCast(arg3), @intCast(arg4)),
        SYS_TIMERFD_CREATE => sys_timerfd_create(@intCast(arg1), @intCast(arg2)),
        SYS_TIMERFD_SETTIME => sys_timerfd_settime(@intCast(arg1), @intCast(arg2), arg3, arg4),
        SYS_TIMERFD_GETTIME => sys_timerfd_gettime(@intCast(arg1), arg2),
        SYS_SHMGET => sys_shmget(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_SHMAT => sys_shmat(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_SHMDT => sys_shmdt(arg1),
        SYS_SHMCTL => sys_shmctl(@intCast(arg1), @intCast(arg2), arg3),
        SYS_SEMGET => sys_semget(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_SEMOP => sys_semop(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_SEMCTL => sys_semctl(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4),
        SYS_TIMES => sys_times(arg1),
        SYS_GETRUSAGE => sys_getrusage(@intCast(arg1), arg2),
        SYS_MKNOD => sys_mknod(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2), @intCast(arg3)),
        SYS_GETRANDOM => sys_getrandom(@as([*]u8, @ptrFromInt(arg1)), arg2, @intCast(arg3)),
        SYS_PIPE2 => sys_pipe2(@as(?*[2]i32, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_DUP3 => sys_dup3(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_ACCEPT4 => sys_accept4(@intCast(arg1), arg2, arg3, @intCast(arg4)),
        SYS_EVENTFD => sys_eventfd(@intCast(arg1)),
        SYS_EVENTFD2 => sys_eventfd2(@intCast(arg1), @intCast(arg2)),
        SYS_PRCTL => sys_prctl(@intCast(arg1), arg2, arg3, arg4, arg5),
        SYS_SIGNALFD => sys_signalfd(@intCast(arg1), arg2, @intCast(arg3)),
        SYS_SIGNALFD4 => sys_signalfd4(@intCast(arg1), arg2, @intCast(arg3), @intCast(arg4)),
        SYS_PPOLL => sys_ppoll(arg1, @intCast(arg2), arg3, arg4),
        SYS_PSELECT6 => sys_pselect6(@intCast(arg1), arg2, arg3, arg4, arg5, @as(usize, @bitCast(@as(i32, @intCast(regs.ebp))))),
        SYS_FACCESSAT => sys_faccessat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), 0),
        SYS_FACCESSAT2 => sys_faccessat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), @intCast(arg4)),
        SYS_STATX => sys_statx(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), @intCast(arg4), arg5),
        SYS_MEMBARRIER => sys_membarrier(@intCast(arg1), @intCast(arg2)),
        SYS_COPY_FILE_RANGE => sys_copy_file_range(@intCast(arg1), arg2, @intCast(arg3), arg4, arg5),
        SYS_FADVISE64 => sys_fadvise64(@intCast(arg1), @as(i64, @bitCast(@as(u64, arg2) | (@as(u64, arg3) << 32))), arg4, @intCast(arg5)),
        SYS_READAHEAD => sys_readahead(@intCast(arg1), @as(i64, @bitCast(@as(u64, arg2) | (@as(u64, arg3) << 32))), arg4),
        SYS_SYNC_FILE_RANGE => sys_sync_file_range(@intCast(arg1), @as(i64, @bitCast(@as(u64, arg2) | (@as(u64, arg3) << 32))), @as(i64, @bitCast(@as(u64, arg4) | (@as(u64, arg5) << 32))), @intCast(@as(i32, @bitCast(regs.ebp)))),
        SYS_SYNCFS => sys_syncfs(@intCast(arg1)),
        SYS_GETPRIORITY => sys_getpriority(@intCast(arg1), @intCast(arg2)),
        SYS_SETPRIORITY => sys_setpriority(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_SCHED_GETAFFINITY => sys_sched_getaffinity(@intCast(arg1), arg2, arg3),
        SYS_SCHED_SETAFFINITY => sys_sched_setaffinity(@intCast(arg1), arg2, arg3),
        SYS_UTIMENSAT => sys_utimensat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, @intCast(arg4)),
        SYS_FUTIMESAT => sys_futimesat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_FSTATAT => sys_fstatat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, @intCast(arg4)),
        SYS_SYMLINKAT => sys_symlinkat(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2), @as([*]const u8, @ptrFromInt(arg3))),
        SYS_READLINKAT => sys_readlinkat(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @as([*]u8, @ptrFromInt(arg3)), arg4),
        SYS_WAITID => sys_waitid(@intCast(arg1), @intCast(arg2), arg3, @intCast(arg4)),
        SYS_SET_TID_ADDRESS => sys_set_tid_address(arg1),
        SYS_GET_ROBUST_LIST => sys_get_robust_list(@intCast(arg1), arg2, arg3),
        SYS_SET_ROBUST_LIST => sys_set_robust_list(arg1, arg2),
        SYS_TGKILL => sys_tgkill(@intCast(arg1), @intCast(arg2), @intCast(arg3)),
        SYS_TKILL => sys_tkill(@intCast(arg1), @intCast(arg2)),
        SYS_INOTIFY_INIT => sys_inotify_init(),
        SYS_INOTIFY_INIT1 => sys_inotify_init1(@intCast(arg1)),
        SYS_INOTIFY_ADD_WATCH => sys_inotify_add_watch(@intCast(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_INOTIFY_RM_WATCH => sys_inotify_rm_watch(@intCast(arg1), @intCast(arg2)),
        SYS_MLOCK => sys_mlock(arg1, arg2),
        SYS_MUNLOCK => sys_munlock(arg1, arg2),
        SYS_MLOCKALL => sys_mlockall(@intCast(arg1)),
        SYS_MUNLOCKALL => sys_munlockall(),
        SYS_MADVISE => sys_madvise(arg1, arg2, @intCast(arg3)),
        SYS_MINCORE => sys_mincore(arg1, arg2, arg3),
        SYS_GETRLIMIT => sys_getrlimit(@intCast(arg1), arg2),
        SYS_SETRLIMIT => sys_setrlimit(@intCast(arg1), arg2),
        SYS_PRLIMIT64 => sys_prlimit64(@intCast(arg1), @intCast(arg2), arg3, arg4),
        SYS_MPROTECT => sys_mprotect(arg1, arg2, @intCast(arg3)),
        SYS_SOCKETPAIR => sys_socketpair(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4),
        SYS_SYSINFO => sys_sysinfo(arg1),
        SYS_CLOCK_SETTIME => sys_clock_settime(@intCast(arg1), arg2),
        SYS_CLOCK_GETRES => sys_clock_getres(@intCast(arg1), arg2),
        SYS_CLOCK_NANOSLEEP => sys_clock_nanosleep(@intCast(arg1), @intCast(arg2), arg3, arg4),
        SYS_TIMER_CREATE => sys_timer_create(@intCast(arg1), arg2, arg3),
        SYS_TIMER_DELETE => sys_timer_delete(@intCast(arg1)),
        SYS_TIMER_SETTIME => sys_timer_settime(@intCast(arg1), @intCast(arg2), arg3, arg4),
        SYS_TIMER_GETTIME => sys_timer_gettime(@intCast(arg1), arg2),
        SYS_TIMER_GETOVERRUN => sys_timer_getoverrun(@intCast(arg1)),
        SYS_CHROOT => sys_chroot(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_MOUNT => sys_mount(arg1, arg2, arg3, arg4, arg5),
        SYS_UMOUNT2 => sys_umount2(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_SWAPON => sys_swapon(@as([*]const u8, @ptrFromInt(arg1)), @intCast(arg2)),
        SYS_SWAPOFF => sys_swapoff(@as([*]const u8, @ptrFromInt(arg1))),
        SYS_REBOOT => sys_reboot(@intCast(arg1), @intCast(arg2), @intCast(arg3), arg4),
        else => ENOSYS,
    };

    regs.eax = @intCast(@as(i32, result));

    signal.handlePendingSignals();
}

fn sys_exit(status: i32) i32 {
    if (process.current_process) |proc| {
        proc.state = .Terminated;
        proc.exit_code = status;

        if (proc.parent_pid != 0) {
            if (process.getProcessByPid(proc.parent_pid)) |parent| {
                signal.sendSignal(parent, signal.SIGCHLD);
            }
        }

        _ = process.schedule();

        x86.hlt();
    }

    return 0;
}

fn sys_write(fd: i32, buf: [*]const u8, count: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return EINVAL;
    }

    if (fd == STDOUT or fd == STDERR) {
        // SAFETY: filled by the subsequent copyFromUser call
        var kernel_buffer: [256]u8 = undefined;
        var written: usize = 0;

        while (written < count) {
            const chunk_size = @min(count - written, kernel_buffer.len);
            protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch {
                return EINVAL;
            };

            var i: usize = 0;
            while (i < chunk_size) : (i += 1) {
                vga.print(&[_]u8{kernel_buffer[i]});
            }

            written += chunk_size;
        }

        return @intCast(count);
    }

    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent copyFromUser call
    var kernel_buffer: [512]u8 = undefined;
    var written: usize = 0;

    while (written < count) {
        const chunk_size = @min(count - written, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch {
            return EINVAL;
        };

        const bytes_written = vfs.write(vfs_fd, kernel_buffer[0..chunk_size]) catch |err| return vfsErrno(err);
        written += bytes_written;
        if (bytes_written < chunk_size) break;
    }

    return @intCast(written);
}

fn sys_read(fd: i32, buf: [*]u8, count: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) {
        return EINVAL;
    }

    if (fd == STDIN) {
        // SAFETY: filled by the subsequent keyboard.getchar calls
        var kernel_buffer: [256]u8 = undefined;
        const read_size = @min(count, kernel_buffer.len);
        var i: usize = 0;

        while (i < read_size) : (i += 1) {
            while (!keyboard.has_char()) {
                x86.hlt();
            }

            if (keyboard.getchar()) |ch| {
                kernel_buffer[i] = ch;

                if (ch == '\n') {
                    i += 1;
                    break;
                }
            }
        }

        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..i]) catch {
            return EINVAL;
        };

        return @intCast(i);
    }

    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent vfs.read call
    var kernel_buffer: [512]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < count) {
        const chunk_size = @min(count - total_read, kernel_buffer.len);
        const bytes_read = vfs.read(vfs_fd, kernel_buffer[0..chunk_size]) catch |err| return vfsErrno(err);
        if (bytes_read == 0) break;

        protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch {
            return EINVAL;
        };

        total_read += bytes_read;
        if (bytes_read < chunk_size) break;
    }

    return @intCast(total_read);
}

fn sys_getpid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.pid);
    }
    return 0;
}

fn sys_yield() i32 {
    process.yield();
    return 0;
}

fn sys_mkdir(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const mode_struct = vfs.FileMode{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };

    vfs.mkdir(path_slice, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_rmdir(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.rmdir(path_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_unlink(pathname: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.unlink(path_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_rename(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256) or
        !protection.verifyUserPointer(@intFromPtr(newpath), 256))
    {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var old_buffer: [256]u8 = undefined;
    // SAFETY: filled by the subsequent copyStringFromUser call
    var new_buffer: [256]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return EINVAL;

    vfs.rename(old_slice, new_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_open(pathname: [*]const u8, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    if (process.current_process) |proc| {
        if (vfs.lookupPath(path_slice)) |vnode| {
            const access_mode = flags & 0x3;
            var access: u3 = 0;
            if (access_mode == 0 or access_mode == 2) access |= 4;
            if (access_mode == 1 or access_mode == 2) access |= 2;
            if (!credentials.checkPermission(&proc.creds, vnode.mode, vnode.uid, vnode.gid, access)) {
                return EACCES;
            }
        } else |_| {}
    }

    const vfs_fd = vfs.open(path_slice, flags) catch |err| return vfsErrno(err);
    return @intCast(@as(i32, @intCast(vfs_fd)) + FD_OFFSET);
}

fn sys_close(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    vfs.close(vfs_fd) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_lseek(fd: i32, offset: i64, whence: u32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    const result = vfs.lseek(vfs_fd, offset, whence) catch |err| return vfsErrno(err);
    if (result > 0x7FFFFFFF) return EOVERFLOW;
    return @intCast(result);
}

fn sys_stat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    // SAFETY: filled by the subsequent vfs.stat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(path_slice, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return EINVAL;
    return 0;
}

pub fn init() void {
    idt.register_interrupt_handler(0x80, syscall_handler);

    idt.set_gate_flags(0x80, 0x8E | 0x60);
}

pub fn syscall0(num: u32) i32 {
    // SAFETY: populated by the subsequent inline assembly (int $0x80)
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
        : "memory"
    );
    return result;
}

pub fn syscall1(num: u32, arg1: usize) i32 {
    // SAFETY: populated by the subsequent inline assembly (int $0x80)
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
        : "memory"
    );
    return result;
}

pub fn syscall3(num: u32, arg1: usize, arg2: usize, arg3: usize) i32 {
    // SAFETY: populated by the subsequent inline assembly (int $0x80)
    var result: i32 = undefined;
    asm volatile (
        \\int $0x80
        : [result] "={eax}" (result),
        : [num] "{eax}" (num),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
        : "memory"
    );
    return result;
}

fn sys_getuid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.uid);
    }
    return 0;
}

fn sys_getgid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.gid);
    }
    return 0;
}

fn sys_setuid(uid: u16) i32 {
    const proc = process.current_process orelse return ESRCH;
    if (proc.creds.euid == 0 or proc.creds.uid == uid) {
        proc.creds.uid = uid;
        proc.creds.euid = uid;
        return 0;
    }
    return EPERM;
}

fn sys_setgid(gid: u16) i32 {
    const proc = process.current_process orelse return ESRCH;
    if (proc.creds.euid == 0 or proc.creds.gid == gid) {
        proc.creds.gid = gid;
        proc.creds.egid = gid;
        return 0;
    }
    return EPERM;
}

fn sys_chown(pathname: [*]const u8, uid: u16, gid: u16) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) {
        return EINVAL;
    }

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    if (process.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return EPERM;
        }
    }

    vfs.chown(path_slice, uid, gid) catch |err| return vfsErrno(err);
    return 0;
}

const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

const SockAddrIn = extern struct {
    family: u16,
    port: u16,
    addr: u32,
    zero: [8]u8,
};

const SockAddrIn6 = extern struct {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [16]u8,
    scope_id: u32,
};

const SockAddrUn = extern struct {
    family: u16,
    path: [108]u8,
};

const UnixSocket = struct {
    path: [108]u8,
    path_len: usize,
    peer: ?*UnixSocket,
    recv_buffer: [4096]u8,
    recv_head: usize,
    recv_tail: usize,
    recv_count: usize,
    listening: bool,
    connected: bool,
    in_use: bool,
};

var unix_sockets: [64]UnixSocket = [_]UnixSocket{.{
    .path = [_]u8{0} ** 108,
    .path_len = 0,
    .peer = null,
    .recv_buffer = [_]u8{0} ** 4096,
    .recv_head = 0,
    .recv_tail = 0,
    .recv_count = 0,
    .listening = false,
    .connected = false,
    .in_use = false,
}} ** 64;

var socket_table: [64]?*socket.Socket = [_]?*socket.Socket{null} ** 64;

fn sys_socket(domain: u32, sock_type: u32, protocol: u32) i32 {
    _ = protocol;

    if (domain == AF_UNIX) {
        for (&unix_sockets, 0..) |*usock, i| {
            if (!usock.in_use) {
                usock.in_use = true;
                usock.path_len = 0;
                usock.peer = null;
                usock.recv_head = 0;
                usock.recv_tail = 0;
                usock.recv_count = 0;
                usock.listening = false;
                usock.connected = false;
                return @intCast(@as(i32, @intCast(i)) + 1000);
            }
        }
        return EMFILE;
    }

    const addr_family: socket.AddressFamily = switch (domain) {
        AF_INET => .AF_INET,
        AF_INET6 => .AF_INET6,
        else => return EAFNOSUPPORT,
    };

    const s_type: socket.SocketType = switch (sock_type) {
        SOCK_STREAM => .STREAM,
        SOCK_DGRAM => .DGRAM,
        else => return EINVAL,
    };

    const s_proto: socket.Protocol = switch (sock_type) {
        SOCK_STREAM => .TCP,
        SOCK_DGRAM => .UDP,
        else => return EINVAL,
    };

    const sock = socket.createSocket(s_type, s_proto) catch return ENOMEM;
    sock.address_family = addr_family;

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = sock;
            return @intCast(i);
        }
    }

    sock.close();
    return EMFILE;
}

fn sys_bind(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd >= 1000 and sockfd < 1064) {
        const idx: usize = @intCast(sockfd - 1000);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return EBADF;

        if (addr_len < 3) return EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @min(addr_len, @sizeOf(SockAddrUn)))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrUn)]u8 = undefined;
        const copy_len = @min(addr_len, @sizeOf(SockAddrUn));
        protection.copyFromUser(addr_buf[0..copy_len], addr_ptr) catch return EINVAL;
        const addr: *const SockAddrUn = @ptrCast(@alignCast(&addr_buf));

        const path_end = std.mem.indexOfScalar(u8, &addr.path, 0) orelse addr.path.len;
        @memcpy(usock.path[0..path_end], addr.path[0..path_end]);
        usock.path_len = path_end;
        return 0;
    }

    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        sock.local_ipv6 = @import("../net/ipv6.zig").IPv6Address{ .octets = addr.addr };
        sock.local_port = @byteSwap(addr.port);
        return 0;
    }

    if (addr_len < @sizeOf(SockAddrIn)) return EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    const ipv4_addr = @import("../net/ipv4.zig").IPv4Address{
        .octets = .{
            @intCast((addr.addr >> 0) & 0xFF),
            @intCast((addr.addr >> 8) & 0xFF),
            @intCast((addr.addr >> 16) & 0xFF),
            @intCast((addr.addr >> 24) & 0xFF),
        },
    };

    sock.bind(ipv4_addr, @byteSwap(addr.port)) catch |err| return socketErrno(err);
    return 0;
}

fn sys_connect(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    if (sockfd >= 1000 and sockfd < 1064) {
        const idx: usize = @intCast(sockfd - 1000);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return EBADF;

        if (addr_len < 3) return EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @min(addr_len, @sizeOf(SockAddrUn)))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrUn)]u8 = undefined;
        const copy_len = @min(addr_len, @sizeOf(SockAddrUn));
        protection.copyFromUser(addr_buf[0..copy_len], addr_ptr) catch return EINVAL;
        const addr: *const SockAddrUn = @ptrCast(@alignCast(&addr_buf));

        const path_end = std.mem.indexOfScalar(u8, &addr.path, 0) orelse addr.path.len;

        for (&unix_sockets) |*peer| {
            if (peer.in_use and peer.listening and peer.path_len == path_end) {
                if (std.mem.eql(u8, peer.path[0..path_end], addr.path[0..path_end])) {
                    usock.peer = peer;
                    usock.connected = true;
                    return 0;
                }
            }
        }
        return ECONNREFUSED;
    }

    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return EINVAL;
        if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        sock.remote_ipv6 = @import("../net/ipv6.zig").IPv6Address{ .octets = addr.addr };
        sock.remote_port = @byteSwap(addr.port);
        sock.state = .CONNECTED;
        return 0;
    }

    if (addr_len < @sizeOf(SockAddrIn)) return EINVAL;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return EINVAL;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    const ipv4_addr = @import("../net/ipv4.zig").IPv4Address{
        .octets = .{
            @intCast((addr.addr >> 0) & 0xFF),
            @intCast((addr.addr >> 8) & 0xFF),
            @intCast((addr.addr >> 16) & 0xFF),
            @intCast((addr.addr >> 24) & 0xFF),
        },
    };

    sock.connect(ipv4_addr, @byteSwap(addr.port)) catch |err| return socketErrno(err);
    return 0;
}

fn sys_listen(sockfd: i32, backlog: u32) i32 {
    _ = backlog;
    if (sockfd >= 1000 and sockfd < 1064) {
        const idx: usize = @intCast(sockfd - 1000);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return EBADF;
        usock.listening = true;
        return 0;
    }

    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    sock.listen(5) catch |err| return socketErrno(err);
    return 0;
}

fn sys_accept(sockfd: i32) i32 {
    if (sockfd >= 1000 and sockfd < 1064) {
        const idx: usize = @intCast(sockfd - 1000);
        const usock = &unix_sockets[idx];
        if (!usock.in_use or !usock.listening) return EBADF;

        for (&unix_sockets, 0..) |*peer, i| {
            if (peer.in_use and peer.connected and peer.peer == usock) {
                for (&unix_sockets, 0..) |*new_sock, j| {
                    if (!new_sock.in_use) {
                        new_sock.in_use = true;
                        new_sock.connected = true;
                        new_sock.peer = peer;
                        peer.peer = new_sock;
                        _ = i;
                        return @intCast(@as(i32, @intCast(j)) + 1000);
                    }
                }
                return EMFILE;
            }
        }
        return EAGAIN;
    }

    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    const client = sock.accept() catch |err| return socketErrno(err);

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = client;
            return @intCast(i);
        }
    }

    client.close();
    return EMFILE;
}

fn sys_send(sockfd: i32, buf: [*]const u8, len: usize) i32 {
    if (sockfd >= 1000 and sockfd < 1064) {
        const idx: usize = @intCast(sockfd - 1000);
        const usock = &unix_sockets[idx];
        if (!usock.in_use or !usock.connected) return EBADF;

        const peer = usock.peer orelse return ENOTCONN;
        if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

        var kernel_buffer: [4096]u8 = undefined;
        const to_send = @min(len, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return EINVAL;

        const available = peer.recv_buffer.len - peer.recv_count;
        const copy_len = @min(to_send, available);
        if (copy_len == 0) return EAGAIN;

        for (0..copy_len) |i| {
            peer.recv_buffer[peer.recv_tail] = kernel_buffer[i];
            peer.recv_tail = (peer.recv_tail + 1) % peer.recv_buffer.len;
        }
        peer.recv_count += copy_len;
        return @intCast(copy_len);
    }

    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return EINVAL;

    const sent = sock.send(kernel_buffer[0..to_send]) catch |err| return socketErrno(err);
    return @intCast(sent);
}

fn sys_recv(sockfd: i32, buf: [*]u8, len: usize) i32 {
    if (sockfd >= 1000 and sockfd < 1064) {
        const idx: usize = @intCast(sockfd - 1000);
        const usock = &unix_sockets[idx];
        if (!usock.in_use) return EBADF;

        if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

        if (usock.recv_count == 0) return 0;

        var kernel_buffer: [4096]u8 = undefined;
        const to_recv = @min(len, @min(usock.recv_count, kernel_buffer.len));

        for (0..to_recv) |i| {
            kernel_buffer[i] = usock.recv_buffer[usock.recv_head];
            usock.recv_head = (usock.recv_head + 1) % usock.recv_buffer.len;
        }
        usock.recv_count -= to_recv;

        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..to_recv]) catch return EINVAL;
        return @intCast(to_recv);
    }

    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return socketErrno(err);
    if (received == 0) return 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
    return @intCast(received);
}

fn sys_shutdown(sockfd: i32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    sock.close();
    socket_table[@intCast(sockfd)] = null;
    return 0;
}

fn sys_kill(pid: i32, signum: i32) i32 {
    signal.kill(pid, signum) catch |err| {
        return switch (err) {
            error.InvalidSignal => EINVAL,
            error.NoSuchProcess => ESRCH,
        };
    };
    return 0;
}

fn sys_sigaction(signum: i32, act_addr: usize, oldact_addr: usize) i32 {
    var act: ?*const signal.SigAction = null;
    var oldact: ?*signal.SigAction = null;

    // SAFETY: filled by the subsequent copyFromUser call
    var act_buf: [@sizeOf(signal.SigAction)]u8 = undefined;
    // SAFETY: filled by the subsequent sigaction call
    var oldact_buf: signal.SigAction = undefined;

    if (act_addr != 0) {
        if (!protection.verifyUserPointer(act_addr, @sizeOf(signal.SigAction))) return EINVAL;
        protection.copyFromUser(&act_buf, act_addr) catch return EINVAL;
        act = @ptrCast(@alignCast(&act_buf));
    }

    if (oldact_addr != 0) {
        if (!protection.verifyUserPointer(oldact_addr, @sizeOf(signal.SigAction))) return EINVAL;
        oldact = &oldact_buf;
    }

    signal.sigaction(signum, act, oldact) catch return EINVAL;

    if (oldact_addr != 0) {
        protection.copyToUser(oldact_addr, std.mem.asBytes(&oldact_buf)) catch return EINVAL;
    }

    return 0;
}

var current_working_dir: [256]u8 = [_]u8{0} ** 256;
var cwd_len: usize = 1;
var cwd_initialized: bool = false;

fn ensureCwdInit() void {
    if (!cwd_initialized) {
        current_working_dir[0] = '/';
        cwd_len = 1;
        cwd_initialized = true;
    }
}

pub fn getCwd() []const u8 {
    ensureCwdInit();
    return current_working_dir[0..cwd_len];
}

pub fn setCwd(path: []const u8) bool {
    ensureCwdInit();
    const node = vfs.lookupPath(path) catch return false;
    if (node.file_type != .Directory) return false;
    @memcpy(current_working_dir[0..path.len], path);
    cwd_len = path.len;
    return true;
}

fn sys_getcwd(buf: [*]u8, size: usize) i32 {
    ensureCwdInit();
    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return EINVAL;
    if (size < cwd_len + 1) return EINVAL;

    // SAFETY: cwd_len bytes + null terminator written before copy
    var kernel_buf: [257]u8 = undefined;
    @memcpy(kernel_buf[0..cwd_len], current_working_dir[0..cwd_len]);
    kernel_buf[cwd_len] = 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buf[0 .. cwd_len + 1]) catch return EINVAL;
    return @intCast(cwd_len);
}

fn sys_chdir(pathname: [*]const u8) i32 {
    ensureCwdInit();
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const node = vfs.lookupPath(path_slice) catch return ENOENT;
    if (node.file_type != .Directory) return ENOTDIR;

    @memcpy(current_working_dir[0..path_slice.len], path_slice);
    cwd_len = path_slice.len;

    return 0;
}

fn sys_fstat(fd: i32, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) {
        return EINVAL;
    }

    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent vfs.fstat call
    var stat_buf: vfs.FileStat = undefined;
    vfs.fstat(vfs_fd, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return EINVAL;
    return 0;
}

fn sys_pipe(pipefd: ?*[2]i32) i32 {
    if (pipefd == null) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(pipefd), @sizeOf([2]i32))) {
        return EINVAL;
    }

    const result = vfs.createPipe() catch |err| return vfsErrno(err);
    const fds = [2]i32{
        @as(i32, @intCast(result.read_fd)) + FD_OFFSET,
        @as(i32, @intCast(result.write_fd)) + FD_OFFSET,
    };

    protection.copyToUser(@intFromPtr(pipefd), std.mem.asBytes(&fds)) catch return EINVAL;
    return 0;
}

fn sys_dup2(old_fd: i32, new_fd: i32) i32 {
    if (old_fd < FD_OFFSET or new_fd < FD_OFFSET) return EBADF;
    const old_vfs_fd: u32 = @intCast(old_fd - FD_OFFSET);
    const new_vfs_fd: u32 = @intCast(new_fd - FD_OFFSET);

    const result = vfs.dup2(old_vfs_fd, new_vfs_fd) catch |err| return vfsErrno(err);
    return @as(i32, @intCast(result)) + FD_OFFSET;
}

fn sys_fork() i32 {
    const result = posix.fork() catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.NoProcessSlots => EAGAIN,
            error.OutOfMemory => ENOMEM,
        };
    };
    return result;
}

fn sys_execve(path: [*]const u8, argv: usize, envp: usize) i32 {
    // SAFETY: filled by the subsequent copyStringFromUser call
    var path_buf: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(path)) catch {
        return EINVAL;
    };

    // SAFETY: entries written before read; argv_count tracks valid entries
    var argv_array: [32][]const u8 = undefined;
    var argv_count: usize = 0;
    // SAFETY: entries filled by subsequent copyStringFromUser calls
    var argv_buffers: [32][256]u8 = undefined;

    if (argv != 0) {
        while (argv_count < 32) {
            const ptr_addr = argv + argv_count * @sizeOf(usize);
            if (!protection.verifyUserPointer(ptr_addr, @sizeOf(usize))) {
                break;
            }

            const str_ptr = @as(*const usize, @ptrFromInt(ptr_addr)).*;
            if (str_ptr == 0) break;

            const arg_slice = protection.copyStringFromUser(&argv_buffers[argv_count], str_ptr) catch {
                break;
            };
            argv_array[argv_count] = arg_slice;
            argv_count += 1;
        }
    }

    // SAFETY: entries written before read; envp_count tracks valid entries
    var envp_array: [32][]const u8 = undefined;
    var envp_count: usize = 0;
    // SAFETY: entries filled by subsequent copyStringFromUser calls
    var envp_buffers: [32][256]u8 = undefined;

    if (envp != 0) {
        while (envp_count < 32) {
            const ptr_addr = envp + envp_count * @sizeOf(usize);
            if (!protection.verifyUserPointer(ptr_addr, @sizeOf(usize))) {
                break;
            }

            const str_ptr = @as(*const usize, @ptrFromInt(ptr_addr)).*;
            if (str_ptr == 0) break;

            const env_slice = protection.copyStringFromUser(&envp_buffers[envp_count], str_ptr) catch {
                break;
            };
            envp_array[envp_count] = env_slice;
            envp_count += 1;
        }
    }

    const argv_slice = argv_array[0..argv_count];
    const envp_slice = envp_array[0..envp_count];

    posix.execve(path_slice, argv_slice, envp_slice) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.OutOfMemory => ENOMEM,
            error.FileReadError => ENOENT,
            else => EINVAL,
        };
    };

    return 0;
}

fn sys_wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) i32 {
    const result = posix.wait4(pid, status, options, rusage) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => ENOSYS,
            error.InvalidPointer => EINVAL,
        };
    };
    return result;
}

var current_brk: usize = protection.USER_HEAP_START;

fn sys_brk(addr: usize) i32 {
    if (addr == 0) {
        return @intCast(current_brk);
    }

    if (addr < protection.USER_HEAP_START or addr >= protection.USER_SPACE_END) {
        return @intCast(current_brk);
    }

    const new_brk = (addr + 0xFFF) & ~@as(usize, 0xFFF);

    if (new_brk > current_brk) {
        var page_addr = current_brk;
        while (page_addr < new_brk) : (page_addr += 0x1000) {
            const phys_page = memory.allocatePhysicalPage() orelse {
                return @intCast(current_brk);
            };
            paging.mapPage(@intCast(page_addr), phys_page, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
        }
    } else if (new_brk < current_brk) {
        var page_addr = new_brk;
        while (page_addr < current_brk) : (page_addr += 0x1000) {
            paging.unmap_page(@intCast(page_addr));
        }
    }

    current_brk = new_brk;
    return @intCast(current_brk);
}

const MAP_SHARED = 0x01;
const MAP_PRIVATE = 0x02;
const MAP_ANONYMOUS = 0x20;
const MAP_FIXED = 0x10;

fn sys_mmap(addr: usize, length: usize, prot: i32, flags: i32, fd: i32, offset: i32) i32 {
    if (length == 0) {
        return EINVAL;
    }

    if ((flags & MAP_ANONYMOUS) == 0) {
        if (fd < 0) {
            return EINVAL;
        }

        _ = offset;
        return ENOSYS;
    }

    if ((flags & MAP_PRIVATE) != 0 and (flags & MAP_SHARED) != 0) {
        return EINVAL;
    }
    if ((flags & MAP_PRIVATE) == 0 and (flags & MAP_SHARED) == 0) {
        return EINVAL;
    }

    // SAFETY: assigned in every branch of the if/else below
    var result_addr: usize = undefined;
    if (addr != 0) {
        const aligned_addr = addr & ~@as(usize, 0xFFF);

        if ((flags & MAP_FIXED) != 0) {
            if (aligned_addr < protection.USER_HEAP_START or aligned_addr >= protection.USER_SPACE_END) {
                return EINVAL;
            }

            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch {
                return ENOMEM;
            };
        } else {
            result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch {
                return ENOMEM;
            };
        }
    } else {
        result_addr = protection.allocateUserMemory(length, @intCast(prot)) catch {
            return ENOMEM;
        };
    }

    return @intCast(result_addr);
}

fn sys_msgget(max_messages: u32) i32 {
    const pid = if (process.current_process) |proc| proc.pid else return ENOSYS;
    const clamped = if (max_messages == 0) @as(u32, 16) else @min(max_messages, 256);

    if (ipc.getMessageQueue(pid) != null) return 0;

    _ = ipc.createMessageQueue(pid, clamped) catch return ENOMEM;
    return 0;
}

fn sys_msgsnd(receiver_pid: u32, buf: [*]const u8, len: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;
    const sender_pid = if (process.current_process) |proc| proc.pid else return ENOSYS;

    const msg_len = @min(len, 256);
    // SAFETY: filled by the subsequent copyFromUser call
    var kernel_buffer: [256]u8 = undefined;
    protection.copyFromUser(kernel_buffer[0..msg_len], @intFromPtr(buf)) catch return EINVAL;

    ipc.sendMessage(sender_pid, receiver_pid, .Data, kernel_buffer[0..msg_len]) catch |err| {
        return switch (err) {
            error.OutOfMemory => ENOMEM,
            error.ReceiverNotFound => ESRCH,
            error.QueueFull => EAGAIN,
        };
    };
    return 0;
}

fn sys_msgrcv(buf: [*]u8, size: usize, flags: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return EINVAL;
    const pid = if (process.current_process) |proc| proc.pid else return ENOSYS;

    const queue = ipc.getMessageQueue(pid) orelse return ENOENT;

    const msg = if (flags != 0) queue.tryReceive() else queue.receive();
    if (msg == null) return 0;

    const m = msg.?;
    const copy_len = @min(m.data_len, @as(u32, @intCast(size)));
    protection.copyToUser(@intFromPtr(buf), m.data[0..copy_len]) catch {
        ipc.freeMessage(m);
        return EINVAL;
    };
    ipc.freeMessage(m);
    return @intCast(copy_len);
}

fn sys_munmap(addr: usize, length: usize) i32 {
    if (addr == 0 or length == 0) return EINVAL;
    if (addr & 0xFFF != 0) return EINVAL;
    if (addr < protection.USER_HEAP_START or addr >= protection.USER_SPACE_END) return EINVAL;

    protection.freeUserMemory(addr, length);
    return 0;
}

fn sys_ioctl(fd: i32, request: u32, arg: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    const result = vfs.ioctl(vfs_fd, request, arg) catch |err| return vfsErrno(err);
    return result;
}

fn sys_getppid_syscall() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.parent_pid);
    }
    return 0;
}

fn sys_getpgid(pid: i32) i32 {
    if (pid == 0) {
        if (process.current_process) |proc| {
            return @intCast(proc.process_group);
        }
        return ESRCH;
    }

    if (pid > 0) {
        if (process.getProcessByPid(@intCast(pid))) |proc| {
            return @intCast(proc.process_group);
        }
    }
    return ESRCH;
}

fn sys_setpgid(pid: i32, pgid: i32) i32 {
    const target = blk: {
        if (pid == 0) {
            break :blk process.current_process orelse return ESRCH;
        }
        if (pid > 0) {
            break :blk process.getProcessByPid(@as(u32, @intCast(pid))) orelse return ESRCH;
        }
        return EINVAL;
    };

    if (pgid == 0) {
        target.process_group = target.pid;
    } else if (pgid > 0) {
        target.process_group = @intCast(pgid);
    } else {
        return EINVAL;
    }

    return 0;
}

fn sys_setsid() i32 {
    const proc = process.current_process orelse return EPERM;
    proc.process_group = proc.pid;
    return @intCast(proc.pid);
}

const TimeSpec = extern struct {
    tv_sec: i32,
    tv_nsec: i32,
};

fn sys_nanosleep(req_addr: usize, rem_addr: usize) i32 {
    if (!protection.verifyUserPointer(req_addr, @sizeOf(TimeSpec))) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
    var req: TimeSpec = undefined;
    protection.copyFromUser(std.mem.asBytes(&req), req_addr) catch return EINVAL;

    if (req.tv_sec < 0 or req.tv_nsec < 0 or req.tv_nsec >= 1_000_000_000) return EINVAL;

    const total_ms: u64 = @as(u64, @intCast(req.tv_sec)) * 1000 + @as(u64, @intCast(req.tv_nsec)) / 1_000_000;
    const ticks_to_wait = total_ms / 10;

    const start = process.getSystemTime();
    while (process.getSystemTime() - start < ticks_to_wait) {
        process.yield();
    }

    if (rem_addr != 0 and protection.verifyUserPointer(rem_addr, @sizeOf(TimeSpec))) {
        var zero = TimeSpec{ .tv_sec = 0, .tv_nsec = 0 };
        protection.copyToUser(rem_addr, std.mem.asBytes(&zero)) catch {};
    }

    return 0;
}

const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

fn sys_clock_gettime(clock_id: i32, tp_addr: usize) i32 {
    if (!protection.verifyUserPointer(tp_addr, @sizeOf(TimeSpec))) return EINVAL;

    switch (clock_id) {
        CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID => {},
        else => return EINVAL,
    }

    const ticks = process.getSystemTime();
    const total_ms = ticks * 10;

    const tp = TimeSpec{
        .tv_sec = @intCast(total_ms / 1000),
        .tv_nsec = @intCast((total_ms % 1000) * 1_000_000),
    };

    protection.copyToUser(tp_addr, std.mem.asBytes(&tp)) catch return EINVAL;
    return 0;
}

fn sys_access(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const vnode = vfs.lookupPath(path_slice) catch return ENOENT;

    if (mode == 0) return 0;

    if (process.current_process) |proc| {
        var access_bits: u3 = 0;
        if (mode & 4 != 0) access_bits |= 4;
        if (mode & 2 != 0) access_bits |= 2;
        if (mode & 1 != 0) access_bits |= 1;
        if (!credentials.checkPermission(&proc.creds, vnode.mode, vnode.uid, vnode.gid, access_bits)) {
            return EACCES;
        }
    }

    return 0;
}

fn sys_chmod_syscall(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const mode_struct = vfs.FileMode{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };

    vfs.chmod(path_slice, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_fchmod(fd: i32, mode: u32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    const mode_struct = vfs.FileMode{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };

    vfs.fchmod(vfs_fd, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_ftruncate(fd: i32, length: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    vfs.ftruncate(vfs_fd, length) catch |err| return vfsErrno(err);
    return 0;
}

const LinuxDirent = extern struct {
    d_ino: u32,
    d_off: u32,
    d_reclen: u16,
    d_type: u8,
};

fn sys_getdents(fd: i32, buf_addr: usize, buf_size: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    if (!protection.verifyUserPointer(buf_addr, buf_size)) return EINVAL;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    // SAFETY: filled by the subsequent vfs.readdir calls
    var dirent: vfs.DirEntry = undefined;
    var offset: usize = 0;
    var index: u64 = 0;

    while (offset + @sizeOf(LinuxDirent) + 1 < buf_size) {
        const has_entry = vfs.readdir(vfs_fd, &dirent, index) catch |err| return vfsErrno(err);
        if (!has_entry) break;

        const name_len = dirent.name_len;
        const reclen: u16 = @intCast(@sizeOf(LinuxDirent) + name_len + 1);
        if (offset + reclen > buf_size) break;

        var kernel_entry: LinuxDirent = .{
            .d_ino = @intCast(dirent.inode & 0xFFFFFFFF),
            .d_off = @intCast(index + 1),
            .d_reclen = reclen,
            .d_type = @intFromEnum(dirent.file_type),
        };

        protection.copyToUser(buf_addr + offset, std.mem.asBytes(&kernel_entry)) catch return EINVAL;
        protection.copyToUser(buf_addr + offset + @sizeOf(LinuxDirent), dirent.name[0..name_len]) catch return EINVAL;
        const null_byte = [_]u8{0};
        protection.copyToUser(buf_addr + offset + @sizeOf(LinuxDirent) + name_len, &null_byte) catch return EINVAL;

        offset += reclen;
        index += 1;
    }

    return @intCast(offset);
}

fn sys_symlink(target: [*]const u8, linkpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(target), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(linkpath), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser calls
    var target_buf: [256]u8 = undefined;
    var link_buf: [256]u8 = undefined;

    const target_slice = protection.copyStringFromUser(&target_buf, @intFromPtr(target)) catch return EINVAL;
    const link_slice = protection.copyStringFromUser(&link_buf, @intFromPtr(linkpath)) catch return EINVAL;

    vfs.symlink(target_slice, link_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_link(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(newpath), 256)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser calls
    var old_buf: [256]u8 = undefined;
    var new_buf: [256]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buf, @intFromPtr(oldpath)) catch return EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buf, @intFromPtr(newpath)) catch return EINVAL;

    vfs.link(old_slice, new_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_readlink(pathname: [*]const u8, buf: [*]u8, buf_size: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(buf), buf_size)) return EINVAL;

    // SAFETY: filled by the subsequent copyStringFromUser call
    var path_buf: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(pathname)) catch return EINVAL;

    // SAFETY: filled by the subsequent vfs.readlink call
    var kernel_buf: [256]u8 = undefined;
    const read_size = @min(buf_size, kernel_buf.len);
    const link_len = vfs.readlink(path_slice, kernel_buf[0..read_size]) catch |err| return vfsErrno(err);

    protection.copyToUser(@intFromPtr(buf), kernel_buf[0..link_len]) catch return EINVAL;
    return @intCast(link_len);
}

fn sys_sigprocmask(how: i32, set_addr: usize, oldset_addr: usize) i32 {
    var set_ptr: ?*const signal.SigSet = null;
    var oldset_ptr: ?*signal.SigSet = null;

    // SAFETY: filled by the subsequent copyFromUser call
    var set_buf: signal.SigSet = undefined;
    // SAFETY: filled by the subsequent sigprocmask call
    var oldset_buf: signal.SigSet = undefined;

    if (set_addr != 0) {
        if (!protection.verifyUserPointer(set_addr, @sizeOf(signal.SigSet))) return EINVAL;
        protection.copyFromUser(std.mem.asBytes(&set_buf), set_addr) catch return EINVAL;
        set_ptr = &set_buf;
    }

    if (oldset_addr != 0) {
        if (!protection.verifyUserPointer(oldset_addr, @sizeOf(signal.SigSet))) return EINVAL;
        oldset_ptr = &oldset_buf;
    }

    signal.sigprocmask(how, set_ptr, oldset_ptr) catch return EINVAL;

    if (oldset_addr != 0) {
        protection.copyToUser(oldset_addr, std.mem.asBytes(&oldset_buf)) catch return EINVAL;
    }

    return 0;
}

fn sys_sigpending(set_addr: usize) i32 {
    if (!protection.verifyUserPointer(set_addr, @sizeOf(signal.SigSet))) return EINVAL;

    // SAFETY: filled by the subsequent sigpending call
    var set: signal.SigSet = undefined;
    signal.sigpending(&set);

    protection.copyToUser(set_addr, std.mem.asBytes(&set)) catch return EINVAL;
    return 0;
}

fn sys_sigsuspend(mask_addr: usize) i32 {
    if (!protection.verifyUserPointer(mask_addr, @sizeOf(signal.SigSet))) return EINVAL;

    // SAFETY: filled by the subsequent copyFromUser call
    var mask: signal.SigSet = undefined;
    protection.copyFromUser(std.mem.asBytes(&mask), mask_addr) catch return EINVAL;

    signal.sigsuspend(&mask) catch |err| {
        return switch (err) {
            error.Interrupted => EINTR,
        };
    };
    return EINTR;
}

fn sys_dup(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    var new_fd: u32 = 0;
    while (new_fd < 256) : (new_fd += 1) {
        const result = vfs.dup2(vfs_fd, new_fd) catch continue;
        return @as(i32, @intCast(result)) + FD_OFFSET;
    }
    return EMFILE;
}

const F_DUPFD = 0;
const F_GETFD = 1;
const F_SETFD = 2;
const F_GETFL = 3;
const F_SETFL = 4;
const FD_CLOEXEC: u32 = 1;

const Flock = extern struct {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
};

const FileLock = struct {
    fd: u32,
    l_type: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
    in_use: bool,
};

var file_locks: [256]FileLock = [_]FileLock{.{
    .fd = 0,
    .l_type = F_UNLCK,
    .l_start = 0,
    .l_len = 0,
    .l_pid = 0,
    .in_use = false,
}} ** 256;

fn sys_fcntl(fd: i32, cmd: i32, arg: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    const ucmd: u32 = @bitCast(cmd);
    switch (ucmd) {
        F_DUPFD => {
            const min_fd = if (arg >= FD_OFFSET) @as(u32, @intCast(arg - FD_OFFSET)) else 0;
            var new_fd = min_fd;
            while (new_fd < 256) : (new_fd += 1) {
                const result = vfs.dup2(vfs_fd, new_fd) catch continue;
                return @as(i32, @intCast(result)) + FD_OFFSET;
            }
            return EMFILE;
        },
        F_GETFD => {
            const fd_flags = vfs.getFdFlags(vfs_fd) catch return EBADF;
            return @intCast(fd_flags);
        },
        F_SETFD => {
            vfs.setFdFlags(vfs_fd, @intCast(arg & FD_CLOEXEC)) catch return EBADF;
            return 0;
        },
        F_GETFL => {
            const flags = vfs.getFileFlags(vfs_fd) catch return EBADF;
            return @intCast(flags);
        },
        F_SETFL => {
            vfs.setFileFlags(vfs_fd, @intCast(arg)) catch return EBADF;
            return 0;
        },
        F_GETLK => {
            if (!protection.verifyUserPointer(arg, @sizeOf(Flock))) return EINVAL;
            var flock: Flock = undefined;
            protection.copyFromUser(std.mem.asBytes(&flock), arg) catch return EINVAL;

            for (file_locks) |lock| {
                if (lock.in_use and lock.fd == vfs_fd) {
                    if (locksOverlap(flock.l_start, flock.l_len, lock.l_start, lock.l_len)) {
                        if (lock.l_type == F_WRLCK or flock.l_type == F_WRLCK) {
                            flock.l_type = lock.l_type;
                            flock.l_start = lock.l_start;
                            flock.l_len = lock.l_len;
                            flock.l_pid = lock.l_pid;
                            protection.copyToUser(arg, std.mem.asBytes(&flock)) catch return EINVAL;
                            return 0;
                        }
                    }
                }
            }
            flock.l_type = F_UNLCK;
            protection.copyToUser(arg, std.mem.asBytes(&flock)) catch return EINVAL;
            return 0;
        },
        F_SETLK, F_SETLKW => {
            if (!protection.verifyUserPointer(arg, @sizeOf(Flock))) return EINVAL;
            var flock: Flock = undefined;
            protection.copyFromUser(std.mem.asBytes(&flock), arg) catch return EINVAL;

            const pid: i32 = if (process.current_process) |p| @intCast(p.pid) else 0;

            if (flock.l_type == F_UNLCK) {
                for (&file_locks) |*lock| {
                    if (lock.in_use and lock.fd == vfs_fd and lock.l_pid == pid) {
                        if (locksOverlap(flock.l_start, flock.l_len, lock.l_start, lock.l_len)) {
                            lock.in_use = false;
                        }
                    }
                }
                return 0;
            }

            for (file_locks) |lock| {
                if (lock.in_use and lock.fd == vfs_fd and lock.l_pid != pid) {
                    if (locksOverlap(flock.l_start, flock.l_len, lock.l_start, lock.l_len)) {
                        if (lock.l_type == F_WRLCK or flock.l_type == F_WRLCK) {
                            return EAGAIN;
                        }
                    }
                }
            }

            for (&file_locks) |*lock| {
                if (!lock.in_use) {
                    lock.* = FileLock{
                        .fd = vfs_fd,
                        .l_type = flock.l_type,
                        .l_start = flock.l_start,
                        .l_len = flock.l_len,
                        .l_pid = pid,
                        .in_use = true,
                    };
                    return 0;
                }
            }
            return ENOLCK;
        },
        else => return EINVAL,
    }
}

fn locksOverlap(start1: i64, len1: i64, start2: i64, len2: i64) bool {
    const end1 = if (len1 == 0) std.math.maxInt(i64) else start1 + len1;
    const end2 = if (len2 == 0) std.math.maxInt(i64) else start2 + len2;
    return start1 < end2 and start2 < end1;
}

const FdSet = extern struct {
    fds_bits: [8]u32,
};

const Timeval = extern struct {
    tv_sec: i32,
    tv_usec: i32,
};

fn selectCheckFds(nfds: u32, readfds: *const FdSet, writefds: *const FdSet, exceptfds: *const FdSet, result_readfds: *FdSet, result_writefds: *FdSet, result_exceptfds: *FdSet) i32 {
    result_readfds.* = std.mem.zeroes(FdSet);
    result_writefds.* = std.mem.zeroes(FdSet);
    result_exceptfds.* = std.mem.zeroes(FdSet);

    var count: i32 = 0;
    var i: u32 = 0;
    while (i < nfds) : (i += 1) {
        const word_idx = i / 32;
        const bit_idx: u5 = @intCast(i % 32);
        const mask = @as(u32, 1) << bit_idx;

        if (readfds.fds_bits[word_idx] & mask != 0) {
            if (i < FD_OFFSET) {
                if (i == STDIN) {
                    result_readfds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            } else {
                const vfs_fd: u32 = i - FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    result_readfds.fds_bits[word_idx] |= mask;
                    count += 1;
                } else |_| {}
            }
        }

        if (writefds.fds_bits[word_idx] & mask != 0) {
            if (i < FD_OFFSET) {
                if (i == STDOUT or i == STDERR) {
                    result_writefds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            } else {
                const vfs_fd: u32 = i - FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    result_writefds.fds_bits[word_idx] |= mask;
                    count += 1;
                } else |_| {}
            }
        }

        if (exceptfds.fds_bits[word_idx] & mask != 0) {
            if (i >= FD_OFFSET) {
                const vfs_fd: u32 = i - FD_OFFSET;
                if (vfs.getFileFlags(vfs_fd)) |_| {} else |_| {
                    result_exceptfds.fds_bits[word_idx] |= mask;
                    count += 1;
                }
            }
        }
    }
    return count;
}

fn sys_select(nfds: i32, readfds_addr: usize, writefds_addr: usize, exceptfds_addr: usize, timeout_addr: usize) i32 {
    if (nfds < 0 or nfds > 256) return EINVAL;

    var readfds: FdSet = std.mem.zeroes(FdSet);
    var writefds: FdSet = std.mem.zeroes(FdSet);
    var exceptfds: FdSet = std.mem.zeroes(FdSet);
    var result_readfds: FdSet = std.mem.zeroes(FdSet);
    var result_writefds: FdSet = std.mem.zeroes(FdSet);
    var result_exceptfds: FdSet = std.mem.zeroes(FdSet);

    if (readfds_addr != 0) {
        if (!protection.verifyUserPointer(readfds_addr, @sizeOf(FdSet))) return EINVAL;
        protection.copyFromUser(std.mem.asBytes(&readfds), readfds_addr) catch return EINVAL;
    }

    if (writefds_addr != 0) {
        if (!protection.verifyUserPointer(writefds_addr, @sizeOf(FdSet))) return EINVAL;
        protection.copyFromUser(std.mem.asBytes(&writefds), writefds_addr) catch return EINVAL;
    }

    if (exceptfds_addr != 0) {
        if (!protection.verifyUserPointer(exceptfds_addr, @sizeOf(FdSet))) return EINVAL;
        protection.copyFromUser(std.mem.asBytes(&exceptfds), exceptfds_addr) catch return EINVAL;
    }

    var timeout_ms: i64 = -1;
    if (timeout_addr != 0) {
        if (!protection.verifyUserPointer(timeout_addr, @sizeOf(Timeval))) return EINVAL;
        var tv: Timeval = undefined;
        protection.copyFromUser(std.mem.asBytes(&tv), timeout_addr) catch return EINVAL;
        timeout_ms = @as(i64, tv.tv_sec) * 1000 + @divTrunc(tv.tv_usec, 1000);
    }

    var count = selectCheckFds(@intCast(nfds), &readfds, &writefds, &exceptfds, &result_readfds, &result_writefds, &result_exceptfds);

    if (timeout_ms == 0 or count > 0) {
        if (readfds_addr != 0) {
            protection.copyToUser(readfds_addr, std.mem.asBytes(&result_readfds)) catch return EINVAL;
        }
        if (writefds_addr != 0) {
            protection.copyToUser(writefds_addr, std.mem.asBytes(&result_writefds)) catch return EINVAL;
        }
        if (exceptfds_addr != 0) {
            protection.copyToUser(exceptfds_addr, std.mem.asBytes(&result_exceptfds)) catch return EINVAL;
        }
        return count;
    }

    const timer = @import("../timer/timer.zig");
    const start_ticks = timer.getTicks();
    const timeout_ticks: u64 = if (timeout_ms < 0) std.math.maxInt(u64) else @as(u64, @intCast(timeout_ms)) / 10;

    while (count == 0) {
        const elapsed = timer.getTicks() - start_ticks;
        if (timeout_ms >= 0 and elapsed >= timeout_ticks) break;

        process.yield();
        count = selectCheckFds(@intCast(nfds), &readfds, &writefds, &exceptfds, &result_readfds, &result_writefds, &result_exceptfds);
    }

    if (readfds_addr != 0) {
        protection.copyToUser(readfds_addr, std.mem.asBytes(&result_readfds)) catch return EINVAL;
    }
    if (writefds_addr != 0) {
        protection.copyToUser(writefds_addr, std.mem.asBytes(&result_writefds)) catch return EINVAL;
    }
    if (exceptfds_addr != 0) {
        protection.copyToUser(exceptfds_addr, std.mem.asBytes(&result_exceptfds)) catch return EINVAL;
    }

    return count;
}

fn sys_umask(mask: u16) i32 {
    const proc = process.current_process orelse return ESRCH;
    const old = proc.umask;
    proc.umask = mask & 0o777;
    return @intCast(old);
}

const UtsName = extern struct {
    sysname: [65]u8,
    nodename: [65]u8,
    release: [65]u8,
    version: [65]u8,
    machine: [65]u8,
};

var system_hostname: [65]u8 = blk: {
    var name = [_]u8{0} ** 65;
    name[0] = 'z';
    name[1] = 'i';
    name[2] = 'g';
    name[3] = 'o';
    name[4] = 's';
    break :blk name;
};
var hostname_len: usize = 5;

pub fn getHostname() []const u8 {
    return system_hostname[0..hostname_len];
}

pub fn setHostname(name: []const u8) void {
    const len = @min(name.len, 64);
    @memset(&system_hostname, 0);
    @memcpy(system_hostname[0..len], name[0..len]);
    hostname_len = len;
}

fn sys_gethostname(name_addr: usize, len: usize) i32 {
    if (len == 0) return EINVAL;
    if (!protection.verifyUserPointer(name_addr, len)) return EINVAL;

    const copy_len = @min(len - 1, hostname_len);
    var buf: [65]u8 = undefined;
    @memcpy(buf[0..copy_len], system_hostname[0..copy_len]);
    buf[copy_len] = 0;

    protection.copyToUser(name_addr, buf[0 .. copy_len + 1]) catch return EINVAL;
    return 0;
}

fn sys_sethostname(name_addr: usize, len: usize) i32 {
    if (process.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return EPERM;
        }
    }

    if (len > 64) return EINVAL;
    if (!protection.verifyUserPointer(name_addr, len)) return EINVAL;

    var buf: [64]u8 = undefined;
    protection.copyFromUser(buf[0..len], name_addr) catch return EINVAL;

    setHostname(buf[0..len]);
    return 0;
}

fn fillField(dest: *[65]u8, src: []const u8) void {
    @memset(dest, 0);
    const len = @min(src.len, 64);
    @memcpy(dest[0..len], src[0..len]);
}

fn sys_uname(buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(UtsName))) return EINVAL;

    var buf: UtsName = undefined;
    fillField(&buf.sysname, "ZigOS");
    fillField(&buf.nodename, system_hostname[0..hostname_len]);
    fillField(&buf.release, "0.1.0");
    fillField(&buf.version, "ZigOS 0.1.0 (Zig 0.16.0-dev)");
    fillField(&buf.machine, "i386");

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return EINVAL;
    return 0;
}

fn sys_truncate(pathname: [*]const u8, length: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.truncate(path_slice, length) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_pread(fd: i32, buf: [*]u8, count: usize, offset: u64) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) return EINVAL;
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    var kernel_buffer: [512]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < count) {
        const chunk_size = @min(count - total_read, kernel_buffer.len);
        const bytes_read = vfs.pread(vfs_fd, kernel_buffer[0..chunk_size], offset + total_read) catch |err| return vfsErrno(err);
        if (bytes_read == 0) break;

        protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch return EINVAL;
        total_read += bytes_read;
        if (bytes_read < chunk_size) break;
    }

    return @intCast(total_read);
}

fn sys_pwrite(fd: i32, buf: [*]const u8, count: usize, offset: u64) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) return EINVAL;
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    var kernel_buffer: [512]u8 = undefined;
    var written: usize = 0;

    while (written < count) {
        const chunk_size = @min(count - written, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch return EINVAL;
        const bytes_written = vfs.pwrite(vfs_fd, kernel_buffer[0..chunk_size], offset + written) catch |err| return vfsErrno(err);
        written += bytes_written;
        if (bytes_written < chunk_size) break;
    }

    return @intCast(written);
}

fn parseSockAddr(addr_ptr: usize, addr_len: u32) ?struct { addr: @import("../net/ipv4.zig").IPv4Address, port: u16 } {
    if (addr_len < @sizeOf(SockAddrIn)) return null;
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return null;

    var addr_buf: [@sizeOf(SockAddrIn)]u8 = undefined;
    protection.copyFromUser(&addr_buf, addr_ptr) catch return null;
    const addr: *const SockAddrIn = @ptrCast(@alignCast(&addr_buf));

    return .{
        .addr = @import("../net/ipv4.zig").IPv4Address{
            .octets = .{
                @intCast((addr.addr >> 0) & 0xFF),
                @intCast((addr.addr >> 8) & 0xFF),
                @intCast((addr.addr >> 16) & 0xFF),
                @intCast((addr.addr >> 24) & 0xFF),
            },
        },
        .port = @byteSwap(addr.port),
    };
}

fn writeSockAddr(addr_ptr: usize, len_ptr: usize, ipv4_addr: @import("../net/ipv4.zig").IPv4Address, port: u16) i32 {
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn))) return EINVAL;

    const addr = SockAddrIn{
        .family = @intCast(AF_INET),
        .port = @byteSwap(port),
        .addr = @as(u32, ipv4_addr.octets[0]) |
            (@as(u32, ipv4_addr.octets[1]) << 8) |
            (@as(u32, ipv4_addr.octets[2]) << 16) |
            (@as(u32, ipv4_addr.octets[3]) << 24),
        .zero = [_]u8{0} ** 8,
    };

    protection.copyToUser(addr_ptr, std.mem.asBytes(&addr)) catch return EINVAL;
    if (len_ptr != 0 and protection.verifyUserPointer(len_ptr, @sizeOf(u32))) {
        var len: u32 = @sizeOf(SockAddrIn);
        protection.copyToUser(len_ptr, std.mem.asBytes(&len)) catch {};
    }
    return 0;
}

fn writeSockAddr6(addr_ptr: usize, len_ptr: usize, ipv6_addr: @import("../net/ipv6.zig").IPv6Address, port: u16) i32 {
    if (!protection.verifyUserPointer(addr_ptr, @sizeOf(SockAddrIn6))) return EINVAL;

    const addr = SockAddrIn6{
        .family = @intCast(AF_INET6),
        .port = @byteSwap(port),
        .flowinfo = 0,
        .addr = ipv6_addr.octets,
        .scope_id = 0,
    };

    protection.copyToUser(addr_ptr, std.mem.asBytes(&addr)) catch return EINVAL;
    if (len_ptr != 0 and protection.verifyUserPointer(len_ptr, @sizeOf(u32))) {
        var len: u32 = @sizeOf(SockAddrIn6);
        protection.copyToUser(len_ptr, std.mem.asBytes(&len)) catch {};
    }
    return 0;
}

fn sys_sendto(sockfd: i32, buf: [*]const u8, len: usize, dest_addr: usize, addr_len: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_send = @min(len, kernel_buffer.len);
    protection.copyFromUser(kernel_buffer[0..to_send], @intFromPtr(buf)) catch return EINVAL;

    if (dest_addr == 0) {
        if (sock.address_family == .AF_INET6) {
            if (sock.remote_ipv6) |dst| {
                @import("../net/ipv6.zig").sendPacket(dst, @import("../net/ipv6.zig").NEXT_HEADER_UDP, kernel_buffer[0..to_send]);
                return @intCast(to_send);
            }
            return ENOTCONN;
        }
        const sent = sock.send(kernel_buffer[0..to_send]) catch |err| return socketErrno(err);
        return @intCast(sent);
    }

    if (sock.address_family == .AF_INET6) {
        if (addr_len < @sizeOf(SockAddrIn6)) return EINVAL;
        if (!protection.verifyUserPointer(dest_addr, @sizeOf(SockAddrIn6))) return EINVAL;

        var addr_buf: [@sizeOf(SockAddrIn6)]u8 = undefined;
        protection.copyFromUser(&addr_buf, dest_addr) catch return EINVAL;
        const addr: *const SockAddrIn6 = @ptrCast(@alignCast(&addr_buf));

        const dst = @import("../net/ipv6.zig").IPv6Address{ .octets = addr.addr };
        @import("../net/ipv6.zig").sendPacket(dst, @import("../net/ipv6.zig").NEXT_HEADER_UDP, kernel_buffer[0..to_send]);
        return @intCast(to_send);
    }

    const parsed = parseSockAddr(dest_addr, addr_len) orelse return EINVAL;
    sock.sendTo(kernel_buffer[0..to_send], parsed.addr, parsed.port) catch |err| return socketErrno(err);
    return @intCast(to_send);
}

fn sys_recvfrom(sockfd: i32, buf: [*]u8, len: usize, src_addr: usize, addr_len_ptr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return EINVAL;

    var kernel_buffer: [4096]u8 = undefined;
    const to_recv = @min(len, kernel_buffer.len);

    if (src_addr == 0) {
        const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return socketErrno(err);
        if (received == 0) return 0;
        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
        return @intCast(received);
    }

    if (sock.address_family == .AF_INET6) {
        const received = sock.recv(kernel_buffer[0..to_recv]) catch |err| return socketErrno(err);
        if (received == 0) return 0;
        protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
        if (sock.remote_ipv6) |from_ipv6| {
            _ = writeSockAddr6(src_addr, addr_len_ptr, from_ipv6, sock.remote_port);
        }
        return @intCast(received);
    }

    var from_addr = @import("../net/ipv4.zig").IPv4Address{ .octets = .{ 0, 0, 0, 0 } };
    var from_port: u16 = 0;
    const received = sock.recvFrom(kernel_buffer[0..to_recv], &from_addr, &from_port) catch |err| return socketErrno(err);
    if (received == 0) return 0;

    protection.copyToUser(@intFromPtr(buf), kernel_buffer[0..received]) catch return EINVAL;
    _ = writeSockAddr(src_addr, addr_len_ptr, from_addr, from_port);
    return @intCast(received);
}

fn sys_getsockname(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    if (sock.address_family == .AF_INET6) {
        const local = sock.local_ipv6 orelse @import("../net/ipv6.zig").UNSPECIFIED;
        return writeSockAddr6(addr_ptr, addr_len_ptr, local, sock.local_port);
    }
    return writeSockAddr(addr_ptr, addr_len_ptr, sock.local_addr, sock.local_port);
}

fn sys_getpeername(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;
    if (sock.state != .CONNECTED) return ENOTCONN;
    if (sock.address_family == .AF_INET6) {
        const remote = sock.remote_ipv6 orelse @import("../net/ipv6.zig").UNSPECIFIED;
        return writeSockAddr6(addr_ptr, addr_len_ptr, remote, sock.remote_port);
    }
    return writeSockAddr(addr_ptr, addr_len_ptr, sock.remote_addr, sock.remote_port);
}

fn sys_fchown(fd: i32, uid: u16, gid: u16) i32 {
    if (fd < FD_OFFSET) return EBADF;

    if (process.current_process) |proc| {
        if (!credentials.isRoot(&proc.creds)) {
            return EPERM;
        }
    }

    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    vfs.fchown(vfs_fd, uid, gid) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_fsync(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    return 0;
}

const PollFd = extern struct {
    fd: i32,
    events: i16,
    revents: i16,
};

const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;

fn pollCheckFds(kernel_fds: []PollFd, nfds: u32) i32 {
    var count: i32 = 0;
    var i: u32 = 0;
    while (i < nfds) : (i += 1) {
        kernel_fds[i].revents = 0;
        const fd = kernel_fds[i].fd;

        if (fd < 0) continue;

        if (fd < FD_OFFSET) {
            if (fd == STDIN and (kernel_fds[i].events & POLLIN) != 0) {
                kernel_fds[i].revents |= POLLIN;
                count += 1;
            }
            if ((fd == STDOUT or fd == STDERR) and (kernel_fds[i].events & POLLOUT) != 0) {
                kernel_fds[i].revents |= POLLOUT;
                count += 1;
            }
            continue;
        }

        const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
        if (vfs.getFileFlags(vfs_fd)) |flags| {
            const access_mode = flags & 0x3;
            if ((kernel_fds[i].events & POLLIN) != 0 and (access_mode == 0 or access_mode == 2)) {
                kernel_fds[i].revents |= POLLIN;
            }
            if ((kernel_fds[i].events & POLLOUT) != 0 and (access_mode == 1 or access_mode == 2)) {
                kernel_fds[i].revents |= POLLOUT;
            }
            if (kernel_fds[i].revents != 0) count += 1;
        } else |_| {
            kernel_fds[i].revents = POLLNVAL;
            count += 1;
        }
    }
    return count;
}

fn sys_poll(fds_addr: usize, nfds: u32, timeout: i32) i32 {
    if (nfds == 0) return 0;
    if (nfds > 256) return EINVAL;

    const copy_size = nfds * @sizeOf(PollFd);
    if (!protection.verifyUserPointer(fds_addr, copy_size)) return EINVAL;

    var kernel_fds: [256]PollFd = undefined;
    protection.copyFromUser(std.mem.asBytes(&kernel_fds)[0..copy_size], fds_addr) catch return EINVAL;

    var count = pollCheckFds(kernel_fds[0..nfds], nfds);

    if (timeout == 0 or count > 0) {
        protection.copyToUser(fds_addr, std.mem.asBytes(&kernel_fds)[0..copy_size]) catch return EINVAL;
        return count;
    }

    const timer = @import("../timer/timer.zig");
    const start_ticks = timer.getTicks();
    const timeout_ticks: u64 = if (timeout < 0) std.math.maxInt(u64) else @as(u64, @intCast(timeout)) / 10;

    while (count == 0) {
        const elapsed = timer.getTicks() - start_ticks;
        if (timeout >= 0 and elapsed >= timeout_ticks) break;

        process.yield();
        count = pollCheckFds(kernel_fds[0..nfds], nfds);
    }

    protection.copyToUser(fds_addr, std.mem.asBytes(&kernel_fds)[0..copy_size]) catch return EINVAL;
    return count;
}

fn sys_lstat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;
    if (!protection.verifyUserPointer(stat_buf_addr, @sizeOf(vfs.FileStat))) return EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(path_slice, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(stat_buf_addr, std.mem.asBytes(&stat_buf)) catch return EINVAL;
    return 0;
}

const SOL_SOCKET: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_BROADCAST: i32 = 6;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_LINGER: i32 = 13;
const SO_RCVTIMEO: i32 = 20;
const SO_SNDTIMEO: i32 = 21;
const TCP_NODELAY: i32 = 1;

fn sys_getsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen_addr: usize) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (!protection.verifyUserPointer(optval_addr, @sizeOf(i32))) return EINVAL;

    var val: i32 = 0;

    if (level == SOL_SOCKET) {
        switch (optname) {
            SO_TYPE => val = switch (sock.socket_type) {
                .STREAM => @intCast(SOCK_STREAM),
                .DGRAM => @intCast(SOCK_DGRAM),
                else => 0,
            },
            SO_ERROR => val = 0,
            SO_REUSEADDR, SO_KEEPALIVE, SO_BROADCAST => val = 0,
            SO_SNDBUF => val = 4096,
            SO_RCVBUF => val = 4096,
            SO_LINGER => val = 0,
            SO_RCVTIMEO, SO_SNDTIMEO => val = 0,
            else => return ENOPROTOOPT,
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
            TCP_NODELAY => val = 1,
            else => return ENOPROTOOPT,
        }
    } else {
        return ENOPROTOOPT;
    }

    protection.copyToUser(optval_addr, std.mem.asBytes(&val)) catch return EINVAL;
    if (optlen_addr != 0 and protection.verifyUserPointer(optlen_addr, @sizeOf(u32))) {
        var len: u32 = @sizeOf(i32);
        protection.copyToUser(optlen_addr, std.mem.asBytes(&len)) catch {};
    }
    return 0;
}

fn sys_setsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen: u32) i32 {
    if (sockfd < 0 or sockfd >= 64) return EBADF;
    _ = socket_table[@intCast(sockfd)] orelse return EBADF;

    if (optlen < @sizeOf(i32)) return EINVAL;
    if (!protection.verifyUserPointer(optval_addr, @sizeOf(i32))) return EINVAL;

    if (level == SOL_SOCKET) {
        switch (optname) {
            SO_REUSEADDR, SO_KEEPALIVE, SO_BROADCAST => return 0,
            SO_SNDBUF, SO_RCVBUF => return 0,
            SO_LINGER => return 0,
            SO_RCVTIMEO, SO_SNDTIMEO => return 0,
            else => return ENOPROTOOPT,
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
            TCP_NODELAY => return 0,
            else => return ENOPROTOOPT,
        }
    } else {
        return ENOPROTOOPT;
    }
}

const IoVec = extern struct {
    iov_base: usize,
    iov_len: usize,
};

fn sys_readv(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    if (iovcnt <= 0 or iovcnt > 16) return EINVAL;
    const cnt: u32 = @intCast(iovcnt);
    const iov_size = cnt * @sizeOf(IoVec);
    if (!protection.verifyUserPointer(iov_addr, iov_size)) return EINVAL;

    var iov: [16]IoVec = undefined;
    protection.copyFromUser(std.mem.asBytes(&iov)[0..iov_size], iov_addr) catch return EINVAL;

    var total: usize = 0;
    var i: u32 = 0;
    while (i < cnt) : (i += 1) {
        if (iov[i].iov_len == 0) continue;
        if (!protection.verifyUserPointer(iov[i].iov_base, iov[i].iov_len)) return EINVAL;

        const result = sys_read(fd, @ptrFromInt(iov[i].iov_base), iov[i].iov_len);
        if (result < 0) {
            if (total > 0) return @intCast(total);
            return result;
        }
        total += @intCast(result);
        if (@as(usize, @intCast(result)) < iov[i].iov_len) break;
    }

    return @intCast(total);
}

fn sys_writev(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    if (iovcnt <= 0 or iovcnt > 16) return EINVAL;
    const cnt: u32 = @intCast(iovcnt);
    const iov_size = cnt * @sizeOf(IoVec);
    if (!protection.verifyUserPointer(iov_addr, iov_size)) return EINVAL;

    var iov: [16]IoVec = undefined;
    protection.copyFromUser(std.mem.asBytes(&iov)[0..iov_size], iov_addr) catch return EINVAL;

    var total: usize = 0;
    var i: u32 = 0;
    while (i < cnt) : (i += 1) {
        if (iov[i].iov_len == 0) continue;
        if (!protection.verifyUserPointer(iov[i].iov_base, iov[i].iov_len)) return EINVAL;

        const result = sys_write(fd, @ptrFromInt(iov[i].iov_base), iov[i].iov_len);
        if (result < 0) {
            if (total > 0) return @intCast(total);
            return result;
        }
        total += @intCast(result);
        if (@as(usize, @intCast(result)) < iov[i].iov_len) break;
    }

    return @intCast(total);
}

fn sys_geteuid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.euid);
    }
    return 0;
}

fn sys_getegid() i32 {
    if (process.current_process) |proc| {
        return @intCast(proc.creds.egid);
    }
    return 0;
}

fn sys_isatty(fd: i32) i32 {
    if (fd == STDIN or fd == STDOUT or fd == STDERR) {
        return 1;
    }
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);
    if (vfs.getFileFlags(vfs_fd)) |_| {
        return 0;
    } else |_| {
        return EBADF;
    }
}

const StatFs = extern struct {
    f_type: u32,
    f_bsize: u32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]u32,
    f_namelen: u32,
    f_frsize: u32,
    f_flags: u32,
    f_spare: [4]u32,
};

fn sys_statfs(pathname: [*]const u8, buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(StatFs))) return EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    _ = vfs.lookupPath(path_slice) catch |err| return vfsErrno(err);

    const buf = StatFs{
        .f_type = 0x858458f6,
        .f_bsize = 4096,
        .f_blocks = 1024 * 1024,
        .f_bfree = 512 * 1024,
        .f_bavail = 512 * 1024,
        .f_files = 65536,
        .f_ffree = 32768,
        .f_fsid = .{ 0, 0 },
        .f_namelen = 255,
        .f_frsize = 4096,
        .f_flags = 0,
        .f_spare = .{ 0, 0, 0, 0 },
    };

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return EINVAL;
    return 0;
}

fn sys_fstatfs(fd: i32, buf_addr: usize) i32 {
    if (!protection.verifyUserPointer(buf_addr, @sizeOf(StatFs))) return EINVAL;
    if (fd < FD_OFFSET) return EBADF;
    const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

    _ = vfs.getFileFlags(vfs_fd) catch return EBADF;

    const buf = StatFs{
        .f_type = 0x858458f6,
        .f_bsize = 4096,
        .f_blocks = 1024 * 1024,
        .f_bfree = 512 * 1024,
        .f_bavail = 512 * 1024,
        .f_files = 65536,
        .f_ffree = 32768,
        .f_fsid = .{ 0, 0 },
        .f_namelen = 255,
        .f_frsize = 4096,
        .f_flags = 0,
        .f_spare = .{ 0, 0, 0, 0 },
    };

    protection.copyToUser(buf_addr, std.mem.asBytes(&buf)) catch return EINVAL;
    return 0;
}

fn resolveDirFd(dirfd: i32, path: []const u8, buf: *[512]u8) ?[]const u8 {
    if (path.len > 0 and path[0] == '/') {
        return path;
    }

    var base_path: []const u8 = undefined;
    if (dirfd == AT_FDCWD) {
        ensureCwdInit();
        base_path = current_working_dir[0..cwd_len];
    } else {
        if (dirfd < FD_OFFSET) return null;
        const vfs_fd: u32 = @intCast(dirfd - FD_OFFSET);
        const vnode = vfs.getVNodeFromFd(vfs_fd) catch return null;
        if (vnode.file_type != .Directory) return null;
        base_path = vfs.getNodePath(vnode) catch return null;
    }

    if (base_path.len + 1 + path.len >= buf.len) return null;

    @memcpy(buf[0..base_path.len], base_path);
    var pos = base_path.len;
    if (pos > 0 and buf[pos - 1] != '/') {
        buf[pos] = '/';
        pos += 1;
    }
    @memcpy(buf[pos .. pos + path.len], path);
    pos += path.len;

    return buf[0..pos];
}

fn sys_openat(dirfd: i32, pathname: [*]const u8, flags: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EINVAL;

    var resolved_buf: [512]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return EBADF;

    const fd = vfs.open(resolved, @intCast(flags)) catch |err| return vfsErrno(err);
    return @intCast(@as(i32, @intCast(fd)) + FD_OFFSET);
}

fn sys_mkdirat(dirfd: i32, pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EINVAL;

    var resolved_buf: [512]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return EBADF;

    const mode_struct = vfs.FileMode{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };

    vfs.mkdir(resolved, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_unlinkat(dirfd: i32, pathname: [*]const u8, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EINVAL;

    var resolved_buf: [512]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return EBADF;

    if (flags & AT_REMOVEDIR != 0) {
        vfs.rmdir(resolved) catch |err| return vfsErrno(err);
    } else {
        vfs.unlink(resolved) catch |err| return vfsErrno(err);
    }
    return 0;
}

fn sys_linkat(olddirfd: i32, oldpath: [*]const u8, newdirfd: i32, newpath: [*]const u8, _: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(newpath), 256)) return EINVAL;

    var old_buffer: [256]u8 = undefined;
    var new_buffer: [256]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return EINVAL;

    var resolved_old_buf: [512]u8 = undefined;
    var resolved_new_buf: [512]u8 = undefined;

    const resolved_old = resolveDirFd(olddirfd, old_slice, &resolved_old_buf) orelse return EBADF;
    const resolved_new = resolveDirFd(newdirfd, new_slice, &resolved_new_buf) orelse return EBADF;

    vfs.link(resolved_old, resolved_new) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_fchmodat(dirfd: i32, pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EINVAL;

    var resolved_buf: [512]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return EBADF;

    const mode_struct = vfs.FileMode{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };

    vfs.chmod(resolved, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_fchownat(dirfd: i32, pathname: [*]const u8, owner: i32, group: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EINVAL;

    var resolved_buf: [512]u8 = undefined;
    const resolved = resolveDirFd(dirfd, path_slice, &resolved_buf) orelse return EBADF;

    const uid: u32 = if (owner < 0) 0xFFFFFFFF else @intCast(owner);
    const gid: u32 = if (group < 0) 0xFFFFFFFF else @intCast(group);

    vfs.chown(resolved, uid, gid) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_renameat(olddirfd: i32, oldpath: [*]const u8, newdirfd: i32, newpath: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(oldpath), 256)) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(newpath), 256)) return EINVAL;

    var old_buffer: [256]u8 = undefined;
    var new_buffer: [256]u8 = undefined;

    const old_slice = protection.copyStringFromUser(&old_buffer, @intFromPtr(oldpath)) catch return EINVAL;
    const new_slice = protection.copyStringFromUser(&new_buffer, @intFromPtr(newpath)) catch return EINVAL;

    var resolved_old_buf: [512]u8 = undefined;
    var resolved_new_buf: [512]u8 = undefined;

    const resolved_old = resolveDirFd(olddirfd, old_slice, &resolved_old_buf) orelse return EBADF;
    const resolved_new = resolveDirFd(newdirfd, new_slice, &resolved_new_buf) orelse return EBADF;

    vfs.rename(resolved_old, resolved_new) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_getgroups(size: i32, list_addr: usize) i32 {
    const proc = process.current_process orelse return ESRCH;

    if (size == 0) {
        return @intCast(proc.creds.ngroups);
    }

    if (size < 0) return EINVAL;
    const usize_size: usize = @intCast(size);
    if (!protection.verifyUserPointer(list_addr, usize_size * @sizeOf(u32))) return EINVAL;

    const count: usize = @min(usize_size, proc.creds.ngroups);
    var groups: [16]u32 = undefined;
    for (0..count) |i| {
        groups[i] = proc.creds.groups[i];
    }

    protection.copyToUser(list_addr, std.mem.sliceAsBytes(groups[0..count])) catch return EINVAL;
    return @intCast(count);
}

fn sys_setgroups(size: i32, list_addr: usize) i32 {
    const proc = process.current_process orelse return ESRCH;
    if (!credentials.isRoot(&proc.creds)) return EPERM;

    if (size < 0 or size > 16) return EINVAL;
    const usize_size: usize = @intCast(size);

    if (usize_size > 0) {
        if (!protection.verifyUserPointer(list_addr, usize_size * @sizeOf(u32))) return EINVAL;
    }

    var groups: [16]u32 = undefined;
    if (usize_size > 0) {
        protection.copyFromUser(std.mem.sliceAsBytes(groups[0..usize_size]), list_addr) catch return EINVAL;
    }

    for (0..usize_size) |i| {
        proc.creds.groups[i] = @intCast(groups[i]);
    }
    proc.creds.ngroups = @intCast(usize_size);

    return 0;
}

const Itimerval = extern struct {
    it_interval_sec: u32,
    it_interval_usec: u32,
    it_value_sec: u32,
    it_value_usec: u32,
};

var process_itimers: [256][3]Itimerval = [_][3]Itimerval{[_]Itimerval{.{
    .it_interval_sec = 0,
    .it_interval_usec = 0,
    .it_value_sec = 0,
    .it_value_usec = 0,
}} ** 3} ** 256;

fn sys_getitimer(which: u32, value_addr: usize) i32 {
    if (which > ITIMER_PROF) return EINVAL;
    if (!protection.verifyUserPointer(value_addr, @sizeOf(Itimerval))) return EINVAL;

    const proc = process.current_process orelse return ESRCH;
    const timer = process_itimers[proc.pid][which];

    protection.copyToUser(value_addr, std.mem.asBytes(&timer)) catch return EINVAL;
    return 0;
}

fn sys_setitimer(which: u32, new_value_addr: usize, old_value_addr: usize) i32 {
    if (which > ITIMER_PROF) return EINVAL;
    if (!protection.verifyUserPointer(new_value_addr, @sizeOf(Itimerval))) return EINVAL;
    if (old_value_addr != 0 and !protection.verifyUserPointer(old_value_addr, @sizeOf(Itimerval))) return EINVAL;

    const proc = process.current_process orelse return ESRCH;

    if (old_value_addr != 0) {
        const old_timer = process_itimers[proc.pid][which];
        protection.copyToUser(old_value_addr, std.mem.asBytes(&old_timer)) catch return EINVAL;
    }

    var new_timer: Itimerval = undefined;
    protection.copyFromUser(std.mem.asBytes(&new_timer), new_value_addr) catch return EINVAL;
    process_itimers[proc.pid][which] = new_timer;

    return 0;
}

fn sys_mkfifo(pathname: [*]const u8, mode: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const mode_struct = vfs.FileMode{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };

    vfs.mkfifo(path_slice, mode_struct) catch |err| return vfsErrno(err);
    return 0;
}

const EpollEvent = extern struct {
    events: u32,
    data: u64,
};

const EpollEntry = struct {
    fd: i32,
    events: u32,
    data: u64,
};

const EpollInstance = struct {
    entries: [64]?EpollEntry,
    count: usize,
    in_use: bool,
};

var epoll_instances: [64]EpollInstance = [_]EpollInstance{.{
    .entries = [_]?EpollEntry{null} ** 64,
    .count = 0,
    .in_use = false,
}} ** 64;

fn sys_epoll_create(_: i32) i32 {
    for (&epoll_instances, 0..) |*inst, i| {
        if (!inst.in_use) {
            inst.in_use = true;
            inst.count = 0;
            for (&inst.entries) |*e| {
                e.* = null;
            }
            return @intCast(@as(i32, @intCast(i)) + FD_OFFSET + 200);
        }
    }
    return EMFILE;
}

fn sys_epoll_ctl(epfd: i32, op: u32, fd: i32, event_addr: usize) i32 {
    const idx = epfd - FD_OFFSET - 200;
    if (idx < 0 or idx >= 64) return EBADF;
    const inst = &epoll_instances[@intCast(idx)];
    if (!inst.in_use) return EBADF;

    switch (op) {
        EPOLL_CTL_ADD => {
            if (event_addr == 0) return EINVAL;
            if (!protection.verifyUserPointer(event_addr, @sizeOf(EpollEvent))) return EINVAL;
            var ev: EpollEvent = undefined;
            protection.copyFromUser(std.mem.asBytes(&ev), event_addr) catch return EINVAL;

            for (&inst.entries) |*e| {
                if (e.* == null) {
                    e.* = EpollEntry{ .fd = fd, .events = ev.events, .data = ev.data };
                    inst.count += 1;
                    return 0;
                }
            }
            return ENOSPC;
        },
        EPOLL_CTL_DEL => {
            for (&inst.entries) |*e| {
                if (e.*) |entry| {
                    if (entry.fd == fd) {
                        e.* = null;
                        inst.count -= 1;
                        return 0;
                    }
                }
            }
            return ENOENT;
        },
        EPOLL_CTL_MOD => {
            if (event_addr == 0) return EINVAL;
            if (!protection.verifyUserPointer(event_addr, @sizeOf(EpollEvent))) return EINVAL;
            var ev: EpollEvent = undefined;
            protection.copyFromUser(std.mem.asBytes(&ev), event_addr) catch return EINVAL;

            for (&inst.entries) |*e| {
                if (e.*) |*entry| {
                    if (entry.fd == fd) {
                        entry.events = ev.events;
                        entry.data = ev.data;
                        return 0;
                    }
                }
            }
            return ENOENT;
        },
        else => return EINVAL,
    }
}

fn sys_epoll_wait(epfd: i32, events_addr: usize, maxevents: i32, _: i32) i32 {
    const idx = epfd - FD_OFFSET - 200;
    if (idx < 0 or idx >= 64) return EBADF;
    const inst = &epoll_instances[@intCast(idx)];
    if (!inst.in_use) return EBADF;

    if (maxevents <= 0) return EINVAL;
    const max: usize = @intCast(maxevents);
    if (!protection.verifyUserPointer(events_addr, max * @sizeOf(EpollEvent))) return EINVAL;

    var count: usize = 0;
    var events: [64]EpollEvent = undefined;

    for (inst.entries) |maybe_entry| {
        if (maybe_entry) |entry| {
            if (count >= max) break;
            var ready: u32 = 0;

            if (entry.fd >= FD_OFFSET) {
                const vfs_fd: u32 = @intCast(entry.fd - FD_OFFSET);
                if (vfs.getFileFlags(vfs_fd)) |_| {
                    if (entry.events & EPOLLIN != 0) ready |= EPOLLIN;
                    if (entry.events & EPOLLOUT != 0) ready |= EPOLLOUT;
                } else |_| {
                    ready |= EPOLLERR;
                }
            }

            if (ready != 0) {
                events[count] = EpollEvent{ .events = ready, .data = entry.data };
                count += 1;
            }
        }
    }

    if (count > 0) {
        protection.copyToUser(events_addr, std.mem.sliceAsBytes(events[0..count])) catch return EINVAL;
    }
    return @intCast(count);
}

const ItimerSpec = extern struct {
    it_interval_sec: u32,
    it_interval_nsec: u32,
    it_value_sec: u32,
    it_value_nsec: u32,
};

const TimerFd = struct {
    clockid: u32,
    flags: u32,
    spec: ItimerSpec,
    in_use: bool,
};

var timerfd_table: [64]TimerFd = [_]TimerFd{.{
    .clockid = 0,
    .flags = 0,
    .spec = .{ .it_interval_sec = 0, .it_interval_nsec = 0, .it_value_sec = 0, .it_value_nsec = 0 },
    .in_use = false,
}} ** 64;

fn sys_timerfd_create(clockid: u32, flags: u32) i32 {
    if (clockid != CLOCK_REALTIME and clockid != CLOCK_MONOTONIC) return EINVAL;

    for (&timerfd_table, 0..) |*tfd, i| {
        if (!tfd.in_use) {
            tfd.in_use = true;
            tfd.clockid = clockid;
            tfd.flags = flags;
            tfd.spec = .{ .it_interval_sec = 0, .it_interval_nsec = 0, .it_value_sec = 0, .it_value_nsec = 0 };
            return @intCast(@as(i32, @intCast(i)) + FD_OFFSET + 300);
        }
    }
    return EMFILE;
}

fn sys_timerfd_settime(fd: i32, _: u32, new_value_addr: usize, old_value_addr: usize) i32 {
    const idx = fd - FD_OFFSET - 300;
    if (idx < 0 or idx >= 64) return EBADF;
    const tfd = &timerfd_table[@intCast(idx)];
    if (!tfd.in_use) return EBADF;

    if (!protection.verifyUserPointer(new_value_addr, @sizeOf(ItimerSpec))) return EINVAL;

    if (old_value_addr != 0) {
        if (!protection.verifyUserPointer(old_value_addr, @sizeOf(ItimerSpec))) return EINVAL;
        protection.copyToUser(old_value_addr, std.mem.asBytes(&tfd.spec)) catch return EINVAL;
    }

    protection.copyFromUser(std.mem.asBytes(&tfd.spec), new_value_addr) catch return EINVAL;
    return 0;
}

fn sys_timerfd_gettime(fd: i32, value_addr: usize) i32 {
    const idx = fd - FD_OFFSET - 300;
    if (idx < 0 or idx >= 64) return EBADF;
    const tfd = &timerfd_table[@intCast(idx)];
    if (!tfd.in_use) return EBADF;

    if (!protection.verifyUserPointer(value_addr, @sizeOf(ItimerSpec))) return EINVAL;
    protection.copyToUser(value_addr, std.mem.asBytes(&tfd.spec)) catch return EINVAL;
    return 0;
}

const ShmSegment = struct {
    key: i32,
    size: usize,
    addr: ?[*]u8,
    mode: u32,
    nattch: u32,
    in_use: bool,
};

var shm_segments: [64]ShmSegment = [_]ShmSegment{.{
    .key = 0,
    .size = 0,
    .addr = null,
    .mode = 0,
    .nattch = 0,
    .in_use = false,
}} ** 64;

fn sys_shmget(key: i32, size: usize, shmflg: u32) i32 {
    if (key != 0) {
        for (shm_segments, 0..) |seg, i| {
            if (seg.in_use and seg.key == key) {
                if (shmflg & IPC_CREAT != 0 and shmflg & IPC_EXCL != 0) {
                    return EEXIST;
                }
                return @intCast(i);
            }
        }
    }

    if (shmflg & IPC_CREAT == 0 and key != 0) return ENOENT;

    for (&shm_segments, 0..) |*seg, i| {
        if (!seg.in_use) {
            const mem = memory.kmalloc(size) orelse return ENOMEM;
            seg.in_use = true;
            seg.key = key;
            seg.size = size;
            seg.addr = @ptrCast(@alignCast(mem));
            seg.mode = shmflg & 0o777;
            seg.nattch = 0;
            return @intCast(i);
        }
    }
    return ENOSPC;
}

fn sys_shmat(shmid: i32, _: usize, _: u32) i32 {
    if (shmid < 0 or shmid >= 64) return EINVAL;
    const seg = &shm_segments[@intCast(shmid)];
    if (!seg.in_use) return EINVAL;

    seg.nattch += 1;
    if (seg.addr) |addr| {
        return @intCast(@intFromPtr(addr));
    }
    return EINVAL;
}

fn sys_shmdt(addr: usize) i32 {
    for (&shm_segments) |*seg| {
        if (seg.in_use) {
            if (seg.addr) |a| {
                if (@intFromPtr(a) == addr) {
                    if (seg.nattch > 0) seg.nattch -= 1;
                    return 0;
                }
            }
        }
    }
    return EINVAL;
}

const ShmidDs = extern struct {
    shm_perm_mode: u32,
    shm_segsz: u32,
    shm_atime: u32,
    shm_dtime: u32,
    shm_ctime: u32,
    shm_cpid: u32,
    shm_lpid: u32,
    shm_nattch: u32,
};

fn sys_shmctl(shmid: i32, cmd: u32, buf_addr: usize) i32 {
    if (shmid < 0 or shmid >= 64) return EINVAL;
    const seg = &shm_segments[@intCast(shmid)];
    if (!seg.in_use) return EINVAL;

    switch (cmd) {
        IPC_STAT => {
            if (!protection.verifyUserPointer(buf_addr, @sizeOf(ShmidDs))) return EINVAL;
            const ds = ShmidDs{
                .shm_perm_mode = seg.mode,
                .shm_segsz = @intCast(seg.size),
                .shm_atime = 0,
                .shm_dtime = 0,
                .shm_ctime = 0,
                .shm_cpid = 0,
                .shm_lpid = 0,
                .shm_nattch = seg.nattch,
            };
            protection.copyToUser(buf_addr, std.mem.asBytes(&ds)) catch return EINVAL;
            return 0;
        },
        IPC_RMID => {
            if (seg.nattch == 0) {
                if (seg.addr) |addr| {
                    memory.kfree(@ptrCast(addr));
                }
                seg.in_use = false;
                seg.addr = null;
            }
            return 0;
        },
        else => return EINVAL,
    }
}

const Semaphore = struct {
    value: i16,
};

const SemSet = struct {
    key: i32,
    sems: [32]Semaphore,
    nsems: u32,
    mode: u32,
    in_use: bool,
};

var sem_sets: [64]SemSet = [_]SemSet{.{
    .key = 0,
    .sems = [_]Semaphore{.{ .value = 0 }} ** 32,
    .nsems = 0,
    .mode = 0,
    .in_use = false,
}} ** 64;

fn sys_semget(key: i32, nsems: u32, semflg: u32) i32 {
    if (nsems > 32) return EINVAL;

    if (key != 0) {
        for (sem_sets, 0..) |set, i| {
            if (set.in_use and set.key == key) {
                if (semflg & IPC_CREAT != 0 and semflg & IPC_EXCL != 0) {
                    return EEXIST;
                }
                return @intCast(i);
            }
        }
    }

    if (semflg & IPC_CREAT == 0 and key != 0) return ENOENT;

    for (&sem_sets, 0..) |*set, i| {
        if (!set.in_use) {
            set.in_use = true;
            set.key = key;
            set.nsems = nsems;
            set.mode = semflg & 0o777;
            for (&set.sems) |*s| {
                s.value = 0;
            }
            return @intCast(i);
        }
    }
    return ENOSPC;
}

const Sembuf = extern struct {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
};

fn sys_semop(semid: i32, sops_addr: usize, nsops: u32) i32 {
    if (semid < 0 or semid >= 64) return EINVAL;
    const set = &sem_sets[@intCast(semid)];
    if (!set.in_use) return EINVAL;
    if (nsops == 0 or nsops > 32) return EINVAL;

    if (!protection.verifyUserPointer(sops_addr, nsops * @sizeOf(Sembuf))) return EINVAL;

    var sops: [32]Sembuf = undefined;
    protection.copyFromUser(std.mem.sliceAsBytes(sops[0..nsops]), sops_addr) catch return EINVAL;

    for (sops[0..nsops]) |op| {
        if (op.sem_num >= set.nsems) return EINVAL;
    }

    for (sops[0..nsops]) |op| {
        const sem = &set.sems[op.sem_num];
        if (op.sem_op > 0) {
            sem.value += op.sem_op;
        } else if (op.sem_op < 0) {
            if (sem.value < -op.sem_op) {
                return EAGAIN;
            }
            sem.value += op.sem_op;
        }
    }

    return 0;
}

fn sys_semctl(semid: i32, semnum: u32, cmd: u32, arg: usize) i32 {
    if (semid < 0 or semid >= 64) return EINVAL;
    const set = &sem_sets[@intCast(semid)];
    if (!set.in_use) return EINVAL;

    switch (cmd) {
        GETVAL => {
            if (semnum >= set.nsems) return EINVAL;
            return set.sems[semnum].value;
        },
        SETVAL => {
            if (semnum >= set.nsems) return EINVAL;
            set.sems[semnum].value = @intCast(arg & 0xFFFF);
            return 0;
        },
        IPC_RMID => {
            set.in_use = false;
            return 0;
        },
        else => return EINVAL,
    }
}

const Tms = extern struct {
    tms_utime: u32,
    tms_stime: u32,
    tms_cutime: u32,
    tms_cstime: u32,
};

fn sys_times(buf_addr: usize) i32 {
    if (buf_addr != 0) {
        if (!protection.verifyUserPointer(buf_addr, @sizeOf(Tms))) return EINVAL;
        const tms = Tms{
            .tms_utime = 0,
            .tms_stime = 0,
            .tms_cutime = 0,
            .tms_cstime = 0,
        };
        protection.copyToUser(buf_addr, std.mem.asBytes(&tms)) catch return EINVAL;
    }
    return 0;
}

const Rusage = extern struct {
    ru_utime_sec: u32,
    ru_utime_usec: u32,
    ru_stime_sec: u32,
    ru_stime_usec: u32,
    ru_maxrss: u32,
    ru_ixrss: u32,
    ru_idrss: u32,
    ru_isrss: u32,
    ru_minflt: u32,
    ru_majflt: u32,
    ru_nswap: u32,
    ru_inblock: u32,
    ru_oublock: u32,
    ru_msgsnd: u32,
    ru_msgrcv: u32,
    ru_nsignals: u32,
    ru_nvcsw: u32,
    ru_nivcsw: u32,
};

fn sys_getrusage(who: i32, usage_addr: usize) i32 {
    if (who != RUSAGE_SELF and who != RUSAGE_CHILDREN) return EINVAL;
    if (!protection.verifyUserPointer(usage_addr, @sizeOf(Rusage))) return EINVAL;

    const usage = Rusage{
        .ru_utime_sec = 0,
        .ru_utime_usec = 0,
        .ru_stime_sec = 0,
        .ru_stime_usec = 0,
        .ru_maxrss = 0,
        .ru_ixrss = 0,
        .ru_idrss = 0,
        .ru_isrss = 0,
        .ru_minflt = 0,
        .ru_majflt = 0,
        .ru_nswap = 0,
        .ru_inblock = 0,
        .ru_oublock = 0,
        .ru_msgsnd = 0,
        .ru_msgrcv = 0,
        .ru_nsignals = 0,
        .ru_nvcsw = 0,
        .ru_nivcsw = 0,
    };

    protection.copyToUser(usage_addr, std.mem.asBytes(&usage)) catch return EINVAL;
    return 0;
}

fn sys_mknod(pathname: [*]const u8, mode: u32, dev: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EINVAL;

    const file_type = mode & S_IFMT;
    const perms = mode & 0o777;

    const mode_struct = vfs.FileMode{
        .owner_read = (perms & 0o400) != 0,
        .owner_write = (perms & 0o200) != 0,
        .owner_exec = (perms & 0o100) != 0,
        .group_read = (perms & 0o040) != 0,
        .group_write = (perms & 0o020) != 0,
        .group_exec = (perms & 0o010) != 0,
        .other_read = (perms & 0o004) != 0,
        .other_write = (perms & 0o002) != 0,
        .other_exec = (perms & 0o001) != 0,
    };

    if (file_type == S_IFIFO) {
        vfs.mkfifo(path_slice, mode_struct) catch |err| return vfsErrno(err);
        return 0;
    }

    if (file_type == S_IFREG) {
        vfs.create(path_slice, mode_struct) catch |err| return vfsErrno(err);
        return 0;
    }

    _ = dev;
    return EINVAL;
}

var getrandom_state: u32 = 0xDEADBEEF;

fn getrandomXorshift() u32 {
    var x = getrandom_state;
    if (x == 0) {
        const timer = @import("../timer/timer.zig");
        x = @truncate(timer.getTicks() | 1);
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    getrandom_state = x;
    return x;
}

fn sys_getrandom(buf: [*]u8, buflen: usize, flags: u32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), buflen)) return EFAULT;
    _ = flags;

    var kernel_buffer: [256]u8 = undefined;
    var written: usize = 0;

    while (written < buflen) {
        const chunk_size = @min(buflen - written, kernel_buffer.len);
        var i: usize = 0;
        while (i + 4 <= chunk_size) : (i += 4) {
            const val = getrandomXorshift();
            kernel_buffer[i] = @truncate(val);
            kernel_buffer[i + 1] = @truncate(val >> 8);
            kernel_buffer[i + 2] = @truncate(val >> 16);
            kernel_buffer[i + 3] = @truncate(val >> 24);
        }
        while (i < chunk_size) : (i += 1) {
            kernel_buffer[i] = @truncate(getrandomXorshift());
        }

        protection.copyToUser(@intFromPtr(buf) + written, kernel_buffer[0..chunk_size]) catch return EFAULT;
        written += chunk_size;
    }

    return @intCast(written);
}

fn sys_pipe2(pipefd: ?*[2]i32, flags: u32) i32 {
    if (pipefd == null) return EINVAL;
    if (!protection.verifyUserPointer(@intFromPtr(pipefd), @sizeOf([2]i32))) {
        return EINVAL;
    }

    const result = vfs.createPipe() catch |err| return vfsErrno(err);
    const fds = [2]i32{
        @as(i32, @intCast(result.read_fd)) + FD_OFFSET,
        @as(i32, @intCast(result.write_fd)) + FD_OFFSET,
    };

    if ((flags & O_CLOEXEC) != 0) {
        vfs.setFdFlags(result.read_fd, FD_CLOEXEC) catch {};
        vfs.setFdFlags(result.write_fd, FD_CLOEXEC) catch {};
    }

    if ((flags & vfs.O_NONBLOCK) != 0) {
        vfs.setFileFlags(result.read_fd, vfs.O_NONBLOCK) catch {};
        vfs.setFileFlags(result.write_fd, vfs.O_NONBLOCK) catch {};
    }

    protection.copyToUser(@intFromPtr(pipefd), std.mem.asBytes(&fds)) catch return EINVAL;
    return 0;
}

fn sys_dup3(old_fd: i32, new_fd: i32, flags: u32) i32 {
    if (old_fd < FD_OFFSET or new_fd < FD_OFFSET) return EBADF;
    if (old_fd == new_fd) return EINVAL;

    const old_vfs_fd: u32 = @intCast(old_fd - FD_OFFSET);
    const new_vfs_fd: u32 = @intCast(new_fd - FD_OFFSET);

    const result = vfs.dup2(old_vfs_fd, new_vfs_fd) catch |err| return vfsErrno(err);

    if ((flags & O_CLOEXEC) != 0) {
        vfs.setFdFlags(new_vfs_fd, FD_CLOEXEC) catch {};
    }

    return @as(i32, @intCast(result)) + FD_OFFSET;
}

fn sys_accept4(sockfd: i32, addr: usize, addrlen: usize, flags: u32) i32 {
    _ = addr;
    _ = addrlen;

    if (sockfd >= 1000 and sockfd < 1064) {
        const idx: usize = @intCast(sockfd - 1000);
        const usock = &unix_sockets[idx];
        if (!usock.in_use or !usock.listening) return EBADF;

        for (&unix_sockets) |*peer| {
            if (peer.in_use and peer.connected and peer.peer == usock) {
                for (&unix_sockets, 0..) |*new_sock, j| {
                    if (!new_sock.in_use) {
                        new_sock.in_use = true;
                        new_sock.connected = true;
                        new_sock.peer = peer;
                        peer.peer = new_sock;
                        const new_fd: i32 = @intCast(@as(i32, @intCast(j)) + 1000);
                        _ = flags;
                        return new_fd;
                    }
                }
                return EMFILE;
            }
        }
        return EAGAIN;
    }

    if (sockfd < 0 or sockfd >= 64) return EBADF;
    const sock = socket_table[@intCast(sockfd)] orelse return EBADF;

    const client = sock.accept() catch |err| return socketErrno(err);

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = client;
            return @intCast(i);
        }
    }

    return EMFILE;
}

const EventFD = struct {
    counter: u64,
    flags: u32,
    in_use: bool,
};

var eventfd_table: [64]EventFD = [_]EventFD{.{ .counter = 0, .flags = 0, .in_use = false }} ** 64;

fn sys_eventfd(initval: u32) i32 {
    return sys_eventfd2(initval, 0);
}

fn sys_eventfd2(initval: u32, flags: u32) i32 {
    for (&eventfd_table, 0..) |*efd, i| {
        if (!efd.in_use) {
            efd.in_use = true;
            efd.counter = initval;
            efd.flags = flags;
            return @intCast(@as(i32, @intCast(i)) + 2000);
        }
    }
    return EMFILE;
}

var process_names: [256][16]u8 = [_][16]u8{[_]u8{0} ** 16} ** 256;
var process_dumpable: [256]u32 = [_]u32{1} ** 256;
var process_keepcaps: [256]u32 = [_]u32{0} ** 256;
var process_pdeathsig: [256]u32 = [_]u32{0} ** 256;

fn sys_prctl(option: u32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
    _ = arg4;
    _ = arg5;

    const proc = process.current_process orelse return ESRCH;
    const pid_idx: usize = @intCast(proc.pid);

    switch (option) {
        PR_SET_NAME => {
            if (!protection.verifyUserPointer(arg2, 16)) return EFAULT;
            var name_buf: [16]u8 = [_]u8{0} ** 16;
            protection.copyFromUser(&name_buf, arg2) catch return EFAULT;
            process_names[pid_idx] = name_buf;
            return 0;
        },
        PR_GET_NAME => {
            if (!protection.verifyUserPointer(arg2, 16)) return EFAULT;
            protection.copyToUser(arg2, &process_names[pid_idx]) catch return EFAULT;
            return 0;
        },
        PR_SET_DUMPABLE => {
            if (arg2 > 2) return EINVAL;
            process_dumpable[pid_idx] = @intCast(arg2);
            return 0;
        },
        PR_GET_DUMPABLE => {
            return @intCast(process_dumpable[pid_idx]);
        },
        PR_SET_KEEPCAPS => {
            process_keepcaps[pid_idx] = if (arg2 != 0) 1 else 0;
            return 0;
        },
        PR_GET_KEEPCAPS => {
            return @intCast(process_keepcaps[pid_idx]);
        },
        PR_SET_PDEATHSIG => {
            if (arg2 > 64) return EINVAL;
            process_pdeathsig[pid_idx] = @intCast(arg2);
            return 0;
        },
        PR_GET_PDEATHSIG => {
            if (!protection.verifyUserPointer(arg2, @sizeOf(i32))) return EFAULT;
            const sig: i32 = @intCast(process_pdeathsig[pid_idx]);
            protection.copyToUser(arg2, std.mem.asBytes(&sig)) catch return EFAULT;
            return 0;
        },
        else => return EINVAL,
    }
    _ = arg3;
}

const SignalFD = struct {
    mask: u64,
    flags: u32,
    in_use: bool,
};

var signalfd_table: [64]SignalFD = [_]SignalFD{.{ .mask = 0, .flags = 0, .in_use = false }} ** 64;

fn sys_signalfd(fd: i32, mask_ptr: usize, sizemask: usize) i32 {
    return sys_signalfd4(fd, mask_ptr, sizemask, 0);
}

fn sys_signalfd4(fd: i32, mask_ptr: usize, sizemask: usize, flags: u32) i32 {
    _ = sizemask;

    if (!protection.verifyUserPointer(mask_ptr, @sizeOf(u64))) return EFAULT;

    var mask: u64 = 0;
    protection.copyFromUser(std.mem.asBytes(&mask), mask_ptr) catch return EFAULT;

    if (fd == -1) {
        for (&signalfd_table, 0..) |*sfd, i| {
            if (!sfd.in_use) {
                sfd.in_use = true;
                sfd.mask = mask;
                sfd.flags = flags;
                return @intCast(@as(i32, @intCast(i)) + 3000);
            }
        }
        return EMFILE;
    }

    if (fd >= 3000 and fd < 3064) {
        const idx: usize = @intCast(fd - 3000);
        if (!signalfd_table[idx].in_use) return EBADF;
        signalfd_table[idx].mask = mask;
        return fd;
    }

    return EBADF;
}

const Timespec = extern struct {
    tv_sec: i32,
    tv_nsec: i32,
};

fn sys_ppoll(fds_ptr: usize, nfds: u32, timeout_ptr: usize, sigmask_ptr: usize) i32 {
    _ = sigmask_ptr;

    var timeout_ms: i32 = -1;
    if (timeout_ptr != 0) {
        if (!protection.verifyUserPointer(timeout_ptr, @sizeOf(Timespec))) return EFAULT;
        var ts: Timespec = undefined;
        protection.copyFromUser(std.mem.asBytes(&ts), timeout_ptr) catch return EFAULT;
        timeout_ms = ts.tv_sec * 1000 + @divTrunc(ts.tv_nsec, 1000000);
    }

    return sys_poll(fds_ptr, nfds, timeout_ms);
}

fn sys_pselect6(nfds: i32, readfds: usize, writefds: usize, exceptfds: usize, timeout_ptr: usize, sigmask_ptr: usize) i32 {
    _ = sigmask_ptr;

    var timeout_arg: usize = 0;
    var timeval_buf: [8]u8 = undefined;

    if (timeout_ptr != 0) {
        if (!protection.verifyUserPointer(timeout_ptr, @sizeOf(Timespec))) return EFAULT;
        var ts: Timespec = undefined;
        protection.copyFromUser(std.mem.asBytes(&ts), timeout_ptr) catch return EFAULT;

        const tv_sec: u32 = @intCast(ts.tv_sec);
        const tv_usec: u32 = @intCast(@divTrunc(ts.tv_nsec, 1000));
        @memcpy(timeval_buf[0..4], std.mem.asBytes(&tv_sec));
        @memcpy(timeval_buf[4..8], std.mem.asBytes(&tv_usec));
        timeout_arg = @intFromPtr(&timeval_buf);
    }

    return sys_select(nfds, readfds, writefds, exceptfds, timeout_arg);
}

fn sys_faccessat(dirfd: i32, pathname: [*]const u8, mode: u32, flags: u32) i32 {
    _ = flags;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EFAULT;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EFAULT;

    var full_path_buf: [512]u8 = undefined;
    const full_path = if (path_slice.len > 0 and path_slice[0] == '/') blk: {
        break :blk path_slice;
    } else blk: {
        if (dirfd == AT_FDCWD) {
            ensureCwdInit();
            const cwd = current_working_dir[0..cwd_len];
            const cwdlen = cwd.len;
            @memcpy(full_path_buf[0..cwdlen], cwd);
            if (cwdlen > 0 and cwd[cwdlen - 1] != '/') {
                full_path_buf[cwdlen] = '/';
                @memcpy(full_path_buf[cwdlen + 1 .. cwdlen + 1 + path_slice.len], path_slice);
                break :blk full_path_buf[0 .. cwdlen + 1 + path_slice.len];
            } else {
                @memcpy(full_path_buf[cwdlen .. cwdlen + path_slice.len], path_slice);
                break :blk full_path_buf[0 .. cwdlen + path_slice.len];
            }
        }
        return EBADF;
    };

    const vnode = vfs.lookupPath(full_path) catch |err| return vfsErrno(err);
    _ = vnode;
    _ = mode;

    return 0;
}

const StatxTimestamp = extern struct {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
};

const Statx = extern struct {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    __spare2: u64,
    __spare3: [12]u64,
};

fn sys_statx(dirfd: i32, pathname: [*]const u8, flags: u32, mask: u32, statxbuf: usize) i32 {
    _ = flags;
    _ = mask;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EFAULT;
    if (!protection.verifyUserPointer(statxbuf, @sizeOf(Statx))) return EFAULT;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EFAULT;

    var full_path_buf: [512]u8 = undefined;
    const full_path = if (path_slice.len > 0 and path_slice[0] == '/') blk: {
        break :blk path_slice;
    } else blk: {
        if (dirfd == AT_FDCWD) {
            ensureCwdInit();
            const cwd = current_working_dir[0..cwd_len];
            const cwdlen = cwd.len;
            @memcpy(full_path_buf[0..cwdlen], cwd);
            if (cwdlen > 0 and cwd[cwdlen - 1] != '/') {
                full_path_buf[cwdlen] = '/';
                @memcpy(full_path_buf[cwdlen + 1 .. cwdlen + 1 + path_slice.len], path_slice);
                break :blk full_path_buf[0 .. cwdlen + 1 + path_slice.len];
            } else {
                @memcpy(full_path_buf[cwdlen .. cwdlen + path_slice.len], path_slice);
                break :blk full_path_buf[0 .. cwdlen + path_slice.len];
            }
        }
        return EBADF;
    };

    const vnode = vfs.lookupPath(full_path) catch |err| return vfsErrno(err);

    var stat_buf: vfs.FileStat = undefined;
    vnode.ops.stat(vnode, &stat_buf) catch |err| return vfsErrno(err);

    const mode_bits: u16 = @as(u16, if (stat_buf.mode.owner_read) 0o400 else 0) |
        @as(u16, if (stat_buf.mode.owner_write) 0o200 else 0) |
        @as(u16, if (stat_buf.mode.owner_exec) 0o100 else 0) |
        @as(u16, if (stat_buf.mode.group_read) 0o040 else 0) |
        @as(u16, if (stat_buf.mode.group_write) 0o020 else 0) |
        @as(u16, if (stat_buf.mode.group_exec) 0o010 else 0) |
        @as(u16, if (stat_buf.mode.other_read) 0o004 else 0) |
        @as(u16, if (stat_buf.mode.other_write) 0o002 else 0) |
        @as(u16, if (stat_buf.mode.other_exec) 0o001 else 0);

    const type_bits: u16 = switch (stat_buf.file_type) {
        .Regular => 0o100000,
        .Directory => 0o040000,
        .SymLink => 0o120000,
        .CharDevice => 0o020000,
        .BlockDevice => 0o060000,
        .Pipe => 0o010000,
        .Socket => 0o140000,
    };

    var result = Statx{
        .stx_mask = STATX_BASIC_STATS,
        .stx_blksize = stat_buf.block_size,
        .stx_attributes = 0,
        .stx_nlink = 1,
        .stx_uid = stat_buf.uid,
        .stx_gid = stat_buf.gid,
        .stx_mode = mode_bits | type_bits,
        .__spare0 = 0,
        .stx_ino = stat_buf.inode,
        .stx_size = stat_buf.size,
        .stx_blocks = stat_buf.blocks,
        .stx_attributes_mask = 0,
        .stx_atime = .{ .tv_sec = @intCast(stat_buf.atime), .tv_nsec = 0, .__reserved = 0 },
        .stx_btime = .{ .tv_sec = 0, .tv_nsec = 0, .__reserved = 0 },
        .stx_ctime = .{ .tv_sec = @intCast(stat_buf.ctime), .tv_nsec = 0, .__reserved = 0 },
        .stx_mtime = .{ .tv_sec = @intCast(stat_buf.mtime), .tv_nsec = 0, .__reserved = 0 },
        .stx_rdev_major = 0,
        .stx_rdev_minor = 0,
        .stx_dev_major = 0,
        .stx_dev_minor = 0,
        .stx_mnt_id = 0,
        .__spare2 = 0,
        .__spare3 = [_]u64{0} ** 12,
    };

    protection.copyToUser(statxbuf, std.mem.asBytes(&result)) catch return EFAULT;
    return 0;
}

fn sys_membarrier(cmd: u32, flags: u32) i32 {
    _ = flags;

    switch (cmd) {
        MEMBARRIER_CMD_QUERY => {
            return @intCast(MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED | MEMBARRIER_CMD_PRIVATE_EXPEDITED);
        },
        MEMBARRIER_CMD_GLOBAL, MEMBARRIER_CMD_GLOBAL_EXPEDITED, MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
            return 0;
        },
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            return 0;
        },
        else => return EINVAL,
    }
}

fn sys_copy_file_range(fd_in: i32, off_in_ptr: usize, fd_out: i32, off_out_ptr: usize, len: usize) i32 {
    if (fd_in < FD_OFFSET or fd_out < FD_OFFSET) return EBADF;

    const vfs_fd_in: u32 = @intCast(fd_in - FD_OFFSET);
    const vfs_fd_out: u32 = @intCast(fd_out - FD_OFFSET);

    var off_in: i64 = -1;
    var off_out: i64 = -1;

    if (off_in_ptr != 0) {
        if (!protection.verifyUserPointer(off_in_ptr, @sizeOf(i64))) return EFAULT;
        protection.copyFromUser(std.mem.asBytes(&off_in), off_in_ptr) catch return EFAULT;
    }

    if (off_out_ptr != 0) {
        if (!protection.verifyUserPointer(off_out_ptr, @sizeOf(i64))) return EFAULT;
        protection.copyFromUser(std.mem.asBytes(&off_out), off_out_ptr) catch return EFAULT;
    }

    var buffer: [512]u8 = undefined;
    var total_copied: usize = 0;
    var remaining = len;

    while (remaining > 0) {
        const chunk = @min(remaining, buffer.len);

        const bytes_read = if (off_in >= 0) blk: {
            const r = vfs.pread(vfs_fd_in, buffer[0..chunk], @intCast(off_in)) catch |err| return vfsErrno(err);
            off_in += @intCast(r);
            break :blk r;
        } else blk: {
            break :blk vfs.read(vfs_fd_in, buffer[0..chunk]) catch |err| return vfsErrno(err);
        };

        if (bytes_read == 0) break;

        const bytes_written = if (off_out >= 0) blk: {
            const w = vfs.pwrite(vfs_fd_out, buffer[0..bytes_read], @intCast(off_out)) catch |err| return vfsErrno(err);
            off_out += @intCast(w);
            break :blk w;
        } else blk: {
            break :blk vfs.write(vfs_fd_out, buffer[0..bytes_read]) catch |err| return vfsErrno(err);
        };

        total_copied += bytes_written;
        remaining -= bytes_written;

        if (bytes_written < bytes_read) break;
    }

    if (off_in_ptr != 0) {
        protection.copyToUser(off_in_ptr, std.mem.asBytes(&off_in)) catch return EFAULT;
    }
    if (off_out_ptr != 0) {
        protection.copyToUser(off_out_ptr, std.mem.asBytes(&off_out)) catch return EFAULT;
    }

    return @intCast(total_copied);
}

fn sys_fadvise64(fd: i32, offset: i64, len: usize, advice: u32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    _ = offset;
    _ = len;
    _ = advice;
    return 0;
}

fn sys_readahead(fd: i32, offset: i64, count: usize) i32 {
    if (fd < FD_OFFSET) return EBADF;
    _ = offset;
    _ = count;
    return 0;
}

fn sys_sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    _ = offset;
    _ = nbytes;
    _ = flags;
    return 0;
}

fn sys_syncfs(fd: i32) i32 {
    if (fd < FD_OFFSET) return EBADF;
    return 0;
}

var process_priorities: [256]i32 = [_]i32{0} ** 256;

fn sys_getpriority(which: u32, who: i32) i32 {
    switch (which) {
        PRIO_PROCESS => {
            const pid: usize = if (who == 0) blk: {
                const proc = process.current_process orelse return ESRCH;
                break :blk @intCast(proc.pid);
            } else @intCast(who);
            if (pid >= 256) return ESRCH;
            return 20 - process_priorities[pid];
        },
        PRIO_PGRP, PRIO_USER => {
            return 20;
        },
        else => return EINVAL,
    }
}

fn sys_setpriority(which: u32, who: i32, prio: i32) i32 {
    const nice = @max(-20, @min(19, prio));

    switch (which) {
        PRIO_PROCESS => {
            const pid: usize = if (who == 0) blk: {
                const proc = process.current_process orelse return ESRCH;
                break :blk @intCast(proc.pid);
            } else @intCast(who);
            if (pid >= 256) return ESRCH;
            process_priorities[pid] = nice;
            return 0;
        },
        PRIO_PGRP, PRIO_USER => {
            return 0;
        },
        else => return EINVAL,
    }
}

fn sys_sched_getaffinity(pid: i32, cpusetsize: usize, mask_ptr: usize) i32 {
    _ = pid;
    if (!protection.verifyUserPointer(mask_ptr, cpusetsize)) return EFAULT;

    var mask: [128]u8 = [_]u8{0} ** 128;
    mask[0] = 1;

    const copy_size = @min(cpusetsize, 128);
    protection.copyToUser(mask_ptr, mask[0..copy_size]) catch return EFAULT;
    return @intCast(copy_size);
}

fn sys_sched_setaffinity(pid: i32, cpusetsize: usize, mask_ptr: usize) i32 {
    _ = pid;
    if (!protection.verifyUserPointer(mask_ptr, cpusetsize)) return EFAULT;
    return 0;
}

const UtimensatTimespec = extern struct {
    tv_sec: i32,
    tv_nsec: i32,
};

fn sys_utimensat(dirfd: i32, pathname: [*]const u8, times_ptr: usize, flags: u32) i32 {
    _ = dirfd;
    _ = flags;

    if (@intFromPtr(pathname) != 0) {
        if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EFAULT;
    }

    if (times_ptr != 0) {
        if (!protection.verifyUserPointer(times_ptr, @sizeOf(UtimensatTimespec) * 2)) return EFAULT;
    }

    return 0;
}

fn sys_futimesat(dirfd: i32, pathname: [*]const u8, times_ptr: usize) i32 {
    _ = dirfd;

    if (@intFromPtr(pathname) != 0) {
        if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EFAULT;
    }

    if (times_ptr != 0) {
        if (!protection.verifyUserPointer(times_ptr, 16)) return EFAULT;
    }

    return 0;
}

fn sys_fstatat(dirfd: i32, pathname: [*]const u8, statbuf: usize, flags: u32) i32 {
    _ = flags;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EFAULT;
    if (!protection.verifyUserPointer(statbuf, @sizeOf(vfs.FileStat))) return EFAULT;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EFAULT;

    var full_path_buf: [512]u8 = undefined;
    const full_path = if (path_slice.len > 0 and path_slice[0] == '/') blk: {
        break :blk path_slice;
    } else blk: {
        if (dirfd == AT_FDCWD) {
            ensureCwdInit();
            const cwd = current_working_dir[0..cwd_len];
            const cwdlen = cwd.len;
            @memcpy(full_path_buf[0..cwdlen], cwd);
            if (cwdlen > 0 and cwd[cwdlen - 1] != '/') {
                full_path_buf[cwdlen] = '/';
                @memcpy(full_path_buf[cwdlen + 1 .. cwdlen + 1 + path_slice.len], path_slice);
                break :blk full_path_buf[0 .. cwdlen + 1 + path_slice.len];
            } else {
                @memcpy(full_path_buf[cwdlen .. cwdlen + path_slice.len], path_slice);
                break :blk full_path_buf[0 .. cwdlen + path_slice.len];
            }
        }
        return EBADF;
    };

    var stat_buf: vfs.FileStat = undefined;
    vfs.stat(full_path, &stat_buf) catch |err| return vfsErrno(err);

    protection.copyToUser(statbuf, std.mem.asBytes(&stat_buf)) catch return EFAULT;
    return 0;
}

fn sys_symlinkat(target: [*]const u8, newdirfd: i32, linkpath: [*]const u8) i32 {
    _ = newdirfd;

    if (!protection.verifyUserPointer(@intFromPtr(target), 256)) return EFAULT;
    if (!protection.verifyUserPointer(@intFromPtr(linkpath), 256)) return EFAULT;

    var target_buffer: [256]u8 = undefined;
    const target_slice = protection.copyStringFromUser(&target_buffer, @intFromPtr(target)) catch return EFAULT;

    var link_buffer: [256]u8 = undefined;
    const link_slice = protection.copyStringFromUser(&link_buffer, @intFromPtr(linkpath)) catch return EFAULT;

    vfs.symlink(target_slice, link_slice) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_readlinkat(dirfd: i32, pathname: [*]const u8, buf: [*]u8, bufsiz: usize) i32 {
    _ = dirfd;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EFAULT;
    if (!protection.verifyUserPointer(@intFromPtr(buf), bufsiz)) return EFAULT;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EFAULT;

    var link_target: [256]u8 = undefined;
    const len = vfs.readlink(path_slice, &link_target) catch |err| return vfsErrno(err);

    const copy_len = @min(len, bufsiz);
    protection.copyToUser(@intFromPtr(buf), link_target[0..copy_len]) catch return EFAULT;
    return @intCast(copy_len);
}

const SigInfo = extern struct {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    si_pid: i32,
    si_uid: u32,
    si_status: i32,
    _pad: [26]i32,
};

fn sys_waitid(idtype: u32, id: i32, infop: usize, options: u32) i32 {
    _ = options;

    if (infop != 0) {
        if (!protection.verifyUserPointer(infop, @sizeOf(SigInfo))) return EFAULT;
    }

    switch (idtype) {
        P_ALL => {
            for (&process.process_table) |*proc| {
                if (proc.pid != 0 and (proc.state == .Zombie or proc.state == .Terminated)) {
                    if (infop != 0) {
                        var info = SigInfo{
                            .si_signo = signal.SIGCHLD,
                            .si_errno = 0,
                            .si_code = 1,
                            .si_pid = @intCast(proc.pid),
                            .si_uid = 0,
                            .si_status = proc.exit_code,
                            ._pad = [_]i32{0} ** 26,
                        };
                        protection.copyToUser(infop, std.mem.asBytes(&info)) catch return EFAULT;
                    }
                    return 0;
                }
            }
            return ECHILD;
        },
        P_PID => {
            if (id < 0) return EINVAL;
            const proc = process.getProcessByPid(@intCast(id)) orelse return ECHILD;
            if (proc.state == .Zombie or proc.state == .Terminated) {
                if (infop != 0) {
                    var info = SigInfo{
                        .si_signo = signal.SIGCHLD,
                        .si_errno = 0,
                        .si_code = 1,
                        .si_pid = @intCast(proc.pid),
                        .si_uid = 0,
                        .si_status = proc.exit_code,
                        ._pad = [_]i32{0} ** 26,
                    };
                    protection.copyToUser(infop, std.mem.asBytes(&info)) catch return EFAULT;
                }
                return 0;
            }
            return ECHILD;
        },
        P_PGID => {
            return ECHILD;
        },
        else => return EINVAL,
    }
}

var tid_addresses: [256]usize = [_]usize{0} ** 256;

fn sys_set_tid_address(tidptr: usize) i32 {
    const proc = process.current_process orelse return ESRCH;
    const pid_idx: usize = @intCast(proc.pid);
    tid_addresses[pid_idx] = tidptr;
    return @intCast(proc.pid);
}

var robust_list_heads: [256]usize = [_]usize{0} ** 256;
var robust_list_lens: [256]usize = [_]usize{0} ** 256;

fn sys_get_robust_list(pid: i32, head_ptr: usize, len_ptr: usize) i32 {
    if (!protection.verifyUserPointer(head_ptr, @sizeOf(usize))) return EFAULT;
    if (!protection.verifyUserPointer(len_ptr, @sizeOf(usize))) return EFAULT;

    const pid_idx: usize = if (pid == 0) blk: {
        const proc = process.current_process orelse return ESRCH;
        break :blk @intCast(proc.pid);
    } else @intCast(pid);

    if (pid_idx >= 256) return ESRCH;

    const head = robust_list_heads[pid_idx];
    const len = robust_list_lens[pid_idx];

    protection.copyToUser(head_ptr, std.mem.asBytes(&head)) catch return EFAULT;
    protection.copyToUser(len_ptr, std.mem.asBytes(&len)) catch return EFAULT;
    return 0;
}

fn sys_set_robust_list(head: usize, len: usize) i32 {
    const proc = process.current_process orelse return ESRCH;
    const pid_idx: usize = @intCast(proc.pid);

    robust_list_heads[pid_idx] = head;
    robust_list_lens[pid_idx] = len;
    return 0;
}

fn sys_tgkill(tgid: i32, tid: i32, sig: i32) i32 {
    _ = tgid;
    return sys_tkill(tid, sig);
}

fn sys_tkill(tid: i32, sig: i32) i32 {
    if (sig < 0 or sig > 64) return EINVAL;
    if (tid < 0) return EINVAL;

    const proc = process.getProcessByPid(@intCast(tid)) orelse return ESRCH;

    if (sig == 0) return 0;

    signal.sendSignal(proc, @intCast(sig));
    return 0;
}

const InotifyWatch = struct {
    wd: i32,
    pathname: [256]u8,
    path_len: usize,
    mask: u32,
    in_use: bool,
};

const InotifyInstance = struct {
    watches: [16]InotifyWatch,
    flags: u32,
    in_use: bool,
};

var inotify_instances: [32]InotifyInstance = [_]InotifyInstance{.{
    .watches = [_]InotifyWatch{.{
        .wd = -1,
        .pathname = [_]u8{0} ** 256,
        .path_len = 0,
        .mask = 0,
        .in_use = false,
    }} ** 16,
    .flags = 0,
    .in_use = false,
}} ** 32;

var next_inotify_wd: i32 = 1;

fn sys_inotify_init() i32 {
    return sys_inotify_init1(0);
}

fn sys_inotify_init1(flags: u32) i32 {
    for (&inotify_instances, 0..) |*inst, i| {
        if (!inst.in_use) {
            inst.in_use = true;
            inst.flags = flags;
            for (&inst.watches) |*w| {
                w.in_use = false;
                w.wd = -1;
            }
            return @intCast(@as(i32, @intCast(i)) + 4000);
        }
    }
    return EMFILE;
}

fn sys_inotify_add_watch(fd: i32, pathname: [*]const u8, mask: u32) i32 {
    if (fd < 4000 or fd >= 4032) return EBADF;
    const idx: usize = @intCast(fd - 4000);
    if (!inotify_instances[idx].in_use) return EBADF;

    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EFAULT;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(pathname)) catch return EFAULT;

    for (&inotify_instances[idx].watches) |*w| {
        if (!w.in_use) {
            w.in_use = true;
            w.wd = next_inotify_wd;
            next_inotify_wd += 1;
            @memset(&w.pathname, 0);
            @memcpy(w.pathname[0..path_slice.len], path_slice);
            w.path_len = path_slice.len;
            w.mask = mask;
            return w.wd;
        }
    }
    return ENOSPC;
}

fn sys_inotify_rm_watch(fd: i32, wd: i32) i32 {
    if (fd < 4000 or fd >= 4032) return EBADF;
    const idx: usize = @intCast(fd - 4000);
    if (!inotify_instances[idx].in_use) return EBADF;

    for (&inotify_instances[idx].watches) |*w| {
        if (w.in_use and w.wd == wd) {
            w.in_use = false;
            w.wd = -1;
            return 0;
        }
    }
    return EINVAL;
}

fn sys_mlock(addr: usize, len: usize) i32 {
    _ = addr;
    _ = len;
    return 0;
}

fn sys_munlock(addr: usize, len: usize) i32 {
    _ = addr;
    _ = len;
    return 0;
}

fn sys_mlockall(flags: u32) i32 {
    _ = flags;
    return 0;
}

fn sys_munlockall() i32 {
    return 0;
}

fn sys_madvise(addr: usize, length: usize, advice: u32) i32 {
    _ = addr;
    _ = length;
    _ = advice;
    return 0;
}

fn sys_mincore(addr: usize, length: usize, vec: usize) i32 {
    if (!protection.verifyUserPointer(vec, (length + 4095) / 4096)) return EFAULT;
    _ = addr;

    const pages = (length + 4095) / 4096;
    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const byte: u8 = 1;
        protection.copyToUser(vec + i, &[_]u8{byte}) catch return EFAULT;
    }
    return 0;
}

const Rlimit = extern struct {
    rlim_cur: u64,
    rlim_max: u64,
};

var process_rlimits: [256][10]Rlimit = [_][10]Rlimit{[_]Rlimit{.{
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
}} ** 10} ** 256;

fn sys_getrlimit(resource: u32, rlim_ptr: usize) i32 {
    if (resource >= 10) return EINVAL;
    if (!protection.verifyUserPointer(rlim_ptr, @sizeOf(Rlimit))) return EFAULT;

    const proc = process.current_process orelse return ESRCH;
    const pid_idx: usize = @intCast(proc.pid);

    const rlim = process_rlimits[pid_idx][resource];
    protection.copyToUser(rlim_ptr, std.mem.asBytes(&rlim)) catch return EFAULT;
    return 0;
}

fn sys_setrlimit(resource: u32, rlim_ptr: usize) i32 {
    if (resource >= 10) return EINVAL;
    if (!protection.verifyUserPointer(rlim_ptr, @sizeOf(Rlimit))) return EFAULT;

    const proc = process.current_process orelse return ESRCH;
    const pid_idx: usize = @intCast(proc.pid);

    var rlim: Rlimit = undefined;
    protection.copyFromUser(std.mem.asBytes(&rlim), rlim_ptr) catch return EFAULT;

    process_rlimits[pid_idx][resource] = rlim;
    return 0;
}

fn sys_prlimit64(pid: i32, resource: u32, new_limit: usize, old_limit: usize) i32 {
    if (resource >= 10) return EINVAL;

    const pid_idx: usize = if (pid == 0) blk: {
        const proc = process.current_process orelse return ESRCH;
        break :blk @intCast(proc.pid);
    } else blk: {
        if (pid < 0) return EINVAL;
        break :blk @intCast(pid);
    };

    if (pid_idx >= 256) return ESRCH;

    if (old_limit != 0) {
        if (!protection.verifyUserPointer(old_limit, @sizeOf(Rlimit))) return EFAULT;
        const rlim = process_rlimits[pid_idx][resource];
        protection.copyToUser(old_limit, std.mem.asBytes(&rlim)) catch return EFAULT;
    }

    if (new_limit != 0) {
        if (!protection.verifyUserPointer(new_limit, @sizeOf(Rlimit))) return EFAULT;
        var rlim: Rlimit = undefined;
        protection.copyFromUser(std.mem.asBytes(&rlim), new_limit) catch return EFAULT;
        process_rlimits[pid_idx][resource] = rlim;
    }

    return 0;
}

fn sys_mprotect(addr: usize, len: usize, prot: u32) i32 {
    _ = addr;
    _ = len;
    _ = prot;
    return 0;
}

fn sys_socketpair(domain: i32, sock_type: i32, protocol: i32, sv: usize) i32 {
    _ = protocol;

    if (!protection.verifyUserPointer(sv, @sizeOf([2]i32))) return EFAULT;

    if (domain != 1) return EAFNOSUPPORT;

    var fd1: i32 = -1;
    var fd2: i32 = -1;

    for (&unix_sockets, 0..) |*usock, i| {
        if (!usock.in_use) {
            if (fd1 == -1) {
                usock.in_use = true;
                usock.connected = true;
                fd1 = @intCast(@as(i32, @intCast(i)) + 1000);
            } else {
                usock.in_use = true;
                usock.connected = true;
                fd2 = @intCast(@as(i32, @intCast(i)) + 1000);

                const idx1: usize = @intCast(fd1 - 1000);
                unix_sockets[idx1].peer = usock;
                usock.peer = &unix_sockets[idx1];
                break;
            }
        }
    }

    if (fd1 == -1 or fd2 == -1) return EMFILE;

    _ = sock_type;
    const fds = [2]i32{ fd1, fd2 };
    protection.copyToUser(sv, std.mem.asBytes(&fds)) catch return EFAULT;
    return 0;
}

const Sysinfo = extern struct {
    uptime: i32,
    loads: [3]u32,
    totalram: u32,
    freeram: u32,
    sharedram: u32,
    bufferram: u32,
    totalswap: u32,
    freeswap: u32,
    procs: u16,
    pad: u16,
    totalhigh: u32,
    freehigh: u32,
    mem_unit: u32,
    _padding: [8]u8,
};

fn sys_sysinfo(info_ptr: usize) i32 {
    if (!protection.verifyUserPointer(info_ptr, @sizeOf(Sysinfo))) return EFAULT;

    const timer = @import("../timer/timer.zig");
    const ticks = timer.getTicks();

    const info = Sysinfo{
        .uptime = @intCast(ticks / 100),
        .loads = [3]u32{ 0, 0, 0 },
        .totalram = 16 * 1024 * 1024,
        .freeram = 8 * 1024 * 1024,
        .sharedram = 0,
        .bufferram = 0,
        .totalswap = 0,
        .freeswap = 0,
        .procs = 1,
        .pad = 0,
        .totalhigh = 0,
        .freehigh = 0,
        .mem_unit = 1,
        ._padding = [_]u8{0} ** 8,
    };

    protection.copyToUser(info_ptr, std.mem.asBytes(&info)) catch return EFAULT;
    return 0;
}

fn sys_clock_settime(clock_id: u32, tp: usize) i32 {
    _ = clock_id;
    if (!protection.verifyUserPointer(tp, @sizeOf(Timespec))) return EFAULT;
    return EPERM;
}

fn sys_clock_getres(clock_id: u32, res: usize) i32 {
    if (res == 0) return 0;
    if (!protection.verifyUserPointer(res, @sizeOf(Timespec))) return EFAULT;

    _ = clock_id;

    const resolution = Timespec{
        .tv_sec = 0,
        .tv_nsec = 10000000,
    };

    protection.copyToUser(res, std.mem.asBytes(&resolution)) catch return EFAULT;
    return 0;
}

fn sys_clock_nanosleep(clock_id: u32, flags: u32, request: usize, remain: usize) i32 {
    _ = clock_id;
    _ = flags;
    _ = remain;

    if (!protection.verifyUserPointer(request, @sizeOf(Timespec))) return EFAULT;

    var req: Timespec = undefined;
    protection.copyFromUser(std.mem.asBytes(&req), request) catch return EFAULT;

    const timer = @import("../timer/timer.zig");
    const ticks_to_sleep: u64 = @intCast(@max(0, req.tv_sec) * 100 + @divTrunc(@max(0, req.tv_nsec), 10000000));
    const start_ticks = timer.getTicks();

    while (timer.getTicks() - start_ticks < ticks_to_sleep) {
        x86.hlt();
    }

    return 0;
}

const PosixTimer = struct {
    clock_id: u32,
    interval: ItimerSpec,
    in_use: bool,
};

var posix_timers: [32]PosixTimer = [_]PosixTimer{.{
    .clock_id = 0,
    .interval = .{
        .it_interval_sec = 0,
        .it_interval_nsec = 0,
        .it_value_sec = 0,
        .it_value_nsec = 0,
    },
    .in_use = false,
}} ** 32;

fn sys_timer_create(clock_id: u32, sevp: usize, timerid: usize) i32 {
    _ = sevp;

    if (!protection.verifyUserPointer(timerid, @sizeOf(i32))) return EFAULT;

    for (&posix_timers, 0..) |*timer, i| {
        if (!timer.in_use) {
            timer.in_use = true;
            timer.clock_id = clock_id;
            const id: i32 = @intCast(i);
            protection.copyToUser(timerid, std.mem.asBytes(&id)) catch return EFAULT;
            return 0;
        }
    }
    return EAGAIN;
}

fn sys_timer_delete(timerid: i32) i32 {
    if (timerid < 0 or timerid >= 32) return EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return EINVAL;
    posix_timers[idx].in_use = false;
    return 0;
}

fn sys_timer_settime(timerid: i32, flags: u32, new_value: usize, old_value: usize) i32 {
    _ = flags;

    if (timerid < 0 or timerid >= 32) return EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return EINVAL;

    if (!protection.verifyUserPointer(new_value, @sizeOf(ItimerSpec))) return EFAULT;

    if (old_value != 0) {
        if (!protection.verifyUserPointer(old_value, @sizeOf(ItimerSpec))) return EFAULT;
        protection.copyToUser(old_value, std.mem.asBytes(&posix_timers[idx].interval)) catch return EFAULT;
    }

    var new_interval: ItimerSpec = undefined;
    protection.copyFromUser(std.mem.asBytes(&new_interval), new_value) catch return EFAULT;
    posix_timers[idx].interval = new_interval;

    return 0;
}

fn sys_timer_gettime(timerid: i32, curr_value: usize) i32 {
    if (timerid < 0 or timerid >= 32) return EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return EINVAL;

    if (!protection.verifyUserPointer(curr_value, @sizeOf(ItimerSpec))) return EFAULT;

    protection.copyToUser(curr_value, std.mem.asBytes(&posix_timers[idx].interval)) catch return EFAULT;
    return 0;
}

fn sys_timer_getoverrun(timerid: i32) i32 {
    if (timerid < 0 or timerid >= 32) return EINVAL;
    const idx: usize = @intCast(timerid);
    if (!posix_timers[idx].in_use) return EINVAL;
    return 0;
}

var chroot_path: [256]u8 = [_]u8{0} ** 256;
var chroot_len: usize = 0;

fn sys_chroot(path: [*]const u8) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(path), 256)) return EFAULT;

    var path_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buffer, @intFromPtr(path)) catch return EFAULT;

    const vnode = vfs.lookupPath(path_slice) catch |err| return vfsErrno(err);
    if (vnode.file_type != .Directory) return ENOTDIR;

    @memset(&chroot_path, 0);
    @memcpy(chroot_path[0..path_slice.len], path_slice);
    chroot_len = path_slice.len;

    return 0;
}

fn sys_mount(source: usize, target: usize, fstype: usize, mountflags: usize, data: usize) i32 {
    _ = data;

    const proc = process.current_process orelse return ESRCH;
    if (proc.creds.euid != 0) return EPERM;

    if (!protection.verifyUserPointer(source, 256)) return EFAULT;
    if (!protection.verifyUserPointer(target, 256)) return EFAULT;
    if (!protection.verifyUserPointer(fstype, 32)) return EFAULT;

    var source_buf: [256]u8 = undefined;
    var target_buf: [256]u8 = undefined;
    var fstype_buf: [32]u8 = undefined;

    const source_path = protection.copyStringFromUser(&source_buf, source) catch return EFAULT;
    const target_path = protection.copyStringFromUser(&target_buf, target) catch return EFAULT;
    const fstype_str = protection.copyStringFromUser(&fstype_buf, fstype) catch return EFAULT;

    vfs.mount(source_path, target_path, fstype_str, @truncate(mountflags)) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_umount2(target: [*]const u8, flags: u32) i32 {
    _ = flags;

    const proc = process.current_process orelse return ESRCH;
    if (proc.creds.euid != 0) return EPERM;

    if (!protection.verifyUserPointer(@intFromPtr(target), 256)) return EFAULT;

    var target_buf: [256]u8 = undefined;
    const target_path = protection.copyStringFromUser(&target_buf, @intFromPtr(target)) catch return EFAULT;

    vfs.unmount(target_path) catch |err| return vfsErrno(err);
    return 0;
}

fn sys_swapon(path: [*]const u8, swapflags: u32) i32 {
    _ = path;
    _ = swapflags;
    return EPERM;
}

fn sys_swapoff(path: [*]const u8) i32 {
    _ = path;
    return EPERM;
}

fn sys_reboot(magic1: u32, magic2: u32, cmd: u32, arg: usize) i32 {
    _ = arg;

    if (magic1 != LINUX_REBOOT_MAGIC1) return EINVAL;
    if (magic2 != LINUX_REBOOT_MAGIC2 and magic2 != 0x85072010 and magic2 != 0x5121996 and magic2 != 0x16041998) return EINVAL;

    switch (cmd) {
        LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_CMD_HALT, LINUX_REBOOT_CMD_POWER_OFF => {
            vga.print("\nSystem halting...\n");
            x86.hlt();
            while (true) {
                x86.hlt();
            }
        },
        else => return EINVAL,
    }
}
