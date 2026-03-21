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
pub const SYS_GETPROCS = 182;
pub const SYS_PING = 183;
pub const SYS_SPAWN = 184;
pub const SYS_SPAWN_WITH_FDS = 185;

pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;
pub const FD_OFFSET = 3;

pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_CREAT: u32 = 0x0040;
pub const O_TRUNC: u32 = 0x0200;
pub const O_APPEND: u32 = 0x0400;

pub const DT_REG: u8 = 1;
pub const DT_DIR: u8 = 2;

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

pub const WNOHANG: u32 = 0x01;
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
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;

pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TTY_LFLAG_ISIG: u32 = 0x0001;
pub const TTY_LFLAG_ICANON: u32 = 0x0002;
pub const TTY_LFLAG_ECHO: u32 = 0x0008;

pub const SIGINT = 2;
pub const SIGKILL = 9;
pub const SIGTERM = 15;
pub const SIGCONT = 18;
pub const SIGSTOP = 19;
pub const SIGTSTP = 20;

pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;
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

pub const ProcInfo = extern struct {
    pid: u32,
    parent_pid: u32,
    state: u8,
    _padding: [3]u8,
    name: [64]u8,
};
