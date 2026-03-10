const std = @import("std");
const x86 = @import("../../arch/x86.zig");
const idt = @import("../interrupts/idt.zig");
const process = @import("process.zig");
const vga = @import("../drivers/vga.zig");
const console = @import("../utils/console.zig");
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
const abi = @import("syscall/abi.zig");
const syscall_at = @import("syscall/at.zig");
const syscall_cwd = @import("syscall/cwd.zig");
const errno = @import("syscall/errno.zig");
const syscall_descriptor = @import("syscall/descriptor.zig");
const syscall_event = @import("syscall/event.zig");
const syscall_fd = @import("syscall/fd.zig");
const syscall_fs = @import("syscall/fs.zig");
const syscall_net = @import("syscall/net.zig");
const syscall_process = @import("syscall/process_ops.zig");
const syscall_signal = @import("syscall/signal.zig");
const syscall_system = @import("syscall/system.zig");
const syscall_time = @import("syscall/time.zig");

pub const SYS_EXIT = abi.SYS_EXIT;
pub const SYS_WRITE = abi.SYS_WRITE;
pub const SYS_READ = abi.SYS_READ;
pub const SYS_OPEN = abi.SYS_OPEN;
pub const SYS_CLOSE = abi.SYS_CLOSE;
pub const SYS_GETPID = abi.SYS_GETPID;
pub const SYS_YIELD = abi.SYS_YIELD;
pub const SYS_FORK = abi.SYS_FORK;
pub const SYS_EXECVE = abi.SYS_EXECVE;
pub const SYS_WAIT4 = abi.SYS_WAIT4;
pub const SYS_BRK = abi.SYS_BRK;
pub const SYS_MMAP = abi.SYS_MMAP;
pub const SYS_MKDIR = abi.SYS_MKDIR;
pub const SYS_RMDIR = abi.SYS_RMDIR;
pub const SYS_UNLINK = abi.SYS_UNLINK;
pub const SYS_RENAME = abi.SYS_RENAME;
pub const SYS_LSEEK = abi.SYS_LSEEK;
pub const SYS_STAT = abi.SYS_STAT;
pub const SYS_FSTAT = abi.SYS_FSTAT;
pub const SYS_GETUID = abi.SYS_GETUID;
pub const SYS_GETGID = abi.SYS_GETGID;
pub const SYS_SETUID = abi.SYS_SETUID;
pub const SYS_SETGID = abi.SYS_SETGID;
pub const SYS_CHOWN = abi.SYS_CHOWN;
pub const SYS_PIPE = abi.SYS_PIPE;
pub const SYS_DUP2 = abi.SYS_DUP2;
pub const SYS_SOCKET = abi.SYS_SOCKET;
pub const SYS_BIND = abi.SYS_BIND;
pub const SYS_CONNECT = abi.SYS_CONNECT;
pub const SYS_LISTEN = abi.SYS_LISTEN;
pub const SYS_ACCEPT = abi.SYS_ACCEPT;
pub const SYS_SEND = abi.SYS_SEND;
pub const SYS_RECV = abi.SYS_RECV;
pub const SYS_SHUTDOWN = abi.SYS_SHUTDOWN;
pub const SYS_KILL = abi.SYS_KILL;
pub const SYS_SIGACTION = abi.SYS_SIGACTION;
pub const SYS_GETCWD = abi.SYS_GETCWD;
pub const SYS_CHDIR = abi.SYS_CHDIR;
pub const SYS_MSGGET = abi.SYS_MSGGET;
pub const SYS_MSGSND = abi.SYS_MSGSND;
pub const SYS_MSGRCV = abi.SYS_MSGRCV;
pub const SYS_MUNMAP = abi.SYS_MUNMAP;
pub const SYS_IOCTL = abi.SYS_IOCTL;
pub const SYS_GETPPID = abi.SYS_GETPPID;
pub const SYS_GETPGID = abi.SYS_GETPGID;
pub const SYS_SETPGID = abi.SYS_SETPGID;
pub const SYS_SETSID = abi.SYS_SETSID;
pub const SYS_NANOSLEEP = abi.SYS_NANOSLEEP;
pub const SYS_CLOCK_GETTIME = abi.SYS_CLOCK_GETTIME;
pub const SYS_ACCESS = abi.SYS_ACCESS;
pub const SYS_CHMOD = abi.SYS_CHMOD;
pub const SYS_FCHMOD = abi.SYS_FCHMOD;
pub const SYS_FTRUNCATE = abi.SYS_FTRUNCATE;
pub const SYS_GETDENTS = abi.SYS_GETDENTS;
pub const SYS_SYMLINK = abi.SYS_SYMLINK;
pub const SYS_LINK = abi.SYS_LINK;
pub const SYS_READLINK = abi.SYS_READLINK;
pub const SYS_SIGPROCMASK = abi.SYS_SIGPROCMASK;
pub const SYS_SIGPENDING = abi.SYS_SIGPENDING;
pub const SYS_SIGSUSPEND = abi.SYS_SIGSUSPEND;
pub const SYS_DUP = abi.SYS_DUP;
pub const SYS_FCNTL = abi.SYS_FCNTL;
pub const SYS_SELECT = abi.SYS_SELECT;
pub const SYS_UMASK = abi.SYS_UMASK;
pub const SYS_UNAME = abi.SYS_UNAME;
pub const SYS_TRUNCATE = abi.SYS_TRUNCATE;
pub const SYS_PREAD = abi.SYS_PREAD;
pub const SYS_PWRITE = abi.SYS_PWRITE;
pub const SYS_SENDTO = abi.SYS_SENDTO;
pub const SYS_RECVFROM = abi.SYS_RECVFROM;
pub const SYS_GETSOCKNAME = abi.SYS_GETSOCKNAME;
pub const SYS_GETPEERNAME = abi.SYS_GETPEERNAME;
pub const SYS_FCHOWN = abi.SYS_FCHOWN;
pub const SYS_FSYNC = abi.SYS_FSYNC;
pub const SYS_FDATASYNC = abi.SYS_FDATASYNC;
pub const SYS_POLL = abi.SYS_POLL;
pub const SYS_LSTAT = abi.SYS_LSTAT;
pub const SYS_GETSOCKOPT = abi.SYS_GETSOCKOPT;
pub const SYS_SETSOCKOPT = abi.SYS_SETSOCKOPT;
pub const SYS_READV = abi.SYS_READV;
pub const SYS_WRITEV = abi.SYS_WRITEV;
pub const SYS_GETEUID = abi.SYS_GETEUID;
pub const SYS_GETEGID = abi.SYS_GETEGID;
pub const SYS_ISATTY = abi.SYS_ISATTY;
pub const SYS_STATFS = abi.SYS_STATFS;
pub const SYS_FSTATFS = abi.SYS_FSTATFS;
pub const SYS_GETHOSTNAME = abi.SYS_GETHOSTNAME;
pub const SYS_SETHOSTNAME = abi.SYS_SETHOSTNAME;
pub const SYS_OPENAT = abi.SYS_OPENAT;
pub const SYS_MKDIRAT = abi.SYS_MKDIRAT;
pub const SYS_UNLINKAT = abi.SYS_UNLINKAT;
pub const SYS_LINKAT = abi.SYS_LINKAT;
pub const SYS_FCHMODAT = abi.SYS_FCHMODAT;
pub const SYS_FCHOWNAT = abi.SYS_FCHOWNAT;
pub const SYS_RENAMEAT = abi.SYS_RENAMEAT;
pub const SYS_GETGROUPS = abi.SYS_GETGROUPS;
pub const SYS_SETGROUPS = abi.SYS_SETGROUPS;
pub const SYS_GETITIMER = abi.SYS_GETITIMER;
pub const SYS_SETITIMER = abi.SYS_SETITIMER;
pub const SYS_MKFIFO = abi.SYS_MKFIFO;
pub const SYS_EPOLL_CREATE = abi.SYS_EPOLL_CREATE;
pub const SYS_EPOLL_CTL = abi.SYS_EPOLL_CTL;
pub const SYS_EPOLL_WAIT = abi.SYS_EPOLL_WAIT;
pub const SYS_TIMERFD_CREATE = abi.SYS_TIMERFD_CREATE;
pub const SYS_TIMERFD_SETTIME = abi.SYS_TIMERFD_SETTIME;
pub const SYS_TIMERFD_GETTIME = abi.SYS_TIMERFD_GETTIME;
pub const SYS_SHMGET = abi.SYS_SHMGET;
pub const SYS_SHMAT = abi.SYS_SHMAT;
pub const SYS_SHMDT = abi.SYS_SHMDT;
pub const SYS_SHMCTL = abi.SYS_SHMCTL;
pub const SYS_SEMGET = abi.SYS_SEMGET;
pub const SYS_SEMOP = abi.SYS_SEMOP;
pub const SYS_SEMCTL = abi.SYS_SEMCTL;
pub const SYS_TIMES = abi.SYS_TIMES;
pub const SYS_GETRUSAGE = abi.SYS_GETRUSAGE;
pub const SYS_MKNOD = abi.SYS_MKNOD;
pub const SYS_GETRANDOM = abi.SYS_GETRANDOM;
pub const SYS_PIPE2 = abi.SYS_PIPE2;
pub const SYS_DUP3 = abi.SYS_DUP3;
pub const SYS_ACCEPT4 = abi.SYS_ACCEPT4;
pub const SYS_EVENTFD = abi.SYS_EVENTFD;
pub const SYS_EVENTFD2 = abi.SYS_EVENTFD2;
pub const SYS_PRCTL = abi.SYS_PRCTL;
pub const SYS_SIGNALFD = abi.SYS_SIGNALFD;
pub const SYS_SIGNALFD4 = abi.SYS_SIGNALFD4;
pub const SYS_PPOLL = abi.SYS_PPOLL;
pub const SYS_PSELECT6 = abi.SYS_PSELECT6;
pub const SYS_FACCESSAT = abi.SYS_FACCESSAT;
pub const SYS_FACCESSAT2 = abi.SYS_FACCESSAT2;
pub const SYS_STATX = abi.SYS_STATX;
pub const SYS_MEMBARRIER = abi.SYS_MEMBARRIER;
pub const SYS_COPY_FILE_RANGE = abi.SYS_COPY_FILE_RANGE;
pub const SYS_FADVISE64 = abi.SYS_FADVISE64;
pub const SYS_READAHEAD = abi.SYS_READAHEAD;
pub const SYS_SYNC_FILE_RANGE = abi.SYS_SYNC_FILE_RANGE;
pub const SYS_SYNCFS = abi.SYS_SYNCFS;
pub const SYS_GETPRIORITY = abi.SYS_GETPRIORITY;
pub const SYS_SETPRIORITY = abi.SYS_SETPRIORITY;
pub const SYS_SCHED_GETAFFINITY = abi.SYS_SCHED_GETAFFINITY;
pub const SYS_SCHED_SETAFFINITY = abi.SYS_SCHED_SETAFFINITY;
pub const SYS_UTIMENSAT = abi.SYS_UTIMENSAT;
pub const SYS_FUTIMESAT = abi.SYS_FUTIMESAT;
pub const SYS_FSTATAT = abi.SYS_FSTATAT;
pub const SYS_SYMLINKAT = abi.SYS_SYMLINKAT;
pub const SYS_READLINKAT = abi.SYS_READLINKAT;
pub const SYS_WAITID = abi.SYS_WAITID;
pub const SYS_SET_TID_ADDRESS = abi.SYS_SET_TID_ADDRESS;
pub const SYS_GET_ROBUST_LIST = abi.SYS_GET_ROBUST_LIST;
pub const SYS_SET_ROBUST_LIST = abi.SYS_SET_ROBUST_LIST;
pub const SYS_TGKILL = abi.SYS_TGKILL;
pub const SYS_TKILL = abi.SYS_TKILL;
pub const SYS_INOTIFY_INIT = abi.SYS_INOTIFY_INIT;
pub const SYS_INOTIFY_INIT1 = abi.SYS_INOTIFY_INIT1;
pub const SYS_INOTIFY_ADD_WATCH = abi.SYS_INOTIFY_ADD_WATCH;
pub const SYS_INOTIFY_RM_WATCH = abi.SYS_INOTIFY_RM_WATCH;
pub const SYS_MLOCK = abi.SYS_MLOCK;
pub const SYS_MUNLOCK = abi.SYS_MUNLOCK;
pub const SYS_MLOCKALL = abi.SYS_MLOCKALL;
pub const SYS_MUNLOCKALL = abi.SYS_MUNLOCKALL;
pub const SYS_MADVISE = abi.SYS_MADVISE;
pub const SYS_MINCORE = abi.SYS_MINCORE;
pub const SYS_GETRLIMIT = abi.SYS_GETRLIMIT;
pub const SYS_SETRLIMIT = abi.SYS_SETRLIMIT;
pub const SYS_PRLIMIT64 = abi.SYS_PRLIMIT64;
pub const SYS_MPROTECT = abi.SYS_MPROTECT;
pub const SYS_SOCKETPAIR = abi.SYS_SOCKETPAIR;
pub const SYS_SYSINFO = abi.SYS_SYSINFO;
pub const SYS_CLOCK_SETTIME = abi.SYS_CLOCK_SETTIME;
pub const SYS_CLOCK_GETRES = abi.SYS_CLOCK_GETRES;
pub const SYS_CLOCK_NANOSLEEP = abi.SYS_CLOCK_NANOSLEEP;
pub const SYS_TIMER_CREATE = abi.SYS_TIMER_CREATE;
pub const SYS_TIMER_DELETE = abi.SYS_TIMER_DELETE;
pub const SYS_TIMER_SETTIME = abi.SYS_TIMER_SETTIME;
pub const SYS_TIMER_GETTIME = abi.SYS_TIMER_GETTIME;
pub const SYS_TIMER_GETOVERRUN = abi.SYS_TIMER_GETOVERRUN;
pub const SYS_CHROOT = abi.SYS_CHROOT;
pub const SYS_MOUNT = abi.SYS_MOUNT;
pub const SYS_UMOUNT2 = abi.SYS_UMOUNT2;
pub const SYS_SWAPON = abi.SYS_SWAPON;
pub const SYS_SWAPOFF = abi.SYS_SWAPOFF;
pub const SYS_REBOOT = abi.SYS_REBOOT;

pub const STDIN = abi.STDIN;
pub const STDOUT = abi.STDOUT;
pub const STDERR = abi.STDERR;
const FD_OFFSET = abi.FD_OFFSET;

pub const EPERM = abi.EPERM;
pub const ENOENT = abi.ENOENT;
pub const ESRCH = abi.ESRCH;
pub const EINTR = abi.EINTR;
pub const EIO = abi.EIO;
pub const E2BIG = abi.E2BIG;
pub const EBADF = abi.EBADF;
pub const EAGAIN = abi.EAGAIN;
pub const EWOULDBLOCK = abi.EWOULDBLOCK;
pub const ENOMEM = abi.ENOMEM;
pub const EACCES = abi.EACCES;
pub const EFAULT = abi.EFAULT;
pub const ENOTDIR = abi.ENOTDIR;
pub const EINVAL = abi.EINVAL;
pub const EBUSY = abi.EBUSY;
pub const EEXIST = abi.EEXIST;
pub const EISDIR = abi.EISDIR;
pub const ENFILE = abi.ENFILE;
pub const EMFILE = abi.EMFILE;
pub const ENOSPC = abi.ENOSPC;
pub const EROFS = abi.EROFS;
pub const EPIPE = abi.EPIPE;
pub const ENAMETOOLONG = abi.ENAMETOOLONG;
pub const ENOSYS = abi.ENOSYS;
pub const EOVERFLOW = abi.EOVERFLOW;
pub const ENODEV = abi.ENODEV;
pub const EOPNOTSUPP = abi.EOPNOTSUPP;
pub const EAFNOSUPPORT = abi.EAFNOSUPPORT;
pub const EADDRINUSE = abi.EADDRINUSE;
pub const EADDRNOTAVAIL = abi.EADDRNOTAVAIL;
pub const ENETDOWN = abi.ENETDOWN;
pub const ENETUNREACH = abi.ENETUNREACH;
pub const ECONNABORTED = abi.ECONNABORTED;
pub const ECONNRESET = abi.ECONNRESET;
pub const ENOBUFS = abi.ENOBUFS;
pub const EISCONN = abi.EISCONN;
pub const ENOTCONN = abi.ENOTCONN;
pub const ETIMEDOUT = abi.ETIMEDOUT;
pub const ECONNREFUSED = abi.ECONNREFUSED;
pub const EHOSTUNREACH = abi.EHOSTUNREACH;
pub const ENXIO = abi.ENXIO;
pub const ENOEXEC = abi.ENOEXEC;
pub const EXDEV = abi.EXDEV;
pub const ENOTTY = abi.ENOTTY;
pub const ETXTBSY = abi.ETXTBSY;
pub const ELOOP = abi.ELOOP;
pub const EMSGSIZE = abi.EMSGSIZE;
pub const ENOPROTOOPT = abi.ENOPROTOOPT;

pub const AT_FDCWD = abi.AT_FDCWD;
pub const AT_REMOVEDIR = abi.AT_REMOVEDIR;

pub const ITIMER_REAL = abi.ITIMER_REAL;
pub const ITIMER_VIRTUAL = abi.ITIMER_VIRTUAL;
pub const ITIMER_PROF = abi.ITIMER_PROF;

pub const EPOLL_CTL_ADD = abi.EPOLL_CTL_ADD;
pub const EPOLL_CTL_DEL = abi.EPOLL_CTL_DEL;
pub const EPOLL_CTL_MOD = abi.EPOLL_CTL_MOD;

pub const EPOLLIN = abi.EPOLLIN;
pub const EPOLLOUT = abi.EPOLLOUT;
pub const EPOLLERR = abi.EPOLLERR;
pub const EPOLLHUP = abi.EPOLLHUP;
pub const EPOLLRDHUP = abi.EPOLLRDHUP;
pub const EPOLLET = abi.EPOLLET;

pub const TFD_CLOEXEC = abi.TFD_CLOEXEC;
pub const TFD_NONBLOCK = abi.TFD_NONBLOCK;

pub const IPC_CREAT = abi.IPC_CREAT;
pub const IPC_EXCL = abi.IPC_EXCL;
pub const IPC_NOWAIT = abi.IPC_NOWAIT;
pub const IPC_RMID = abi.IPC_RMID;
pub const IPC_SET = abi.IPC_SET;
pub const IPC_STAT = abi.IPC_STAT;

pub const SHM_RDONLY = abi.SHM_RDONLY;
pub const SHM_RND = abi.SHM_RND;

pub const GETVAL = abi.GETVAL;
pub const SETVAL = abi.SETVAL;
pub const GETALL = abi.GETALL;
pub const SETALL = abi.SETALL;

pub const F_GETLK = abi.F_GETLK;
pub const F_SETLK = abi.F_SETLK;
pub const F_SETLKW = abi.F_SETLKW;

pub const F_RDLCK = abi.F_RDLCK;
pub const F_WRLCK = abi.F_WRLCK;
pub const F_UNLCK = abi.F_UNLCK;

pub const S_IFMT = abi.S_IFMT;
pub const S_IFREG = abi.S_IFREG;
pub const S_IFDIR = abi.S_IFDIR;
pub const S_IFCHR = abi.S_IFCHR;
pub const S_IFBLK = abi.S_IFBLK;
pub const S_IFIFO = abi.S_IFIFO;
pub const S_IFLNK = abi.S_IFLNK;
pub const S_IFSOCK = abi.S_IFSOCK;

pub const RUSAGE_SELF = abi.RUSAGE_SELF;
pub const RUSAGE_CHILDREN = abi.RUSAGE_CHILDREN;

pub const EIDRM = abi.EIDRM;
pub const ENOMSG = abi.ENOMSG;
pub const EDEADLK = abi.EDEADLK;
pub const ENOLCK = abi.ENOLCK;

pub const O_CLOEXEC = abi.O_CLOEXEC;

pub const GRND_NONBLOCK = abi.GRND_NONBLOCK;
pub const GRND_RANDOM = abi.GRND_RANDOM;

pub const EFD_SEMAPHORE = abi.EFD_SEMAPHORE;
pub const EFD_CLOEXEC = abi.EFD_CLOEXEC;
pub const EFD_NONBLOCK = abi.EFD_NONBLOCK;

pub const SOCK_CLOEXEC = abi.SOCK_CLOEXEC;
pub const SOCK_NONBLOCK = abi.SOCK_NONBLOCK;

pub const PR_SET_NAME = abi.PR_SET_NAME;
pub const PR_GET_NAME = abi.PR_GET_NAME;
pub const PR_SET_DUMPABLE = abi.PR_SET_DUMPABLE;
pub const PR_GET_DUMPABLE = abi.PR_GET_DUMPABLE;
pub const PR_SET_KEEPCAPS = abi.PR_SET_KEEPCAPS;
pub const PR_GET_KEEPCAPS = abi.PR_GET_KEEPCAPS;
pub const PR_SET_PDEATHSIG = abi.PR_SET_PDEATHSIG;
pub const PR_GET_PDEATHSIG = abi.PR_GET_PDEATHSIG;

pub const SFD_CLOEXEC = abi.SFD_CLOEXEC;
pub const SFD_NONBLOCK = abi.SFD_NONBLOCK;

pub const AT_EACCESS = abi.AT_EACCESS;
pub const AT_SYMLINK_NOFOLLOW = abi.AT_SYMLINK_NOFOLLOW;

pub const STATX_TYPE = abi.STATX_TYPE;
pub const STATX_MODE = abi.STATX_MODE;
pub const STATX_NLINK = abi.STATX_NLINK;
pub const STATX_UID = abi.STATX_UID;
pub const STATX_GID = abi.STATX_GID;
pub const STATX_ATIME = abi.STATX_ATIME;
pub const STATX_MTIME = abi.STATX_MTIME;
pub const STATX_CTIME = abi.STATX_CTIME;
pub const STATX_INO = abi.STATX_INO;
pub const STATX_SIZE = abi.STATX_SIZE;
pub const STATX_BLOCKS = abi.STATX_BLOCKS;
pub const STATX_BASIC_STATS = abi.STATX_BASIC_STATS;

pub const MEMBARRIER_CMD_QUERY = abi.MEMBARRIER_CMD_QUERY;
pub const MEMBARRIER_CMD_GLOBAL = abi.MEMBARRIER_CMD_GLOBAL;
pub const MEMBARRIER_CMD_GLOBAL_EXPEDITED = abi.MEMBARRIER_CMD_GLOBAL_EXPEDITED;
pub const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED = abi.MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED;
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED = abi.MEMBARRIER_CMD_PRIVATE_EXPEDITED;
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED = abi.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;

pub const POSIX_FADV_NORMAL = abi.POSIX_FADV_NORMAL;
pub const POSIX_FADV_RANDOM = abi.POSIX_FADV_RANDOM;
pub const POSIX_FADV_SEQUENTIAL = abi.POSIX_FADV_SEQUENTIAL;
pub const POSIX_FADV_WILLNEED = abi.POSIX_FADV_WILLNEED;
pub const POSIX_FADV_DONTNEED = abi.POSIX_FADV_DONTNEED;
pub const POSIX_FADV_NOREUSE = abi.POSIX_FADV_NOREUSE;

pub const SYNC_FILE_RANGE_WAIT_BEFORE = abi.SYNC_FILE_RANGE_WAIT_BEFORE;
pub const SYNC_FILE_RANGE_WRITE = abi.SYNC_FILE_RANGE_WRITE;
pub const SYNC_FILE_RANGE_WAIT_AFTER = abi.SYNC_FILE_RANGE_WAIT_AFTER;

pub const PRIO_PROCESS = abi.PRIO_PROCESS;
pub const PRIO_PGRP = abi.PRIO_PGRP;
pub const PRIO_USER = abi.PRIO_USER;

pub const UTIME_NOW = abi.UTIME_NOW;
pub const UTIME_OMIT = abi.UTIME_OMIT;

pub const P_ALL = abi.P_ALL;
pub const P_PID = abi.P_PID;
pub const P_PGID = abi.P_PGID;

pub const WEXITED = abi.WEXITED;
pub const WSTOPPED = abi.WSTOPPED;
pub const WCONTINUED = abi.WCONTINUED;
pub const WNOWAIT = abi.WNOWAIT;

pub const ECHILD = abi.ECHILD;

pub const IN_ACCESS = abi.IN_ACCESS;
pub const IN_MODIFY = abi.IN_MODIFY;
pub const IN_ATTRIB = abi.IN_ATTRIB;
pub const IN_CLOSE_WRITE = abi.IN_CLOSE_WRITE;
pub const IN_CLOSE_NOWRITE = abi.IN_CLOSE_NOWRITE;
pub const IN_OPEN = abi.IN_OPEN;
pub const IN_MOVED_FROM = abi.IN_MOVED_FROM;
pub const IN_MOVED_TO = abi.IN_MOVED_TO;
pub const IN_CREATE = abi.IN_CREATE;
pub const IN_DELETE = abi.IN_DELETE;
pub const IN_DELETE_SELF = abi.IN_DELETE_SELF;
pub const IN_MOVE_SELF = abi.IN_MOVE_SELF;
pub const IN_NONBLOCK = abi.IN_NONBLOCK;
pub const IN_CLOEXEC = abi.IN_CLOEXEC;

pub const MCL_CURRENT = abi.MCL_CURRENT;
pub const MCL_FUTURE = abi.MCL_FUTURE;

pub const MADV_NORMAL = abi.MADV_NORMAL;
pub const MADV_RANDOM = abi.MADV_RANDOM;
pub const MADV_SEQUENTIAL = abi.MADV_SEQUENTIAL;
pub const MADV_WILLNEED = abi.MADV_WILLNEED;
pub const MADV_DONTNEED = abi.MADV_DONTNEED;

pub const RLIMIT_CPU = abi.RLIMIT_CPU;
pub const RLIMIT_FSIZE = abi.RLIMIT_FSIZE;
pub const RLIMIT_DATA = abi.RLIMIT_DATA;
pub const RLIMIT_STACK = abi.RLIMIT_STACK;
pub const RLIMIT_CORE = abi.RLIMIT_CORE;
pub const RLIMIT_RSS = abi.RLIMIT_RSS;
pub const RLIMIT_NPROC = abi.RLIMIT_NPROC;
pub const RLIMIT_NOFILE = abi.RLIMIT_NOFILE;
pub const RLIMIT_MEMLOCK = abi.RLIMIT_MEMLOCK;
pub const RLIMIT_AS = abi.RLIMIT_AS;
pub const RLIM_INFINITY = abi.RLIM_INFINITY;

pub const PROT_NONE = abi.PROT_NONE;
pub const PROT_READ = abi.PROT_READ;
pub const PROT_WRITE = abi.PROT_WRITE;
pub const PROT_EXEC = abi.PROT_EXEC;

pub const CLOCK_MONOTONIC_RAW = abi.CLOCK_MONOTONIC_RAW;
pub const CLOCK_REALTIME_COARSE = abi.CLOCK_REALTIME_COARSE;
pub const CLOCK_MONOTONIC_COARSE = abi.CLOCK_MONOTONIC_COARSE;
pub const CLOCK_BOOTTIME = abi.CLOCK_BOOTTIME;

pub const TIMER_ABSTIME = abi.TIMER_ABSTIME;

pub const MNT_FORCE = abi.MNT_FORCE;
pub const MNT_DETACH = abi.MNT_DETACH;
pub const MNT_EXPIRE = abi.MNT_EXPIRE;
pub const UMOUNT_NOFOLLOW = abi.UMOUNT_NOFOLLOW;

pub const LINUX_REBOOT_MAGIC1 = abi.LINUX_REBOOT_MAGIC1;
pub const LINUX_REBOOT_MAGIC2 = abi.LINUX_REBOOT_MAGIC2;
pub const LINUX_REBOOT_CMD_RESTART = abi.LINUX_REBOOT_CMD_RESTART;
pub const LINUX_REBOOT_CMD_HALT = abi.LINUX_REBOOT_CMD_HALT;
pub const LINUX_REBOOT_CMD_POWER_OFF = abi.LINUX_REBOOT_CMD_POWER_OFF;

const vfsErrno = errno.vfsErrno;
const socketErrno = errno.socketErrno;

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
    if (process.getEffectiveCurrent()) |proc| {
        proc.state = .Terminated;
        proc.exit_code = status;

        if (proc.parent_pid != 0) {
            if (process.getProcessByPid(proc.parent_pid)) |parent| {
                signal.sendSignal(parent, signal.SIGCHLD);
                process.switchToProcess(parent);
            }
        }

        while (true) {
            process.yield();
            x86.hlt();
        }
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

            console.print(kernel_buffer[0..chunk_size]);

            written += chunk_size;
        }

        return @intCast(count);
    }

    if (count == 0) return 0;

    // SAFETY: filled by the subsequent copyFromUser call
    var kernel_buffer: [512]u8 = undefined;
    var written: usize = 0;

    while (written < count) {
        const chunk_size = @min(count - written, kernel_buffer.len);
        protection.copyFromUser(kernel_buffer[0..chunk_size], @intFromPtr(buf) + written) catch {
            return EINVAL;
        };

        if (syscall_descriptor.write(fd, kernel_buffer[0..chunk_size])) |result| {
            if (result < 0) return result;

            const bytes_written: usize = @intCast(result);
            written += bytes_written;
            if (bytes_written < chunk_size) break;
            continue;
        }

        if (fd < FD_OFFSET) return EBADF;
        const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

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

    if (count == 0) return 0;

    // SAFETY: filled by the subsequent special-fd or vfs read call
    var kernel_buffer: [512]u8 = undefined;
    var total_read: usize = 0;

    while (total_read < count) {
        const chunk_size = @min(count - total_read, kernel_buffer.len);

        if (syscall_descriptor.read(fd, kernel_buffer[0..chunk_size])) |result| {
            if (result < 0) return result;
            if (result == 0) break;

            const bytes_read: usize = @intCast(result);
            protection.copyToUser(@intFromPtr(buf) + total_read, kernel_buffer[0..bytes_read]) catch {
                return EINVAL;
            };

            total_read += bytes_read;
            if (bytes_read < chunk_size) break;
            continue;
        }

        if (fd < FD_OFFSET) return EBADF;
        const vfs_fd: u32 = @intCast(fd - FD_OFFSET);

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
    return syscall_process.sys_getpid();
}

fn sys_yield() i32 {
    return syscall_process.sys_yield();
}

fn sys_mkdir(pathname: [*]const u8, mode: u32) i32 {
    return syscall_fs.sys_mkdir(pathname, mode);
}

fn sys_rmdir(pathname: [*]const u8) i32 {
    return syscall_fs.sys_rmdir(pathname);
}

fn sys_unlink(pathname: [*]const u8) i32 {
    return syscall_fs.sys_unlink(pathname);
}

fn sys_rename(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    return syscall_fs.sys_rename(oldpath, newpath);
}

fn sys_open(pathname: [*]const u8, flags: u32) i32 {
    return syscall_fs.sys_open(pathname, flags);
}

fn sys_close(fd: i32) i32 {
    return syscall_fd.sys_close(&unix_sockets, &socket_table, fd);
}

fn sys_lseek(fd: i32, offset: i64, whence: u32) i32 {
    return syscall_fd.sys_lseek(fd, offset, whence);
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
    syscall_net.attachTables(&unix_sockets, &socket_table);
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
        : .{ .memory = true });
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
    // SAFETY: populated by the subsequent inline assembly (int $0x80)
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
    syscall_event.notifyInotifyPathEvent(path_slice, abi.IN_ATTRIB, 0);
    return 0;
}

const AF_UNIX = syscall_net.AF_UNIX;
const AF_INET = syscall_net.AF_INET;
const AF_INET6 = syscall_net.AF_INET6;
const SOCK_STREAM = syscall_net.SOCK_STREAM;
const SOCK_DGRAM = syscall_net.SOCK_DGRAM;

const SockAddrIn = syscall_net.SockAddrIn;
const SockAddrIn6 = syscall_net.SockAddrIn6;
const SockAddrUn = syscall_net.SockAddrUn;
const UnixSocket = syscall_net.UnixSocket;

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
    return syscall_net.sys_socket(&unix_sockets, &socket_table, domain, sock_type, protocol);
}

fn sys_bind(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    return syscall_net.sys_bind(&unix_sockets, &socket_table, sockfd, addr_ptr, addr_len);
}

fn sys_connect(sockfd: i32, addr_ptr: usize, addr_len: u32) i32 {
    return syscall_net.sys_connect(&unix_sockets, &socket_table, sockfd, addr_ptr, addr_len);
}

fn sys_listen(sockfd: i32, backlog: u32) i32 {
    return syscall_net.sys_listen(&unix_sockets, &socket_table, sockfd, backlog);
}

fn sys_accept(sockfd: i32) i32 {
    return syscall_net.sys_accept(&unix_sockets, &socket_table, sockfd);
}

fn sys_send(sockfd: i32, buf: [*]const u8, len: usize) i32 {
    return syscall_net.sys_send(&unix_sockets, &socket_table, sockfd, buf, len);
}

fn sys_recv(sockfd: i32, buf: [*]u8, len: usize) i32 {
    return syscall_net.sys_recv(&unix_sockets, &socket_table, sockfd, buf, len);
}

fn sys_shutdown(sockfd: i32) i32 {
    return syscall_net.sys_shutdown(&socket_table, sockfd);
}

fn sys_kill(pid: i32, signum: i32) i32 {
    return syscall_signal.sys_kill(pid, signum);
}

fn sys_sigaction(signum: i32, act_addr: usize, oldact_addr: usize) i32 {
    return syscall_signal.sys_sigaction(signum, act_addr, oldact_addr);
}

pub fn getCwd() []const u8 {
    return syscall_cwd.getCwd();
}

pub fn setCwd(path: []const u8) bool {
    return syscall_cwd.setCwd(path);
}

fn sys_getcwd(buf: [*]u8, size: usize) i32 {
    return syscall_cwd.sys_getcwd(buf, size);
}

fn sys_chdir(pathname: [*]const u8) i32 {
    return syscall_cwd.sys_chdir(pathname);
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
    return syscall_fs.sys_pipe(pipefd);
}

fn sys_dup2(old_fd: i32, new_fd: i32) i32 {
    return syscall_fs.sys_dup2(old_fd, new_fd);
}

fn sys_fork() i32 {
    return syscall_process.sys_fork();
}

fn sys_execve(path: [*]const u8, argv: usize, envp: usize) i32 {
    return syscall_process.sys_execve(path, argv, envp);
}

fn sys_wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) i32 {
    return syscall_process.sys_wait4(pid, status, options, rusage);
}

fn sys_brk(addr: usize) i32 {
    return syscall_process.sys_brk(addr);
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
    return syscall_fd.sys_ioctl(fd, request, arg);
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

fn sys_nanosleep(req_addr: usize, rem_addr: usize) i32 {
    return syscall_time.sys_nanosleep(req_addr, rem_addr);
}

fn sys_clock_gettime(clock_id: i32, tp_addr: usize) i32 {
    return syscall_time.sys_clock_gettime(clock_id, tp_addr);
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
    syscall_event.notifyInotifyPathEvent(path_slice, abi.IN_ATTRIB, 0);
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
    syscall_event.notifyInotifyPathEvent(link_slice, abi.IN_CREATE, abi.IN_CREATE);
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
    syscall_event.notifyInotifyPathEvent(new_slice, abi.IN_CREATE, abi.IN_CREATE);
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
    return syscall_signal.sys_sigprocmask(how, set_addr, oldset_addr);
}

fn sys_sigpending(set_addr: usize) i32 {
    return syscall_signal.sys_sigpending(set_addr);
}

fn sys_sigsuspend(mask_addr: usize) i32 {
    return syscall_signal.sys_sigsuspend(mask_addr);
}

fn sys_dup(fd: i32) i32 {
    return syscall_fd.sys_dup(fd);
}

fn sys_fcntl(fd: i32, cmd: i32, arg: usize) i32 {
    return syscall_fd.sys_fcntl(fd, cmd, arg);
}

fn sys_select(nfds: i32, readfds_addr: usize, writefds_addr: usize, exceptfds_addr: usize, timeout_addr: usize) i32 {
    return syscall_event.sys_select(nfds, readfds_addr, writefds_addr, exceptfds_addr, timeout_addr);
}

fn sys_umask(mask: u16) i32 {
    const proc = process.current_process orelse return ESRCH;
    const old = proc.umask;
    proc.umask = mask & 0o777;
    return @intCast(old);
}

pub fn getHostname() []const u8 {
    return syscall_system.getHostname();
}

pub fn setHostname(name: []const u8) void {
    syscall_system.setHostname(name);
}

fn sys_gethostname(name_addr: usize, len: usize) i32 {
    return syscall_system.sys_gethostname(name_addr, len);
}

fn sys_sethostname(name_addr: usize, len: usize) i32 {
    return syscall_system.sys_sethostname(name_addr, len);
}

fn sys_uname(buf_addr: usize) i32 {
    return syscall_system.sys_uname(buf_addr);
}

fn sys_truncate(pathname: [*]const u8, length: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(pathname), 256)) return EINVAL;

    var kernel_buffer: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&kernel_buffer, @intFromPtr(pathname)) catch return EINVAL;

    vfs.truncate(path_slice, length) catch |err| return vfsErrno(err);
    syscall_event.notifyInotifyPathEvent(path_slice, abi.IN_MODIFY, 0);
    return 0;
}

fn sys_pread(fd: i32, buf: [*]u8, count: usize, offset: u64) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), count)) return EINVAL;
    if (fd < FD_OFFSET) return EBADF;
    if (syscall_fd.isSpecialFd(fd)) return EBADF;
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
    if (syscall_fd.isSpecialFd(fd)) return EBADF;
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
    const sock = syscall_net.getInetSocket(sockfd) orelse return EBADF;

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
    const sock = syscall_net.getInetSocket(sockfd) orelse return EBADF;

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
    const sock = syscall_net.getInetSocket(sockfd) orelse return EBADF;
    if (sock.address_family == .AF_INET6) {
        const local = sock.local_ipv6 orelse @import("../net/ipv6.zig").UNSPECIFIED;
        return writeSockAddr6(addr_ptr, addr_len_ptr, local, sock.local_port);
    }
    return writeSockAddr(addr_ptr, addr_len_ptr, sock.local_addr, sock.local_port);
}

fn sys_getpeername(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    const sock = syscall_net.getInetSocket(sockfd) orelse return EBADF;
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
    return syscall_fd.sys_fsync(fd);
}

fn sys_poll(fds_addr: usize, nfds: u32, timeout: i32) i32 {
    return syscall_event.sys_poll(fds_addr, nfds, timeout);
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
    const sock = syscall_net.getInetSocket(sockfd) orelse return EBADF;

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
    _ = syscall_net.getInetSocket(sockfd) orelse return EBADF;

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

fn sys_openat(dirfd: i32, pathname: [*]const u8, flags: i32) i32 {
    return syscall_at.sys_openat(dirfd, pathname, flags);
}

fn sys_mkdirat(dirfd: i32, pathname: [*]const u8, mode: u32) i32 {
    return syscall_at.sys_mkdirat(dirfd, pathname, mode);
}

fn sys_unlinkat(dirfd: i32, pathname: [*]const u8, flags: u32) i32 {
    return syscall_at.sys_unlinkat(dirfd, pathname, flags);
}

fn sys_linkat(olddirfd: i32, oldpath: [*]const u8, newdirfd: i32, newpath: [*]const u8, flags: u32) i32 {
    return syscall_at.sys_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

fn sys_fchmodat(dirfd: i32, pathname: [*]const u8, mode: u32) i32 {
    return syscall_at.sys_fchmodat(dirfd, pathname, mode);
}

fn sys_fchownat(dirfd: i32, pathname: [*]const u8, owner: i32, group: i32) i32 {
    return syscall_at.sys_fchownat(dirfd, pathname, owner, group);
}

fn sys_renameat(olddirfd: i32, oldpath: [*]const u8, newdirfd: i32, newpath: [*]const u8) i32 {
    return syscall_at.sys_renameat(olddirfd, oldpath, newdirfd, newpath);
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

fn sys_getitimer(which: u32, value_addr: usize) i32 {
    return syscall_time.sys_getitimer(which, value_addr);
}

fn sys_setitimer(which: u32, new_value_addr: usize, old_value_addr: usize) i32 {
    return syscall_time.sys_setitimer(which, new_value_addr, old_value_addr);
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

fn sys_epoll_create(size: i32) i32 {
    return syscall_event.sys_epoll_create(size);
}

fn sys_epoll_ctl(epfd: i32, op: u32, fd: i32, event_addr: usize) i32 {
    return syscall_event.sys_epoll_ctl(epfd, op, fd, event_addr);
}

fn sys_epoll_wait(epfd: i32, events_addr: usize, maxevents: i32, timeout: i32) i32 {
    return syscall_event.sys_epoll_wait(epfd, events_addr, maxevents, timeout);
}

fn sys_timerfd_create(clockid: u32, flags: u32) i32 {
    return syscall_time.sys_timerfd_create(clockid, flags);
}

fn sys_timerfd_settime(fd: i32, flags: u32, new_value_addr: usize, old_value_addr: usize) i32 {
    return syscall_time.sys_timerfd_settime(fd, flags, new_value_addr, old_value_addr);
}

fn sys_timerfd_gettime(fd: i32, value_addr: usize) i32 {
    return syscall_time.sys_timerfd_gettime(fd, value_addr);
}

const ShmSegment = struct {
    key: i32,
    size: usize,
    addr: ?[*]u8,
    mode: u32,
    nattch: u32,
    in_use: bool,
    marked_for_deletion: bool,
};

var shm_segments: [64]ShmSegment = [_]ShmSegment{.{
    .key = 0,
    .size = 0,
    .addr = null,
    .mode = 0,
    .nattch = 0,
    .in_use = false,
    .marked_for_deletion = false,
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
            seg.marked_for_deletion = false;
            return @intCast(i);
        }
    }
    return ENOSPC;
}

fn sys_shmat(shmid: i32, _: usize, _: u32) i32 {
    if (shmid < 0 or shmid >= 64) return EINVAL;
    const seg = &shm_segments[@intCast(shmid)];
    if (!seg.in_use) return EINVAL;
    if (seg.marked_for_deletion) return EINVAL;

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
                    if (seg.marked_for_deletion and seg.nattch == 0) {
                        memory.kfree(@ptrCast(a));
                        seg.in_use = false;
                        seg.addr = null;
                        seg.marked_for_deletion = false;
                    }
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
            } else {
                seg.marked_for_deletion = true;
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
        } else {
            if (sem.value != 0) return EAGAIN;
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

fn sys_times(buf_addr: usize) i32 {
    return syscall_time.sys_times(buf_addr);
}

fn sys_getrusage(who: i32, usage_addr: usize) i32 {
    return syscall_time.sys_getrusage(who, usage_addr);
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
    return syscall_fd.sys_pipe2(pipefd, flags);
}

fn sys_dup3(old_fd: i32, new_fd: i32, flags: u32) i32 {
    return syscall_fd.sys_dup3(old_fd, new_fd, flags);
}

fn sys_accept4(sockfd: i32, addr: usize, addrlen: usize, flags: u32) i32 {
    _ = addr;
    _ = addrlen;

    if (sockfd >= syscall_net.unix_socket_fd_base and sockfd < syscall_net.unix_socket_fd_base + @as(i32, @intCast(syscall_net.unix_socket_count))) {
        const idx: usize = @intCast(sockfd - syscall_net.unix_socket_fd_base);
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
                        const new_fd: i32 = @intCast(@as(i32, @intCast(j)) + syscall_net.unix_socket_fd_base);
                        _ = flags;
                        return new_fd;
                    }
                }
                return EMFILE;
            }
        }
        return EAGAIN;
    }

    const sock = syscall_net.getInetSocket(sockfd) orelse return EBADF;

    const client = sock.accept() catch |err| return socketErrno(err);

    for (&socket_table, 0..) |*slot, i| {
        if (slot.* == null) {
            slot.* = client;
            return @intCast(@as(i32, @intCast(i)) + syscall_net.socket_fd_base);
        }
    }

    client.close();
    return EMFILE;
}

fn sys_eventfd(initval: u32) i32 {
    return syscall_event.sys_eventfd(initval);
}

fn sys_eventfd2(initval: u32, flags: u32) i32 {
    return syscall_event.sys_eventfd2(initval, flags);
}

var process_names: [256][16]u8 = [_][16]u8{[_]u8{0} ** 16} ** 256;
var process_dumpable: [256]u32 = [_]u32{1} ** 256;
var process_keepcaps: [256]u32 = [_]u32{0} ** 256;
var process_pdeathsig: [256]u32 = [_]u32{0} ** 256;

fn sys_prctl(option: u32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
    _ = arg4;
    _ = arg5;

    const proc = process.current_process orelse return ESRCH;
    const pid_idx: usize = proc.pid % 256;

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

fn sys_signalfd(fd: i32, mask_ptr: usize, sizemask: usize) i32 {
    return syscall_event.sys_signalfd(fd, mask_ptr, sizemask);
}

fn sys_signalfd4(fd: i32, mask_ptr: usize, sizemask: usize, flags: u32) i32 {
    return syscall_event.sys_signalfd4(fd, mask_ptr, sizemask, flags);
}

fn sys_ppoll(fds_ptr: usize, nfds: u32, timeout_ptr: usize, sigmask_ptr: usize) i32 {
    return syscall_event.sys_ppoll(fds_ptr, nfds, timeout_ptr, sigmask_ptr);
}

fn sys_pselect6(nfds: i32, readfds: usize, writefds: usize, exceptfds: usize, timeout_ptr: usize, sigmask_ptr: usize) i32 {
    return syscall_event.sys_pselect6(nfds, readfds, writefds, exceptfds, timeout_ptr, sigmask_ptr);
}

fn sys_faccessat(dirfd: i32, pathname: [*]const u8, mode: u32, flags: u32) i32 {
    return syscall_at.sys_faccessat(dirfd, pathname, mode, flags);
}

fn sys_statx(dirfd: i32, pathname: [*]const u8, flags: u32, mask: u32, statxbuf: usize) i32 {
    return syscall_at.sys_statx(dirfd, pathname, flags, mask, statxbuf);
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
    return syscall_fd.sys_copy_file_range(fd_in, off_in_ptr, fd_out, off_out_ptr, len);
}

fn sys_fadvise64(fd: i32, offset: i64, len: usize, advice: u32) i32 {
    return syscall_fd.sys_fadvise64(fd, offset, len, advice);
}

fn sys_readahead(fd: i32, offset: i64, count: usize) i32 {
    return syscall_fd.sys_readahead(fd, offset, count);
}

fn sys_sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) i32 {
    return syscall_fd.sys_sync_file_range(fd, offset, nbytes, flags);
}

fn sys_syncfs(fd: i32) i32 {
    return syscall_fd.sys_syncfs(fd);
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

fn sys_utimensat(dirfd: i32, pathname: [*]const u8, times_ptr: usize, flags: u32) i32 {
    return syscall_at.sys_utimensat(dirfd, pathname, times_ptr, flags);
}

fn sys_futimesat(dirfd: i32, pathname: [*]const u8, times_ptr: usize) i32 {
    return syscall_at.sys_futimesat(dirfd, pathname, times_ptr);
}

fn sys_fstatat(dirfd: i32, pathname: [*]const u8, statbuf: usize, flags: u32) i32 {
    return syscall_at.sys_fstatat(dirfd, pathname, statbuf, flags);
}

fn sys_symlinkat(target: [*]const u8, newdirfd: i32, linkpath: [*]const u8) i32 {
    return syscall_at.sys_symlinkat(target, newdirfd, linkpath);
}

fn sys_readlinkat(dirfd: i32, pathname: [*]const u8, buf: [*]u8, bufsiz: usize) i32 {
    return syscall_at.sys_readlinkat(dirfd, pathname, buf, bufsiz);
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
    const pid_idx: usize = proc.pid % 256;
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
    const pid_idx: usize = proc.pid % 256;

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

fn sys_inotify_init() i32 {
    return syscall_event.sys_inotify_init();
}

fn sys_inotify_init1(flags: u32) i32 {
    return syscall_event.sys_inotify_init1(flags);
}

fn sys_inotify_add_watch(fd: i32, pathname: [*]const u8, mask: u32) i32 {
    return syscall_event.sys_inotify_add_watch(fd, pathname, mask);
}

fn sys_inotify_rm_watch(fd: i32, wd: i32) i32 {
    return syscall_event.sys_inotify_rm_watch(fd, wd);
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
    const pid_idx: usize = proc.pid % 256;

    const rlim = process_rlimits[pid_idx][resource];
    protection.copyToUser(rlim_ptr, std.mem.asBytes(&rlim)) catch return EFAULT;
    return 0;
}

fn sys_setrlimit(resource: u32, rlim_ptr: usize) i32 {
    if (resource >= 10) return EINVAL;
    if (!protection.verifyUserPointer(rlim_ptr, @sizeOf(Rlimit))) return EFAULT;

    const proc = process.current_process orelse return ESRCH;
    const pid_idx: usize = proc.pid % 256;

    var rlim: Rlimit = undefined;
    protection.copyFromUser(std.mem.asBytes(&rlim), rlim_ptr) catch return EFAULT;

    process_rlimits[pid_idx][resource] = rlim;
    return 0;
}

fn sys_prlimit64(pid: i32, resource: u32, new_limit: usize, old_limit: usize) i32 {
    if (resource >= 10) return EINVAL;

    const pid_idx: usize = if (pid == 0) blk: {
        const proc = process.current_process orelse return ESRCH;
        break :blk proc.pid % 256;
    } else blk: {
        if (pid < 0) return EINVAL;
        break :blk @as(usize, @intCast(pid)) % 256;
    };

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
                fd1 = @intCast(@as(i32, @intCast(i)) + syscall_net.unix_socket_fd_base);
            } else {
                usock.in_use = true;
                usock.connected = true;
                fd2 = @intCast(@as(i32, @intCast(i)) + syscall_net.unix_socket_fd_base);

                const idx1: usize = @intCast(fd1 - syscall_net.unix_socket_fd_base);
                unix_sockets[idx1].peer = usock;
                usock.peer = &unix_sockets[idx1];
                break;
            }
        }
    }

    if (fd1 == -1 or fd2 == -1) {
        if (fd1 != -1) {
            const idx: usize = @intCast(fd1 - syscall_net.unix_socket_fd_base);
            unix_sockets[idx].in_use = false;
            unix_sockets[idx].connected = false;
        }
        return EMFILE;
    }

    _ = sock_type;
    const fds = [2]i32{ fd1, fd2 };
    protection.copyToUser(sv, std.mem.asBytes(&fds)) catch {
        const idx1: usize = @intCast(fd1 - syscall_net.unix_socket_fd_base);
        const idx2: usize = @intCast(fd2 - syscall_net.unix_socket_fd_base);
        unix_sockets[idx1].in_use = false;
        unix_sockets[idx1].connected = false;
        unix_sockets[idx1].peer = null;
        unix_sockets[idx2].in_use = false;
        unix_sockets[idx2].connected = false;
        unix_sockets[idx2].peer = null;
        return EFAULT;
    };
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
        .uptime = @intCast(ticks / timer.TICKS_PER_SECOND),
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
    return syscall_time.sys_clock_settime(clock_id, tp);
}

fn sys_clock_getres(clock_id: u32, res: usize) i32 {
    return syscall_time.sys_clock_getres(clock_id, res);
}

fn sys_clock_nanosleep(clock_id: u32, flags: u32, request: usize, remain: usize) i32 {
    return syscall_time.sys_clock_nanosleep(clock_id, flags, request, remain);
}

fn sys_timer_create(clock_id: u32, sevp: usize, timerid: usize) i32 {
    return syscall_time.sys_timer_create(clock_id, sevp, timerid);
}

fn sys_timer_delete(timerid: i32) i32 {
    return syscall_time.sys_timer_delete(timerid);
}

fn sys_timer_settime(timerid: i32, flags: u32, new_value: usize, old_value: usize) i32 {
    return syscall_time.sys_timer_settime(timerid, flags, new_value, old_value);
}

fn sys_timer_gettime(timerid: i32, curr_value: usize) i32 {
    return syscall_time.sys_timer_gettime(timerid, curr_value);
}

fn sys_timer_getoverrun(timerid: i32) i32 {
    return syscall_time.sys_timer_getoverrun(timerid);
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
