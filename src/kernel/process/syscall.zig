const idt = @import("../interrupts/idt.zig");
const signal = @import("signal.zig");
const socket = @import("../net/socket.zig");
const abi = @import("syscall/abi.zig");
const syscall_at = @import("syscall/at.zig");
const syscall_cwd = @import("syscall/cwd.zig");
const syscall_event = @import("syscall/event.zig");
const syscall_fd = @import("syscall/fd.zig");
const syscall_fs = @import("syscall/fs.zig");
const syscall_io = @import("syscall/io.zig");
const syscall_ipc = @import("syscall/ipc.zig");
const syscall_misc = @import("syscall/misc.zig");
const syscall_net = @import("syscall/net.zig");
const syscall_process = @import("syscall/process_ops.zig");
const syscall_process_state = @import("syscall/process_state.zig");
const syscall_readiness = @import("syscall/readiness.zig");
const syscall_resource = @import("syscall/resource.zig");
const runtime = @import("syscall/runtime.zig");
const syscall_signal = @import("syscall/signal.zig");
const support = @import("syscall/support.zig");
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
pub const SYS_GETPROCS = abi.SYS_GETPROCS;
pub const SYS_PING = abi.SYS_PING;
pub const SYS_SPAWN = abi.SYS_SPAWN;
pub const STDIN = abi.STDIN;
pub const STDOUT = abi.STDOUT;
pub const STDERR = abi.STDERR;
pub const FD_OFFSET = abi.FD_OFFSET;
pub const O_RDONLY: u32 = abi.O_RDONLY;
pub const O_WRONLY: u32 = abi.O_WRONLY;
pub const O_RDWR: u32 = abi.O_RDWR;
pub const O_CREAT: u32 = abi.O_CREAT;
pub const O_TRUNC: u32 = abi.O_TRUNC;
pub const DT_REG: u8 = abi.DT_REG;
pub const DT_DIR: u8 = abi.DT_DIR;
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
pub const AT_FDCWD: i32 = abi.AT_FDCWD;
pub const AT_REMOVEDIR: u32 = abi.AT_REMOVEDIR;
pub const ITIMER_REAL: u32 = abi.ITIMER_REAL;
pub const ITIMER_VIRTUAL: u32 = abi.ITIMER_VIRTUAL;
pub const ITIMER_PROF: u32 = abi.ITIMER_PROF;
pub const EPOLL_CTL_ADD: u32 = abi.EPOLL_CTL_ADD;
pub const EPOLL_CTL_DEL: u32 = abi.EPOLL_CTL_DEL;
pub const EPOLL_CTL_MOD: u32 = abi.EPOLL_CTL_MOD;
pub const EPOLLIN: u32 = abi.EPOLLIN;
pub const EPOLLOUT: u32 = abi.EPOLLOUT;
pub const EPOLLERR: u32 = abi.EPOLLERR;
pub const EPOLLHUP: u32 = abi.EPOLLHUP;
pub const EPOLLRDHUP: u32 = abi.EPOLLRDHUP;
pub const EPOLLET: u32 = abi.EPOLLET;
pub const TFD_CLOEXEC: u32 = abi.TFD_CLOEXEC;
pub const TFD_NONBLOCK: u32 = abi.TFD_NONBLOCK;
pub const IPC_CREAT: u32 = abi.IPC_CREAT;
pub const IPC_EXCL: u32 = abi.IPC_EXCL;
pub const IPC_NOWAIT: u32 = abi.IPC_NOWAIT;
pub const IPC_RMID: u32 = abi.IPC_RMID;
pub const IPC_SET: u32 = abi.IPC_SET;
pub const IPC_STAT: u32 = abi.IPC_STAT;
pub const SHM_RDONLY: u32 = abi.SHM_RDONLY;
pub const SHM_RND: u32 = abi.SHM_RND;
pub const GETVAL: u32 = abi.GETVAL;
pub const SETVAL: u32 = abi.SETVAL;
pub const GETALL: u32 = abi.GETALL;
pub const SETALL: u32 = abi.SETALL;
pub const F_GETLK: u32 = abi.F_GETLK;
pub const F_SETLK: u32 = abi.F_SETLK;
pub const F_SETLKW: u32 = abi.F_SETLKW;
pub const F_RDLCK: i16 = abi.F_RDLCK;
pub const F_WRLCK: i16 = abi.F_WRLCK;
pub const F_UNLCK: i16 = abi.F_UNLCK;
pub const S_IFMT: u32 = abi.S_IFMT;
pub const S_IFREG: u32 = abi.S_IFREG;
pub const S_IFDIR: u32 = abi.S_IFDIR;
pub const S_IFCHR: u32 = abi.S_IFCHR;
pub const S_IFBLK: u32 = abi.S_IFBLK;
pub const S_IFIFO: u32 = abi.S_IFIFO;
pub const S_IFLNK: u32 = abi.S_IFLNK;
pub const S_IFSOCK: u32 = abi.S_IFSOCK;
pub const RUSAGE_SELF: i32 = abi.RUSAGE_SELF;
pub const RUSAGE_CHILDREN: i32 = abi.RUSAGE_CHILDREN;
pub const EIDRM = abi.EIDRM;
pub const ENOMSG = abi.ENOMSG;
pub const EDEADLK = abi.EDEADLK;
pub const ENOLCK = abi.ENOLCK;
pub const O_CLOEXEC: u32 = abi.O_CLOEXEC;
pub const GRND_NONBLOCK: u32 = abi.GRND_NONBLOCK;
pub const GRND_RANDOM: u32 = abi.GRND_RANDOM;
pub const EFD_SEMAPHORE: u32 = abi.EFD_SEMAPHORE;
pub const EFD_CLOEXEC: u32 = abi.EFD_CLOEXEC;
pub const EFD_NONBLOCK: u32 = abi.EFD_NONBLOCK;
pub const SOCK_CLOEXEC: u32 = abi.SOCK_CLOEXEC;
pub const SOCK_NONBLOCK: u32 = abi.SOCK_NONBLOCK;
pub const PR_SET_NAME: u32 = abi.PR_SET_NAME;
pub const PR_GET_NAME: u32 = abi.PR_GET_NAME;
pub const PR_SET_DUMPABLE: u32 = abi.PR_SET_DUMPABLE;
pub const PR_GET_DUMPABLE: u32 = abi.PR_GET_DUMPABLE;
pub const PR_SET_KEEPCAPS: u32 = abi.PR_SET_KEEPCAPS;
pub const PR_GET_KEEPCAPS: u32 = abi.PR_GET_KEEPCAPS;
pub const PR_SET_PDEATHSIG: u32 = abi.PR_SET_PDEATHSIG;
pub const PR_GET_PDEATHSIG: u32 = abi.PR_GET_PDEATHSIG;
pub const SFD_CLOEXEC: u32 = abi.SFD_CLOEXEC;
pub const SFD_NONBLOCK: u32 = abi.SFD_NONBLOCK;
pub const AT_EACCESS: u32 = abi.AT_EACCESS;
pub const AT_SYMLINK_NOFOLLOW: u32 = abi.AT_SYMLINK_NOFOLLOW;
pub const STATX_TYPE: u32 = abi.STATX_TYPE;
pub const STATX_MODE: u32 = abi.STATX_MODE;
pub const STATX_NLINK: u32 = abi.STATX_NLINK;
pub const STATX_UID: u32 = abi.STATX_UID;
pub const STATX_GID: u32 = abi.STATX_GID;
pub const STATX_ATIME: u32 = abi.STATX_ATIME;
pub const STATX_MTIME: u32 = abi.STATX_MTIME;
pub const STATX_CTIME: u32 = abi.STATX_CTIME;
pub const STATX_INO: u32 = abi.STATX_INO;
pub const STATX_SIZE: u32 = abi.STATX_SIZE;
pub const STATX_BLOCKS: u32 = abi.STATX_BLOCKS;
pub const STATX_BASIC_STATS: u32 = abi.STATX_BASIC_STATS;
pub const MEMBARRIER_CMD_QUERY: u32 = abi.MEMBARRIER_CMD_QUERY;
pub const MEMBARRIER_CMD_GLOBAL: u32 = abi.MEMBARRIER_CMD_GLOBAL;
pub const MEMBARRIER_CMD_GLOBAL_EXPEDITED: u32 = abi.MEMBARRIER_CMD_GLOBAL_EXPEDITED;
pub const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: u32 = abi.MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED;
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u32 = abi.MEMBARRIER_CMD_PRIVATE_EXPEDITED;
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u32 = abi.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
pub const POSIX_FADV_NORMAL: u32 = abi.POSIX_FADV_NORMAL;
pub const POSIX_FADV_RANDOM: u32 = abi.POSIX_FADV_RANDOM;
pub const POSIX_FADV_SEQUENTIAL: u32 = abi.POSIX_FADV_SEQUENTIAL;
pub const POSIX_FADV_WILLNEED: u32 = abi.POSIX_FADV_WILLNEED;
pub const POSIX_FADV_DONTNEED: u32 = abi.POSIX_FADV_DONTNEED;
pub const POSIX_FADV_NOREUSE: u32 = abi.POSIX_FADV_NOREUSE;
pub const SYNC_FILE_RANGE_WAIT_BEFORE: u32 = abi.SYNC_FILE_RANGE_WAIT_BEFORE;
pub const SYNC_FILE_RANGE_WRITE: u32 = abi.SYNC_FILE_RANGE_WRITE;
pub const SYNC_FILE_RANGE_WAIT_AFTER: u32 = abi.SYNC_FILE_RANGE_WAIT_AFTER;
pub const PRIO_PROCESS: u32 = abi.PRIO_PROCESS;
pub const PRIO_PGRP: u32 = abi.PRIO_PGRP;
pub const PRIO_USER: u32 = abi.PRIO_USER;
pub const UTIME_NOW: i32 = abi.UTIME_NOW;
pub const UTIME_OMIT: i32 = abi.UTIME_OMIT;
pub const P_ALL: u32 = abi.P_ALL;
pub const P_PID: u32 = abi.P_PID;
pub const P_PGID: u32 = abi.P_PGID;
pub const WEXITED: u32 = abi.WEXITED;
pub const WSTOPPED: u32 = abi.WSTOPPED;
pub const WCONTINUED: u32 = abi.WCONTINUED;
pub const WNOWAIT: u32 = abi.WNOWAIT;
pub const ECHILD = abi.ECHILD;
pub const IN_ACCESS: u32 = abi.IN_ACCESS;
pub const IN_MODIFY: u32 = abi.IN_MODIFY;
pub const IN_ATTRIB: u32 = abi.IN_ATTRIB;
pub const IN_CLOSE_WRITE: u32 = abi.IN_CLOSE_WRITE;
pub const IN_CLOSE_NOWRITE: u32 = abi.IN_CLOSE_NOWRITE;
pub const IN_OPEN: u32 = abi.IN_OPEN;
pub const IN_MOVED_FROM: u32 = abi.IN_MOVED_FROM;
pub const IN_MOVED_TO: u32 = abi.IN_MOVED_TO;
pub const IN_CREATE: u32 = abi.IN_CREATE;
pub const IN_DELETE: u32 = abi.IN_DELETE;
pub const IN_DELETE_SELF: u32 = abi.IN_DELETE_SELF;
pub const IN_MOVE_SELF: u32 = abi.IN_MOVE_SELF;
pub const IN_NONBLOCK: u32 = abi.IN_NONBLOCK;
pub const IN_CLOEXEC: u32 = abi.IN_CLOEXEC;
pub const MCL_CURRENT: u32 = abi.MCL_CURRENT;
pub const MCL_FUTURE: u32 = abi.MCL_FUTURE;
pub const MADV_NORMAL: u32 = abi.MADV_NORMAL;
pub const MADV_RANDOM: u32 = abi.MADV_RANDOM;
pub const MADV_SEQUENTIAL: u32 = abi.MADV_SEQUENTIAL;
pub const MADV_WILLNEED: u32 = abi.MADV_WILLNEED;
pub const MADV_DONTNEED: u32 = abi.MADV_DONTNEED;
pub const RLIMIT_CPU: u32 = abi.RLIMIT_CPU;
pub const RLIMIT_FSIZE: u32 = abi.RLIMIT_FSIZE;
pub const RLIMIT_DATA: u32 = abi.RLIMIT_DATA;
pub const RLIMIT_STACK: u32 = abi.RLIMIT_STACK;
pub const RLIMIT_CORE: u32 = abi.RLIMIT_CORE;
pub const RLIMIT_RSS: u32 = abi.RLIMIT_RSS;
pub const RLIMIT_NPROC: u32 = abi.RLIMIT_NPROC;
pub const RLIMIT_NOFILE: u32 = abi.RLIMIT_NOFILE;
pub const RLIMIT_MEMLOCK: u32 = abi.RLIMIT_MEMLOCK;
pub const RLIMIT_AS: u32 = abi.RLIMIT_AS;
pub const RLIM_INFINITY: u64 = abi.RLIM_INFINITY;
pub const PROT_NONE: u32 = abi.PROT_NONE;
pub const PROT_READ: u32 = abi.PROT_READ;
pub const PROT_WRITE: u32 = abi.PROT_WRITE;
pub const PROT_EXEC: u32 = abi.PROT_EXEC;
pub const MAP_SHARED: u32 = abi.MAP_SHARED;
pub const MAP_PRIVATE: u32 = abi.MAP_PRIVATE;
pub const MAP_FIXED: u32 = abi.MAP_FIXED;
pub const MAP_ANONYMOUS: u32 = abi.MAP_ANONYMOUS;
pub const TCGETS: u32 = abi.TCGETS;
pub const TCSETS: u32 = abi.TCSETS;
pub const TCSETSW: u32 = abi.TCSETSW;
pub const TCSETSF: u32 = abi.TCSETSF;
pub const TIOCGWINSZ: u32 = abi.TIOCGWINSZ;
pub const TTY_LFLAG_ISIG: u32 = abi.TTY_LFLAG_ISIG;
pub const TTY_LFLAG_ICANON: u32 = abi.TTY_LFLAG_ICANON;
pub const TTY_LFLAG_ECHO: u32 = abi.TTY_LFLAG_ECHO;
pub const SIGINT = abi.SIGINT;
pub const SIGKILL = abi.SIGKILL;
pub const SIGTERM = abi.SIGTERM;
pub const SIGCONT = abi.SIGCONT;
pub const SIGSTOP = abi.SIGSTOP;
pub const SIGTSTP = abi.SIGTSTP;
pub const CLOCK_REALTIME: u32 = abi.CLOCK_REALTIME;
pub const CLOCK_MONOTONIC: u32 = abi.CLOCK_MONOTONIC;
pub const CLOCK_MONOTONIC_RAW: u32 = abi.CLOCK_MONOTONIC_RAW;
pub const CLOCK_REALTIME_COARSE: u32 = abi.CLOCK_REALTIME_COARSE;
pub const CLOCK_MONOTONIC_COARSE: u32 = abi.CLOCK_MONOTONIC_COARSE;
pub const CLOCK_BOOTTIME: u32 = abi.CLOCK_BOOTTIME;
pub const TIMER_ABSTIME: u32 = abi.TIMER_ABSTIME;
pub const MNT_FORCE: u32 = abi.MNT_FORCE;
pub const MNT_DETACH: u32 = abi.MNT_DETACH;
pub const MNT_EXPIRE: u32 = abi.MNT_EXPIRE;
pub const UMOUNT_NOFOLLOW: u32 = abi.UMOUNT_NOFOLLOW;
pub const LINUX_REBOOT_MAGIC1: u32 = abi.LINUX_REBOOT_MAGIC1;
pub const LINUX_REBOOT_MAGIC2: u32 = abi.LINUX_REBOOT_MAGIC2;
pub const LINUX_REBOOT_CMD_RESTART: u32 = abi.LINUX_REBOOT_CMD_RESTART;
pub const LINUX_REBOOT_CMD_HALT: u32 = abi.LINUX_REBOOT_CMD_HALT;
pub const LINUX_REBOOT_CMD_POWER_OFF: u32 = abi.LINUX_REBOOT_CMD_POWER_OFF;

const rawArgI32 = support.rawArgI32;
const rawResultU32 = support.rawResultU32;

pub const syscall0 = runtime.syscall0;
pub const syscall1 = runtime.syscall1;
pub const syscall2 = runtime.syscall2;
pub const syscall3 = runtime.syscall3;
pub const syscall4 = runtime.syscall4;
pub const syscall5 = runtime.syscall5;
pub const syscall6 = runtime.syscall6;

// Keep thin wrappers local so the syscall dispatch surface stays unchanged.
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

fn sys_lseek(fd: i32, offset: i64, whence: u32) i32 {
    return syscall_fd.sys_lseek(fd, offset, whence);
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

fn sys_spawn(path: [*]const u8, argv: usize, envp: usize) i32 {
    return syscall_process.sys_spawn(path, argv, envp);
}

fn sys_wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) i32 {
    return syscall_process.sys_wait4(pid, status, options, rusage);
}

fn sys_brk(addr: usize) i32 {
    return syscall_process.sys_brk(addr);
}

fn sys_nanosleep(req_addr: usize, rem_addr: usize) i32 {
    return syscall_time.sys_nanosleep(req_addr, rem_addr);
}

fn sys_clock_gettime(clock_id: i32, tp_addr: usize) i32 {
    return syscall_time.sys_clock_gettime(clock_id, tp_addr);
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

fn sys_fsync(fd: i32) i32 {
    return syscall_fd.sys_fsync(fd);
}

fn sys_poll(fds_addr: usize, nfds: u32, timeout: i32) i32 {
    return syscall_event.sys_poll(fds_addr, nfds, timeout);
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

fn sys_getitimer(which: u32, value_addr: usize) i32 {
    return syscall_time.sys_getitimer(which, value_addr);
}

fn sys_setitimer(which: u32, new_value_addr: usize, old_value_addr: usize) i32 {
    return syscall_time.sys_setitimer(which, new_value_addr, old_value_addr);
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

fn sys_times(buf_addr: usize) i32 {
    return syscall_time.sys_times(buf_addr);
}

fn sys_getrusage(who: i32, usage_addr: usize) i32 {
    return syscall_time.sys_getrusage(who, usage_addr);
}

fn sys_pipe2(pipefd: ?*[2]i32, flags: u32) i32 {
    return syscall_fd.sys_pipe2(pipefd, flags);
}

fn sys_dup3(old_fd: i32, new_fd: i32, flags: u32) i32 {
    return syscall_fd.sys_dup3(old_fd, new_fd, flags);
}

fn sys_eventfd(initval: u32) i32 {
    return syscall_event.sys_eventfd(initval);
}

fn sys_eventfd2(initval: u32, flags: u32) i32 {
    return syscall_event.sys_eventfd2(initval, flags);
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
        SYS_SPAWN => sys_spawn(@as([*]const u8, @ptrFromInt(arg1)), arg2, arg3),
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
        SYS_OPENAT => sys_openat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_MKDIRAT => sys_mkdirat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_UNLINKAT => sys_unlinkat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_LINKAT => sys_linkat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), rawArgI32(arg3), @as([*]const u8, @ptrFromInt(arg4)), @intCast(arg5)),
        SYS_FCHMODAT => sys_fchmodat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3)),
        SYS_FCHOWNAT => sys_fchownat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), rawArgI32(arg3), rawArgI32(arg4)),
        SYS_RENAMEAT => sys_renameat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), rawArgI32(arg3), @as([*]const u8, @ptrFromInt(arg4))),
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
        SYS_SIGNALFD => sys_signalfd(rawArgI32(arg1), arg2, @intCast(arg3)),
        SYS_SIGNALFD4 => sys_signalfd4(rawArgI32(arg1), arg2, @intCast(arg3), @intCast(arg4)),
        SYS_PPOLL => sys_ppoll(arg1, @intCast(arg2), arg3, arg4),
        SYS_PSELECT6 => sys_pselect6(@intCast(arg1), arg2, arg3, arg4, arg5, @as(usize, @bitCast(@as(i32, @intCast(regs.ebp))))),
        SYS_FACCESSAT => sys_faccessat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), 0),
        SYS_FACCESSAT2 => sys_faccessat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), @intCast(arg4)),
        SYS_STATX => sys_statx(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @intCast(arg3), @intCast(arg4), arg5),
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
        SYS_UTIMENSAT => sys_utimensat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, @intCast(arg4)),
        SYS_FUTIMESAT => sys_futimesat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3),
        SYS_FSTATAT => sys_fstatat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), arg3, @intCast(arg4)),
        SYS_SYMLINKAT => sys_symlinkat(@as([*]const u8, @ptrFromInt(arg1)), rawArgI32(arg2), @as([*]const u8, @ptrFromInt(arg3))),
        SYS_READLINKAT => sys_readlinkat(rawArgI32(arg1), @as([*]const u8, @ptrFromInt(arg2)), @as([*]u8, @ptrFromInt(arg3)), arg4),
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
        SYS_GETPROCS => sys_getprocs(arg1, arg2),
        SYS_PING => sys_ping(@intCast(arg1)),
        else => ENOSYS,
    };

    regs.eax = rawResultU32(result);

    signal.handlePendingSignals();
}

fn sys_exit(status: i32) i32 {
    return syscall_process.sys_exit(status);
}

fn sys_write(fd: i32, buf: [*]const u8, count: usize) i32 {
    return syscall_io.sys_write(fd, buf, count);
}

fn sys_read(fd: i32, buf: [*]u8, count: usize) i32 {
    return syscall_io.sys_read(fd, buf, count);
}

fn sys_close(fd: i32) i32 {
    return syscall_fd.sys_close(&unix_sockets, &socket_table, fd);
}

fn sys_stat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    return syscall_io.sys_stat(pathname, stat_buf_addr);
}

pub fn init() void {
    syscall_readiness.init();
    syscall_system.init();
    syscall_net.attachTables(&unix_sockets, &socket_table);
    syscall_event.init();
    idt.register_interrupt_handler(0x80, syscall_handler);

    idt.set_gate_flags(0x80, 0x8E | 0x60);
}

fn sys_getuid() i32 {
    return syscall_misc.sys_getuid();
}

fn sys_getgid() i32 {
    return syscall_misc.sys_getgid();
}

fn sys_setuid(uid: u16) i32 {
    return syscall_misc.sys_setuid(uid);
}

fn sys_setgid(gid: u16) i32 {
    return syscall_misc.sys_setgid(gid);
}

fn sys_chown(pathname: [*]const u8, uid: u16, gid: u16) i32 {
    return syscall_misc.sys_chown(pathname, uid, gid);
}

const UnixSocket = syscall_net.UnixSocket;

var unix_sockets: [64]UnixSocket = [_]UnixSocket{.{
    .path = [_]u8{0} ** 108,
    .path_len = 0,
    .peer = null,
    .recv_buffer = [_]u8{0} ** syscall_net.UNIX_SOCKET_BUFFER_SIZE,
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

fn sys_fstat(fd: i32, stat_buf_addr: usize) i32 {
    return syscall_io.sys_fstat(fd, stat_buf_addr);
}

fn sys_mmap(addr: usize, length: usize, prot: i32, flags: i32, fd: i32, offset: i32) i32 {
    return syscall_process.sys_mmap(addr, length, prot, flags, fd, offset);
}

fn sys_msgget(max_messages: u32) i32 {
    return syscall_process.sys_msgget(max_messages);
}

fn sys_msgsnd(receiver_pid: u32, buf: [*]const u8, len: usize) i32 {
    return syscall_process.sys_msgsnd(receiver_pid, buf, len);
}

fn sys_msgrcv(buf: [*]u8, size: usize, flags: i32) i32 {
    return syscall_process.sys_msgrcv(buf, size, flags);
}

fn sys_munmap(addr: usize, length: usize) i32 {
    return syscall_process.sys_munmap(addr, length);
}

fn sys_ioctl(fd: i32, request: u32, arg: usize) i32 {
    return syscall_io.sys_ioctl(fd, request, arg);
}

fn sys_getppid_syscall() i32 {
    return syscall_process.sys_getppid();
}

fn sys_getpgid(pid: i32) i32 {
    return syscall_process.sys_getpgid(pid);
}

fn sys_setpgid(pid: i32, pgid: i32) i32 {
    return syscall_process.sys_setpgid(pid, pgid);
}

fn sys_setsid() i32 {
    return syscall_process.sys_setsid();
}

fn sys_access(pathname: [*]const u8, mode: u32) i32 {
    return syscall_misc.sys_access(pathname, mode);
}

fn sys_chmod_syscall(pathname: [*]const u8, mode: u32) i32 {
    return syscall_misc.sys_chmod(pathname, mode);
}

fn sys_fchmod(fd: i32, mode: u32) i32 {
    return syscall_misc.sys_fchmod(fd, mode);
}

fn sys_ftruncate(fd: i32, length: usize) i32 {
    return syscall_misc.sys_ftruncate(fd, length);
}

fn sys_getdents(fd: i32, buf_addr: usize, buf_size: usize) i32 {
    return syscall_io.sys_getdents(fd, buf_addr, buf_size);
}

fn sys_symlink(target: [*]const u8, linkpath: [*]const u8) i32 {
    return syscall_misc.sys_symlink(target, linkpath);
}

fn sys_link(oldpath: [*]const u8, newpath: [*]const u8) i32 {
    return syscall_misc.sys_link(oldpath, newpath);
}

fn sys_readlink(pathname: [*]const u8, buf: [*]u8, buf_size: usize) i32 {
    return syscall_misc.sys_readlink(pathname, buf, buf_size);
}

fn sys_umask(mask: u16) i32 {
    return syscall_misc.sys_umask(mask);
}

fn sys_truncate(pathname: [*]const u8, length: usize) i32 {
    return syscall_misc.sys_truncate(pathname, length);
}

fn sys_pread(fd: i32, buf: [*]u8, count: usize, offset: u64) i32 {
    return syscall_io.sys_pread(fd, buf, count, offset);
}

fn sys_pwrite(fd: i32, buf: [*]const u8, count: usize, offset: u64) i32 {
    return syscall_io.sys_pwrite(fd, buf, count, offset);
}

fn sys_sendto(sockfd: i32, buf: [*]const u8, len: usize, dest_addr: usize, addr_len: u32) i32 {
    return syscall_net.sys_sendto(sockfd, buf, len, dest_addr, addr_len);
}

fn sys_recvfrom(sockfd: i32, buf: [*]u8, len: usize, src_addr: usize, addr_len_ptr: usize) i32 {
    return syscall_net.sys_recvfrom(sockfd, buf, len, src_addr, addr_len_ptr);
}

fn sys_getsockname(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    return syscall_net.sys_getsockname(sockfd, addr_ptr, addr_len_ptr);
}

fn sys_getpeername(sockfd: i32, addr_ptr: usize, addr_len_ptr: usize) i32 {
    return syscall_net.sys_getpeername(sockfd, addr_ptr, addr_len_ptr);
}

fn sys_fchown(fd: i32, uid: u16, gid: u16) i32 {
    return syscall_misc.sys_fchown(fd, uid, gid);
}

fn sys_lstat(pathname: [*]const u8, stat_buf_addr: usize) i32 {
    return syscall_misc.sys_lstat(pathname, stat_buf_addr);
}

fn sys_getsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen_addr: usize) i32 {
    return syscall_net.sys_getsockopt(sockfd, level, optname, optval_addr, optlen_addr);
}

fn sys_setsockopt(sockfd: i32, level: i32, optname: i32, optval_addr: usize, optlen: u32) i32 {
    return syscall_net.sys_setsockopt(sockfd, level, optname, optval_addr, optlen);
}

fn sys_readv(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    return syscall_io.sys_readv(fd, iov_addr, iovcnt);
}

fn sys_writev(fd: i32, iov_addr: usize, iovcnt: i32) i32 {
    return syscall_io.sys_writev(fd, iov_addr, iovcnt);
}

fn sys_geteuid() i32 {
    return syscall_misc.sys_geteuid();
}

fn sys_getegid() i32 {
    return syscall_misc.sys_getegid();
}

fn sys_isatty(fd: i32) i32 {
    return syscall_io.sys_isatty(fd);
}

fn sys_statfs(pathname: [*]const u8, buf_addr: usize) i32 {
    return syscall_io.sys_statfs(pathname, buf_addr);
}

fn sys_fstatfs(fd: i32, buf_addr: usize) i32 {
    return syscall_io.sys_fstatfs(fd, buf_addr);
}

fn sys_getgroups(size: i32, list_addr: usize) i32 {
    return syscall_process_state.sys_getgroups(size, list_addr);
}

fn sys_setgroups(size: i32, list_addr: usize) i32 {
    return syscall_process_state.sys_setgroups(size, list_addr);
}

fn sys_mkfifo(pathname: [*]const u8, mode: u32) i32 {
    return syscall_misc.sys_mkfifo(pathname, mode);
}

fn sys_shmget(key: i32, size: usize, shmflg: u32) i32 {
    return syscall_ipc.sys_shmget(key, size, shmflg);
}

fn sys_shmat(shmid: i32, shmaddr: usize, shmflg: u32) i32 {
    return syscall_ipc.sys_shmat(shmid, shmaddr, shmflg);
}

fn sys_shmdt(addr: usize) i32 {
    return syscall_ipc.sys_shmdt(addr);
}

fn sys_shmctl(shmid: i32, cmd: u32, buf_addr: usize) i32 {
    return syscall_ipc.sys_shmctl(shmid, cmd, buf_addr);
}

fn sys_semget(key: i32, nsems: u32, semflg: u32) i32 {
    return syscall_ipc.sys_semget(key, nsems, semflg);
}

fn sys_semop(semid: i32, sops_addr: usize, nsops: u32) i32 {
    return syscall_ipc.sys_semop(semid, sops_addr, nsops);
}

fn sys_semctl(semid: i32, semnum: u32, cmd: u32, arg: usize) i32 {
    return syscall_ipc.sys_semctl(semid, semnum, cmd, arg);
}

fn sys_mknod(pathname: [*]const u8, mode: u32, dev: u32) i32 {
    return syscall_misc.sys_mknod(pathname, mode, dev);
}

fn sys_getrandom(buf: [*]u8, buflen: usize, flags: u32) i32 {
    return syscall_misc.sys_getrandom(buf, buflen, flags);
}

fn sys_accept4(sockfd: i32, addr: usize, addrlen: usize, flags: u32) i32 {
    return syscall_net.sys_accept4(&unix_sockets, &socket_table, sockfd, addr, addrlen, flags);
}

fn sys_prctl(option: u32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
    return syscall_process_state.sys_prctl(option, arg2, arg3, arg4, arg5);
}

fn sys_membarrier(cmd: u32, flags: u32) i32 {
    return syscall_resource.sys_membarrier(cmd, flags);
}

fn sys_getpriority(which: u32, who: i32) i32 {
    return syscall_process_state.sys_getpriority(which, who);
}

fn sys_setpriority(which: u32, who: i32, prio: i32) i32 {
    return syscall_process_state.sys_setpriority(which, who, prio);
}

fn sys_sched_getaffinity(pid: i32, cpusetsize: usize, mask_ptr: usize) i32 {
    return syscall_process_state.sys_sched_getaffinity(pid, cpusetsize, mask_ptr);
}

fn sys_sched_setaffinity(pid: i32, cpusetsize: usize, mask_ptr: usize) i32 {
    return syscall_process_state.sys_sched_setaffinity(pid, cpusetsize, mask_ptr);
}

fn sys_waitid(idtype: u32, id: i32, infop: usize, options: u32) i32 {
    return syscall_process_state.sys_waitid(idtype, id, infop, options);
}

fn sys_set_tid_address(tidptr: usize) i32 {
    return syscall_process_state.sys_set_tid_address(tidptr);
}

fn sys_get_robust_list(pid: i32, head_ptr: usize, len_ptr: usize) i32 {
    return syscall_process_state.sys_get_robust_list(pid, head_ptr, len_ptr);
}

fn sys_set_robust_list(head: usize, len: usize) i32 {
    return syscall_process_state.sys_set_robust_list(head, len);
}

fn sys_tgkill(tgid: i32, tid: i32, sig: i32) i32 {
    return syscall_process_state.sys_tgkill(tgid, tid, sig);
}

fn sys_tkill(tid: i32, sig: i32) i32 {
    return syscall_process_state.sys_tkill(tid, sig);
}

fn sys_mlock(addr: usize, len: usize) i32 {
    return syscall_resource.sys_mlock(addr, len);
}

fn sys_munlock(addr: usize, len: usize) i32 {
    return syscall_resource.sys_munlock(addr, len);
}

fn sys_mlockall(flags: u32) i32 {
    return syscall_resource.sys_mlockall(flags);
}

fn sys_munlockall() i32 {
    return syscall_resource.sys_munlockall();
}

fn sys_madvise(addr: usize, length: usize, advice: u32) i32 {
    return syscall_resource.sys_madvise(addr, length, advice);
}

fn sys_mincore(addr: usize, length: usize, vec: usize) i32 {
    return syscall_resource.sys_mincore(addr, length, vec);
}

fn sys_getrlimit(resource: u32, rlim_ptr: usize) i32 {
    return syscall_resource.sys_getrlimit(resource, rlim_ptr);
}

fn sys_setrlimit(resource: u32, rlim_ptr: usize) i32 {
    return syscall_resource.sys_setrlimit(resource, rlim_ptr);
}

fn sys_prlimit64(pid: i32, resource: u32, new_limit: usize, old_limit: usize) i32 {
    return syscall_resource.sys_prlimit64(pid, resource, new_limit, old_limit);
}

fn sys_mprotect(addr: usize, len: usize, prot: u32) i32 {
    return syscall_resource.sys_mprotect(addr, len, prot);
}

fn sys_socketpair(domain: i32, sock_type: i32, protocol: i32, sv: usize) i32 {
    return syscall_net.sys_socketpair(&unix_sockets, domain, sock_type, protocol, sv);
}

fn sys_sysinfo(info_ptr: usize) i32 {
    return syscall_misc.sys_sysinfo(info_ptr);
}

fn sys_getprocs(buffer_ptr: usize, capacity: usize) i32 {
    return syscall_misc.sys_getprocs(buffer_ptr, capacity);
}

fn sys_ping(ipv4_addr: u32) i32 {
    return syscall_misc.sys_ping(ipv4_addr);
}

fn sys_chroot(path: [*]const u8) i32 {
    return syscall_system.sys_chroot(path);
}

fn sys_mount(source: usize, target: usize, fstype: usize, mountflags: usize, data: usize) i32 {
    return syscall_system.sys_mount(source, target, fstype, mountflags, data);
}

fn sys_umount2(target: [*]const u8, flags: u32) i32 {
    return syscall_system.sys_umount2(target, flags);
}

fn sys_swapon(path: [*]const u8, swapflags: u32) i32 {
    return syscall_system.sys_swapon(path, swapflags);
}

fn sys_swapoff(path: [*]const u8) i32 {
    return syscall_system.sys_swapoff(path);
}

fn sys_reboot(magic1: u32, magic2: u32, cmd: u32, arg: usize) i32 {
    return syscall_system.sys_reboot(magic1, magic2, cmd, arg);
}
