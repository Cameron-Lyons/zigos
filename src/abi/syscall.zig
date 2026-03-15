pub const SYS_EXIT = 1;
pub const SYS_WRITE = 2;
pub const SYS_READ = 3;
pub const SYS_OPEN = 4;
pub const SYS_CLOSE = 5;
pub const SYS_GETPID = 6;
pub const SYS_FORK = 8;
pub const SYS_EXECVE = 9;
pub const SYS_WAIT4 = 10;
pub const SYS_BRK = 11;
pub const SYS_MMAP = 12;
pub const SYS_MKDIR = 13;
pub const SYS_UNLINK = 15;
pub const SYS_RENAME = 16;
pub const SYS_GETUID = 20;
pub const SYS_GETGID = 21;
pub const SYS_KILL = 35;
pub const SYS_GETCWD = 37;
pub const SYS_CHDIR = 38;
pub const SYS_MUNMAP = 42;
pub const SYS_IOCTL = 43;
pub const SYS_NANOSLEEP = 48;
pub const SYS_CLOCK_GETTIME = 49;
pub const SYS_GETDENTS = 54;
pub const SYS_GETEUID = 82;
pub const SYS_GETEGID = 83;
pub const SYS_ISATTY = 84;
pub const SYS_GETHOSTNAME = 87;
pub const SYS_SETHOSTNAME = 88;
pub const SYS_MPROTECT = 165;
pub const SYS_GETPROCS = 182;
pub const SYS_PING = 183;

pub const STDIN = 0;
pub const STDOUT = 1;
pub const STDERR = 2;

pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_CREAT: u32 = 0x0040;
pub const O_TRUNC: u32 = 0x0200;

pub const DT_REG: u8 = 1;
pub const DT_DIR: u8 = 2;

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

pub const CLOCK_REALTIME = 0;
pub const CLOCK_MONOTONIC = 1;

pub const ProcInfo = extern struct {
    pid: u32,
    parent_pid: u32,
    state: u8,
    _padding: [3]u8,
    name: [64]u8,
};
