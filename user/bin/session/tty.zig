const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    if (syscall.isatty(syscall.STDIN) != 1) {
        stdio.puts("not a tty\n");
        return 1;
    }

    var winsize = syscall.WinSize{
        .ws_row = 0,
        .ws_col = 0,
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };
    if (syscall.ioctl(syscall.STDOUT, syscall.TIOCGWINSZ, @intFromPtr(&winsize)) != 0) {
        stdio.eputs("tty: failed to query terminal size\n");
        return 1;
    }

    stdio.puts("/dev/tty\n");
    return 0;
}
