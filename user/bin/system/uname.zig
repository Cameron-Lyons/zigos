const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    var show_all = false;
    var show_sysname = false;
    var show_nodename = false;
    var show_release = false;
    var show_version = false;
    var show_machine = false;

    if (argc <= 1) {
        show_sysname = true;
    } else {
        var i: usize = 1;
        while (i < argc) : (i += 1) {
            const arg = argv[i] orelse continue;
            if (argEq(arg, "-a") or argEq(arg, "--all")) {
                show_all = true;
            } else if (argEq(arg, "-s") or argEq(arg, "--kernel-name")) {
                show_sysname = true;
            } else if (argEq(arg, "-n") or argEq(arg, "--nodename")) {
                show_nodename = true;
            } else if (argEq(arg, "-r") or argEq(arg, "--kernel-release")) {
                show_release = true;
            } else if (argEq(arg, "-v") or argEq(arg, "--kernel-version")) {
                show_version = true;
            } else if (argEq(arg, "-m") or argEq(arg, "--machine")) {
                show_machine = true;
            }
        }
    }

    var hostname_buf: [256]u8 = undefined;
    const hostname_len = syscall.gethostname(&hostname_buf);
    const hostname = if (!syscall.isError(hostname_len)) hostname_buf[0..@intCast(hostname_len)] else "unknown";

    var first = true;
    if (show_all or show_sysname) {
        stdio.puts("ZigOS");
        first = false;
    }
    if (show_all or show_nodename) {
        if (!first) stdio.puts(" ");
        stdio.puts(hostname);
        first = false;
    }
    if (show_all or show_release) {
        if (!first) stdio.puts(" ");
        stdio.puts("0.1.0");
        first = false;
    }
    if (show_all or show_version) {
        if (!first) stdio.puts(" ");
        stdio.puts("ZigOS 0.1.0");
        first = false;
    }
    if (show_all or show_machine) {
        if (!first) stdio.puts(" ");
        stdio.puts("i386");
        first = false;
    }
    if (first) {
        stdio.puts("ZigOS");
    }
    stdio.puts("\n");
    return 0;
}

fn argEq(value: [*:0]const u8, expected: []const u8) bool {
    const slice = cstr.slice(value);
    if (slice.len != expected.len) return false;

    var i: usize = 0;
    while (i < slice.len) : (i += 1) {
        if (slice[i] != expected[i]) return false;
    }
    return true;
}
