const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        stdio.eputs("Usage: sleep <seconds>\n");
        return 1;
    }

    const arg = argv[1] orelse return 1;
    const seconds = parseSeconds(cstr.slice(arg)) orelse {
        stdio.eputs("sleep: invalid duration\n");
        return 1;
    };

    const req = syscall.TimeSpec{
        .tv_sec = @intCast(seconds),
        .tv_nsec = 0,
    };
    if (syscall.nanosleep(&req, null) < 0) {
        stdio.eputs("sleep: nanosleep failed\n");
        return 1;
    }

    return 0;
}

fn parseSeconds(text: []const u8) ?u32 {
    if (text.len == 0) return null;

    var value: u32 = 0;
    for (text) |char| {
        if (char < '0' or char > '9') return null;
        value = value * 10 + (char - '0');
    }
    return value;
}
