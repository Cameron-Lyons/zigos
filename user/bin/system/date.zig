const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    var ts = syscall.TimeSpec{ .tv_sec = 0, .tv_nsec = 0 };
    if (syscall.clock_gettime(syscall.CLOCK_REALTIME, &ts) != 0) {
        stdio.eputs("date: failed to read clock\n");
        return 1;
    }

    const total_secs: u32 = @intCast(ts.tv_sec);
    const hours = total_secs / 3600;
    const mins = (total_secs % 3600) / 60;
    const secs = total_secs % 60;
    stdio.print("{d:0>2}:{d:0>2}:{d:0>2}\n", .{ hours, mins, secs });
    return 0;
}
