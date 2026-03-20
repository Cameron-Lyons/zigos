const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const max_processes = 128;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    var processes: [max_processes]syscall.ProcInfo = undefined;
    const rc = syscall.getprocs(&processes);
    if (syscall.isError(rc)) {
        stdio.eputs("ps: failed to query processes\n");
        return 1;
    }

    stdio.puts("PID  PPID STATE      NAME\n");
    stdio.puts("---  ---- ---------- ----\n");

    const count: usize = @intCast(rc);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const proc = processes[i];
        stdio.print("{d} {d} {s} {s}\n", .{ proc.pid, proc.parent_pid, stateName(proc.state), procName(&proc.name) });
    }

    return 0;
}

fn procName(name: *const [64]u8) []const u8 {
    var len: usize = 0;
    while (len < name.len and name[len] != 0) : (len += 1) {}
    return name[0..len];
}

fn stateName(state: u8) []const u8 {
    return switch (state) {
        0 => "READY     ",
        1 => "RUNNING   ",
        2 => "BLOCKED   ",
        3 => "TERMINATED",
        4 => "ZOMBIE    ",
        5 => "STOPPED   ",
        6 => "WAITING   ",
        else => "UNKNOWN   ",
    };
}
