const cstr = @import("cstr");
const processutil = @import("processutil");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        stdio.eputs("kill: usage: kill [-SIGNAL] <pid> [pid ...]\n");
        return 1;
    }

    var signum: i32 = syscall.SIGTERM;
    var pid_index: usize = 1;

    const first = argv[1] orelse return 1;
    if (first[0] == '-' and first[1] != 0) {
        signum = processutil.parseSignal(first + 1) orelse {
            stdio.eputs("kill: invalid signal\n");
            return 1;
        };
        pid_index = 2;
    }

    if (pid_index >= argc) {
        stdio.eputs("kill: usage: kill [-SIGNAL] <pid> [pid ...]\n");
        return 1;
    }

    var exit_code: i32 = 0;
    var i = pid_index;
    while (i < argc) : (i += 1) {
        const pid_arg = argv[i] orelse continue;
        const pid = processutil.parsePid(pid_arg) orelse {
            stdio.eputs("kill: invalid pid\n");
            exit_code = 1;
            continue;
        };

        if (syscall.kill(pid, signum) != 0) {
            stdio.eprint("kill: failed to signal {s}\n", .{cstr.slice(pid_arg)});
            exit_code = 1;
        }
    }

    return exit_code;
}
