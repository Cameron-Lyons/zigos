const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;

    stdio.puts("init: starting console getty\n");

    while (true) {
        var getty_argv: [2]?[*:0]const u8 = [_]?[*:0]const u8{ "/bin/getty", null };
        const pid = syscall.spawnve("/bin/getty", &getty_argv, envp);
        if (syscall.isError(pid)) {
            stdio.eprint("init: failed to spawn getty rc={d}\n", .{pid});
            return 1;
        }

        var status: i32 = 0;
        const waited = syscall.wait4(pid, &status, 0, null);
        if (syscall.isError(waited)) {
            stdio.eputs("init: wait4 failed\n");
            return 1;
        }

        stdio.puts("init: getty exited, respawning\n");
    }
}
