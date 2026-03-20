const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    var buffer: [256]u8 = undefined;
    const rc = syscall.getcwd(&buffer);
    if (syscall.isError(rc)) {
        stdio.eputs("pwd: failed to get cwd\n");
        return 1;
    }

    stdio.writeAll(syscall.STDOUT, buffer[0..@intCast(rc)]);
    stdio.puts("\n");
    return 0;
}
