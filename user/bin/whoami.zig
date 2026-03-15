const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    stdio.puts(userName(syscall.geteuid()));
    stdio.puts("\n");
    return 0;
}

fn userName(uid: i32) []const u8 {
    return if (uid == 0) "root" else "user";
}
