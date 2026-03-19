const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    stdio.puts("\nZigOS console login\n");

    var login_argv: [3]?[*:0]const u8 = [_]?[*:0]const u8{ "/bin/login", null, null };
    if (argc >= 2) {
        login_argv[1] = argv[1];
    }

    _ = syscall.execve("/bin/login", &login_argv, envp);
    stdio.eputs("getty: failed to exec /bin/login\n");
    return 1;
}
