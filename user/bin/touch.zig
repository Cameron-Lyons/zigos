const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        stdio.eputs("touch: missing operand\n");
        return 1;
    }

    var exit_code: i32 = 0;
    var i: usize = 1;
    while (i < argc) : (i += 1) {
        const path = argv[i] orelse continue;
        const fd = syscall.open(path, syscall.O_CREAT | syscall.O_RDWR);
        if (syscall.isError(fd)) {
            stdio.eprint("touch: failed to open {s}\n", .{cstr.slice(path)});
            exit_code = 1;
            continue;
        }
        _ = syscall.close(fd);
    }

    return exit_code;
}
