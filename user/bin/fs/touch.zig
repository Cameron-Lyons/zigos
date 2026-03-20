const cstr = @import("cstr");
const cli = @import("cli");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

fn touchPath(path: [*:0]const u8) bool {
    const fd = syscall.open(path, syscall.O_CREAT | syscall.O_RDWR);
    if (syscall.isError(fd)) {
        stdio.eprint("touch: failed to open {s}\n", .{cstr.slice(path)});
        return false;
    }

    _ = syscall.close(fd);
    return true;
}

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (!cli.requireOperand(argc, "touch: missing operand\n")) return 1;
    return cli.forEachOperand(argc, argv, touchPath);
}
