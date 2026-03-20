const cstr = @import("cstr");
const cli = @import("cli");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

fn removePath(path: [*:0]const u8) bool {
    if (syscall.unlink(path) != 0) {
        stdio.eprint("rm: failed to remove {s}\n", .{cstr.slice(path)});
        return false;
    }

    return true;
}

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (!cli.requireOperand(argc, "rm: missing operand\n")) return 1;
    return cli.forEachOperand(argc, argv, removePath);
}
