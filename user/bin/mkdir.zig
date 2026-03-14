const cstr = @import("cstr");
const cli = @import("cli");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;
const default_mode: u32 = 0o755;

fn createDirectory(path: [*:0]const u8) bool {
    if (syscall.mkdir(path, default_mode) != 0) {
        stdio.eprint("mkdir: failed to create {s}\n", .{cstr.slice(path)});
        return false;
    }

    return true;
}

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (!cli.requireOperand(argc, "mkdir: missing operand\n")) return 1;
    return cli.forEachOperand(argc, argv, createDirectory);
}
