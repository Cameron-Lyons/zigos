const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc != 3) {
        stdio.eputs("mv: usage: mv <source> <destination>\n");
        return 1;
    }

    const source = argv[1] orelse return 1;
    const destination = argv[2] orelse return 1;
    if (syscall.rename(source, destination) != 0) {
        stdio.eprint("mv: failed to move {s} to {s}\n", .{ cstr.slice(source), cstr.slice(destination) });
        return 1;
    }

    return 0;
}
