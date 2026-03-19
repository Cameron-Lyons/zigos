const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        stdio.eputs("umount: usage: umount <target>\n");
        return 1;
    }

    const target = argv[1].?;
    const rc = syscall.umount(target);
    if (syscall.isError(rc)) {
        stdio.eprint("umount: failed to unmount {s}\n", .{cstr.slice(target)});
        return 1;
    }

    return 0;
}
