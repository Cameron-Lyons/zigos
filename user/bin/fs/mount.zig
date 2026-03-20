const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 4) {
        stdio.eputs("mount: usage: mount <source> <target> <fstype>\n");
        return 1;
    }

    const source = argv[1].?;
    const target = argv[2].?;
    const fstype = argv[3].?;

    const rc = syscall.mount(source, target, fstype, 0);
    if (syscall.isError(rc)) {
        stdio.eprint("mount: failed to mount {s} on {s} as {s}\n", .{
            cstr.slice(source),
            cstr.slice(target),
            cstr.slice(fstype),
        });
        return 1;
    }

    return 0;
}
