const cstr = @import("cstr");
const runtime = @import("runtime");
const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    var symbolic = false;
    var arg_index: usize = 1;
    if (argc > 1) {
        const first = cstr.slice(argv[1] orelse return 1);
        if (std.mem.eql(u8, first, "-s")) {
            symbolic = true;
            arg_index = 2;
        }
    }

    if (argc != arg_index + 2) {
        stdio.eputs("ln: usage: ln [-s] <target> <linkname>\n");
        return 1;
    }

    const target = argv[arg_index] orelse return 1;
    const link_name = argv[arg_index + 1] orelse return 1;
    const rc = if (symbolic) syscall.symlink(target, link_name) else syscall.link(target, link_name);
    if (rc != 0) {
        if (symbolic) {
            stdio.eprint("ln: failed to create symlink {s}\n", .{cstr.slice(link_name)});
        } else {
            stdio.eprint("ln: failed to create link {s}\n", .{cstr.slice(link_name)});
        }
        return 1;
    }

    return 0;
}
