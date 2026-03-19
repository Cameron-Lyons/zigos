const cstr = @import("cstr");
const runtime = @import("runtime");
const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

fn parseMode(text: []const u8) ?u32 {
    const mode = std.fmt.parseInt(u32, text, 8) catch return null;
    if (mode > 0o7777) return null;
    return mode;
}

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 3) {
        stdio.eputs("chmod: usage: chmod <mode> <path> [path ...]\n");
        return 1;
    }

    const mode_text = cstr.slice(argv[1] orelse return 1);
    const mode = parseMode(mode_text) orelse {
        stdio.eputs("chmod: invalid mode\n");
        return 1;
    };

    var exit_code: i32 = 0;
    var i: usize = 2;
    while (i < argc) : (i += 1) {
        const path = argv[i] orelse continue;
        if (syscall.chmod(path, mode) != 0) {
            stdio.eprint("chmod: failed to change mode on {s}\n", .{cstr.slice(path)});
            exit_code = 1;
        }
    }

    return exit_code;
}
