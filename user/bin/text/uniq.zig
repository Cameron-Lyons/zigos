const cstr = @import("cstr");
const fsutil = @import("fsutil");
const runtime = @import("runtime");
const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");
const textutil = @import("textutil");

pub const panic = runtime.panic;

const buffer_size = 4096;
const max_lines = 128;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) return if (uniqFd(syscall.STDIN, null)) 0 else 1;

    const path = argv[1] orelse return 1;
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("uniq: failed to open {s}\n", .{cstr.slice(path)});
        return 1;
    }
    defer _ = syscall.close(fd);
    return if (uniqFd(fd, path)) 0 else 1;
}

fn uniqFd(fd: i32, path: ?[*:0]const u8) bool {
    var buffer: [buffer_size]u8 = undefined;
    const content = fsutil.readAll(fd, &buffer) catch |err| {
        textutil.printReadAllError("uniq", path, err);
        return false;
    };

    var lines: [max_lines][]const u8 = undefined;
    const line_count = textutil.splitLines(content, lines[0..]) catch {
        stdio.eputs("uniq: too many lines\n");
        return false;
    };

    var prev: ?[]const u8 = null;
    for (lines[0..line_count]) |line| {
        if (prev != null and std.mem.eql(u8, prev.?, line)) continue;
        fsutil.writeAll(syscall.STDOUT, line) catch return false;
        fsutil.writeAll(syscall.STDOUT, "\n") catch return false;
        prev = line;
    }
    return true;
}
