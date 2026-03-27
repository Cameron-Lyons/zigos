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

    if (argc < 2) return if (sortFd(syscall.STDIN, null)) 0 else 1;

    const path = argv[1] orelse return 1;
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("sort: failed to open {s}\n", .{cstr.slice(path)});
        return 1;
    }
    defer _ = syscall.close(fd);
    return if (sortFd(fd, path)) 0 else 1;
}

fn sortFd(fd: i32, path: ?[*:0]const u8) bool {
    var buffer: [buffer_size]u8 = undefined;
    const content = fsutil.readAll(fd, &buffer) catch |err| {
        textutil.printReadAllError("sort", path, err);
        return false;
    };

    var lines: [max_lines][]const u8 = undefined;
    const line_count = textutil.splitLines(content, lines[0..]) catch {
        stdio.eputs("sort: too many lines\n");
        return false;
    };

    insertionSort(lines[0..line_count]);
    for (lines[0..line_count]) |line| {
        fsutil.writeAll(syscall.STDOUT, line) catch return false;
        fsutil.writeAll(syscall.STDOUT, "\n") catch return false;
    }
    return true;
}

fn insertionSort(lines: [][]const u8) void {
    var i: usize = 1;
    while (i < lines.len) : (i += 1) {
        const current = lines[i];
        var j = i;
        while (j > 0 and std.mem.order(u8, current, lines[j - 1]) == .lt) : (j -= 1) {
            lines[j] = lines[j - 1];
        }
        lines[j] = current;
    }
}
