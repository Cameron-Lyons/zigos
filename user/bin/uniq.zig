const cstr = @import("cstr");
const fsutil = @import("fsutil");
const runtime = @import("runtime");
const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");

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
        printReadError(path, err);
        return false;
    };

    var lines: [max_lines][]const u8 = undefined;
    const line_count = splitLines(content, &lines) catch {
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

fn splitLines(content: []const u8, lines: *[max_lines][]const u8) error{TooManyLines}!usize {
    var count: usize = 0;
    var start: usize = 0;
    var i: usize = 0;
    while (i < content.len) : (i += 1) {
        if (content[i] != '\n') continue;
        if (count >= lines.len) return error.TooManyLines;
        lines[count] = trimCarriageReturn(content[start..i]);
        count += 1;
        start = i + 1;
    }
    if (start < content.len or content.len == 0) {
        if (count >= lines.len) return error.TooManyLines;
        lines[count] = trimCarriageReturn(content[start..]);
        count += 1;
    }
    return count;
}

fn trimCarriageReturn(line: []const u8) []const u8 {
    if (line.len != 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
    return line;
}

fn printReadError(path: ?[*:0]const u8, err: fsutil.ReadAllError) void {
    switch (err) {
        error.ReadFailed => if (path) |value| {
            stdio.eprint("uniq: failed to read {s}\n", .{cstr.slice(value)});
        } else {
            stdio.eputs("uniq: failed to read stdin\n");
        },
        error.BufferTooSmall => stdio.eputs("uniq: input too large\n"),
    }
}
