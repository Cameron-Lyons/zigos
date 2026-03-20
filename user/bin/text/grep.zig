const cstr = @import("cstr");
const runtime = @import("runtime");
const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");
const fsutil = @import("fsutil");

pub const panic = runtime.panic;

const read_buffer_size = 512;
const line_buffer_size = 1024;

const SearchStatus = enum {
    matched,
    not_matched,
    failed,
};

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        stdio.eputs("grep: usage: grep <pattern> [file ...]\n");
        return 2;
    }

    const pattern_ptr = argv[1] orelse return 2;
    const pattern = cstr.slice(pattern_ptr);
    if (pattern.len == 0) {
        stdio.eputs("grep: empty pattern\n");
        return 2;
    }

    if (argc == 2) {
        return switch (searchFd(syscall.STDIN, pattern, null, false)) {
            .matched => 0,
            .not_matched => 1,
            .failed => 2,
        };
    }

    const multiple_files = argc > 3;
    var matched_any = false;
    var failed_any = false;
    var i: usize = 2;
    while (i < argc) : (i += 1) {
        const path = argv[i] orelse continue;
        const fd = syscall.open(path, syscall.O_RDONLY);
        if (syscall.isError(fd)) {
            stdio.eprint("grep: failed to open {s}\n", .{cstr.slice(path)});
            failed_any = true;
            continue;
        }

        switch (searchFd(fd, pattern, path, multiple_files)) {
            .matched => matched_any = true,
            .not_matched => {},
            .failed => failed_any = true,
        }
        _ = syscall.close(fd);
    }

    if (failed_any) return 2;
    return if (matched_any) 0 else 1;
}

fn searchFd(fd: i32, pattern: []const u8, path: ?[*:0]const u8, print_prefix: bool) SearchStatus {
    var read_buffer: [read_buffer_size]u8 = undefined;
    var line_buffer: [line_buffer_size]u8 = undefined;
    var line_len: usize = 0;
    var matched = false;

    while (true) {
        const rc = syscall.read(fd, &read_buffer);
        if (rc == 0) break;
        if (syscall.isError(rc)) {
            if (path) |value| {
                stdio.eprint("grep: failed to read {s}\n", .{cstr.slice(value)});
            } else {
                stdio.eputs("grep: failed to read stdin\n");
            }
            return .failed;
        }

        for (read_buffer[0..@intCast(rc)]) |byte| {
            if (line_len >= line_buffer.len) {
                stdio.eputs("grep: line too long\n");
                return .failed;
            }

            line_buffer[line_len] = byte;
            line_len += 1;

            if (byte == '\n') {
                if (flushLine(line_buffer[0..line_len], pattern, path, print_prefix) catch return .failed) {
                    matched = true;
                }
                line_len = 0;
            }
        }
    }

    if (line_len != 0 and (flushLine(line_buffer[0..line_len], pattern, path, print_prefix) catch return .failed)) {
        matched = true;
    }

    return if (matched) .matched else .not_matched;
}

fn flushLine(line: []const u8, pattern: []const u8, path: ?[*:0]const u8, print_prefix: bool) fsutil.CopyError!bool {
    var normalized = line;
    if (normalized.len != 0 and normalized[normalized.len - 1] == '\n') {
        normalized = normalized[0 .. normalized.len - 1];
    }
    if (normalized.len != 0 and normalized[normalized.len - 1] == '\r') {
        normalized = normalized[0 .. normalized.len - 1];
    }
    if (std.mem.indexOf(u8, normalized, pattern) == null) return false;

    if (print_prefix) {
        if (path) |value| {
            try fsutil.writeAll(syscall.STDOUT, cstr.slice(value));
            try fsutil.writeAll(syscall.STDOUT, ":");
        }
    }
    try fsutil.writeAll(syscall.STDOUT, normalized);
    try fsutil.writeAll(syscall.STDOUT, "\n");
    return true;
}
