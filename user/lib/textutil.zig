const cstr = @import("cstr");
const fsutil = @import("fsutil");
const stdio = @import("stdio");

pub fn parseCount(value: [*:0]const u8) ?usize {
    const slice = cstr.slice(value);
    if (slice.len == 0) return null;

    var result: usize = 0;
    for (slice) |char| {
        if (char < '0' or char > '9') return null;
        result = result * 10 + (char - '0');
    }
    return result;
}

pub fn splitLines(content: []const u8, lines: [][]const u8) error{TooManyLines}!usize {
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

pub fn printReadError(name: []const u8, path: ?[*:0]const u8) void {
    if (path) |value| {
        stdio.eprint("{s}: failed to read {s}\n", .{ name, cstr.slice(value) });
    } else {
        stdio.eprint("{s}: failed to read stdin\n", .{name});
    }
}

pub fn printReadAllError(name: []const u8, path: ?[*:0]const u8, err: fsutil.ReadAllError) void {
    switch (err) {
        error.ReadFailed => printReadError(name, path),
        error.BufferTooSmall => stdio.eprint("{s}: input too large\n", .{name}),
    }
}

fn trimCarriageReturn(line: []const u8) []const u8 {
    if (line.len != 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
    return line;
}
