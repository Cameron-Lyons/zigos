const std = @import("std");

pub const Entry = struct {
    name: []const u8,
    password: []const u8,
    uid: u16,
    gid: u16,
    gecos: []const u8,
    home: []const u8,
    shell: []const u8,
};

pub fn nextLine(data: []const u8, cursor: *usize) ?[]const u8 {
    if (cursor.* >= data.len) return null;

    const start = cursor.*;
    var end = start;
    while (end < data.len and data[end] != '\n') : (end += 1) {}
    cursor.* = if (end < data.len) end + 1 else end;
    return trimLine(data[start..end]);
}

pub fn parseLine(line: []const u8) ?Entry {
    if (line.len == 0 or line[0] == '#') return null;

    var cursor: usize = 0;
    const name = nextField(line, &cursor) orelse return null;
    const password = nextField(line, &cursor) orelse return null;
    const uid_field = nextField(line, &cursor) orelse return null;
    const gid_field = nextField(line, &cursor) orelse return null;
    const gecos = nextField(line, &cursor) orelse return null;
    const home = nextField(line, &cursor) orelse return null;
    const shell = nextField(line, &cursor) orelse return null;

    if (name.len == 0 or home.len == 0 or shell.len == 0) return null;

    return .{
        .name = name,
        .password = password,
        .uid = parseDecimalU16(uid_field) orelse return null,
        .gid = parseDecimalU16(gid_field) orelse return null,
        .gecos = gecos,
        .home = home,
        .shell = shell,
    };
}

fn nextField(line: []const u8, cursor: *usize) ?[]const u8 {
    if (cursor.* > line.len) return null;

    const start = cursor.*;
    while (cursor.* < line.len and line[cursor.*] != ':') : (cursor.* += 1) {}
    const end = cursor.*;
    if (cursor.* < line.len and line[cursor.*] == ':') cursor.* += 1;
    return line[start..end];
}

fn trimLine(line: []const u8) []const u8 {
    if (line.len > 0 and line[line.len - 1] == '\r') {
        return line[0 .. line.len - 1];
    }
    return line;
}

fn parseDecimalU16(slice: []const u8) ?u16 {
    if (slice.len == 0) return null;

    var value: u32 = 0;
    for (slice) |char| {
        if (char < '0' or char > '9') return null;
        value = value * 10 + (char - '0');
        if (value > std.math.maxInt(u16)) return null;
    }

    return @intCast(value);
}
