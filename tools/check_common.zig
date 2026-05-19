const std = @import("std");

pub const stdout_buffer_bytes: usize = 1024;
pub const source_file_max_bytes: usize = 16 * 1024 * 1024;
pub const coverage_manifest_max_bytes: usize = 8 * 1024 * 1024;
pub const production_readiness_manifest_max_bytes: usize = 4 * 1024 * 1024;
pub const child_stdout_max_bytes: usize = source_file_max_bytes;
pub const child_stderr_max_bytes: usize = 64 * 1024;

pub fn addError(
    errors: *std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    try errors.append(allocator, try std.fmt.allocPrint(allocator, fmt, args));
}

pub fn printErrors(errors: []const []const u8) void {
    for (errors) |message| {
        std.debug.print("{s}\n", .{message});
    }
}

pub fn printStdout(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var stdout_buffer: [stdout_buffer_bytes]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    try stdout_writer.interface.print(fmt, args);
    try stdout_writer.interface.flush();
}

pub fn readFileAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_bytes));
}

pub fn pathExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

pub fn field(value: std.json.Value, name: []const u8) ?std.json.Value {
    return switch (value) {
        .object => |object| object.get(name),
        else => null,
    };
}

pub fn collectStringArray(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    maybe_value: ?std.json.Value,
    context: []const u8,
    required_non_empty: bool,
) ![]const []const u8 {
    var values = std.ArrayList([]const u8).empty;
    const value = maybe_value orelse {
        try addError(errors, allocator, "{s} must be an array", .{context});
        return values.toOwnedSlice(allocator);
    };

    switch (value) {
        .array => |array| {
            for (array.items, 0..) |item, index| {
                switch (item) {
                    .string => |text| try values.append(allocator, text),
                    else => try addError(
                        errors,
                        allocator,
                        "{s} entry at index {d} must be a string",
                        .{ context, index },
                    ),
                }
            }
        },
        else => try addError(errors, allocator, "{s} must be an array", .{context}),
    }

    if (required_non_empty and values.items.len == 0) {
        try addError(errors, allocator, "{s} must be non-empty", .{context});
    }

    return values.toOwnedSlice(allocator);
}

pub fn collectUniqueStrings(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    values: []const []const u8,
    context: []const u8,
) !std.StringHashMap(void) {
    var set = std.StringHashMap(void).init(allocator);
    for (values) |value| {
        const gop = try set.getOrPut(value);
        if (gop.found_existing) {
            try addError(errors, allocator, "Duplicate {s}: {s}", .{ context, value });
        }
    }
    return set;
}

pub fn expectStringField(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
) !?[]const u8 {
    const value = field(object, name) orelse {
        try addError(errors, allocator, "{s} must include {s}", .{ context, name });
        return null;
    };
    return switch (value) {
        .string => |text| text,
        else => {
            try addError(errors, allocator, "{s} {s} must be a string", .{ context, name });
            return null;
        },
    };
}

pub fn expectObjectField(
    allocator: std.mem.Allocator,
    errors: *std.ArrayList([]const u8),
    object: std.json.Value,
    context: []const u8,
    name: []const u8,
) !?std.json.Value {
    const value = field(object, name) orelse {
        try addError(errors, allocator, "{s} must include {s}", .{ context, name });
        return null;
    };
    switch (value) {
        .object => return value,
        else => {
            try addError(errors, allocator, "{s} {s} must be an object", .{ context, name });
            return null;
        },
    }
}

pub fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var offset: usize = 0;
    while (offset + needle.len <= haystack.len) : (offset += 1) {
        var matched = true;
        for (needle, 0..) |needle_byte, index| {
            if (std.ascii.toLower(haystack[offset + index]) != std.ascii.toLower(needle_byte)) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}

pub fn errorContains(errors: []const []const u8, needle: []const u8) bool {
    for (errors) |message| {
        if (std.mem.indexOf(u8, message, needle) != null) return true;
    }
    return false;
}
