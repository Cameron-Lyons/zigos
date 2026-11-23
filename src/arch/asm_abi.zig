const std = @import("std");

/// Compare the `#define NAME VALUE` lines of an assembly source with their Zig
/// definitions. Callers run this in a top-level comptime block, so a layout,
/// MSR or control-bit drift between the two ABI views fails every image and
/// test that links the assembly instead of reaching hardware.
pub fn expectConstants(comptime file: []const u8, comptime source: []const u8, comptime pairs: anytype) void {
    @setEvalBranchQuota(2_000_000);
    var seen: [pairs.len]bool = @splat(false);
    var lines = std.mem.tokenizeScalar(u8, source, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, std.mem.trimStart(u8, line, " \t"), "#define")) continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        _ = fields.next();
        const name = fields.next() orelse continue;
        for (pairs, &seen) |pair, *found| {
            if (!std.mem.eql(u8, name, pair[0])) continue;
            const text = fields.next() orelse @compileError(file ++ " " ++ pair[0] ++ " has no value");
            if (found.* or fields.next() != null) @compileError(file ++ " " ++ pair[0] ++ " is not one plain definition");
            const value = std.fmt.parseInt(u64, text, 0) catch @compileError(file ++ " " ++ pair[0] ++ " is not an integer");
            if (value != pair[1]) @compileError(file ++ " " ++ pair[0] ++ " does not match its Zig definition");
            found.* = true;
        }
    }
    for (pairs, seen) |pair, found| {
        if (!found) @compileError(file ++ " does not define " ++ pair[0]);
    }
}
