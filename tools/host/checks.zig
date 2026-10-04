const std = @import("std");
const common = @import("common.zig");

pub fn run(ctx: *common.Context, command: []const u8, args: []const []const u8) !void {
    try common.requireArgs(args, 0, 0);
    if (std.mem.eql(u8, command, "fmt-check")) {
        const result = try ctx.captureChecked(&.{ "jj", "file", "list", "-T", "path ++ \"\\0\"", "glob:**/*.zig" });
        var files = std.mem.splitScalar(u8, result, 0);
        var batch = std.ArrayList([]const u8).empty;
        const prefix = [_][]const u8{ ctx.envDefault("ZIG_BIN", "zig"), "fmt", "--check" };
        try batch.appendSlice(ctx.allocator, &prefix);
        while (files.next()) |path| {
            if (path.len == 0 or !ctx.exists(path)) continue;
            try batch.append(ctx.allocator, path);
            if (batch.items.len == 131) {
                try ctx.run(batch.items);
                batch.shrinkRetainingCapacity(3);
            }
        }
        if (batch.items.len > 3) try ctx.run(batch.items);
        return;
    }
    if (std.mem.eql(u8, command, "lint-shell")) {
        if (try ctx.findExecutable("shellcheck") == null) return error.ShellcheckRequired;
        var argv = std.ArrayList([]const u8).empty;
        try argv.appendSlice(ctx.allocator, &.{ "shellcheck", "--shell=bash" });
        var directory = try std.Io.Dir.cwd().openDir(ctx.io, "scripts", .{ .iterate = true });
        defer directory.close(ctx.io);
        var walker = try directory.walk(ctx.allocator);
        defer walker.deinit();
        while (try walker.next(ctx.io)) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.path, ".sh")) try argv.append(ctx.allocator, try ctx.fmt("scripts/{s}", .{entry.path}));
        }
        if (argv.items.len > 2) try ctx.run(argv.items);
        return;
    }
    if (std.mem.eql(u8, command, "lint-actions")) {
        if (try ctx.findExecutable("actionlint") == null) {
            if (std.mem.eql(u8, ctx.envDefault("ZIGOS_REQUIRE_ACTIONLINT", "0"), "1")) return error.ActionlintRequired;
            return ctx.warn("actionlint not found; skipping optional GitHub workflow lint. Set ZIGOS_REQUIRE_ACTIONLINT=1 to make this mandatory.\n", .{});
        }
        return ctx.run(&.{"actionlint"});
    }
    if (std.mem.eql(u8, command, "lint-zig")) {
        const required = std.mem.eql(u8, ctx.envDefault("ZIGOS_REQUIRE_ZLINT", "0"), "1");
        const executable = try ctx.findExecutable("zlint") orelse {
            if (required) return error.ZlintRequired;
            return ctx.warn("zlint not found; skipping optional Zig lint. Set ZIGOS_REQUIRE_ZLINT=1 to make this mandatory.\n", .{});
        };
        const result = try ctx.capture(&.{ executable, "-f", "github", "--deny-warnings", "src" });
        if (result.term.success()) return ctx.print("{s}{s}", .{ result.stdout, result.stderr });
        const output = try ctx.fmt("{s}{s}", .{ result.stdout, result.stderr });
        if (std.mem.indexOf(u8, output, "flag provided but not defined: -f") != null and !required) {
            return ctx.warn("zlint at {s} is not the Zig source linter; skipping optional Zig lint. Set ZIGOS_REQUIRE_ZLINT=1 to make this mandatory.\n", .{executable});
        }
        std.debug.print("{s}", .{output});
        common.child_failure_exit_code = common.exitCode(result.term);
        return error.ChildProcessFailed;
    }
    return error.UnknownCommand;
}
