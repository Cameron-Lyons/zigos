const std = @import("std");
const common = @import("../common.zig");

var interrupted = std.atomic.Value(u8).init(0);

fn handleSignal(signal: std.posix.SIG) callconv(.c) void {
    interrupted.store(@intCast(@backingInt(signal)), .monotonic);
}

pub const Signals = struct {
    old_int: std.posix.Sigaction,
    old_term: std.posix.Sigaction,

    pub fn install() Signals {
        interrupted.store(0, .monotonic);
        var result: Signals = undefined;
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = handleSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(.INT, &action, &result.old_int);
        std.posix.sigaction(.TERM, &action, &result.old_term);
        return result;
    }

    pub fn restore(self: Signals) void {
        std.posix.sigaction(.INT, &self.old_int, null);
        std.posix.sigaction(.TERM, &self.old_term, null);
    }
};

pub fn checkInterrupted() !void {
    if (interrupted.load(.monotonic) != 0) return error.Interrupted;
}

pub fn interruptionExitCode() u8 {
    const signal = interrupted.load(.monotonic);
    return if (signal == 0) 130 else 128 + signal;
}

pub fn pause(ctx: *common.Context, milliseconds: i64) !void {
    var remaining = milliseconds;
    while (remaining > 0) {
        try checkInterrupted();
        const quantum = @min(remaining, 100);
        try std.Io.sleep(ctx.io, .fromMilliseconds(quantum), .awake);
        remaining -= quantum;
    }
    try checkInterrupted();
}

/// Each external service has its own process group. Cancellation stops that
/// group, waits for the direct child, and closes the redirected file.
pub const Child = struct {
    child: std.process.Child,
    group: std.posix.pid_t,
    term: ?std.process.Child.Term = null,
    stopped: bool = false,

    pub fn start(ctx: *common.Context, argv: []const []const u8, log_path: ?[]const u8) !Child {
        try checkInterrupted();
        var file: ?std.Io.File = null;
        if (log_path) |path| {
            try ctx.mkdir(std.fs.path.dirname(path) orelse ".");
            file = try std.Io.Dir.cwd().createFile(ctx.io, path, .{});
        }
        defer if (file) |f| f.close(ctx.io);
        const child = try std.process.spawn(ctx.io, .{
            .argv = argv,
            .environ_map = ctx.environ,
            .stdout = if (file) |f| .{ .file = f } else .inherit,
            .stderr = if (file) |f| .{ .file = f } else .inherit,
            .pgid = 0,
        });
        return .{ .child = child, .group = child.id.? };
    }

    pub fn poll(self: *Child) !bool {
        const pid = self.child.id orelse return false;
        var wait_status: c_int = undefined;
        const result = std.c.waitpid(pid, &wait_status, std.posix.W.NOHANG);
        if (result == 0) return true;
        if (result < 0) {
            if (std.posix.errno(result) == .INTR) return true;
            return error.ChildWaitFailed;
        }
        self.child.id = null;
        const raw: u32 = @bitCast(wait_status);
        self.term = if (std.posix.W.IFEXITED(raw))
            .{ .exited = std.posix.W.EXITSTATUS(raw) }
        else if (std.posix.W.IFSIGNALED(raw))
            .{ .signal = std.posix.W.TERMSIG(raw) }
        else
            .{ .unknown = raw };
        return false;
    }

    pub fn wait(self: *Child, ctx: *common.Context) !std.process.Child.Term {
        while (try self.poll()) try pause(ctx, 100);
        return self.term.?;
    }

    pub fn stop(self: *Child, ctx: *common.Context, grace_seconds: u32) void {
        if (self.stopped) return;
        self.stopped = true;
        const pid = self.group;
        std.posix.kill(-pid, .TERM) catch {};
        var ticks: u64 = @as(u64, grace_seconds) * 10;
        while (ticks > 0) : (ticks -= 1) {
            const running = self.poll() catch false;
            const group_exists = std.c.kill(-pid, @fromBackingInt(@intCast(0))) == 0;
            if (!running and !group_exists) return;
            std.Io.sleep(ctx.io, .fromMilliseconds(100), .awake) catch {};
        }
        std.posix.kill(-pid, .KILL) catch {};
        if (self.child.id != null) {
            self.term = self.child.wait(ctx.io) catch .{ .unknown = 0 };
        }
    }

    pub fn status(self: Child) u32 {
        return switch (self.term orelse return 255) {
            .exited => |code| code,
            .signal => |signal| 128 + @as(u32, @intCast(@backingInt(signal))),
            else => 255,
        };
    }
};

pub fn seconds(ctx: *common.Context, name: []const u8, default: []const u8) !u32 {
    const value = ctx.envDefault(name, default);
    const parsed = std.fmt.parseInt(u32, value, 10) catch {
        try ctx.print("{s} must be a positive integer\n", .{name});
        return error.InvalidArguments;
    };
    if (parsed == 0 or std.mem.indexOfNone(u8, value, "0123456789") != null) {
        try ctx.print("{s} must be a positive integer\n", .{name});
        return error.InvalidArguments;
    }
    return parsed;
}

pub fn grace(ctx: *common.Context) u32 {
    return std.fmt.parseInt(u32, ctx.envDefault("QEMU_STOP_GRACE_SECONDS", "10"), 10) catch 10;
}

pub fn elapsed(ctx: *common.Context, start: std.Io.Timestamp) i64 {
    return start.durationTo(.now(ctx.io, .awake)).toMilliseconds();
}

pub fn run(ctx: *common.Context, argv: []const []const u8, log_path: ?[]const u8) !u32 {
    var child = try Child.start(ctx, argv, log_path);
    defer child.stop(ctx, grace(ctx));
    _ = try child.wait(ctx);
    return child.status();
}

pub fn timed(ctx: *common.Context, argv: []const []const u8, log_path: ?[]const u8, limit: u32) !u32 {
    var child = try Child.start(ctx, argv, log_path);
    defer child.stop(ctx, 5);
    const start = std.Io.Timestamp.now(ctx.io, .awake);
    while (try child.poll()) {
        if (elapsed(ctx, start) >= @as(i64, limit) * 1000) {
            child.stop(ctx, 5);
            return if (child.status() == 137) 137 else 124;
        }
        try pause(ctx, 100);
    }
    return child.status();
}

test "managed child preserves status and drains combined redirected output" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environment };
    const temporary = try ctx.tempDir("zigos-process-test");
    defer ctx.removeTree(temporary) catch {};
    const output = try ctx.fmt("{s}/output", .{temporary});
    try std.testing.expectEqual(@as(u32, 0), try run(&ctx, &.{ "/bin/echo", "child-output" }, output));
    try std.testing.expectEqualStrings("child-output\n", try ctx.read(output));
    try std.testing.expectEqual(@as(u32, 1), try run(&ctx, &.{"/usr/bin/false"}, null));
}

test "deadline terminates and reaps a long-running process" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var environment = std.process.Environ.Map.init(arena.allocator());
    var ctx: common.Context = .{ .allocator = arena.allocator(), .io = std.testing.io, .environ = &environment };
    const start = std.Io.Timestamp.now(ctx.io, .awake);
    try std.testing.expectEqual(@as(u32, 124), try timed(&ctx, &.{ "/bin/sleep", "20" }, null, 1));
    try std.testing.expect(elapsed(&ctx, start) < 5000);
}
