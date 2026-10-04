const std = @import("std");

pub var child_failure_exit_code: u8 = 1;

/// Host tools share the invoking process's arena and explicit I/O environment.
pub const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: *std.process.Environ.Map,

    /// Configure caches retain only explicit wrapper arguments. Ambient settings
    /// come from this invocation, then the build's compiler and overrides apply.
    pub fn buildCommandArgs(self: *Context, args: []const []const u8) ![]const []const u8 {
        var remaining = args;
        while (remaining.len != 0) {
            if (std.mem.eql(u8, remaining[0], "--build-zig")) {
                if (remaining.len < 2 or remaining[1].len == 0) return error.InvalidArguments;
                try self.environ.put("ZIG_BIN", remaining[1]);
                remaining = remaining[2..];
            } else if (std.mem.eql(u8, remaining[0], "--build-env")) {
                if (remaining.len < 3 or remaining[1].len == 0 or std.mem.indexOfScalar(u8, remaining[1], '=') != null) return error.InvalidArguments;
                try self.environ.put(remaining[1], remaining[2]);
                remaining = remaining[3..];
            } else break;
        }
        return remaining;
    }

    pub fn env(self: *Context, name: []const u8) ?[]const u8 {
        return self.environ.get(name);
    }

    pub fn envDefault(self: *Context, name: []const u8, fallback: []const u8) []const u8 {
        const value = self.env(name) orelse return fallback;
        return if (value.len == 0) fallback else value;
    }

    pub fn fmt(self: *Context, comptime format: []const u8, args: anytype) ![]u8 {
        return std.fmt.allocPrint(self.allocator, format, args);
    }

    pub fn print(self: *Context, comptime format: []const u8, args: anytype) !void {
        var buffer: [4096]u8 = undefined;
        var writer = std.Io.File.stdout().writer(self.io, &buffer);
        try writer.interface.print(format, args);
        try writer.interface.flush();
    }

    pub fn warn(self: *Context, comptime format: []const u8, args: anytype) !void {
        var buffer: [4096]u8 = undefined;
        var writer = std.Io.File.stderr().writer(self.io, &buffer);
        try writer.interface.print(format, args);
        try writer.interface.flush();
    }

    pub fn read(self: *Context, path: []const u8) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(256 * 1024 * 1024));
    }

    pub fn mkdir(self: *Context, path: []const u8) !void {
        if (path.len != 0) try std.Io.Dir.cwd().createDirPath(self.io, path);
    }

    pub fn parent(self: *Context, path: []const u8) !void {
        if (std.fs.path.dirname(path)) |directory| try self.mkdir(directory);
    }

    pub fn write(self: *Context, path: []const u8, data: []const u8) !void {
        try self.parent(path);
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = data });
    }

    pub fn copy(self: *Context, source: []const u8, destination: []const u8) !void {
        try self.parent(destination);
        try std.Io.Dir.cwd().copyFile(source, std.Io.Dir.cwd(), destination, self.io, .{});
    }

    pub fn exists(self: *Context, path: []const u8) bool {
        std.Io.Dir.cwd().access(self.io, path, .{}) catch return false;
        return true;
    }

    pub fn findExecutable(self: *Context, name: []const u8) !?[]const u8 {
        if (std.mem.indexOfScalar(u8, name, '/') != null) return if (self.executable(name)) name else null;
        var paths = std.mem.splitScalar(u8, self.envDefault("PATH", "/usr/bin:/bin"), ':');
        while (paths.next()) |directory| {
            const path = try self.fmt("{s}/{s}", .{ if (directory.len == 0) "." else directory, name });
            if (self.executable(path)) return path;
        }
        return null;
    }

    pub fn executable(self: *Context, path: []const u8) bool {
        const stat = std.Io.Dir.cwd().statFile(self.io, path, .{}) catch return false;
        return stat.kind == .file and stat.permissions.toMode() & 0o111 != 0;
    }

    pub fn captureChecked(self: *Context, argv: []const []const u8) ![]const u8 {
        const result = try self.capture(argv);
        if (!result.term.success()) {
            std.debug.print("{s}{s}", .{ result.stdout, result.stderr });
            return error.ChildProcessFailed;
        }
        return result.stdout;
    }

    pub fn removeFile(self: *Context, path: []const u8) !void {
        std.Io.Dir.cwd().deleteFile(self.io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    pub fn removeTree(self: *Context, path: []const u8) !void {
        try std.Io.Dir.cwd().deleteTree(self.io, path);
    }

    pub fn tempDir(self: *Context, prefix: []const u8) ![]const u8 {
        for (0..32) |_| {
            var random: [16]u8 = undefined;
            try std.Io.randomSecure(self.io, &random);
            const path = try self.fmt("{s}/{s}-{s}", .{ self.envDefault("TMPDIR", "/tmp"), prefix, std.fmt.bytesToHex(random, .lower) });
            std.Io.Dir.cwd().createDir(self.io, path, .fromMode(0o700)) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return err,
            };
            return path;
        }
        return error.TemporaryDirectoryCollision;
    }

    pub fn run(self: *Context, argv: []const []const u8) !void {
        var child = try std.process.spawn(self.io, .{ .argv = argv, .environ_map = self.environ });
        defer child.kill(self.io);
        const term = try child.wait(self.io);
        if (!term.success()) {
            child_failure_exit_code = exitCode(term);
            std.debug.print("{s}: {f}\n", .{ argv[0], term });
            return error.ChildProcessFailed;
        }
    }

    pub fn capture(self: *Context, argv: []const []const u8) !std.process.RunResult {
        return std.process.run(self.allocator, self.io, .{
            .argv = argv,
            .environ_map = self.environ,
            .stdout_limit = .limited(64 * 1024 * 1024),
            .stderr_limit = .limited(1024 * 1024),
        });
    }

    /// A file-backed input avoids pipe deadlocks when a signer emits output
    /// before consuming its complete payload. Output streams are drained together.
    pub fn captureInput(self: *Context, argv: []const []const u8, input: []const u8) !std.process.RunResult {
        const temporary = try self.tempDir("zigos-signer");
        defer self.removeTree(temporary) catch {};
        const input_path = try self.fmt("{s}/input", .{temporary});
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = input_path, .data = input, .flags = .{ .permissions = .fromMode(0o600) } });
        const input_file = try std.Io.Dir.cwd().openFile(self.io, input_path, .{});
        defer input_file.close(self.io);
        var child = try std.process.spawn(self.io, .{
            .argv = argv,
            .environ_map = self.environ,
            .stdin = .{ .file = input_file },
            .stdout = .pipe,
            .stderr = .pipe,
        });
        defer child.kill(self.io);
        var buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
        var reader: std.Io.File.MultiReader = undefined;
        reader.init(self.allocator, self.io, buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
        defer reader.deinit();
        while (reader.fill(4096, .none)) |_| {
            if (reader.reader(0).buffered().len > 64 * 1024 * 1024 or reader.reader(1).buffered().len > 1024 * 1024) return error.StreamTooLong;
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => return err,
        }
        try reader.checkAnyError();
        const term = try child.wait(self.io);
        return .{ .term = term, .stdout = try self.allocator.dupe(u8, reader.reader(0).buffered()), .stderr = try self.allocator.dupe(u8, reader.reader(1).buffered()) };
    }

    pub fn sha256File(self: *Context, path: []const u8) ![64]u8 {
        const file = try std.Io.Dir.cwd().openFile(self.io, path, .{});
        defer file.close(self.io);
        if ((try file.stat(self.io)).kind != .file) return error.NotRegularFile;
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        while (true) {
            const amount = try file.readPositionalAll(self.io, &buffer, offset);
            if (amount == 0) break;
            hash.update(buffer[0..amount]);
            offset += amount;
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        return std.fmt.bytesToHex(digest, .lower);
    }
};

pub fn exitCode(term: std.process.Child.Term) u8 {
    return switch (term) {
        .exited => |code| code,
        .signal => |signal| @intCast(128 + @as(u32, @intCast(@backingInt(signal)))),
        else => 1,
    };
}

pub fn arg(args: []const []const u8, index: usize, fallback: []const u8) []const u8 {
    return if (index < args.len) args[index] else fallback;
}

pub fn requireArgs(args: []const []const u8, minimum: usize, maximum: usize) !void {
    if (args.len < minimum or args.len > maximum) return error.InvalidArguments;
}
