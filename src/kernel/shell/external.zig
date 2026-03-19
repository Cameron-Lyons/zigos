const std = @import("std");
const vga = @import("../drivers/vga.zig");
const console = @import("../utils/console.zig");
const process = @import("../process/process.zig");
const scheduler = @import("../process/scheduler.zig");
const environ = @import("../utils/environ.zig");
const common = @import("common.zig");
const parser = @import("parser.zig");
const posix = @import("../utils/posix.zig");
const vfs = @import("../fs/vfs.zig");
const cwd_mod = @import("../process/syscall/cwd.zig");

const sliceFromCStr = common.sliceFromCStr;
const printString = common.printString;
const MAX_COMMAND_LENGTH = parser.MAX_COMMAND_LENGTH;
const MAX_ARGS = parser.MAX_ARGS;
const MAX_EXTERNAL_LAUNCHES = 8;
const EXTERNAL_LAUNCH_LOOKUP_SIZE = 16;
const EXTERNAL_COMMAND_FILE_STORAGE_SIZE = 32768;

comptime {
    if ((EXTERNAL_LAUNCH_LOOKUP_SIZE & (EXTERNAL_LAUNCH_LOOKUP_SIZE - 1)) != 0) {
        @compileError("EXTERNAL_LAUNCH_LOOKUP_SIZE must be a power of two");
    }
}

pub const ExternalLaunchError = error{
    CommandNotFound,
    CommandPathTooLong,
    ArgumentTooLong,
    CommandReadFailed,
    CommandTooLarge,
    EnvironmentTooLarge,
    RedirectDupFailed,
    TooManyLaunches,
};

const ExternalCommandLaunch = struct {
    in_use: bool = false,
    pid: u32 = 0,
    path_len: usize = 0,
    argc: usize = 0,
    path: [MAX_COMMAND_LENGTH]u8 = [_]u8{0} ** MAX_COMMAND_LENGTH,
    argv_len: [MAX_ARGS]usize = [_]usize{0} ** MAX_ARGS,
    argv_storage: [MAX_ARGS][MAX_COMMAND_LENGTH]u8 = [_][MAX_COMMAND_LENGTH]u8{[_]u8{0} ** MAX_COMMAND_LENGTH} ** MAX_ARGS,
    envc: usize = 0,
    env_len: [environ.MAX_EXPORT_ENTRIES]usize = [_]usize{0} ** environ.MAX_EXPORT_ENTRIES,
    env_storage: [environ.MAX_EXPORT_ENTRIES][environ.MAX_EXPORT_ENTRY_LEN]u8 = [_][environ.MAX_EXPORT_ENTRY_LEN]u8{[_]u8{0} ** environ.MAX_EXPORT_ENTRY_LEN} ** environ.MAX_EXPORT_ENTRIES,
    file_len: usize = 0,
    file_storage: [EXTERNAL_COMMAND_FILE_STORAGE_SIZE]u8 = [_]u8{0} ** EXTERNAL_COMMAND_FILE_STORAGE_SIZE,
};

const ExternalLaunchRegistry = struct {
    launches: [MAX_EXTERNAL_LAUNCHES]ExternalCommandLaunch = [_]ExternalCommandLaunch{ExternalCommandLaunch{}} ** MAX_EXTERNAL_LAUNCHES,
    lookup: [EXTERNAL_LAUNCH_LOOKUP_SIZE]?*ExternalCommandLaunch = [_]?*ExternalCommandLaunch{null} ** EXTERNAL_LAUNCH_LOOKUP_SIZE,

    fn allocate(self: *ExternalLaunchRegistry) ExternalLaunchError!*ExternalCommandLaunch {
        for (&self.launches) |*launch| {
            if (!launch.in_use) {
                launch.in_use = true;
                launch.pid = 0;
                launch.path_len = 0;
                launch.argc = 0;
                launch.envc = 0;
                launch.file_len = 0;
                return launch;
            }
        }
        return error.TooManyLaunches;
    }

    fn release(self: *ExternalLaunchRegistry, launch: *ExternalCommandLaunch) void {
        launch.in_use = false;
        launch.pid = 0;
        launch.path_len = 0;
        launch.argc = 0;
        launch.envc = 0;
        launch.file_len = 0;
        self.rebuildLookup();
    }

    fn find(self: *ExternalLaunchRegistry, pid: u32) ?*ExternalCommandLaunch {
        if (pid == 0) return null;

        var idx = self.lookupIndex(pid);
        var attempts: usize = 0;
        while (attempts < self.lookup.len) : (attempts += 1) {
            const launch = self.lookup[idx] orelse return null;
            if (launch.in_use and launch.pid == pid) return launch;
            idx = (idx + 1) & (self.lookup.len - 1);
        }

        return null;
    }

    fn setPid(self: *ExternalLaunchRegistry, launch: *ExternalCommandLaunch, pid: u32) void {
        launch.pid = pid;
        self.rebuildLookup();
    }

    fn rebuildLookup(self: *ExternalLaunchRegistry) void {
        @memset(&self.lookup, null);
        for (&self.launches) |*launch| {
            if (!launch.in_use or launch.pid == 0) continue;
            self.insertLookup(launch);
        }
    }

    fn insertLookup(self: *ExternalLaunchRegistry, launch: *ExternalCommandLaunch) void {
        var idx = self.lookupIndex(launch.pid);
        while (self.lookup[idx] != null) {
            idx = (idx + 1) & (self.lookup.len - 1);
        }
        self.lookup[idx] = launch;
    }

    fn lookupIndex(self: *const ExternalLaunchRegistry, pid: u32) usize {
        return @intCast(pid & @as(u32, @intCast(self.lookup.len - 1)));
    }
};

var external_launch_registry = ExternalLaunchRegistry{};

pub fn releaseIfPresent(pid: u32) void {
    if (external_launch_registry.find(pid)) |launch| {
        external_launch_registry.release(launch);
    }
}

pub fn launchExternalCommand(command_args: []const [*:0]const u8, nice_value: ?i8, stdin_fd: ?i32, stdout_fd: ?i32) ExternalLaunchError!u32 {
    return launchExternalCommandWithEnv(command_args, null, nice_value, stdin_fd, stdout_fd);
}

pub fn launchExternalCommandWithEnv(command_args: []const [*:0]const u8, env_entries: ?[]const []const u8, nice_value: ?i8, stdin_fd: ?i32, stdout_fd: ?i32) ExternalLaunchError!u32 {
    if (command_args.len == 0) {
        return error.CommandNotFound;
    }

    var resolved_path_buffer: [MAX_COMMAND_LENGTH]u8 = undefined;
    const resolved_path = try resolveExternalCommandPath(sliceFromCStr(command_args[0]), &resolved_path_buffer);
    const launch = try external_launch_registry.allocate();
    errdefer external_launch_registry.release(launch);

    launch.path_len = resolved_path.len;
    @memcpy(launch.path[0..resolved_path.len], resolved_path);
    launch.argc = command_args.len;
    launch.envc = if (env_entries) |entries|
        try copyProvidedEnv(launch, entries)
    else
        environ.exportEntries(&launch.env_storage, &launch.env_len);
    launch.file_len = try readExternalCommandBytes(resolved_path, &launch.file_storage);

    var i: usize = 0;
    while (i < command_args.len) : (i += 1) {
        const arg = sliceFromCStr(command_args[i]);
        if (arg.len > launch.argv_storage[i].len) {
            return error.ArgumentTooLong;
        }
        @memcpy(launch.argv_storage[i][0..arg.len], arg);
        launch.argv_len[i] = arg.len;
    }

    const process_name = sliceFromCStr(command_args[0]);
    const irq_flags = disableInterrupts();
    const user_proc = process.create_exec_process(process_name);
    restoreInterrupts(irq_flags);
    if (process.getEffectiveCurrent()) |parent| {
        user_proc.creds = parent.creds;
    }
    user_proc.stdin_redirect = duplicateRedirectFd(stdin_fd) catch return error.RedirectDupFailed;
    errdefer process.cleanupStdioRedirects(user_proc);
    user_proc.stdout_redirect = duplicateRedirectFd(stdout_fd) catch return error.RedirectDupFailed;
    external_launch_registry.setPid(launch, user_proc.pid);

    if (nice_value) |nice| {
        if (!scheduler.setProcessNice(user_proc.pid, nice)) {
            _ = process.setNice(user_proc.pid, nice);
        }
    }

    return user_proc.pid;
}

fn copyProvidedEnv(launch: *ExternalCommandLaunch, entries: []const []const u8) ExternalLaunchError!usize {
    if (entries.len > launch.env_storage.len) return error.EnvironmentTooLarge;

    var count: usize = 0;
    while (count < entries.len) : (count += 1) {
        const entry = entries[count];
        if (entry.len > launch.env_storage[count].len) return error.EnvironmentTooLarge;

        @memset(&launch.env_storage[count], 0);
        @memcpy(launch.env_storage[count][0..entry.len], entry);
        launch.env_len[count] = entry.len;
    }

    return entries.len;
}

pub fn printExternalCommandError(command: [*:0]const u8, err: ExternalLaunchError) void {
    switch (err) {
        error.CommandNotFound => {
            console.print("Unknown command: ");
            console.print(sliceFromCStr(command));
            console.print("\nType 'help' for available commands.\n");
        },
        error.CommandPathTooLong => console.print("Command path too long\n"),
        error.ArgumentTooLong => console.print("Command argument too long\n"),
        error.CommandReadFailed => console.print("Failed to read command file\n"),
        error.CommandTooLarge => console.print("Command file too large\n"),
        error.EnvironmentTooLarge => console.print("Environment is too large for command launch\n"),
        error.RedirectDupFailed => console.print("Failed to duplicate redirected file descriptor\n"),
        error.TooManyLaunches => console.print("Too many commands are pending launch\n"),
    }
}

pub export fn external_command_entry_c() callconv(.c) void {
    const pid = process.getCurrentPID();
    const launch = external_launch_registry.find(pid) orelse {
        vga.print("exec: missing launch context\n");
        _ = process.terminateProcess(pid);
        return;
    };

    const path = launch.path[0..launch.path_len];
    var argv: [MAX_ARGS][]const u8 = undefined;
    var envp_values: [environ.MAX_EXPORT_ENTRIES][]const u8 = undefined;
    const argc = launch.argc;

    var i: usize = 0;
    while (i < argc) : (i += 1) {
        const arg_len = launch.argv_len[i];
        argv[i] = launch.argv_storage[i][0..arg_len];
    }

    i = 0;
    while (i < launch.envc) : (i += 1) {
        envp_values[i] = launch.env_storage[i][0..launch.env_len[i]];
    }

    posix.execveFromData(launch.file_storage[0..launch.file_len], argv[0..argc], envp_values[0..launch.envc]) catch |err| {
        console.print("Failed to execute ");
        console.print(path);
        console.print(": ");
        console.print(@errorName(err));
        console.print("\n");
        _ = process.terminateProcess(pid);
    };
}

fn duplicateRedirectFd(fd: ?i32) error{DupFailed}!?i32 {
    const value = fd orelse return null;
    if (value < @as(i32, @intCast(vfsAbiFdOffset()))) return value;

    const vfs_fd: u32 = @intCast(value - @as(i32, @intCast(vfsAbiFdOffset())));
    const duped = vfs.dup(vfs_fd) catch return error.DupFailed;
    return @as(i32, @intCast(duped)) + @as(i32, @intCast(vfsAbiFdOffset()));
}

fn vfsAbiFdOffset() u32 {
    return @import("../process/syscall/abi.zig").FD_OFFSET;
}

fn disableInterrupts() u32 {
    var flags: u32 = undefined;
    asm volatile (
        \\pushfl
        \\popl %[flags]
        \\cli
        : [flags] "=r" (flags),
    );
    return flags;
}

fn restoreInterrupts(flags: u32) void {
    asm volatile (
        \\pushl %[flags]
        \\popfl
        :
        : [flags] "r" (flags),
    );
}

fn readExternalCommandBytes(path: []const u8, buffer: []u8) ExternalLaunchError!usize {
    const fd = vfs.open(path, vfs.O_RDONLY) catch return error.CommandReadFailed;
    defer vfs.close(fd) catch {};

    var stat_buf: vfs.FileStat = undefined;
    vfs.fstat(fd, &stat_buf) catch return error.CommandReadFailed;
    const size: usize = @intCast(stat_buf.size);
    if (size > buffer.len) return error.CommandTooLarge;

    const bytes_read = vfs.read(fd, buffer[0..size]) catch return error.CommandReadFailed;
    if (bytes_read != size) return error.CommandReadFailed;
    return size;
}

fn resolveExternalCommandPath(command_name: []const u8, buffer: *[MAX_COMMAND_LENGTH]u8) ExternalLaunchError![]const u8 {
    if (command_name.len == 0) {
        return error.CommandNotFound;
    }

    if (isExplicitCommandPath(command_name)) {
        const direct_path = cwd_mod.resolvePath(command_name, buffer) orelse return error.CommandPathTooLong;
        switch (probeExternalCommandPath(direct_path)) {
            .exists => return direct_path,
            .missing => return error.CommandNotFound,
            .failed => |err| {
                logExternalPathProbeFailure(direct_path, err);
                return error.CommandNotFound;
            },
        }
    }

    const search_prefixes = [_][]const u8{ "/bin/", "/usr/bin/", "/mnt/bin/" };
    var path_too_long = true;

    for (search_prefixes) |prefix| {
        if (prefix.len + command_name.len > buffer.len) {
            continue;
        }

        path_too_long = false;
        @memcpy(buffer[0..prefix.len], prefix);
        @memcpy(buffer[prefix.len .. prefix.len + command_name.len], command_name);

        const candidate = buffer[0 .. prefix.len + command_name.len];
        switch (probeExternalCommandPath(candidate)) {
            .exists => return candidate,
            .missing => {},
            .failed => |err| {
                logExternalPathProbeFailure(candidate, err);
                return error.CommandNotFound;
            },
        }
    }

    if (path_too_long) {
        return error.CommandPathTooLong;
    }

    return error.CommandNotFound;
}

const CommandPathProbe = union(enum) {
    exists,
    missing,
    failed: vfs.VFSError,
};

fn probeExternalCommandPath(path: []const u8) CommandPathProbe {
    const fd = vfs.open(path, vfs.O_RDONLY) catch |err| {
        return if (err == vfs.VFSError.NotFound) .missing else .{ .failed = err };
    };
    vfs.close(fd) catch |err| return .{ .failed = err };
    return .exists;
}

fn logExternalPathProbeFailure(path: []const u8, err: vfs.VFSError) void {
    var line_buf: [192]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "command-path {s}: {s}\n", .{ @errorName(err), path }) catch "command-path failure\n";
    console.print(line);
}

fn isExplicitCommandPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/') return true;

    for (path) |char| {
        if (char == '/') return true;
    }

    return false;
}
