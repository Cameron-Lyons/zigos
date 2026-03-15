const cstr = @import("cstr");
const envutil = @import("envutil");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const path_buffer_size = 256;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    if (argc < 2) {
        stdio.eputs("which: usage: which <command> [command ...]\n");
        return 1;
    }

    const search_path = envutil.lookup(envp, "PATH") orelse envutil.default_path;
    var exit_code: i32 = 0;
    var i: usize = 1;
    while (i < argc) : (i += 1) {
        const command = argv[i] orelse continue;
        var resolved_buffer: [path_buffer_size]u8 = undefined;
        if (locateCommand(command, search_path, &resolved_buffer)) |resolved| {
            stdio.puts(resolved);
            stdio.puts("\n");
        } else {
            stdio.eprint("which: no {s} in PATH\n", .{cstr.slice(command)});
            exit_code = 1;
        }
    }

    return exit_code;
}

fn locateCommand(command: [*:0]const u8, search_path: []const u8, result_buffer: *[path_buffer_size]u8) ?[]const u8 {
    const command_slice = cstr.slice(command);
    if (containsSlash(command_slice)) {
        return if (pathExists(command)) command_slice else null;
    }

    var path_start: usize = 0;
    while (path_start <= search_path.len) {
        var path_end = path_start;
        while (path_end < search_path.len and search_path[path_end] != ':') : (path_end += 1) {}

        const dir = search_path[path_start..path_end];
        if (joinPath(result_buffer, dir, command_slice)) |candidate| {
            if (pathExists(@ptrCast(candidate.ptr))) return candidate;
        }

        if (path_end == search_path.len) break;
        path_start = path_end + 1;
    }

    return null;
}

fn joinPath(buffer: *[path_buffer_size]u8, dir: []const u8, command: []const u8) ?[]const u8 {
    const actual_dir = if (dir.len == 0) "." else dir;
    const needs_slash = actual_dir.len == 0 or actual_dir[actual_dir.len - 1] != '/';
    const total_len = actual_dir.len + @as(usize, if (needs_slash) 1 else 0) + command.len;
    if (total_len >= buffer.len) return null;

    @memcpy(buffer[0..actual_dir.len], actual_dir);
    var offset = actual_dir.len;
    if (needs_slash) {
        buffer[offset] = '/';
        offset += 1;
    }
    @memcpy(buffer[offset .. offset + command.len], command);
    buffer[total_len] = 0;
    return buffer[0..total_len];
}

fn pathExists(path: [*:0]const u8) bool {
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) return false;
    _ = syscall.close(fd);
    return true;
}

fn containsSlash(text: []const u8) bool {
    for (text) |char| {
        if (char == '/') return true;
    }
    return false;
}
