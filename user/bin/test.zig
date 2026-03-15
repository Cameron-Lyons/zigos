const cstr = @import("cstr");
const runtime = @import("runtime");
const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    const args = argv[1..argc];
    return eval(args) catch |err| {
        if (err == error.InvalidUsage) {
            stdio.eputs("test: unsupported expression\n");
            return 2;
        }
        return 1;
    };
}

fn eval(args: []const ?[*:0]const u8) error{InvalidUsage}!i32 {
    if (args.len == 0) return 1;
    if (args.len == 1) {
        return if (cstr.slice(args[0] orelse return 1).len != 0) 0 else 1;
    }

    if (args.len == 2) {
        const op = cstr.slice(args[0] orelse return error.InvalidUsage);
        const value = args[1] orelse return error.InvalidUsage;
        const slice = cstr.slice(value);
        if (std.mem.eql(u8, op, "-n")) return if (slice.len != 0) 0 else 1;
        if (std.mem.eql(u8, op, "-z")) return if (slice.len == 0) 0 else 1;
        if (std.mem.eql(u8, op, "-e")) return if (pathExists(value)) 0 else 1;
        return error.InvalidUsage;
    }

    if (args.len == 3) {
        const left = cstr.slice(args[0] orelse return error.InvalidUsage);
        const op = cstr.slice(args[1] orelse return error.InvalidUsage);
        const right = cstr.slice(args[2] orelse return error.InvalidUsage);
        if (std.mem.eql(u8, op, "=")) return if (std.mem.eql(u8, left, right)) 0 else 1;
        if (std.mem.eql(u8, op, "!=")) return if (!std.mem.eql(u8, left, right)) 0 else 1;
        return error.InvalidUsage;
    }

    return error.InvalidUsage;
}

fn pathExists(path: [*:0]const u8) bool {
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) return false;
    _ = syscall.close(fd);
    return true;
}
