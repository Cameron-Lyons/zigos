const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");
const fsutil = @import("fsutil");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc != 3) {
        stdio.eputs("cp: usage: cp <source> <destination>\n");
        return 1;
    }

    const source = argv[1] orelse return 1;
    const destination = argv[2] orelse return 1;
    return if (copyFile(source, destination)) 0 else 1;
}

fn copyFile(source: [*:0]const u8, destination: [*:0]const u8) bool {
    const source_fd = syscall.open(source, syscall.O_RDONLY);
    if (syscall.isError(source_fd)) {
        stdio.eprint("cp: failed to open {s}\n", .{cstr.slice(source)});
        return false;
    }
    defer _ = syscall.close(source_fd);

    const destination_fd = syscall.open(destination, syscall.O_WRONLY | syscall.O_CREAT | syscall.O_TRUNC);
    if (syscall.isError(destination_fd)) {
        stdio.eprint("cp: failed to open {s}\n", .{cstr.slice(destination)});
        return false;
    }
    defer _ = syscall.close(destination_fd);

    fsutil.copyFd(source_fd, destination_fd) catch |err| {
        stdio.eprint("cp: failed to copy {s} to {s}: {s}\n", .{ cstr.slice(source), cstr.slice(destination), @errorName(err) });
        return false;
    };

    return true;
}
