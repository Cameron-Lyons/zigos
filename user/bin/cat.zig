const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        return if (catStdin()) 0 else 1;
    }

    var exit_code: i32 = 0;
    var i: usize = 1;
    while (i < argc) : (i += 1) {
        const path = argv[i] orelse continue;
        if (!catFile(path)) {
            exit_code = 1;
        }
    }

    return exit_code;
}

fn catStdin() bool {
    var buffer: [512]u8 = undefined;
    while (true) {
        const rc = syscall.read(syscall.STDIN, &buffer);
        if (rc == 0) return true;
        if (syscall.isError(rc)) {
            stdio.eputs("cat: failed to read stdin\n");
            return false;
        }
        stdio.writeAll(syscall.STDOUT, buffer[0..@intCast(rc)]);
    }
}

fn catFile(path: [*:0]const u8) bool {
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("cat: failed to open {s}\n", .{cstr.slice(path)});
        return false;
    }
    defer _ = syscall.close(fd);

    var buffer: [512]u8 = undefined;
    while (true) {
        const rc = syscall.read(fd, &buffer);
        if (rc == 0) return true;
        if (syscall.isError(rc)) {
            stdio.eprint("cat: failed to read {s}\n", .{cstr.slice(path)});
            return false;
        }
        stdio.writeAll(syscall.STDOUT, buffer[0..@intCast(rc)]);
    }
}
