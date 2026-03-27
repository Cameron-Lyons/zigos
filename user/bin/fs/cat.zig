const cstr = @import("cstr");
const cli = @import("cli");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");
const textutil = @import("textutil");

pub const panic = runtime.panic;
const io_buffer_size = 512;
const CatError = error{ReadFailed};

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        return if (catStdin()) 0 else 1;
    }

    return cli.forEachOperand(argc, argv, catFile);
}

fn copyFdToStdout(fd: i32) CatError!void {
    var buffer: [io_buffer_size]u8 = undefined;
    while (true) {
        const rc = syscall.read(fd, &buffer);
        if (rc == 0) return;
        if (syscall.isError(rc)) return error.ReadFailed;
        stdio.writeAll(syscall.STDOUT, buffer[0..@intCast(rc)]);
    }
}

fn catStdin() bool {
    copyFdToStdout(syscall.STDIN) catch {
        textutil.printReadError("cat", null);
        return false;
    };
    return true;
}

fn catFile(path: [*:0]const u8) bool {
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("cat: failed to open {s}\n", .{cstr.slice(path)});
        return false;
    }
    defer _ = syscall.close(fd);

    copyFdToStdout(fd) catch {
        textutil.printReadError("cat", path);
        return false;
    };
    return true;
}
