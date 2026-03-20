const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;
const dirent_buffer_size = 512;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    const path = if (argc > 1) argv[1].? else "/";
    return if (listDirectory(path)) 0 else 1;
}

fn listDirectory(path: [*:0]const u8) bool {
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("ls: failed to open {s}\n", .{cstr.slice(path)});
        return false;
    }
    defer _ = syscall.close(fd);

    var buffer: [dirent_buffer_size]u8 = undefined;
    while (true) {
        const rc = syscall.getdents(fd, &buffer);
        if (rc == 0) return true;
        if (syscall.isError(rc)) {
            stdio.eprint("ls: failed to read {s}\n", .{cstr.slice(path)});
            return false;
        }

        var offset: usize = 0;
        const total: usize = @intCast(rc);
        while (offset < total) {
            const dirent: *align(1) const syscall.LinuxDirent = @ptrCast(&buffer[offset]);
            const name_start = offset + @sizeOf(syscall.LinuxDirent);
            const record_end = offset + dirent.d_reclen;
            var name_end = name_start;
            while (name_end < record_end and buffer[name_end] != 0) : (name_end += 1) {}

            if (dirent.d_type == syscall.DT_DIR) {
                stdio.puts("[DIR] ");
            } else {
                stdio.puts("      ");
            }
            stdio.puts(buffer[name_start..name_end]);
            stdio.puts("\n");

            offset = record_end;
        }
    }
}
