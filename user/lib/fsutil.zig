const syscall = @import("syscall");

pub const CopyError = error{ ReadFailed, WriteFailed };
pub const ReadAllError = error{ ReadFailed, BufferTooSmall };

const copy_buffer_size = 1024;

pub fn writeAll(fd: i32, buffer: []const u8) CopyError!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const rc = syscall.write(fd, buffer[offset..]);
        if (rc <= 0) return error.WriteFailed;
        offset += @intCast(rc);
    }
}

pub fn readFile(path: [*:0]const u8, buffer: []u8) ReadAllError![]u8 {
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) return error.ReadFailed;
    defer _ = syscall.close(fd);
    return readAll(fd, buffer);
}

pub fn copyFd(source_fd: i32, destination_fd: i32) CopyError!void {
    var buffer: [copy_buffer_size]u8 = undefined;

    while (true) {
        const rc = syscall.read(source_fd, &buffer);
        if (rc == 0) return;
        if (syscall.isError(rc)) return error.ReadFailed;

        try writeAll(destination_fd, buffer[0..@intCast(rc)]);
    }
}

pub fn readAll(fd: i32, buffer: []u8) ReadAllError![]u8 {
    var used: usize = 0;
    while (true) {
        if (used >= buffer.len) return error.BufferTooSmall;

        const rc = syscall.read(fd, buffer[used..]);
        if (rc == 0) return buffer[0..used];
        if (syscall.isError(rc)) return error.ReadFailed;
        used += @intCast(rc);
    }
}
