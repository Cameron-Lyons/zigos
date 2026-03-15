const syscall = @import("syscall");

pub const CopyError = error{ ReadFailed, WriteFailed };

const copy_buffer_size = 1024;

pub fn writeAll(fd: i32, buffer: []const u8) CopyError!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const rc = syscall.write(fd, buffer[offset..]);
        if (rc <= 0) return error.WriteFailed;
        offset += @intCast(rc);
    }
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
