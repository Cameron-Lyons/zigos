const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");
const fsutil = @import("fsutil");
const textutil = @import("textutil");

pub const panic = runtime.panic;

const bytes_per_line = 16;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) return if (dumpFd(syscall.STDIN, null)) 0 else 1;

    const path = argv[1] orelse return 1;
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("hexdump: failed to open {s}\n", .{cstr.slice(path)});
        return 1;
    }
    defer _ = syscall.close(fd);
    return if (dumpFd(fd, path)) 0 else 1;
}

fn dumpFd(fd: i32, path: ?[*:0]const u8) bool {
    var buffer: [bytes_per_line]u8 = undefined;
    var offset: usize = 0;
    while (true) {
        const rc = syscall.read(fd, &buffer);
        if (rc == 0) return true;
        if (syscall.isError(rc)) {
            textutil.printReadError("hexdump", path);
            return false;
        }

        var line: [96]u8 = undefined;
        const line_len = formatLine(&line, offset, buffer[0..@intCast(rc)]);
        fsutil.writeAll(syscall.STDOUT, line[0..line_len]) catch return false;
        offset += @intCast(rc);
    }
}

fn formatLine(buffer: *[96]u8, offset: usize, data: []const u8) usize {
    var pos: usize = 0;
    appendHexWidth(buffer, &pos, offset, 8);
    buffer[pos] = ' ';
    pos += 1;
    buffer[pos] = ' ';
    pos += 1;

    var i: usize = 0;
    while (i < bytes_per_line) : (i += 1) {
        if (i < data.len) {
            appendHexWidth(buffer, &pos, data[i], 2);
        } else {
            buffer[pos] = ' ';
            buffer[pos + 1] = ' ';
            pos += 2;
        }
        if (i + 1 != bytes_per_line) {
            buffer[pos] = ' ';
            pos += 1;
        }
    }

    buffer[pos] = ' ';
    buffer[pos + 1] = ' ';
    pos += 2;
    for (data) |byte| {
        buffer[pos] = if (byte >= 32 and byte <= 126) byte else '.';
        pos += 1;
    }
    buffer[pos] = '\n';
    pos += 1;
    return pos;
}

fn appendHexWidth(buffer: *[96]u8, pos: *usize, value: usize, width: usize) void {
    const hex = "0123456789abcdef";
    var shift: usize = width * 4;
    while (shift > 0) {
        shift -= 4;
        buffer[pos.*] = hex[(value >> @intCast(shift)) & 0xF];
        pos.* += 1;
    }
}
