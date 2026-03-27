const cstr = @import("cstr");
const fsutil = @import("fsutil");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");
const textutil = @import("textutil");

pub const panic = runtime.panic;

const buffer_size = 4096;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    var lines: usize = 10;
    var path_index: usize = 1;
    if (argc > 2) {
        const first = argv[1] orelse return 1;
        if (first[0] == '-' and first[1] == 'n') {
            lines = textutil.parseCount(first + 2) orelse {
                stdio.eputs("tail: invalid count\n");
                return 1;
            };
            path_index = 2;
        }
    }

    if (path_index >= argc) {
        return if (writeTail(syscall.STDIN, lines, null)) 0 else 1;
    }

    const path = argv[path_index] orelse return 1;
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("tail: failed to open {s}\n", .{cstr.slice(path)});
        return 1;
    }
    defer _ = syscall.close(fd);
    return if (writeTail(fd, lines, path)) 0 else 1;
}

fn writeTail(fd: i32, lines: usize, path: ?[*:0]const u8) bool {
    var buffer: [buffer_size]u8 = undefined;
    const content = fsutil.readAll(fd, &buffer) catch |err| {
        textutil.printReadAllError("tail", path, err);
        return false;
    };

    const start = findTailStart(content, lines);
    fsutil.writeAll(syscall.STDOUT, content[start..]) catch {
        stdio.eputs("tail: failed to write output\n");
        return false;
    };
    if (content.len != 0 and content[content.len - 1] != '\n') {
        fsutil.writeAll(syscall.STDOUT, "\n") catch return false;
    }
    return true;
}

fn findTailStart(content: []const u8, lines: usize) usize {
    if (lines == 0 or content.len == 0) return content.len;

    var seen: usize = 0;
    var idx = content.len;
    while (idx > 0) {
        idx -= 1;
        if (content[idx] == '\n') {
            seen += 1;
            if (seen > lines) return idx + 1;
        }
    }
    return 0;
}
