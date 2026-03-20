const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");
const fsutil = @import("fsutil");

pub const panic = runtime.panic;

const read_buffer_size = 512;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    var lines: usize = 10;
    var path_index: usize = 1;

    if (argc > 2) {
        const first = argv[1] orelse return 1;
        if (first[0] == '-' and first[1] == 'n') {
            lines = parseCount(first + 2) orelse lines;
            path_index = 2;
        }
    }

    if (path_index >= argc) {
        return if (writeHead(syscall.STDIN, lines, null)) 0 else 1;
    }

    const path = argv[path_index] orelse return 1;
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) {
        stdio.eprint("head: failed to open {s}\n", .{cstr.slice(path)});
        return 1;
    }
    defer _ = syscall.close(fd);

    return if (writeHead(fd, lines, path)) 0 else 1;
}

fn writeHead(fd: i32, max_lines: usize, path: ?[*:0]const u8) bool {
    var buffer: [read_buffer_size]u8 = undefined;
    var lines_left = max_lines;

    while (lines_left > 0) {
        const rc = syscall.read(fd, &buffer);
        if (rc == 0) return true;
        if (syscall.isError(rc)) {
            if (path) |value| {
                stdio.eprint("head: failed to read {s}\n", .{cstr.slice(value)});
            } else {
                stdio.eputs("head: failed to read stdin\n");
            }
            return false;
        }

        const chunk = buffer[0..@intCast(rc)];
        var emit_len = chunk.len;
        var i: usize = 0;
        while (i < chunk.len) : (i += 1) {
            if (chunk[i] == '\n') {
                lines_left -= 1;
                if (lines_left == 0) {
                    emit_len = i + 1;
                    break;
                }
            }
        }

        fsutil.writeAll(syscall.STDOUT, chunk[0..emit_len]) catch {
            stdio.eputs("head: failed to write output\n");
            return false;
        };

        if (emit_len != chunk.len) break;
    }

    return true;
}

fn parseCount(value: [*:0]const u8) ?usize {
    const slice = cstr.slice(value);
    if (slice.len == 0) return null;

    var result: usize = 0;
    for (slice) |char| {
        if (char < '0' or char > '9') return null;
        result = result * 10 + (char - '0');
    }
    return result;
}
