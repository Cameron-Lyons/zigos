const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const read_buffer_size = 512;

const Counts = struct {
    lines: usize = 0,
    words: usize = 0,
    bytes: usize = 0,
};

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 2) {
        return if (printCounts(syscall.STDIN, null)) 0 else 1;
    }

    var exit_code: i32 = 0;
    var i: usize = 1;
    while (i < argc) : (i += 1) {
        const path = argv[i] orelse continue;
        const fd = syscall.open(path, syscall.O_RDONLY);
        if (syscall.isError(fd)) {
            stdio.eprint("wc: failed to open {s}\n", .{cstr.slice(path)});
            exit_code = 1;
            continue;
        }

        if (!printCounts(fd, path)) exit_code = 1;
        _ = syscall.close(fd);
    }

    return exit_code;
}

fn printCounts(fd: i32, path: ?[*:0]const u8) bool {
    const counts = countFd(fd, path) orelse return false;

    stdio.print("{d} {d} {d}", .{ counts.lines, counts.words, counts.bytes });
    if (path) |value| {
        stdio.print(" {s}", .{cstr.slice(value)});
    }
    stdio.puts("\n");
    return true;
}

fn countFd(fd: i32, path: ?[*:0]const u8) ?Counts {
    var counts = Counts{};
    var buffer: [read_buffer_size]u8 = undefined;
    var in_word = false;

    while (true) {
        const rc = syscall.read(fd, &buffer);
        if (rc == 0) return counts;
        if (syscall.isError(rc)) {
            if (path) |value| {
                stdio.eprint("wc: failed to read {s}\n", .{cstr.slice(value)});
            } else {
                stdio.eputs("wc: failed to read stdin\n");
            }
            return null;
        }

        const chunk = buffer[0..@intCast(rc)];
        counts.bytes += chunk.len;
        for (chunk) |byte| {
            if (byte == '\n') counts.lines += 1;
            if (byte == ' ' or byte == '\n' or byte == '\t' or byte == '\r') {
                in_word = false;
            } else if (!in_word) {
                in_word = true;
                counts.words += 1;
            }
        }
    }
}
