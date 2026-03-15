const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const buffer_size = 65;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc > 2) {
        stdio.eputs("hostname: usage: hostname [name]\n");
        return 1;
    }

    if (argc == 2) {
        const name = argv[1] orelse return 1;
        if (syscall.sethostname(sliceFromZ(name)) != 0) {
            stdio.eputs("hostname: failed to set hostname\n");
            return 1;
        }
        return 0;
    }

    var buffer: [buffer_size]u8 = undefined;
    if (syscall.gethostname(&buffer) != 0) {
        stdio.eputs("hostname: failed to get hostname\n");
        return 1;
    }

    stdio.puts(sliceFromBuffer(&buffer));
    stdio.puts("\n");
    return 0;
}

fn sliceFromZ(value: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (value[len] != 0) : (len += 1) {}
    return value[0..len];
}

fn sliceFromBuffer(buffer: *const [buffer_size]u8) []const u8 {
    var len: usize = 0;
    while (len < buffer.len and buffer[len] != 0) : (len += 1) {}
    return buffer[0..len];
}
