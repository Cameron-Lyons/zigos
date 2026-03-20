const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;

    var index: usize = 0;
    while (true) : (index += 1) {
        const entry = envp[index] orelse break;
        stdio.puts(cstr.slice(entry));
        stdio.puts("\n");
    }

    return 0;
}
