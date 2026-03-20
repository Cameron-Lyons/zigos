const cstr = @import("cstr");
const runtime = @import("runtime");
const stdio = @import("stdio");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc <= 1) {
        stdio.puts("\n");
        return 0;
    }

    var i: usize = 1;
    while (i < argc) : (i += 1) {
        if (i > 1) {
            stdio.puts(" ");
        }
        stdio.puts(cstr.optionalSlice(argv[i]));
    }

    stdio.puts("\n");
    return 0;
}
