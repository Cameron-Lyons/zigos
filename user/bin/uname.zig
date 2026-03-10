const runtime = @import("runtime");
const stdio = @import("stdio");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    stdio.puts("ZigOS\n");
    return 0;
}
