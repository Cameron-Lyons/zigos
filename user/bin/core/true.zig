const runtime = @import("runtime");

pub const panic = runtime.panic;

pub export fn main(_: usize, _: [*]const ?[*:0]const u8, _: [*]const ?[*:0]const u8) callconv(.c) i32 {
    return 0;
}
