const benchmark_suite = @import("../benchmark_suite.zig");

pub fn run() noreturn {
    benchmark_suite.run();
}
