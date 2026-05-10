const recovery_suite = @import("../recovery_suite.zig");

pub fn run() noreturn {
    recovery_suite.run();
}
