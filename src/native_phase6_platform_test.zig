const std = @import("std");
const immutable_base = @import("kernel/process/native/immutable_base.zig");
const measured_boot = @import("kernel/process/native/measured_boot.zig");
const native_ux = @import("kernel/process/native/native_ux.zig");
const recovery_environment = @import("kernel/process/native/recovery_environment.zig");

test "phase6 native platform modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(immutable_base);
    std.testing.refAllDecls(measured_boot);
    std.testing.refAllDecls(native_ux);
    std.testing.refAllDecls(recovery_environment);
}
