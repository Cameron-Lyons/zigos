const std = @import("std");

pub const debugger = @import("debugger.zig");
pub const example_apps = @import("example_apps.zig");
pub const idl = @import("idl.zig");
pub const app_platform = @import("app_platform.zig");
pub const simulator = @import("simulator.zig");

test "native app SDK exports developer platform modules" {
    std.testing.refAllDecls(app_platform);
    std.testing.refAllDecls(debugger);
    std.testing.refAllDecls(example_apps);
    std.testing.refAllDecls(idl);
    std.testing.refAllDecls(simulator);
}
