const std = @import("std");

pub const debugger = @import("debugger.zig");
pub const example_apps = @import("example_apps.zig");
pub const component_abi = @import("component_abi.zig");
pub const fixtures = @import("fixtures.zig");
pub const idl = @import("idl.zig");
pub const app_platform = @import("app_platform.zig");
pub const manifest = @import("../policy/manifest.zig");
pub const manifest_linter = @import("manifest_linter.zig");
pub const object_store_api = @import("object_store_api.zig");
pub const package_signing = @import("package_signing.zig");
pub const permissions = @import("permissions.zig");
pub const simulator = @import("simulator.zig");
pub const sync_api = @import("sync_api.zig");
pub const ui = @import("ui.zig");

test "native app SDK exports developer platform modules" {
    std.testing.refAllDecls(app_platform);
    std.testing.refAllDecls(component_abi);
    std.testing.refAllDecls(debugger);
    std.testing.refAllDecls(example_apps);
    std.testing.refAllDecls(fixtures);
    std.testing.refAllDecls(idl);
    std.testing.refAllDecls(manifest_linter);
    std.testing.refAllDecls(object_store_api);
    std.testing.refAllDecls(package_signing);
    std.testing.refAllDecls(permissions);
    std.testing.refAllDecls(simulator);
    std.testing.refAllDecls(sync_api);
    std.testing.refAllDecls(ui);
}
