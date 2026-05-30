const std = @import("std");

const core = @import("core_tests.zig");
const drivers = @import("drivers_tests.zig");
const kernel_api = @import("kernel_api_tests.zig");
const platform = @import("platform_tests.zig");
const policy = @import("policy_tests.zig");
const services = @import("services_tests.zig");
const session = @import("session_tests.zig");
const sdk = @import("sdk_tests.zig");
const storage = @import("storage_tests.zig");
const sync = @import("sync_tests.zig");
const task = @import("task_tests.zig");
const tools = @import("tools_tests.zig");

test "native host root imports domain test suites" {
    std.testing.refAllDecls(core);
    std.testing.refAllDecls(drivers);
    std.testing.refAllDecls(kernel_api);
    std.testing.refAllDecls(platform);
    std.testing.refAllDecls(policy);
    std.testing.refAllDecls(services);
    std.testing.refAllDecls(session);
    std.testing.refAllDecls(sdk);
    std.testing.refAllDecls(storage);
    std.testing.refAllDecls(sync);
    std.testing.refAllDecls(task);
    std.testing.refAllDecls(tools);
}
