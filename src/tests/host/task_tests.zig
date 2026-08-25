const std = @import("std");

const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
const background_dispatch = @import("../../native/task/background_dispatch.zig");
const process_isolation = @import("../../native/task/process_isolation.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const task_runtime_service = @import("../../native/task/task_runtime_service.zig");
const userspace_bootstrap_mailbox = @import("../../native/task/userspace_bootstrap_mailbox.zig");
const userspace_boot_registry = @import("../../native/task/userspace_boot_registry.zig");
const userspace_contract_registry = @import("../../native/task/userspace_contract_registry.zig");
const userspace_executor = @import("../../native/task/userspace_executor.zig");
const userspace_launch = @import("../../native/task/userspace_launch.zig");
const userspace_loader = @import("../../native/task/userspace_loader.zig");
const userspace_manifest_signing = @import("../../native/task/userspace_manifest_signing.zig");
const userspace_registry = @import("../../native/task/userspace_registry.zig");
const userspace_scheduler = @import("../../native/task/userspace_scheduler.zig");
const userspace_service_protocol = @import("../../native/task/userspace_service_protocol.zig");

test "task host tests import native task modules" {
    std.testing.refAllDecls(accelerator_scheduler);
    std.testing.refAllDecls(background_dispatch);
    std.testing.refAllDecls(process_isolation);
    std.testing.refAllDecls(task_runtime);
    std.testing.refAllDecls(task_runtime_service);
    std.testing.refAllDecls(userspace_bootstrap_mailbox);
    std.testing.refAllDecls(userspace_boot_registry);
    std.testing.refAllDecls(userspace_contract_registry);
    std.testing.refAllDecls(userspace_executor);
    std.testing.refAllDecls(userspace_launch);
    std.testing.refAllDecls(userspace_loader);
    std.testing.refAllDecls(userspace_manifest_signing);
    std.testing.refAllDecls(userspace_registry);
    std.testing.refAllDecls(userspace_scheduler);
    std.testing.refAllDecls(userspace_service_protocol);
}
