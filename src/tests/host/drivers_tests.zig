const std = @import("std");

const accelerator_driver_task = @import("../../native/drivers/accelerator_driver_task.zig");
const bootstrap_driver_port = @import("../../native/drivers/bootstrap_driver_port.zig");
const device_inventory = @import("../../native/drivers/device_inventory.zig");
const driver_runtime = @import("../../native/drivers/driver_runtime.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const first_target_telemetry = @import("../../kernel/drivers/first_target_telemetry.zig");
const intel_i225_tx = @import("../../kernel/drivers/intel_i225_tx.zig");
const network_driver_task = @import("../../native/drivers/network_driver_task.zig");

test "driver host tests import native driver modules" {
    std.testing.refAllDecls(accelerator_driver_task);
    std.testing.refAllDecls(bootstrap_driver_port);
    std.testing.refAllDecls(device_inventory);
    std.testing.refAllDecls(driver_runtime);
    std.testing.refAllDecls(driver_service);
    std.testing.refAllDecls(first_target_telemetry);
    std.testing.refAllDecls(intel_i225_tx);
    std.testing.refAllDecls(network_driver_task);
}
