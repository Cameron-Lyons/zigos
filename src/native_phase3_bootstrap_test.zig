const std = @import("std");
const contract = @import("kernel/process/native/contract.zig");
const driver_service = @import("kernel/process/native/driver_service.zig");
const service_contract = @import("kernel/process/native/service_contract.zig");
const supervisor = @import("kernel/process/native/supervisor.zig");

test "phase3 native bootstrap modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(contract);
    std.testing.refAllDecls(driver_service);
    std.testing.refAllDecls(service_contract);
    std.testing.refAllDecls(supervisor);
}
