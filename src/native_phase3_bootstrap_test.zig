const std = @import("std");
const contract = @import("kernel/process/native/contract.zig");
const driver_service = @import("kernel/process/native/driver_service.zig");
const indexing_service = @import("kernel/process/native/indexing_service.zig");
const media_print_service = @import("kernel/process/native/media_print_service.zig");
const package_service = @import("kernel/process/native/package_service.zig");
const service_contract = @import("kernel/process/native/service_contract.zig");
const supervisor = @import("kernel/process/native/supervisor.zig");

test "phase3 native bootstrap modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(contract);
    std.testing.refAllDecls(driver_service);
    std.testing.refAllDecls(indexing_service);
    std.testing.refAllDecls(media_print_service);
    std.testing.refAllDecls(package_service);
    std.testing.refAllDecls(service_contract);
    std.testing.refAllDecls(supervisor);
}
