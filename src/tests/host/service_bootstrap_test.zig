const std = @import("std");
const contract = @import("../../native/session/contract.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const indexing_service = @import("../../native/services/indexing_service.zig");
const media_print_service = @import("../../native/services/media_print_service.zig");
const package_service = @import("../../native/services/package_service.zig");
const service_contract = @import("../../native/session/service_contracts.zig");
const supervisor = @import("../../native/session/supervisor.zig");

test "service bootstrap bootstrap modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(contract);
    std.testing.refAllDecls(driver_service);
    std.testing.refAllDecls(indexing_service);
    std.testing.refAllDecls(media_print_service);
    std.testing.refAllDecls(package_service);
    std.testing.refAllDecls(service_contract);
    std.testing.refAllDecls(supervisor);
}
