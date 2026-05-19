const std = @import("std");

const contract = @import("../../native/session/contract.zig");
const service_bootstrap = @import("../../native/session/service_bootstrap.zig");
const service_catalog = @import("../../native/session/service_catalog.zig");
const service_contract = @import("../../native/session/service_contracts.zig");
const service_path_proofs = @import("../../native/session/service_path_proofs.zig");
const session_manager = @import("../../native/session/session_manager.zig");
const session_manager_test = @import("../../native/session/session_manager_test.zig");
const supervisor = @import("../../native/session/supervisor.zig");

test "session host tests import native session modules" {
    std.testing.refAllDecls(contract);
    std.testing.refAllDecls(service_bootstrap);
    std.testing.refAllDecls(service_catalog);
    std.testing.refAllDecls(service_contract);
    std.testing.refAllDecls(service_path_proofs);
    std.testing.refAllDecls(session_manager);
    std.testing.refAllDecls(session_manager_test);
    std.testing.refAllDecls(supervisor);
}
