const std = @import("std");

const service_bootstrap = @import("../../native/session/service_bootstrap.zig");
const service_catalog = @import("../../native/session/service_catalog.zig");
const service_path_proofs = @import("../../native/session/proofs/service_path_proofs.zig");
const session_manager = @import("../../native/session/session_manager.zig");
const session_manager_test = @import("../../native/session/session_manager_test.zig");
const supervisor = @import("../../native/session/supervisor.zig");

test "session host tests import native session modules" {
    std.testing.refAllDecls(service_bootstrap);
    std.testing.refAllDecls(service_catalog);
    std.testing.refAllDecls(service_path_proofs);
    std.testing.refAllDecls(session_manager);
    std.testing.refAllDecls(session_manager_test);
    std.testing.refAllDecls(supervisor);
}
