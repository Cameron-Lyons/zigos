const std = @import("std");
const policy_port = @import("../../native/policy/policy_component_port.zig");
const review_port = @import("../../native/policy/review_component_port.zig");
const review_service = @import("../../native/policy/permission_review_service.zig");

test "phase2 ports compile and expose their test suites from the src root" {
    std.testing.refAllDecls(policy_port);
    std.testing.refAllDecls(review_port);
    std.testing.refAllDecls(review_service);
}
