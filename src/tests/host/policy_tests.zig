const std = @import("std");

const bootstrap_review_profile = @import("../../native/policy/bootstrap_review_profile.zig");
const denial_explanation = @import("../../native/policy/denial_explanation.zig");
const enterprise_management = @import("../../native/policy/enterprise_management.zig");
const humane_permissions = @import("../../native/policy/humane_permissions.zig");
const manifest = @import("../../native/policy/manifest.zig");
const permission_review = @import("../../native/policy/permission_review.zig");
const permission_review_service = @import("../../native/policy/permission_review_service.zig");
const policy_component_port = @import("../../native/policy/policy_component_port.zig");
const policy_example_enforcement = @import("../../native/policy/policy_example_enforcement.zig");
const policy_mediation = @import("../../native/policy/policy_mediation.zig");
const policy_object = @import("../../native/policy/policy_object.zig");
const review_component_port = @import("../../native/policy/review_component_port.zig");

test "policy host tests import native policy modules" {
    std.testing.refAllDecls(bootstrap_review_profile);
    std.testing.refAllDecls(denial_explanation);
    std.testing.refAllDecls(enterprise_management);
    std.testing.refAllDecls(humane_permissions);
    std.testing.refAllDecls(manifest);
    std.testing.refAllDecls(permission_review);
    std.testing.refAllDecls(permission_review_service);
    std.testing.refAllDecls(policy_component_port);
    std.testing.refAllDecls(policy_example_enforcement);
    std.testing.refAllDecls(policy_mediation);
    std.testing.refAllDecls(policy_object);
    std.testing.refAllDecls(review_component_port);
}
