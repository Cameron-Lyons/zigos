const manifest = @import("../policy/manifest.zig");
const permission_review = @import("../policy/permission_review.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const ui = @import("ui.zig");

pub const MAX_REVIEW_NODES: usize = permission_review.MAX_REVIEW_DECISIONS + 4;
pub const ReviewCommand = permission_review.ReviewCommand;
pub const ReviewDecision = permission_review.ReviewDecision;
pub const UserGrant = policy_mediation.UserGrant;

pub const ReviewPlan = struct {
    session: permission_review.ReviewSession,
    grant_count: usize = 0,
    grants: [permission_review.MAX_REVIEW_DECISIONS]UserGrant =
        [_]UserGrant{.{ .kind = .object_access }} ** permission_review.MAX_REVIEW_DECISIONS,
    node_count: usize = 0,
    nodes: [MAX_REVIEW_NODES]ui.Node = undefined,

    pub fn grantSlice(self: *const ReviewPlan) []const UserGrant {
        return self.grants[0..self.grant_count];
    }
};

pub fn buildReviewPlan(
    task_id: u64,
    bundle: *const manifest.BundleManifest,
    commands: []const ReviewCommand,
) !ReviewPlan {
    var decisions = [_]ReviewDecision{.{
        .kind = .object_access,
        .resource = "",
        .allow = false,
    }} ** permission_review.MAX_REVIEW_DECISIONS;
    var decision_count: usize = 0;
    for (bundle.requested_permissions, 0..) |request, index| {
        if (decision_count >= decisions.len) return error.TooManyPermissions;
        const command = if (index < commands.len) commands[index] else defaultCommand(request);
        decisions[decision_count] = permission_review.decisionFromCommand(request, command);
        decision_count += 1;
    }

    var plan = ReviewPlan{
        .session = permission_review.initSession(task_id, bundle, decisions[0..decision_count]),
    };
    const grants = permission_review.decisionsToGrants(bundle, plan.session.decisions[0..plan.session.decision_count], 1, &plan.grants);
    plan.grant_count = grants.len;
    buildReviewUi(bundle, &plan);
    return plan;
}

pub fn renderReviewText(
    plan: *const ReviewPlan,
    bundle: *const manifest.BundleManifest,
    out: []u8,
) ![]const u8 {
    return permission_review.renderToBuffer(out, &plan.session, bundle);
}

pub fn renderReviewUi(plan: *const ReviewPlan, out: []u8) ![]const u8 {
    var child_refs: [MAX_REVIEW_NODES]*const ui.Node = undefined;
    for (plan.nodes[0..plan.node_count], 0..) |*node, index| {
        child_refs[index] = node;
    }
    const root = ui.window(100, "Permission Review", child_refs[0..plan.node_count]);
    return ui.render(&root, out);
}

fn buildReviewUi(bundle: *const manifest.BundleManifest, plan: *ReviewPlan) void {
    plan.nodes[0] = ui.text(1, bundle.display_name);
    plan.node_count = 1;

    for (bundle.requested_permissions, 0..) |request, index| {
        if (plan.node_count >= plan.nodes.len) break;
        const allowed = index < plan.session.decision_count and plan.session.decisions[index].allow;
        plan.nodes[plan.node_count] = ui.permissionRow(@intCast(10 + index), permissionLabel(request.kind), allowed);
        plan.node_count += 1;
    }
}

fn defaultCommand(request: manifest.PermissionRequest) ReviewCommand {
    return .{
        .allow = true,
        .local_only = request.local_only,
        .lease_ticks = if (request.max_lease_ticks == 0) null else request.max_lease_ticks,
    };
}

fn permissionLabel(kind: manifest.PermissionKind) []const u8 {
    return switch (kind) {
        .object_access => "Object access",
        .network_egress => "Network egress",
        .device_access => "Device access",
        .clipboard => "Clipboard",
        .camera => "Camera",
        .mic => "Microphone",
        .sensor => "Sensor",
        .location => "Location",
        .contacts => "Contacts",
        .screen_capture => "Screen capture",
        .notification_post => "Notifications",
        .background_execution => "Background execution",
        .peer_ipc => "Peer IPC",
    };
}

test "permission SDK builds grants and a native UI review tree" {
    const examples = @import("example_apps.zig");
    const package = examples.firstPartyStudio();
    const plan = try buildReviewPlan(77, &package.bundle, &.{});
    try @import("std").testing.expect(plan.grant_count >= manifest.requiredPermissionCount(package.bundle));

    var text_buffer: [4096]u8 = undefined;
    const rendered_text = try renderReviewText(&plan, &package.bundle, &text_buffer);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, rendered_text, "Zigos Studio") != null);

    var ui_buffer: [ui.MAX_RENDER_BYTES]u8 = undefined;
    const rendered_ui = try renderReviewUi(&plan, &ui_buffer);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, rendered_ui, "role=permission_row") != null);
}
