const std = @import("std");

const manifest = @import("../policy/manifest.zig");
const permission_review = @import("../policy/permission_review.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const ui = @import("ui.zig");

pub const MAX_REVIEW_NODES: usize = permission_review.MAX_REVIEW_DECISIONS + 4;
pub const MAX_REVIEW_TEXT_BYTES: usize = ui.MAX_RENDER_BYTES;
pub const COMPACT_PERMISSION_REVIEW_METADATA = true;
pub const DERIVES_HARNESS_COMMAND_COUNT = true;
pub const REVIEW_PLAN_SIZE_CEILING_BYTES: usize = 3_616;
pub const HARNESS_RESULT_SIZE_CEILING_BYTES: usize = 3_624;
pub const HARNESS_SIZE_CEILING_BYTES: usize = 400;
pub const ReviewCommand = permission_review.ReviewCommand;
pub const ReviewDecision = permission_review.ReviewDecision;
pub const UserGrant = policy_mediation.UserGrant;
pub const HarnessError = error{PermissionNotRequested};

comptime {
    if (permission_review.MAX_REVIEW_DECISIONS > std.math.maxInt(u8) or
        MAX_REVIEW_NODES > std.math.maxInt(u8))
    {
        @compileError("SDK permission review state exceeds compact count metadata capacity");
    }
}

pub const ReviewPlan = struct {
    session: permission_review.ReviewSession,
    grant_count: u8 = 0,
    node_count: u8 = 0,
    grants: [permission_review.MAX_REVIEW_DECISIONS]UserGrant =
        [_]UserGrant{.{ .kind = .object_access }} ** permission_review.MAX_REVIEW_DECISIONS,
    nodes: [MAX_REVIEW_NODES]ui.Node = undefined,

    pub fn grantSlice(self: *const ReviewPlan) []const UserGrant {
        return self.grants[0..@as(usize, self.grant_count)];
    }
};

pub const HarnessResult = struct {
    plan: ReviewPlan,
    required_count: u8 = 0,
    optional_count: u8 = 0,
    denied_required_count: u8 = 0,
    denied_optional_count: u8 = 0,

    pub fn allRequiredGranted(self: *const HarnessResult) bool {
        return self.denied_required_count == 0;
    }
};

pub const Harness = struct {
    task_id: u64,
    bundle: *const manifest.BundleManifest,
    commands: [permission_review.MAX_REVIEW_DECISIONS]ReviewCommand =
        [_]ReviewCommand{.{ .allow = true }} ** permission_review.MAX_REVIEW_DECISIONS,

    pub fn init(task_id: u64, bundle: *const manifest.BundleManifest) Harness {
        var harness = Harness{
            .task_id = task_id,
            .bundle = bundle,
        };
        for (bundle.requested_permissions[0..harness.commandCount()], 0..) |request, index| {
            harness.commands[index] = defaultCommand(request);
        }
        return harness;
    }

    pub fn commandCount(self: *const Harness) usize {
        return @min(self.bundle.requested_permissions.len, permission_review.MAX_REVIEW_DECISIONS);
    }

    pub fn allow(self: *Harness, kind: manifest.PermissionKind) HarnessError!void {
        try self.set(kind, null, .{ .allow = true, .local_only = true });
    }

    pub fn deny(self: *Harness, kind: manifest.PermissionKind) HarnessError!void {
        try self.set(kind, null, .{ .allow = false });
    }

    pub fn run(self: *const Harness) !HarnessResult {
        const command_count = self.commandCount();
        var result = HarnessResult{
            .plan = try buildReviewPlan(self.task_id, self.bundle, self.commands[0..command_count]),
        };

        for (self.bundle.requested_permissions[0..command_count], 0..) |request, index| {
            if (request.required) {
                result.required_count += 1;
            } else {
                result.optional_count += 1;
            }

            if (!self.commands[index].allow) {
                if (request.required) {
                    result.denied_required_count += 1;
                } else {
                    result.denied_optional_count += 1;
                }
            }
        }

        return result;
    }

    fn set(
        self: *Harness,
        kind: manifest.PermissionKind,
        resource: ?[]const u8,
        command: ReviewCommand,
    ) HarnessError!void {
        const index = self.find(kind, resource) orelse return error.PermissionNotRequested;
        self.commands[index] = command;
    }

    fn find(self: *const Harness, kind: manifest.PermissionKind, resource: ?[]const u8) ?usize {
        for (self.bundle.requested_permissions[0..self.commandCount()], 0..) |request, index| {
            if (request.kind != kind) continue;
            if (resource) |expected| {
                if (!std.mem.eql(u8, request.resource, expected)) continue;
            }
            return index;
        }
        return null;
    }
};

comptime {
    if (@sizeOf(ReviewPlan) > REVIEW_PLAN_SIZE_CEILING_BYTES or
        @sizeOf(HarnessResult) > HARNESS_RESULT_SIZE_CEILING_BYTES or
        @sizeOf(Harness) > HARNESS_SIZE_CEILING_BYTES)
    {
        @compileError("SDK permission review state exceeds its compact size ceiling");
    }
}

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
        .session = try permission_review.initSession(task_id, bundle, decisions[0..decision_count]),
    };
    const grants = permission_review.decisionsToGrants(&plan.session, 1, &plan.grants);
    plan.grant_count = @intCast(grants.len);
    buildReviewUi(bundle, &plan);
    return plan;
}

pub fn renderReviewText(
    plan: *const ReviewPlan,
    out: []u8,
) ![]const u8 {
    return permission_review.renderToBuffer(out, &plan.session);
}

pub fn renderReviewUi(plan: *const ReviewPlan, out: []u8) ![]const u8 {
    var child_refs: [MAX_REVIEW_NODES]*const ui.Node = undefined;
    for (plan.nodes[0..@as(usize, plan.node_count)], 0..) |*node, index| {
        child_refs[index] = node;
    }
    const root = ui.window(100, "Permission Review", child_refs[0..@as(usize, plan.node_count)]);
    return ui.render(&root, out);
}

fn buildReviewUi(bundle: *const manifest.BundleManifest, plan: *ReviewPlan) void {
    plan.nodes[0] = ui.text(1, bundle.display_name);
    plan.node_count = 1;

    for (bundle.requested_permissions, 0..) |request, index| {
        if (plan.node_count >= plan.nodes.len) break;
        const allowed = index < plan.session.decision_count and plan.session.decisions[index].allow;
        plan.nodes[plan.node_count] = ui.permissionRow(@intCast(10 + index), manifest.permissionDisplayLabel(request.kind), allowed);
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

test "permission SDK keeps bounded review results compact" {
    try std.testing.expect(DERIVES_HARNESS_COMMAND_COUNT);
    try std.testing.expect(!@hasField(Harness, "command_count"));
    try std.testing.expect(@hasDecl(Harness, "commandCount"));
    try std.testing.expectEqual(u8, @FieldType(ReviewPlan, "grant_count"));
    try std.testing.expectEqual(u8, @FieldType(ReviewPlan, "node_count"));
    try std.testing.expectEqual(u8, @FieldType(HarnessResult, "required_count"));
    try std.testing.expectEqual(u8, @FieldType(HarnessResult, "optional_count"));
    try std.testing.expectEqual(u8, @FieldType(HarnessResult, "denied_required_count"));
    try std.testing.expectEqual(u8, @FieldType(HarnessResult, "denied_optional_count"));
    try std.testing.expect(@sizeOf(ReviewPlan) <= REVIEW_PLAN_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(HarnessResult) <= HARNESS_RESULT_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Harness) <= HARNESS_SIZE_CEILING_BYTES);
}

test "permission SDK builds grants and a native UI review tree" {
    const examples = @import("example_apps.zig");
    const package = examples.firstPartyStudio();
    const plan = try buildReviewPlan(77, &package.bundle, &.{});
    try @import("std").testing.expect(plan.grant_count >= manifest.requiredPermissionCount(package.bundle));

    var text_buffer: [MAX_REVIEW_TEXT_BYTES]u8 = undefined;
    const rendered_text = try renderReviewText(&plan, &text_buffer);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, rendered_text, "Zigos Studio") != null);

    var ui_buffer: [ui.MAX_RENDER_BYTES]u8 = undefined;
    const rendered_ui = try renderReviewUi(&plan, &ui_buffer);
    try @import("std").testing.expect(@import("std").mem.indexOf(u8, rendered_ui, "role=permission_row") != null);
}

test "permission harness proves required and optional review outcomes" {
    const examples = @import("example_apps.zig");
    const package = examples.firstPartyStudio();

    var optional_harness = Harness.init(88, &package.bundle);
    try std.testing.expectEqual(@min(package.bundle.requested_permissions.len, permission_review.MAX_REVIEW_DECISIONS), optional_harness.commandCount());
    try optional_harness.deny(.camera);
    const optional_result = try optional_harness.run();
    try std.testing.expect(optional_result.allRequiredGranted());
    try std.testing.expect(optional_result.denied_optional_count >= 1);
    try std.testing.expect(optional_result.plan.grantSlice().len + @as(usize, optional_result.denied_optional_count) >= manifest.requiredPermissionCount(package.bundle));

    var required_harness = Harness.init(89, &package.bundle);
    try required_harness.deny(.object_access);
    const required_result = try required_harness.run();
    try std.testing.expect(!required_result.allRequiredGranted());
    try std.testing.expectEqual(@as(u8, 1), required_result.denied_required_count);
}
