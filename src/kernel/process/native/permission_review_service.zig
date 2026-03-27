const std = @import("std");
const builtin = @import("builtin");
const manifest = @import("manifest.zig");
const permission_review = @import("permission_review.zig");
const policy_mediation = @import("policy_mediation.zig");
const task_runtime = @import("task_runtime.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../../arch/x86.zig")
else
    struct {
        pub fn hlt() void {}
    };
const keyboard = if (builtin.target.os.tag == .freestanding)
    @import("../../drivers/keyboard.zig")
else
    struct {
        pub fn has_char() bool {
            return false;
        }

        pub fn getchar() u8 {
            return 0;
        }
    };
const serial = if (builtin.target.os.tag == .freestanding)
    @import("../../drivers/serial.zig")
else
    struct {
        pub fn hasChar() bool {
            return false;
        }

        pub fn getchar() ?u8 {
            return null;
        }
    };
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub const MAX_REVIEW_DECISIONS: usize = permission_review.MAX_REVIEW_DECISIONS;
pub const MAX_INPUT_LINE: usize = 96;
pub const Error = task_runtime.Error || manifest.ValidationError;

pub const Service = struct {
    service_id: u64,
    task_id: u64,
    runtime: *task_runtime.Runtime,
    scripted_inputs: []const []const u8,
    scripted_cursor: usize = 0,

    pub fn init(
        service_id: u64,
        task_id: u64,
        runtime: *task_runtime.Runtime,
        scripted_inputs: []const []const u8,
    ) Service {
        return .{
            .service_id = service_id,
            .task_id = task_id,
            .runtime = runtime,
            .scripted_inputs = scripted_inputs,
        };
    }

    pub fn reviewBundle(
        self: *Service,
        app_task_id: u64,
        bundle: manifest.BundleManifest,
        now_ticks: u64,
        output: *[MAX_REVIEW_DECISIONS]policy_mediation.UserGrant,
    ) Error![]const policy_mediation.UserGrant {
        try manifest.validate(bundle);
        var decisions: [MAX_REVIEW_DECISIONS]permission_review.ReviewDecision = undefined;
        var decision_count: usize = 0;

        try self.runtime.audit(app_task_id, .{
            .kind = .permission_prompted,
            .detail = @intCast(bundle.requested_permissions.len),
            .tick = now_ticks,
        });
        common.printBootMarker("ZIGOS:PHASE2:UI:REVIEW_READY");
        common.printBootMarker("ZIGOS:PHASE2:UI:INPUT_LOOP");

        for (bundle.requested_permissions, 0..) |request, index| {
            if (decision_count >= decisions.len) break;

            const session = permission_review.initSession(app_task_id, bundle, decisions[0..decision_count]);
            var prompt_buffer: [512]u8 = undefined;
            const prompt = permission_review.renderRequestToBuffer(&prompt_buffer, &session, bundle, index) catch unreachable;
            console.print(prompt);
            console.print("    command: allow [local] [lease=<ticks>] | deny\n");

            while (true) {
                var input_buffer: [MAX_INPUT_LINE]u8 = undefined;
                const line = self.readCommandLine(&input_buffer);
                const command = permission_review.parseCommand(line) catch {
                    console.print("    invalid command; expected allow [local] [lease=<ticks>] or deny\n");
                    continue;
                };

                decisions[decision_count] = permission_review.decisionFromCommand(request, command);
                decision_count += 1;
                break;
            }
        }

        const reviewed_session = permission_review.initSession(app_task_id, bundle, decisions[0..decision_count]);
        var review_buffer: [2048]u8 = undefined;
        const rendered = permission_review.renderToBuffer(&review_buffer, &reviewed_session, bundle) catch unreachable;
        console.print(rendered);
        common.printBootMarker("ZIGOS:PHASE2:UI:REVIEW_RENDERED");

        const grants = permission_review.decisionsToGrants(
            bundle,
            reviewed_session.decisions[0..reviewed_session.decision_count],
            now_ticks,
            output,
        );
        try self.runtime.audit(app_task_id, .{
            .kind = .permission_reviewed,
            .detail = @intCast(grants.len),
            .tick = now_ticks,
        });
        return grants;
    }

    fn readCommandLine(self: *Service, buffer: *[MAX_INPUT_LINE]u8) []const u8 {
        if (self.scripted_cursor < self.scripted_inputs.len) {
            const line = self.scripted_inputs[self.scripted_cursor];
            self.scripted_cursor += 1;
            console.print("    input> ");
            console.print(line);
            console.print("\n");
            return line;
        }

        console.print("    input> ");
        var length: usize = 0;
        while (true) {
            if (self.tryReadChar()) |ch| {
                switch (ch) {
                    '\r' => {},
                    '\n' => {
                        console.print("\n");
                        return buffer[0..length];
                    },
                    8, 127 => {
                        if (length > 0) {
                            length -= 1;
                        }
                    },
                    else => {
                        if (length < buffer.len) {
                            buffer[length] = ch;
                            length += 1;
                        }
                    },
                }
                continue;
            }

            x86.hlt();
        }
    }

    fn tryReadChar(self: *const Service) ?u8 {
        _ = self;
        if (serial.hasChar()) {
            return serial.getchar();
        }
        if (keyboard.has_char()) {
            return keyboard.getchar();
        }
        return null;
    }
};

test "review service retries invalid commands clamps leases and records audits" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    const scripted_inputs = [_][]const u8{
        "wat",
        "allow local lease=60",
        "deny",
    };
    var service = Service.init(9, 10, &runtime, &scripted_inputs);
    const permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes/documents/notes.md",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
            .max_lease_ticks = 30,
        },
        .{
            .kind = .network_egress,
            .resource = "relay.zigos.dev",
            .rights = .{ .network_remote = true },
            .required = false,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "zigos.dev",
        .requested_permissions = &permissions,
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-dev-key",
        },
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    const grants = try service.reviewBundle(task.id, bundle, 40, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 1), grants.len);
    try std.testing.expectEqual(manifest.PermissionKind.object_access, grants[0].kind);
    try std.testing.expect(grants[0].local_only);
    try std.testing.expectEqual(@as(?u64, 70), grants[0].expires_at_ticks);
    try std.testing.expectEqual(@as(usize, 2), task.audit_count);
    try std.testing.expectEqual(task_runtime.AuditEventKind.permission_prompted, task.audit_trail[0].kind);
    try std.testing.expectEqual(task_runtime.AuditEventKind.permission_reviewed, task.audit_trail[1].kind);
    try std.testing.expectEqual(@as(u32, 2), task.audit_trail[0].detail);
    try std.testing.expectEqual(@as(u32, 1), task.audit_trail[1].detail);
}

test "review service rejects invalid manifests before auditing" {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .component_class = .app_component,
        .budget = .{
            .cpu_time_ticks = 100,
            .memory_bytes = 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 1024,
        },
        .local_only = true,
    });
    const scripted_inputs = [_][]const u8{"allow"};
    var service = Service.init(11, 12, &runtime, &scripted_inputs);
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.sync",
        .display_name = "Sync",
        .publisher = "zigos.dev",
        .background_triggers = &.{.scheduled_sync},
    };
    var grants_buffer: [MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;

    try std.testing.expectError(error.MissingBackgroundPermission, service.reviewBundle(task.id, bundle, 10, &grants_buffer));
    try std.testing.expectEqual(@as(usize, 0), task.audit_count);
}
