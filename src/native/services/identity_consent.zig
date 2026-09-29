//! Native origin owners supply the authenticated RP/origin before showing consent.
//! Signed application provenance identifies the requester, not website ownership.
const std = @import("std");
const auth = @import("../platform/trusted_auth_entry.zig");
const request = @import("identity_request.zig");
const port = @import("../kernel_api/component_port.zig");
const principal = @import("../core/principal.zig");

pub const Request = struct {
    task_id: u64,
    credential_id: u64,
    relying_party_id: []const u8,
    origin: []const u8,
};

// Stable owner backing. Text borrows only the exclusive authentication view,
// retained until approval is consumed or cancelled; no application pointers.
pub const Pending = struct {
    kernel: ?*port.KernelPort = null,
    backend: request.Backend = undefined,
    grant: request.Grant = undefined,
    task_id: u64 = 0,
    task_generation: u32 = 0,
    task_owner: principal.PrincipalId = undefined,
    last_ticks: u64 = 0,

    pub fn begin(self: *Pending, kernel: *port.KernelPort, backend: request.Backend, entry: *auth.Entry, task_id: u64, grant: request.Grant, now: u64) !void {
        if (self.kernel != null or !backend.authorized(backend.context, grant, now)) return error.IdentityRequestDenied;
        const task = kernel.kernel.runtime.findConst(task_id) orelse return error.TaskNotFound;
        if (task.state != .active or !task.runsAsUserspaceProcess() or !task.launch.signed) return error.IdentityRequestDenied;
        try entry.beginReview(task.launchBundleIdSlice(), grant.relying_party_id, grant.origin, grant.expires_at_ticks, now);
        self.* = .{ .kernel = kernel, .backend = backend, .grant = grant, .task_id = task_id, .task_generation = task.process_generation, .task_owner = task.owner, .last_ticks = now };
        self.grant.relying_party_id = entry.view.review.relying_party[0..entry.view.review.relying_party_len];
        self.grant.origin = entry.view.review.origin[0..entry.view.review.origin_len];
    }

    pub fn valid(self: *Pending, entry: *const auth.Entry, now: u64) bool {
        const kernel = self.kernel orelse return false;
        if (now < self.last_ticks or entry.view.status != .hidden or !entry.view.review.visible() or
            !self.backend.authorized(self.backend.context, self.grant, now)) return false;
        self.last_ticks = now;
        const task = kernel.kernel.runtime.findConst(self.task_id) orelse return false;
        return task.state == .active and task.process_generation == self.task_generation and task.owner.eql(self.task_owner) and
            task.runsAsUserspaceProcess() and task.launch.signed and
            std.mem.eql(u8, task.launchBundleIdSlice(), entry.view.review.application[0..entry.view.review.application_len]);
    }

    pub fn clear(self: *Pending, entry: *auth.Entry) void {
        // The session binding is private replay authority even though its text
        // is public. Erase it rather than leave a revoked nonce in idle backing.
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = .{};
        entry.clearReview();
    }

    comptime {
        if (@sizeOf(Pending) > 192) @compileError("credential approval exceeds bounded authority backing");
    }
};
