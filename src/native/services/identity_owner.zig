//! Long-lived native account owner. Storage and the exclusive input router
//! outlive this allocation; no application holds a pointer into its private state.
const std = @import("std");
const backing = @import("../core/table_backing.zig");
const principal = @import("../core/principal.zig");
const router_mod = @import("../platform/input_router.zig");
const setup_entry = @import("../platform/trusted_setup_entry.zig");
const auth_entry = @import("../platform/trusted_auth_entry.zig");
const provisioning = @import("identity_provisioning.zig");
const setup_worker = @import("identity_setup_worker.zig");
const authenticator = @import("identity_authenticator.zig");
const session_mod = @import("identity_session.zig");
const catalog = @import("../storage/vault_catalog.zig");
const storage_mod = @import("../storage/storage_service.zig");
const policy = @import("../policy/policy_object.zig");
const vault_mod = @import("secret_vault_service.zig");
const identity = @import("../platform/os_identity.zig");
const graph_mod = @import("../sync/device_graph.zig");
const channel_mod = @import("identity_channel.zig");
const kernel_port = @import("../kernel_api/component_port.zig");

// The trusted account/permission flow selects these after user approval and
// authenticated origin validation. This is never decoded from application IPC.
pub const CredentialGrant = struct {
    task_id: u64,
    credential_id: u64,
    relying_party_id: []const u8,
    origin: []const u8,
};

pub const HardwareIo = struct {
    pub fn execute(_: *@This(), command: []const u8, response: []u8, timeout_ms: u32) ![]u8 {
        return @import("../../kernel/platform/tpm2_hw.zig").execute(command, response, timeout_ms);
    }
    pub fn random(_: *@This(), out: []u8) !void {
        return @import("../../kernel/platform/secure_random.zig").fill(out);
    }
};

pub const Config = struct {
    owner: principal.PrincipalId,
    parent_handle: u32,
    anchor_index: u32,
    boot_index: u32,
    boot_instance: [16]u8,
    input_timeout_ticks: u64,
    operation_timeout_ticks: u64,
    lifetime_ticks: u64,
};

// A native lifetime handle, never exposed through a syscall or application ABI.
// The manager detaches and drains trusted input before destroy, and calls service
// after entry polling to perform the setup-to-sign-in transition synchronously.
pub const Interface = struct {
    context: *anyopaque,
    service: *const fn (*anyopaque, *router_mod.Router, u64) bool,
    destroy: *const fn (*anyopaque) void,
    grant_credential: *const fn (*anyopaque, *kernel_port.KernelPort, CredentialGrant, u64) anyerror!channel_mod.protocol.Binding,
    revoke_credential: *const fn (*anyopaque, u64, u64) void,
    service_requests: *const fn (*anyopaque, u64) bool,
    requests_ready: *const fn (*anyopaque) bool,
    next_request_wake: *const fn (*anyopaque) ?u64,
};

pub fn Owner(comptime Io: type) type {
    return struct {
        const Self = @This();
        io: *Io,
        storage: *storage_mod.Service,
        config: Config,
        vault: vault_mod.Service,
        identities: identity.Store,
        graph: graph_mod.Graph,
        policies: policy.Directory,
        scratch: [catalog.MAX_BYTES]u8,
        setup_worker: setup_worker.Worker(Io),
        setup: setup_entry.Entry,
        bundle: provisioning.Bundle,
        session: session_mod.Session(Io),
        adapter: authenticator.Adapter(Io),
        authentication: auth_entry.Entry,
        authentication_ready: bool,
        unavailable_reported: bool,
        channels: [4]channel_mod.Channel,
        channel_cursor: u8,

        pub fn create(io: *Io, storage: *storage_mod.Service, config: Config) !*Self {
            if (config.owner.kind != .user or config.owner.serial == 0 or config.lifetime_ticks == 0 or
                config.operation_timeout_ticks == 0 or config.input_timeout_ticks == 0 or
                std.mem.allEqual(u8, &config.boot_instance, 0)) return error.InvalidIdentityOwner;
            try @import("../platform/tpm2_boot_pin.zig").validateIndex(config.boot_index);
            try @import("../platform/tpm2_boot_pin.zig").validateIndex(config.anchor_index);
            if (config.boot_index == config.anchor_index or config.parent_handle < 0x8100_0000 or config.parent_handle >= 0x8180_0000) return error.InvalidIdentityOwner;
            const self = backing.alloc(Self) orelse return error.OutOfMemory;
            errdefer backing.free(Self, self);
            self.io = io;
            self.storage = storage;
            self.config = config;
            self.vault.initializeAllocated();
            self.identities.reset();
            self.graph.initializeAllocated();
            // Bootstrap is private and short-lived. The enrolled root-signed
            // policy must be attached before any user session can be created.
            self.policies.initializeAllocated();
            // Read-only discovery/sign-in does not require fresh object IDs.
            // Choose IDs only when the user starts a new setup operation.
            self.setup_worker = .{ .io = io, .storage = storage, .state = self.state(), .policies = &self.policies, .request = .{ .owner = config.owner, .device = .{ .kind = .device, .serial = 0 }, .record_object_id = 0, .catalog_object_id = 0, .parent_handle = config.parent_handle, .anchor_index = config.anchor_index, .boot_index = config.boot_index, .max_session_ticks = config.lifetime_ticks }, .scratch = &self.scratch, .max_duration_ticks = config.operation_timeout_ticks };
            self.setup = .{ .backend = self.setup_worker.backend(), .input_timeout_ticks = config.input_timeout_ticks, .requires_discovery = true };
            self.authentication_ready = false;
            self.unavailable_reported = false;
            for (&self.channels) |*channel| channel.* = .{};
            self.channel_cursor = 0;
            return self;
        }

        pub fn attach(self: *Self, router: *router_mod.Router, now: u64) Interface {
            router.bindTrustedEntry(.{ .setup = &self.setup }, now);
            self.setup.discover(now);
            router.synchronizeTrustedInput();
            return .{ .context = self, .service = service, .destroy = destroy, .grant_credential = grantCredential, .revoke_credential = revokeCredential, .service_requests = serviceRequests, .requests_ready = requestsReady, .next_request_wake = nextRequestWake };
        }

        fn grantCredential(context: *anyopaque, kernel: *kernel_port.KernelPort, grant: CredentialGrant, now: u64) !channel_mod.protocol.Binding {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.authentication_ready or self.authentication.capturing() or self.authentication.busy()) return error.IdentityUnavailable;
            const session_binding = try self.session.replay.binding();
            const deadline = @min(self.session.expires_at_ticks, std.math.add(u64, now, self.config.operation_timeout_ticks) catch return error.IdentityUnavailable);
            for (&self.channels) |*channel| {
                if (channel.kernel != null and !channel.valid(now)) channel.close(now);
                if (channel.kernel != null and channel.task_id == grant.task_id) return error.IdentityChannelAlreadyOpen;
            }
            for (&self.channels) |*channel| if (channel.kernel == null) {
                return channel.open(kernel, self.adapter.requests(), grant.task_id, self.storage.task_id, .{
                    .credential_id = grant.credential_id,
                    .relying_party_id = grant.relying_party_id,
                    .origin = grant.origin,
                    .session = session_binding,
                    .expires_at_ticks = deadline,
                }, now);
            };
            return error.IdentityChannelTableFull;
        }

        fn revokeCredential(context: *anyopaque, task_id: u64, now: u64) void {
            const self: *Self = @ptrCast(@alignCast(context));
            for (&self.channels) |*channel| if (channel.task_id == task_id) {
                channel.close(now);
            };
        }

        fn serviceRequests(context: *anyopaque, now: u64) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.authentication_ready) return false;
            var work: usize = 0;
            for (0..self.channels.len) |_| {
                const channel = &self.channels[self.channel_cursor];
                self.channel_cursor = @intCast((self.channel_cursor + 1) % self.channels.len);
                if (channel.service(now)) work += 1;
                if (work == 2) break;
            }
            return work != 0;
        }

        fn requestsReady(context: *anyopaque) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            for (&self.channels) |*channel| if (channel.hasPendingWork()) return true;
            return false;
        }

        fn nextRequestWake(context: *anyopaque) ?u64 {
            const self: *Self = @ptrCast(@alignCast(context));
            var wake: ?u64 = null;
            for (&self.channels) |*channel| if (channel.nextWake()) |deadline| {
                wake = @min(wake orelse deadline, deadline);
            };
            return wake;
        }

        fn state(self: *Self) catalog.State {
            return .{ .vault = &self.vault, .identities = &self.identities, .devices = &self.graph };
        }

        fn service(context: *anyopaque, router: *router_mod.Router, now: u64) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.authentication_ready and self.setup.view.status == .unavailable and !self.unavailable_reported) {
                self.unavailable_reported = true;
                if (comptime @import("builtin").target.os.tag == .freestanding)
                    @import("../../kernel/utils/console.zig").print("ZIGOS:IDENTITY:DISCOVERY:UNAVAILABLE\n");
            }
            if (self.authentication_ready or self.setup.view.status != .complete) return false;
            self.handoff(router, now) catch {
                self.setup.requires_discovery = true;
                self.setup.lock(now);
                self.setup.view.notice = .failed;
                router.synchronizeTrustedInput();
            };
            return true;
        }

        fn handoff(self: *Self, router: *router_mod.Router, now: u64) !void {
            const trusted = self.setup.trusted orelse return error.MissingEnrollment;
            const completed = self.setup.identity orelse return error.MissingEnrollment;
            self.bundle = try provisioning.load(self.storage, trusted);
            const enrolled = self.bundle.identity.enrollment;
            if (!std.mem.eql(u8, &(try completed.digest()), &(try self.bundle.identity.digest())) or
                !enrolled.owner.eql(self.config.owner) or enrolled.parent.handle != self.config.parent_handle or
                enrolled.anchor_index != self.config.anchor_index or self.bundle.boot_index != self.config.boot_index) return error.EnrollmentChanged;
            // All device work is complete before swapping owners. The router
            // drains queued reports and requires a new neutral report on bind.
            try self.setup_worker.deinit();
            try self.bundle.session_policy.attach(&self.policies, enrolled.owner, self.bundle.initial_anchor.device_root_pin.?);
            self.session = .{ .io = self.io, .enrollment = enrolled, .state = self.state(), .storage = self.storage, .policies = &self.policies, .subjects = .{ .user_id = enrolled.owner.serial } };
            self.adapter = .{ .session = &self.session, .capsule = &self.bundle.identity.capsule, .recovery_package = &self.bundle.package, .recovery_pin = trusted, .boot_instance = self.config.boot_instance, .lifetime_ticks = @min(self.config.lifetime_ticks, self.bundle.session_policy.max_session_ticks), .scratch = &self.scratch };
            self.authentication = .{ .authenticator = self.adapter.authenticator(), .input_timeout_ticks = self.config.input_timeout_ticks };
            self.authentication_ready = true;
            router.bindTrustedEntry(.{ .authentication = &self.authentication }, now);
        }

        fn destroy(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            for (&self.channels) |*channel| channel.close(0);
            if (self.authentication_ready) {
                self.authentication.quiesce();
                self.adapter.deinit() catch unreachable;
                self.session.close() catch {};
            } else self.setup.quiesce();
            self.setup_worker.deinit() catch unreachable;
            self.vault.unload();
            self.identities.reset();
            self.graph.reset();
            backing.free(Self, self);
        }

        comptime {
            if (@sizeOf(Self) > 512 * 1024) @compileError("identity owner exceeds bounded backing");
        }
    };
}

test "identity owner discovers without input and drains borrowed commands before teardown" {
    const cooperative = @import("../task/cooperative_worker.zig");
    const Io = struct {
        calls: usize = 0,
        pause_command: bool = false,
        fail: bool = false,
        pub fn random(_: *@This(), _: []u8) !void {
            return error.UnexpectedEntropyRequest;
        }
        pub fn execute(self: *@This(), command: []const u8, response: []u8, _: u32) ![]u8 {
            self.calls += 1;
            if (std.mem.readInt(u32, command[6..10], .big) != 0x169) return error.UnexpectedBootMutation;
            const first = command[0];
            if (self.pause_command) cooperative.current().?.yield();
            if (first != command[0]) return error.OverwrittenCommand;
            if (cooperative.current().?.cancel_requested) return error.Cancelled;
            if (self.fail) return error.HardwareUnavailable;
            @memcpy(response[0..10], &[_]u8{ 0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x8b });
            return response[0..10];
        }
    };
    const disk = try @import("../storage/document_save_test.zig").Fixture.init(true);
    defer disk.deinit();
    disk.service.store.next_object_id = 0; // Discovery must still be available.
    const config = Config{ .owner = .{ .kind = .user, .serial = 1 }, .parent_handle = 0x8100_1234, .boot_index = 0x0180_1234, .anchor_index = 0x0180_1235, .boot_instance = @splat(1), .input_timeout_ticks = 20, .operation_timeout_ticks = 20, .lifetime_ticks = 100 };
    for (0..3) |variant| {
        var io = Io{ .pause_command = variant == 2, .fail = variant == 1 };
        var router = router_mod.Router{};
        defer router.deinit();
        const owner = try Owner(Io).create(&io, &disk.service, config);
        const interface = owner.attach(&router, 1);
        defer interface.destroy(interface.context);
        try std.testing.expect(owner.setup.capturing() and owner.setup.nextWake().? == 1);
        try std.testing.expect(owner.setup.prepareWork(1));
        owner.setup.runWork(1);
        owner.setup.tick(1);
        try std.testing.expectEqual(@as(usize, 1), io.calls);
        if (variant == 0) try std.testing.expect(owner.setup.view.status == .choose_pin);
        if (variant == 1) try std.testing.expect(owner.setup.view.status == .unavailable);
        if (variant == 2) try std.testing.expect(owner.setup.busy());
        try std.testing.expect(!interface.service(interface.context, &router, 1));
        router.clearTrustedEntry();
        try std.testing.expect(!owner.setup.busy() and !owner.authentication_ready);
        try std.testing.expect(std.mem.allEqual(u8, owner.setup_worker.stack.?.bytes, 0));
        try std.testing.expect(owner.vault.store.empty() and owner.vault.activeHandleCount() == 0);
        try std.testing.expect(router.trusted_entry == null and router.drain_until_neutral);
    }
}
