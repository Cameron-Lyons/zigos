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
const document_sessions = @import("../session/document_sessions.zig");
const document_worker = @import("document_operation_worker.zig");
const owned_documents = @import("../session/owned_document_launch.zig");
const document_view = @import("../platform/trusted_document_view.zig");

const consent_mod = @import("identity_consent.zig");

pub const CredentialRequest = consent_mod.Request;
pub const ApprovedCredential = struct { task_id: u64, binding: channel_mod.protocol.Binding };

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
    review_credential: *const fn (*anyopaque, *kernel_port.KernelPort, CredentialRequest, u64) anyerror!void,
    take_credential: *const fn (*anyopaque, u64) anyerror!?ApprovedCredential,
    revoke_credential: *const fn (*anyopaque, u64, u64) void,
    service_requests: *const fn (*anyopaque, u64) bool,
    requests_ready: *const fn (*anyopaque) bool,
    next_request_wake: *const fn (*anyopaque) ?u64,
    service_documents: *const fn (*anyopaque, u64) bool,
    documents_ready: *const fn (*anyopaque, u64) bool,
    quiesce_documents: *const fn (*anyopaque, u64) void,
    document_access: *const fn (*anyopaque, u64) ?owned_documents.DocumentAccess,
    set_document_job: *const fn (*anyopaque, ?document_worker.JobInterface) void,
    document_job_busy: *const fn (*anyopaque) bool,
    cancel_document_job: *const fn (*anyopaque, u64) void,
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
        consent: consent_mod.Pending,
        documents: ?*document_sessions.Sessions,
        document_operations: document_worker.Coordinator(Io),
        document_view: ?*document_view.View,

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
            self.document_view = null;
            self.unavailable_reported = false;
            for (&self.channels) |*channel| channel.* = .{};
            self.channel_cursor = 0;
            self.consent = .{};
            self.documents = null;
            self.document_operations = undefined;
            return self;
        }

        pub fn attach(self: *Self, router: *router_mod.Router, now: u64) Interface {
            router.bindTrustedEntry(.{ .setup = &self.setup }, now);
            self.setup.discover(now);
            router.synchronizeTrustedInput();
            return .{ .context = self, .service = service, .destroy = destroy, .review_credential = reviewCredential, .take_credential = takeCredential, .revoke_credential = revokeCredential, .service_requests = serviceRequests, .requests_ready = requestsReady, .next_request_wake = nextRequestWake, .service_documents = serviceDocuments, .documents_ready = documentsReady, .quiesce_documents = quiesceDocuments, .document_access = documentAccess, .set_document_job = setDocumentJob, .document_job_busy = documentJobBusy, .cancel_document_job = cancelDocumentJob };
        }

        // The manager binds its stable channel collection once. No app receives
        // a signer or document authority from this execution-only association.
        pub fn bindDocuments(self: *Self, documents: *document_sessions.Sessions) void {
            if (self.documents != null) @panic("native identity owner binds document storage once");
            self.documents = documents;
            self.document_operations = .{ .session = &self.session, .documents = documents, .timeout_ticks = self.config.operation_timeout_ticks };
        }

        pub fn bindDocumentView(self: *Self, view: *document_view.View) void {
            if (self.document_view != null) @panic("native document view has one stable owner");
            self.document_view = view;
            if (self.authentication_ready) self.authentication.view.documents = view;
        }

        fn setDocumentJob(context: *anyopaque, job: ?document_worker.JobInterface) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.documents == null) @panic("native document job requires the bound channel collection");
            self.document_operations.setJob(job);
            // Teardown detaches the public pointer before Launch backing is
            // freed. Router quiescence and owner destruction can lock again.
            if (job == null) {
                self.document_view = null;
                if (self.authentication_ready) self.authentication.view.documents = null;
            }
        }

        fn documentJobBusy(context: *anyopaque) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.documents != null and self.document_operations.busy();
        }
        fn cancelDocumentJob(context: *anyopaque, now: u64) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.documents != null) self.document_operations.cancelJob(now);
        }

        // Main-context discovery never cancels or yields while the operation
        // worker borrows this session. Publication validates the live guard.
        fn documentAccess(context: *anyopaque, now: u64) ?owned_documents.DocumentAccess {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.authentication_ready or !self.session.replay.active or self.session.lock_pending or
                now < self.session.last_ticks or now < self.session.verified_at_ticks or now >= self.session.expires_at_ticks) return null;
            const binding = self.session.replay.binding() catch return null;
            const coordinator = self.session.coordinator orelse return null;
            const signer = coordinator.signer;
            if (signer.key.authority != &self.session.signing_authority) return null;
            signer.validateService(self.storage.owner, self.storage.task_id, now) catch return null;
            // Open can publish its grant without starting a document Worker.
            // Apply the same live session policy as the operation guard while
            // leaving any current worker's borrowed backing untouched.
            if (!self.session.policies.sessionLifetimeDecision(self.session.subjects, self.session.expires_at_ticks - self.session.verified_at_ticks).allowed) return null;
            const platform_backed = if (self.session.state.devices) |graph|
                if (graph.findDeviceConst(self.session.enrollment.device)) |device| device.usesPlatformBackedKey() else false
            else
                false;
            if (!self.session.policies.sessionTrustDecision(self.session.subjects, .{ .hardware_backed_credential = true, .device_platform_backed = platform_backed, .unlock_age_ticks = now - self.session.verified_at_ticks }).allowed) return null;
            return .{ .owner = self.session.enrollment.owner, .binding = binding, .expires_at_ticks = self.session.expires_at_ticks, .signer = signer, .authorization = .{ .policies = self.session.policies, .subjects = self.session.subjects, .owner = self.session.enrollment.owner, .expires_at_ticks = self.session.expires_at_ticks } };
        }

        fn serviceDocuments(context: *anyopaque, now: u64) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.authentication_ready or self.documents == null) return false;
            return self.document_operations.service(now);
        }

        fn documentsReady(context: *anyopaque, now: u64) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.authentication_ready and self.documents != null and self.document_operations.ready(now);
        }

        fn quiesceDocuments(context: *anyopaque, now: u64) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.authentication_ready or self.documents == null) return;
            self.session.lock();
            self.document_operations.quiesce(now);
        }

        fn reviewCredential(context: *anyopaque, kernel: *kernel_port.KernelPort, request: CredentialRequest, now: u64) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (!self.authentication_ready or self.authentication.capturing() or self.authentication.busy()) return error.IdentityUnavailable;
            for (&self.channels) |*channel| if (channel.kernel != null and channel.task_id == request.task_id) return error.IdentityChannelAlreadyOpen;
            const session_binding = try self.session.replay.binding();
            const deadline = @min(self.session.expires_at_ticks, std.math.add(u64, now, self.config.input_timeout_ticks) catch return error.IdentityUnavailable);
            try self.consent.begin(kernel, self.adapter.requests(), &self.authentication, request.task_id, .{
                .credential_id = request.credential_id,
                .relying_party_id = request.relying_party_id,
                .origin = request.origin,
                .session = session_binding,
                .expires_at_ticks = deadline,
            }, now);
        }

        fn takeCredential(context: *anyopaque, now: u64) !?ApprovedCredential {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.consent.kernel == null) return null;
            self.authentication.tick(now);
            if (!self.consent.valid(&self.authentication, now) or self.authentication.view.review.state == .denied) {
                self.consent.clear(&self.authentication);
                return null;
            }
            if (self.authentication.view.review.state != .approved) return null;
            defer self.consent.clear(&self.authentication);
            // Approval consumes the exact reviewed session and process. Opening
            // never renews the deadline or accepts changed caller-owned strings.
            var grant = self.consent.grant;
            grant.expires_at_ticks = @min(grant.expires_at_ticks, std.math.add(u64, now, self.config.operation_timeout_ticks) catch return error.IdentityUnavailable);
            for (&self.channels) |*channel| if (channel.kernel == null) {
                return .{ .task_id = self.consent.task_id, .binding = try channel.open(self.consent.kernel.?, self.adapter.requests(), self.consent.task_id, self.storage.task_id, grant, now) };
            };
            return error.IdentityChannelTableFull;
        }

        fn revokeCredential(context: *anyopaque, task_id: u64, now: u64) void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.consent.kernel != null and self.consent.task_id == task_id) self.consent.clear(&self.authentication);
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
            if (self.authentication_ready and self.documents != null) wake = self.document_operations.nextWake();
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
            if (self.documents != null) self.document_operations.bind();
            self.adapter = .{ .session = &self.session, .capsule = &self.bundle.identity.capsule, .recovery_package = &self.bundle.package, .recovery_pin = trusted, .boot_instance = self.config.boot_instance, .lifetime_ticks = @min(self.config.lifetime_ticks, self.bundle.session_policy.max_session_ticks), .scratch = &self.scratch };
            self.authentication = .{ .authenticator = self.adapter.authenticator(), .input_timeout_ticks = self.config.input_timeout_ticks };
            self.authentication.view.documents = self.document_view;
            self.authentication_ready = true;
            router.bindTrustedEntry(.{ .authentication = &self.authentication }, now);
        }

        pub fn deinit(self: *Self) void {
            destroy(self);
        }

        fn destroy(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            quiesceDocuments(self, if (self.authentication_ready) self.session.last_ticks else 0);
            for (&self.channels) |*channel| channel.close(0);
            if (self.authentication_ready) {
                self.consent.clear(&self.authentication);
                self.authentication.quiesce();
                self.adapter.deinit() catch unreachable;
                self.session.close() catch {};
            } else self.setup.quiesce();
            self.setup_worker.deinit() catch unreachable;
            if (self.documents != null) self.document_operations.deinit() catch unreachable;
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
        var documents = document_sessions.Sessions{};
        defer documents.deinit(99) catch unreachable;
        owner.bindDocuments(&documents);
        const interface = owner.attach(&router, 1);
        defer interface.destroy(interface.context);
        try std.testing.expect(!interface.documents_ready(interface.context, 1));
        try std.testing.expect(!interface.service_documents(interface.context, 1));
        try std.testing.expect(owner.document_operations.stack == null);
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

test "native document access rechecks current policy without revoking borrowed session state" {
    const cooperative = @import("../task/cooperative_worker.zig");
    const signers = @import("../../tests/fixtures/document_signer.zig");
    const disk_mod = @import("../storage/document_save_test.zig");
    const Io = struct {
        calls: usize = 0,
        pub fn execute(self: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            self.calls += 1;
            return error.UnexpectedHardwareCommand;
        }
        pub fn random(self: *@This(), _: []u8) !void {
            self.calls += 1;
            return error.UnexpectedEntropyRequest;
        }
    };
    const Borrow = struct {
        fn run(context: *anyopaque) void {
            const session: *session_mod.Session(Io) = @ptrCast(@alignCast(context));
            const worker = cooperative.current() orelse @panic("session fixture owns its actual Worker");
            session.beginOperation(worker) catch @panic("session fixture starts idle");
            defer session.endOperation(worker);
            worker.yield();
        }
    };
    const Failure = enum { none, pending_lock, last_clock, verified_clock, expiry, lifetime_policy, trust_policy, platform_policy };
    for (std.enums.values(Failure)) |failure| {
        const disk = try disk_mod.Fixture.init(true);
        defer disk.deinit();
        var keys = signers.Fixture{};
        const signer = try keys.init(.{ .kind = .user, .serial = 1 }, disk.service.owner, disk.service.task_id, disk_mod.signer);
        var io = Io{};
        const owner = try Owner(Io).create(&io, &disk.service, .{ .owner = keys.authority.owner, .parent_handle = 0x8100_1234, .anchor_index = 0x0180_1235, .boot_index = 0x0180_1234, .boot_instance = @splat(1), .input_timeout_ticks = 20, .operation_timeout_ticks = 20, .lifetime_ticks = 100 });
        var router = router_mod.Router{};
        defer router.deinit();
        const interface = owner.attach(&router, 1);
        defer {
            // This callback fixture does not claim to complete a TPM sign-in.
            // Detach discovery and avoid the uninitialized authentication view.
            router.clearTrustedEntry();
            owner.authentication_ready = false;
            interface.destroy(interface.context);
        }
        const record = try @import("../../tests/fixtures/identity_enrollment.zig").record();
        owner.session = .{
            .io = &io,
            .enrollment = record.enrollment,
            .state = .{ .vault = &keys.service, .identities = &owner.identities, .devices = &owner.graph },
            .storage = &disk.service,
            .policies = &keys.policies,
            .subjects = keys.authority.subjects,
            .replay = @import("../../tests/fixtures/identity_vault.zig").unlock_session,
            .signing_authority = keys.authority,
            .verified_at_ticks = 1,
            .last_ticks = 5,
            .expires_at_ticks = 100,
        };
        owner.session.enrollment.owner = keys.authority.owner;
        var current_signer = signer;
        current_signer.key.authority = &owner.session.signing_authority;
        owner.session.coordinator = .{ .state = owner.session.state, .storage = &disk.service, .signer = current_signer, .object_id = record.enrollment.catalog_object_id };
        owner.authentication_ready = true;
        var stack: [32 * 1024]u8 align(16) = undefined;
        var worker = cooperative.Worker{ .stack = &stack };
        try worker.start(&owner.session, Borrow.run);
        try worker.step();
        defer {
            owner.session.lock_pending = false;
            if (worker.state == .suspended) worker.step() catch @panic("borrow fixture returns before Owner teardown");
        }
        try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
        const binding = try owner.session.replay.binding();
        const handle_count = keys.service.activeHandleCount();
        var now: u64 = 10;
        switch (failure) {
            .none => {},
            .pending_lock => owner.session.lock_pending = true,
            .last_clock => now = 4,
            .verified_clock => owner.session.verified_at_ticks = 11,
            .expiry => now = 100,
            .lifetime_policy, .trust_policy, .platform_policy => {
                _ = try keys.policies.create(.{
                    .scope = .user,
                    .subject_id = keys.authority.owner.serial,
                    .issuer = .{ .kind = .policy_authority, .serial = 1 },
                    .label = "current document session restriction",
                    .secret_vault_allowed = true,
                    .require_hardware_backed_secrets = true,
                    .max_secret_handle_lease_ticks = std.math.maxInt(u64),
                    .max_session_unlock_age_ticks = if (failure == .lifetime_policy) 3 else 0,
                    .require_primary_device_session = failure == .trust_policy,
                    .require_platform_backed_device_session = failure == .platform_policy,
                }, disk_mod.signer);
                // The actual sealed signer remains usable: the new denial is
                // session policy, rather than a revoked key or bad signature.
                try current_signer.validateService(disk.service.owner, disk.service.task_id, now);
            },
        }
        const access = interface.document_access(interface.context, now);
        if (failure == .none) {
            const live = access orelse return error.DocumentAccessMissing;
            try std.testing.expectEqualDeep(binding, live.binding);
            try std.testing.expectEqualDeep(current_signer, live.signer);
            try std.testing.expectEqual(@as(u64, 100), live.expires_at_ticks);
        } else try std.testing.expect(access == null);
        try std.testing.expectEqualDeep(binding, try owner.session.replay.binding());
        try std.testing.expect(owner.session.operation_worker == &worker and !worker.cancel_requested);
        try std.testing.expectEqual(cooperative.Worker.State.suspended, worker.state);
        try std.testing.expectEqual(handle_count, keys.service.activeHandleCount());
        try std.testing.expectEqual(@as(usize, 0), io.calls);
        try std.testing.expectEqual(failure == .pending_lock, owner.session.lock_pending);
        try std.testing.expect(owner.session.coordinator != null);
    }
}
