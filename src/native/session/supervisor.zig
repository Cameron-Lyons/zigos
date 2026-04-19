const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const contract = @import("contract.zig");
const driver_service = @import("../drivers/driver_service.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const notification_center = @import("../services/notification_center.zig");
const principal = @import("../core/principal.zig");

pub const MAX_SERVICES: usize = 16;
pub const MAX_DIAGNOSTICS: usize = 64;

pub const ServiceState = enum(u8) {
    registered,
    healthy,
    restarting,
    failed,
};

pub const ServiceRecord = struct {
    id: u64,
    isolation_domain_id: u64,
    class: contract.ServiceClass,
    boundary: contract.ServiceBoundary,
    owner: principal.PrincipalId,
    restartable: bool,
    network_privilege: contract.NetworkPrivilege,
    storage_privilege: contract.StoragePrivilege,
    ui_privilege: contract.UiPrivilege,
    driver_class: ?driver_service.DeviceClass,
    state: ServiceState,
    restart_count: u16,
    last_transition_tick: u64,
};

pub const DiagnosticKind = enum(u8) {
    registered,
    healthy,
    contract_bound,
    driver_attached,
    crash,
    restart_requested,
    restart_completed,
};

pub const DiagnosticEvent = struct {
    sequence: u64,
    service_id: u64,
    class: contract.ServiceClass,
    kind: DiagnosticKind,
    tick: u64,
    related_id: u64 = 0,
    detail: u32 = 0,
};

pub const Error = error{
    ServiceTableFull,
    UnknownServiceClass,
};

pub const DriverRecoveryReport = struct {
    notification_id: ?u64 = null,
    visible_impact: bool = false,
};

const ServiceSlot = struct {
    in_use: bool = false,
    service: ServiceRecord = zeroService(),
};

pub const Supervisor = struct {
    next_service_id: u64 = 1,
    next_isolation_domain_id: u64 = 1,
    services: [MAX_SERVICES]ServiceSlot = [_]ServiceSlot{ServiceSlot{}} ** MAX_SERVICES,
    next_diagnostic_sequence: u64 = 1,
    diagnostics: [MAX_DIAGNOSTICS]DiagnosticEvent = [_]DiagnosticEvent{zeroDiagnostic()} ** MAX_DIAGNOSTICS,
    diagnostic_count: usize = 0,

    pub fn init() Supervisor {
        return Supervisor{};
    }

    pub fn register(self: *Supervisor, class: contract.ServiceClass, owner: principal.PrincipalId) Error!*ServiceRecord {
        const descriptor = contract.serviceDescriptor(class) orelse return error.UnknownServiceClass;

        for (&self.services) |*slot| {
            if (slot.in_use) continue;

            slot.in_use = true;
            slot.service = .{
                .id = self.nextServiceId(),
                .isolation_domain_id = self.nextIsolationDomainId(),
                .class = class,
                .boundary = descriptor.boundary,
                .owner = owner,
                .restartable = descriptor.restartable,
                .network_privilege = descriptor.isolation.network,
                .storage_privilege = descriptor.isolation.storage,
                .ui_privilege = descriptor.isolation.ui,
                .driver_class = descriptor.isolation.driver_class,
                .state = .registered,
                .restart_count = 0,
                .last_transition_tick = 0,
            };
            self.record(slot.service, .registered, 0, 0, 0);
            return &slot.service;
        }

        return error.ServiceTableFull;
    }

    pub fn find(self: *Supervisor, service_id: u64) ?*ServiceRecord {
        for (&self.services) |*slot| {
            if (slot.in_use and slot.service.id == service_id) return &slot.service;
        }
        return null;
    }

    pub fn findByClass(self: *Supervisor, class: contract.ServiceClass) ?*ServiceRecord {
        for (&self.services) |*slot| {
            if (slot.in_use and slot.service.class == class) return &slot.service;
        }
        return null;
    }

    pub fn allowsDriverAttachment(self: *const Supervisor, service_id: u64, device_class: driver_service.DeviceClass) bool {
        const service = self.findConst(service_id) orelse return false;
        const expected = service.driver_class orelse return false;
        return expected == device_class;
    }

    pub fn isolationSeparated(self: *const Supervisor, left_service_id: u64, right_service_id: u64) bool {
        const left = self.findConst(left_service_id) orelse return false;
        const right = self.findConst(right_service_id) orelse return false;
        return left.isolation_domain_id != right.isolation_domain_id;
    }

    pub fn markHealthy(self: *Supervisor, service_id: u64, tick: u64) bool {
        const service = self.find(service_id) orelse return false;
        service.state = .healthy;
        service.last_transition_tick = tick;
        self.record(service.*, .healthy, tick, 0, 0);
        return true;
    }

    pub fn recordCrash(self: *Supervisor, service_id: u64, tick: u64, code: u32) bool {
        const service = self.find(service_id) orelse return false;
        service.state = .failed;
        service.last_transition_tick = tick;
        self.record(service.*, .crash, tick, 0, code);
        return true;
    }

    pub fn requestRestart(self: *Supervisor, service_id: u64, tick: u64) bool {
        const service = self.find(service_id) orelse return false;
        if (!service.restartable) return false;

        service.state = .restarting;
        service.restart_count += 1;
        service.last_transition_tick = tick;
        self.record(service.*, .restart_requested, tick, 0, service.restart_count);
        return true;
    }

    pub fn completeRestart(self: *Supervisor, service_id: u64, tick: u64) bool {
        const service = self.find(service_id) orelse return false;
        service.state = .healthy;
        service.last_transition_tick = tick;
        self.record(service.*, .restart_completed, tick, 0, service.restart_count);
        return true;
    }

    pub fn noteContractBound(self: *Supervisor, service_id: u64, endpoint_id: u64, tick: u64) bool {
        const service = self.find(service_id) orelse return false;
        self.record(service.*, .contract_bound, tick, endpoint_id, 0);
        return true;
    }

    pub fn noteDriverAttached(
        self: *Supervisor,
        service_id: u64,
        device_class: driver_service.DeviceClass,
        authority_capability_id: u64,
        tick: u64,
    ) bool {
        const service = self.find(service_id) orelse return false;
        const expected = service.driver_class orelse return false;
        if (expected != device_class) return false;
        self.record(service.*, .driver_attached, tick, authority_capability_id, @intFromEnum(device_class));
        return true;
    }

    pub fn recoverDriverCrash(
        self: *Supervisor,
        service_id: u64,
        directory: *driver_service.Directory,
        runtime: anytype,
        notifications: ?*notification_center.Center,
        ledger: ?*event_ledger.Ledger,
        tick: u64,
        crash_code: u32,
        detail: []const u8,
    ) !DriverRecoveryReport {
        const service = self.find(service_id) orelse return error.ServiceNotFound;
        const driver = directory.findByService(service_id) orelse return error.DriverNotFound;
        if (!service.restartable) return error.ServiceNotRestartable;

        const restart_detail = if (detail.len != 0)
            detail
        else
            defaultDriverRestartDetail(driver.device_class);
        const visible_impact = driverImpactIsVisible(driver.device_class);

        _ = self.recordCrash(service_id, tick, crash_code);
        if (ledger) |recording| {
            try recording.recordProcessCrash(service.class, service.owner, tick, crash_code, restart_detail);
        }

        _ = self.requestRestart(service_id, tick + 1);
        _ = directory.markRestarted(service_id);
        if (@hasDecl(@TypeOf(runtime.*), "deactivate")) {
            _ = runtime.deactivate(driver.service_id);
        }
        if (@hasDecl(@TypeOf(runtime.*), "activateAt")) {
            _ = try runtime.activateAt(driver, tick + 2);
        } else {
            _ = try runtime.activate(driver);
        }
        _ = self.completeRestart(service_id, tick + 2);

        if (ledger) |recording| {
            try recording.recordDriverRestart(service.class, service.owner, driver.authority_capability_id, tick + 2, restart_detail);
        }

        var notification_id: ?u64 = null;
        if (visible_impact) {
            if (notifications) |center| {
                const notification = try center.post(.{
                    .source = service.owner,
                    .reason = .driver_restart,
                    .urgency = .high,
                    .detail = restart_detail,
                    .expires_at_ticks = tick + 100,
                    .suppression_policy = .replace_same_source_reason,
                });
                notification_id = notification.id;
            }
        }

        return .{
            .notification_id = notification_id,
            .visible_impact = visible_impact,
        };
    }

    pub fn hasDiagnostic(self: *const Supervisor, service_id: u64, kind: DiagnosticKind) bool {
        for (self.diagnostics[0..self.diagnostic_count]) |event| {
            if (event.service_id == service_id and event.kind == kind) return true;
        }
        return false;
    }

    pub fn latestDiagnostic(self: *const Supervisor, service_id: u64) ?DiagnosticEvent {
        var index = self.diagnostic_count;
        while (index > 0) {
            index -= 1;
            const event = self.diagnostics[index];
            if (event.service_id == service_id) return event;
        }
        return null;
    }

    fn nextServiceId(self: *Supervisor) u64 {
        defer self.next_service_id += 1;
        return self.next_service_id;
    }

    fn nextIsolationDomainId(self: *Supervisor) u64 {
        defer self.next_isolation_domain_id += 1;
        return self.next_isolation_domain_id;
    }

    fn record(
        self: *Supervisor,
        service: ServiceRecord,
        kind: DiagnosticKind,
        tick: u64,
        related_id: u64,
        detail: u32,
    ) void {
        const event = DiagnosticEvent{
            .sequence = self.nextDiagnosticSequence(),
            .service_id = service.id,
            .class = service.class,
            .kind = kind,
            .tick = tick,
            .related_id = related_id,
            .detail = detail,
        };

        if (self.diagnostic_count < MAX_DIAGNOSTICS) {
            self.diagnostics[self.diagnostic_count] = event;
            self.diagnostic_count += 1;
            return;
        }

        var index: usize = 1;
        while (index < MAX_DIAGNOSTICS) : (index += 1) {
            self.diagnostics[index - 1] = self.diagnostics[index];
        }
        self.diagnostics[MAX_DIAGNOSTICS - 1] = event;
    }

    fn nextDiagnosticSequence(self: *Supervisor) u64 {
        defer self.next_diagnostic_sequence += 1;
        return self.next_diagnostic_sequence;
    }

    fn findConst(self: *const Supervisor, service_id: u64) ?*const ServiceRecord {
        for (&self.services) |*slot| {
            if (slot.in_use and slot.service.id == service_id) return &slot.service;
        }
        return null;
    }
};

fn zeroService() ServiceRecord {
    return .{
        .id = 0,
        .isolation_domain_id = 0,
        .class = .task_runtime,
        .boundary = .userspace_service,
        .owner = .{ .kind = .service, .serial = 0 },
        .restartable = true,
        .network_privilege = .none,
        .storage_privilege = .none,
        .ui_privilege = .none,
        .driver_class = null,
        .state = .registered,
        .restart_count = 0,
        .last_transition_tick = 0,
    };
}

fn zeroDiagnostic() DiagnosticEvent {
    return .{
        .sequence = 0,
        .service_id = 0,
        .class = .task_runtime,
        .kind = .registered,
        .tick = 0,
        .related_id = 0,
        .detail = 0,
    };
}

fn driverImpactIsVisible(device_class: driver_service.DeviceClass) bool {
    return switch (device_class) {
        .graphics_adapter, .audio_print_io => true,
        .network_adapter, .storage_controller => false,
    };
}

fn defaultDriverRestartDetail(device_class: driver_service.DeviceClass) []const u8 {
    return switch (device_class) {
        .network_adapter => "network driver restarted",
        .storage_controller => "storage driver restarted",
        .graphics_adapter => "graphics driver restarted",
        .audio_print_io => "audio or print driver restarted",
    };
}

fn driverAuthority(
    capability_table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
) !capability.Capability {
    return capability_table.mint(.{
        .holder = holder,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = driver_service.authorityTarget(device_id),
        .rights = driver_service.allowedRightsFor(device_class),
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{},
    });
}

test "supervisor registers services using the contract boundary map" {
    var supervisor = Supervisor.init();
    const service = try supervisor.register(.session_manager, .{ .kind = .service, .serial = 1 });

    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, service.boundary);
    try std.testing.expectEqual(contract.UiPrivilege.session_surface, service.ui_privilege);
    try std.testing.expectEqual(@as(u64, 1), service.isolation_domain_id);
    try std.testing.expect(service.restartable);
    try std.testing.expect(supervisor.markHealthy(service.id, 10));
    try std.testing.expectEqual(ServiceState.healthy, service.state);
}

test "restart requests only succeed for restartable services" {
    var supervisor = Supervisor.init();
    const task_runtime = try supervisor.register(.task_runtime, .{ .kind = .service, .serial = 2 });
    const session = try supervisor.register(.session_manager, .{ .kind = .service, .serial = 3 });

    try std.testing.expect(supervisor.requestRestart(task_runtime.id, 5));
    try std.testing.expect(supervisor.requestRestart(session.id, 7));
    try std.testing.expectEqual(@as(u16, 1), task_runtime.restart_count);
    try std.testing.expectEqual(@as(u16, 1), session.restart_count);
    try std.testing.expectEqual(ServiceState.restarting, task_runtime.state);
    try std.testing.expectEqual(ServiceState.restarting, session.state);
}

test "supervisor emits structured crash and restart diagnostics" {
    var supervisor = Supervisor.init();
    const network = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 4 });

    try std.testing.expect(supervisor.noteContractBound(network.id, 101, 5));
    try std.testing.expect(supervisor.noteDriverAttached(network.id, .network_adapter, 77, 6));
    try std.testing.expect(supervisor.recordCrash(network.id, 7, 0xD1));
    try std.testing.expect(supervisor.requestRestart(network.id, 8));
    try std.testing.expect(supervisor.completeRestart(network.id, 9));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .contract_bound));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .driver_attached));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .crash));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .restart_requested));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .restart_completed));
    try std.testing.expectEqual(ServiceState.healthy, network.state);
    try std.testing.expectEqual(@as(u16, 1), network.restart_count);
    try std.testing.expectEqual(@as(u64, 9), supervisor.latestDiagnostic(network.id).?.tick);
}

test "services can be located by class for mediated routing" {
    var supervisor = Supervisor.init();
    const network = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 4 });
    const storage = try supervisor.register(.storage_object, .{ .kind = .service, .serial = 5 });

    try std.testing.expectEqual(network.id, supervisor.findByClass(.network_stack).?.id);
    try std.testing.expect(supervisor.isolationSeparated(network.id, storage.id));
    try std.testing.expect(supervisor.allowsDriverAttachment(network.id, .network_adapter));
    try std.testing.expect(!supervisor.allowsDriverAttachment(network.id, .storage_controller));
    try std.testing.expect(supervisor.findByClass(.sync_replication) == null);
}

test "driver recovery restarts the failed driver and emits visible diagnostics only when needed" {
    const FakeRuntime = struct {
        activation_count: usize = 0,
        last_service_id: u64 = 0,

        fn activate(self: *@This(), driver: *const driver_service.DriverRecord) !void {
            self.activation_count += 1;
            self.last_service_id = driver.service_id;
        }
    };

    var supervisor = Supervisor.init();
    const compositor = try supervisor.register(.compositor_ui_session, .{ .kind = .service, .serial = 11 });
    const storage = try supervisor.register(.storage_object, .{ .kind = .service, .serial = 12 });
    try std.testing.expect(supervisor.markHealthy(compositor.id, 1));
    try std.testing.expect(supervisor.markHealthy(storage.id, 1));

    var directory = driver_service.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.runtime",
        .display_name = "Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-driver-key",
        },
    };
    const graphics_authority = try driverAuthority(
        &capabilities,
        compositor.owner,
        401,
        0x1234_1111_0001,
        .graphics_adapter,
    );
    const graphics_driver = try directory.register(.{
        .service_id = compositor.id,
        .owner_task_id = 401,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
        .authority_capability_id = graphics_authority.id,
        .capability_table = &capabilities,
        .requester = graphics_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
    });
    const storage_authority = try driverAuthority(
        &capabilities,
        storage.owner,
        402,
        0x0000_1F00_0001,
        .storage_controller,
    );
    _ = try directory.register(.{
        .service_id = storage.id,
        .owner_task_id = 402,
        .device_id = 0x0000_1F00_0001,
        .device_class = .storage_controller,
        .authority_capability_id = storage_authority.id,
        .capability_table = &capabilities,
        .requester = storage_authority.holder,
        .now_ticks = 1,
        .bundle = bundle,
    });

    var runtime = FakeRuntime{};
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    const recovery = try supervisor.recoverDriverCrash(
        compositor.id,
        &directory,
        &runtime,
        &notifications,
        &ledger,
        10,
        0xD1,
        "display driver restart",
    );

    try std.testing.expect(recovery.visible_impact);
    try std.testing.expect(recovery.notification_id != null);
    try std.testing.expectEqual(@as(usize, 1), runtime.activation_count);
    try std.testing.expectEqual(compositor.id, runtime.last_service_id);
    try std.testing.expectEqual(ServiceState.healthy, compositor.state);
    try std.testing.expectEqual(@as(u16, 1), compositor.restart_count);
    try std.testing.expectEqual(@as(u32, 2), graphics_driver.restart_generation);
    try std.testing.expectEqual(notification_center.Reason.driver_restart, notifications.latestVisible(20).?.reason);
    try std.testing.expectEqual(contract.ServiceClass.compositor_ui_session, ledger.latestKind(.process_crash).?.service_class);
    try std.testing.expectEqual(graphics_authority.id, ledger.latestKind(.driver_restart).?.related_id);
    try std.testing.expectEqual(ServiceState.healthy, storage.state);
    try std.testing.expectEqual(@as(u32, 1), directory.findByService(storage.id).?.restart_generation);
}
