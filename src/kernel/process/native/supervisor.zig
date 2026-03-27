const std = @import("std");
const contract = @import("contract.zig");
const driver_service = @import("driver_service.zig");
const principal = @import("principal.zig");

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
    class: contract.ServiceClass,
    boundary: contract.ServiceBoundary,
    owner: principal.PrincipalId,
    restartable: bool,
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

const ServiceSlot = struct {
    in_use: bool = false,
    service: ServiceRecord = zeroService(),
};

pub const Supervisor = struct {
    next_service_id: u64 = 1,
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
                .class = class,
                .boundary = descriptor.boundary,
                .owner = owner,
                .restartable = descriptor.restartable,
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
        self.record(service.*, .driver_attached, tick, authority_capability_id, @intFromEnum(device_class));
        return true;
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
};

fn zeroService() ServiceRecord {
    return .{
        .id = 0,
        .class = .task_runtime,
        .boundary = .in_process_bridge,
        .owner = .{ .kind = .service, .serial = 0 },
        .restartable = false,
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

test "supervisor registers services using the contract boundary map" {
    var supervisor = Supervisor.init();
    const service = try supervisor.register(.session_manager, .{ .kind = .service, .serial = 1 });

    try std.testing.expectEqual(contract.ServiceBoundary.in_process_bridge, service.boundary);
    try std.testing.expect(service.restartable);
    try std.testing.expect(supervisor.markHealthy(service.id, 10));
    try std.testing.expectEqual(ServiceState.healthy, service.state);
}

test "restart requests only succeed for restartable services" {
    var supervisor = Supervisor.init();
    const task_runtime = try supervisor.register(.task_runtime, .{ .kind = .service, .serial = 2 });
    const session = try supervisor.register(.session_manager, .{ .kind = .service, .serial = 3 });

    try std.testing.expect(!supervisor.requestRestart(task_runtime.id, 5));
    try std.testing.expect(supervisor.requestRestart(session.id, 7));
    try std.testing.expectEqual(@as(u16, 1), session.restart_count);
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

    try std.testing.expectEqual(network.id, supervisor.findByClass(.network_stack).?.id);
    try std.testing.expect(supervisor.findByClass(.sync_replication) == null);
}
