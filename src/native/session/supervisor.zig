const std = @import("std");
const capability = @import("../kernel_api/capability.zig");
const contract = @import("contract.zig");
const driver_service = @import("../drivers/driver_service.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const notification_center = @import("../services/notification_center.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

pub const MAX_SERVICES: usize = 24;
pub const MAX_DIAGNOSTICS: usize = 64;
const SERVICE_INDEX_CAPACITY: usize = MAX_SERVICES * 2;

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
    runtime_activation_observed: bool = false,
    runtime_activation_generation: u32 = 0,
    runtime_dma_domain_id: u64 = 0,
    runtime_exclusive_claim: bool = false,
    userspace_brokered_data_plane: bool = false,
};

pub const DriverHotSwapReport = struct {
    notification_id: ?u64 = null,
    visible_impact: bool = false,
    previous_dma_domain_id: u64 = 0,
    next_dma_domain_id: u64 = 0,
    previous_restart_generation: u32 = 0,
    next_restart_generation: u32 = 0,
    runtime_activation_observed: bool = false,
    runtime_activation_generation: u32 = 0,
    runtime_dma_domain_id: u64 = 0,
    runtime_exclusive_claim: bool = false,
    userspace_brokered_data_plane: bool = false,
};

const DriverActivationObservation = struct {
    observed: bool = false,
    activation_generation: u32 = 0,
    dma_domain_id: u64 = 0,
    exclusive_claim: bool = false,
    userspace_brokered_data_plane: bool = false,
};

const ServiceSlot = struct {
    in_use: bool = false,
    service: ServiceRecord = zeroService(),
};

const ServiceArena = indexed_arena.IndexedArena(ServiceSlot, MAX_SERVICES, SERVICE_INDEX_CAPACITY, serviceSlotId);
const ServiceClassIndex = indexed_arena.UniqueIndex(SERVICE_INDEX_CAPACITY);
const DiagnosticServiceIndex = indexed_arena.MultimapIndex(MAX_DIAGNOSTICS, MAX_DIAGNOSTICS, MAX_DIAGNOSTICS * 2);
const DiagnosticServiceKindIndex = indexed_arena.MultimapIndex(MAX_DIAGNOSTICS, MAX_DIAGNOSTICS, MAX_DIAGNOSTICS * 2);

pub const supervisor_indexing = .{
    .uses_service_arena = @hasDecl(ServiceArena, "reserveIndex"),
    .uses_service_class_index = @hasDecl(ServiceClassIndex, "lookup"),
    .uses_diagnostic_service_index = @hasDecl(DiagnosticServiceIndex, "append"),
    .uses_diagnostic_service_kind_index = @hasDecl(DiagnosticServiceKindIndex, "append"),
};

pub const Supervisor = struct {
    next_service_id: u64 = 1,
    next_isolation_domain_id: u64 = 1,
    service_arena: ServiceArena = ServiceArena.init(),
    service_class_index: ServiceClassIndex = ServiceClassIndex.init(),
    next_diagnostic_sequence: u64 = 1,
    diagnostics: [MAX_DIAGNOSTICS]DiagnosticEvent = [_]DiagnosticEvent{zeroDiagnostic()} ** MAX_DIAGNOSTICS,
    diagnostic_count: usize = 0,
    next_diagnostic_slot: usize = 0,
    diagnostic_service_index: DiagnosticServiceIndex = DiagnosticServiceIndex.init(),
    diagnostic_service_kind_index: DiagnosticServiceKindIndex = DiagnosticServiceKindIndex.init(),

    pub fn init() Supervisor {
        return Supervisor{};
    }

    pub fn register(self: *Supervisor, class: contract.ServiceClass, owner: principal.PrincipalId) Error!*ServiceRecord {
        const descriptor = contract.serviceDescriptor(class) orelse return error.UnknownServiceClass;

        const service_id = self.nextReservableServiceId() orelse return error.ServiceTableFull;
        const isolation_domain_id = self.nextReservableIsolationDomainId() orelse return error.ServiceTableFull;
        const slot_index = self.service_arena.reserveIndex(service_id) orelse return error.ServiceTableFull;
        const slot = &self.service_arena.slots[slot_index];

        slot.service = .{
            .id = service_id,
            .isolation_domain_id = isolation_domain_id,
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
        self.service_class_index.insert(serviceClassKey(class), slot_index);
        self.record(slot.service, .registered, 0, 0, 0);
        self.advanceNextServiceIdFrom(service_id);
        self.advanceNextIsolationDomainIdFrom(isolation_domain_id);
        return &slot.service;
    }

    pub fn find(self: *Supervisor, service_id: u64) ?*ServiceRecord {
        const slot = self.service_arena.get(service_id) orelse return null;
        return &slot.service;
    }

    pub fn findByClass(self: *Supervisor, class: contract.ServiceClass) ?*ServiceRecord {
        const slot_index = self.service_class_index.lookup(serviceClassKey(class)) orelse return null;
        const slot = self.serviceSlotAt(slot_index, class) orelse return null;
        return &slot.service;
    }

    pub fn serviceCount(self: *const Supervisor) usize {
        return self.service_arena.countInUse();
    }

    pub fn allowsDriverAttachment(self: *const Supervisor, service_id: u64, device_class: driver_service.DeviceClass) bool {
        const service = self.findConst(service_id) orelse return false;
        return contract.allowsDriverClass(service.class, device_class);
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
        if (!contract.allowsDriverClass(service.class, device_class)) return false;
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
        _ = deactivateRuntimeDriver(runtime, driver.service_id, driver.device_class);
        const activation = try activateRuntimeDriver(runtime, driver, tick + 2);
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
            .runtime_activation_observed = activation.observed,
            .runtime_activation_generation = activation.activation_generation,
            .runtime_dma_domain_id = activation.dma_domain_id,
            .runtime_exclusive_claim = activation.exclusive_claim,
            .userspace_brokered_data_plane = activation.userspace_brokered_data_plane,
        };
    }

    pub fn hotSwapDriver(
        self: *Supervisor,
        request: driver_service.SignedRegistrationRequest,
        directory: *driver_service.Directory,
        runtime: anytype,
        notifications: ?*notification_center.Center,
        ledger: ?*event_ledger.Ledger,
        tick: u64,
        detail: []const u8,
    ) !DriverHotSwapReport {
        const service = self.find(request.service_id) orelse return error.ServiceNotFound;
        if (!service.restartable) return error.ServiceNotRestartable;
        if (!self.allowsDriverAttachment(request.service_id, request.device_class)) {
            return error.DriverAttachmentDenied;
        }
        const previous = (directory.findByServiceAndClass(request.service_id, request.device_class) orelse return error.DriverNotFound).*;

        const swap_detail = if (detail.len != 0)
            detail
        else
            defaultDriverRestartDetail(request.device_class);
        const visible_impact = driverImpactIsVisible(request.device_class);

        _ = self.requestRestart(request.service_id, tick);
        _ = deactivateRuntimeDriver(runtime, request.service_id, request.device_class);

        const swapped = try directory.hotSwapSigned(request);
        if (previous.authority_capability_id != request.authority_capability_id and
            !revokeRuntimeCapability(runtime, previous.owner_task_id, previous.authority_capability_id))
        {
            return error.CapabilityRevokeFailed;
        }

        const activation = try activateRuntimeDriver(runtime, swapped, tick + 1);
        _ = self.noteDriverAttached(request.service_id, request.device_class, swapped.authority_capability_id, tick + 1);
        _ = self.completeRestart(request.service_id, tick + 1);

        if (ledger) |recording| {
            try recording.recordDriverRestart(service.class, service.owner, swapped.authority_capability_id, tick + 1, swap_detail);
        }

        var notification_id: ?u64 = null;
        if (visible_impact) {
            if (notifications) |center| {
                const notification = try center.post(.{
                    .source = service.owner,
                    .reason = .driver_restart,
                    .urgency = .high,
                    .detail = swap_detail,
                    .expires_at_ticks = tick + 100,
                    .suppression_policy = .replace_same_source_reason,
                });
                notification_id = notification.id;
            }
        }

        return .{
            .notification_id = notification_id,
            .visible_impact = visible_impact,
            .previous_dma_domain_id = previous.dma_domain_id,
            .next_dma_domain_id = swapped.dma_domain_id,
            .previous_restart_generation = previous.restart_generation,
            .next_restart_generation = swapped.restart_generation,
            .runtime_activation_observed = activation.observed,
            .runtime_activation_generation = activation.activation_generation,
            .runtime_dma_domain_id = activation.dma_domain_id,
            .runtime_exclusive_claim = activation.exclusive_claim,
            .userspace_brokered_data_plane = activation.userspace_brokered_data_plane,
        };
    }

    pub fn hasDiagnostic(self: *const Supervisor, service_id: u64, kind: DiagnosticKind) bool {
        var slot_index = self.diagnostic_service_kind_index.head(diagnosticServiceKindKey(service_id, kind));
        while (slot_index != indexed_arena.no_index) : (slot_index = self.diagnostic_service_kind_index.next(slot_index)) {
            const event = self.diagnosticAt(slot_index) orelse continue;
            if (event.service_id == service_id and event.kind == kind) return true;
        }
        return false;
    }

    pub fn latestDiagnostic(self: *const Supervisor, service_id: u64) ?DiagnosticEvent {
        const slot_index = self.diagnostic_service_index.tail(diagnosticServiceKey(service_id));
        const event = self.diagnosticAt(slot_index) orelse return null;
        if (event.service_id != service_id) return null;
        return event;
    }

    fn nextReservableServiceId(self: *const Supervisor) ?u64 {
        if (self.serviceCount() >= MAX_SERVICES) return null;

        var service_id = normalizeServiceId(self.next_service_id);
        var attempts: usize = 0;
        while (attempts <= MAX_SERVICES) : (attempts += 1) {
            if (self.findConst(service_id) == null) return service_id;
            service_id = nextServiceIdAfter(service_id);
        }
        return null;
    }

    fn advanceNextServiceIdFrom(self: *Supervisor, service_id: u64) void {
        self.next_service_id = nextServiceIdAfter(service_id);
    }

    fn nextReservableIsolationDomainId(self: *const Supervisor) ?u64 {
        if (self.serviceCount() >= MAX_SERVICES) return null;

        var isolation_domain_id = normalizeIsolationDomainId(self.next_isolation_domain_id);
        var attempts: usize = 0;
        while (attempts <= MAX_SERVICES) : (attempts += 1) {
            if (!self.isolationDomainInUse(isolation_domain_id)) return isolation_domain_id;
            isolation_domain_id = nextIsolationDomainIdAfter(isolation_domain_id);
        }
        return null;
    }

    fn advanceNextIsolationDomainIdFrom(self: *Supervisor, isolation_domain_id: u64) void {
        self.next_isolation_domain_id = nextIsolationDomainIdAfter(isolation_domain_id);
    }

    fn isolationDomainInUse(self: *const Supervisor, isolation_domain_id: u64) bool {
        for (&self.service_arena.slots) |*slot| {
            if (slot.in_use and slot.service.isolation_domain_id == isolation_domain_id) return true;
        }
        return false;
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

        const slot_index = self.nextDiagnosticSlot();
        if (slot_index >= self.diagnostic_count) self.diagnostic_count = slot_index + 1;
        self.removeDiagnosticIndexes(slot_index);
        self.diagnostics[slot_index] = event;
        self.indexDiagnostic(slot_index, event);
    }

    fn nextDiagnosticSlot(self: *Supervisor) usize {
        const slot_index = self.next_diagnostic_slot;
        self.next_diagnostic_slot = (self.next_diagnostic_slot + 1) % MAX_DIAGNOSTICS;
        return slot_index;
    }

    fn indexDiagnostic(self: *Supervisor, slot_index: usize, event: DiagnosticEvent) void {
        if (!self.diagnostic_service_index.append(diagnosticServiceKey(event.service_id), slot_index)) {
            native_util.impossibleByInvariant("supervisor diagnostic service index capacity covers diagnostic slots");
        }
        if (!self.diagnostic_service_kind_index.append(diagnosticServiceKindKey(event.service_id, event.kind), slot_index)) {
            native_util.impossibleByInvariant("supervisor diagnostic service-kind index capacity covers diagnostic slots");
        }
    }

    fn removeDiagnosticIndexes(self: *Supervisor, slot_index: usize) void {
        if (slot_index >= self.diagnostic_count) return;
        const old = self.diagnostics[slot_index];
        if (old.sequence == 0) return;
        _ = self.diagnostic_service_index.remove(diagnosticServiceKey(old.service_id), slot_index);
        _ = self.diagnostic_service_kind_index.remove(diagnosticServiceKindKey(old.service_id, old.kind), slot_index);
    }

    fn diagnosticAt(self: *const Supervisor, slot_index: usize) ?DiagnosticEvent {
        if (slot_index == indexed_arena.no_index or slot_index >= self.diagnostic_count) return null;
        const event = self.diagnostics[slot_index];
        if (event.sequence == 0) return null;
        return event;
    }

    fn nextDiagnosticSequence(self: *Supervisor) u64 {
        const sequence = self.nextReservableDiagnosticSequence() orelse
            native_util.impossibleByInvariant("scanning one more candidate than the diagnostic table holds always finds a free sequence");
        self.next_diagnostic_sequence = nextDiagnosticSequenceAfter(sequence);
        return sequence;
    }

    fn nextReservableDiagnosticSequence(self: *const Supervisor) ?u64 {
        var sequence = normalizeDiagnosticSequence(self.next_diagnostic_sequence);
        var attempts: usize = 0;
        while (attempts <= MAX_DIAGNOSTICS) : (attempts += 1) {
            if (!self.diagnosticSequenceInUse(sequence)) return sequence;
            sequence = nextDiagnosticSequenceAfter(sequence);
        }
        return null;
    }

    fn diagnosticSequenceInUse(self: *const Supervisor, sequence: u64) bool {
        for (self.diagnostics[0..self.diagnostic_count]) |event| {
            if (event.sequence == sequence) return true;
        }
        return false;
    }

    fn findConst(self: *const Supervisor, service_id: u64) ?*const ServiceRecord {
        const slot = self.service_arena.getConst(service_id) orelse return null;
        return &slot.service;
    }

    fn serviceSlotAt(self: *Supervisor, slot_index: usize, class: contract.ServiceClass) ?*ServiceSlot {
        if (slot_index >= MAX_SERVICES) return null;
        const slot = &self.service_arena.slots[slot_index];
        if (!slot.in_use) return null;
        if (slot.service.class != class) return null;
        return slot;
    }
};

fn serviceSlotId(slot: *const ServiceSlot) u64 {
    return slot.service.id;
}

fn serviceClassKey(class: contract.ServiceClass) u64 {
    return @as(u64, @intFromEnum(class)) + 1;
}

fn normalizeServiceId(service_id: u64) u64 {
    return if (service_id == 0) 1 else service_id;
}

fn nextServiceIdAfter(service_id: u64) u64 {
    const next = service_id +% 1;
    return normalizeServiceId(next);
}

fn normalizeIsolationDomainId(isolation_domain_id: u64) u64 {
    return if (isolation_domain_id == 0) 1 else isolation_domain_id;
}

fn nextIsolationDomainIdAfter(isolation_domain_id: u64) u64 {
    const next = isolation_domain_id +% 1;
    return normalizeIsolationDomainId(next);
}

fn normalizeDiagnosticSequence(sequence: u64) u64 {
    return if (sequence == 0) 1 else sequence;
}

fn nextDiagnosticSequenceAfter(sequence: u64) u64 {
    const next = sequence +% 1;
    return normalizeDiagnosticSequence(next);
}

fn diagnosticServiceKey(service_id: u64) u64 {
    return indexed_arena.nonZeroKey(service_id);
}

fn diagnosticServiceKindKey(service_id: u64, kind: DiagnosticKind) u64 {
    const kind_value = @as(u64, @intFromEnum(kind)) + 1;
    return indexed_arena.nonZeroKey((service_id *% 16) ^ kind_value);
}

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
        .usb_controller, .graphics_adapter, .audio_print_io, .input_device, .compositor_policy => true,
        .network_adapter, .storage_controller => false,
    };
}

fn defaultDriverRestartDetail(device_class: driver_service.DeviceClass) []const u8 {
    return switch (device_class) {
        .network_adapter => "network driver restarted",
        .storage_controller => "storage driver restarted",
        .usb_controller => "usb controller driver restarted",
        .graphics_adapter => "graphics driver restarted",
        .audio_print_io => "audio or print driver restarted",
        .input_device => "input driver restarted",
        .compositor_policy => "compositor device policy restarted",
    };
}

fn driverAuthority(
    capability_table: *capability.CapabilityTable,
    holder: principal.PrincipalId,
    task_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
) !capability.Capability {
    return capability_table.mintBootRoot(.{
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

fn activateRuntimeDriver(
    runtime: anytype,
    driver: *const driver_service.DriverRecord,
    tick: u64,
) !DriverActivationObservation {
    if (@hasDecl(@TypeOf(runtime.*), "activateAt")) {
        return observeDriverActivation(try runtime.activateAt(driver, tick));
    }
    return observeDriverActivation(try runtime.activate(driver));
}

fn deactivateRuntimeDriver(runtime: anytype, service_id: u64, device_class: driver_service.DeviceClass) bool {
    if (@hasDecl(@TypeOf(runtime.*), "deactivateDriver")) {
        return runtime.deactivateDriver(service_id, device_class);
    }
    if (@hasDecl(@TypeOf(runtime.*), "deactivate")) {
        return runtime.deactivate(service_id);
    }
    return false;
}

fn revokeRuntimeCapability(runtime: anytype, task_id: u64, capability_id: u64) bool {
    if (@hasDecl(@TypeOf(runtime.*), "revokeCapability")) {
        return runtime.revokeCapability(task_id, capability_id) catch false;
    }
    return true;
}

fn observeDriverActivation(result: anytype) DriverActivationObservation {
    const T = @TypeOf(result);
    if (T == void) return .{};

    var observation = DriverActivationObservation{ .observed = true };
    if (@hasField(T, "activation_generation")) {
        observation.activation_generation = result.activation_generation;
    }
    if (@hasField(T, "dma_domain_id")) {
        observation.dma_domain_id = result.dma_domain_id;
    }
    if (@hasField(T, "exclusive_claim")) {
        observation.exclusive_claim = result.exclusive_claim;
    }
    if (@hasField(T, "mode")) {
        observation.userspace_brokered_data_plane = std.mem.eql(u8, @tagName(result.mode), "userspace_brokered_data_plane");
    }
    return observation;
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

test "supervisor service ids wrap without zero and skip active records" {
    var supervisor = Supervisor.init();

    supervisor.next_service_id = std.math.maxInt(u64);
    supervisor.next_isolation_domain_id = std.math.maxInt(u64);
    const max_service = try supervisor.register(.session_manager, .{ .kind = .service, .serial = 10 });
    try std.testing.expectEqual(std.math.maxInt(u64), max_service.id);
    try std.testing.expectEqual(std.math.maxInt(u64), max_service.isolation_domain_id);
    try std.testing.expectEqual(@as(u64, 1), supervisor.next_service_id);
    try std.testing.expectEqual(@as(u64, 1), supervisor.next_isolation_domain_id);
    try std.testing.expect(supervisor.find(0) == null);

    const wrapped_service = try supervisor.register(.task_runtime, .{ .kind = .service, .serial = 11 });
    try std.testing.expectEqual(@as(u64, 1), wrapped_service.id);
    try std.testing.expectEqual(@as(u64, 1), wrapped_service.isolation_domain_id);
    try std.testing.expectEqual(@as(u64, 2), supervisor.next_service_id);
    try std.testing.expectEqual(@as(u64, 2), supervisor.next_isolation_domain_id);
    try std.testing.expect(supervisor.find(0) == null);

    supervisor.next_service_id = 1;
    supervisor.next_isolation_domain_id = 1;
    const skipped_service = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 12 });
    try std.testing.expectEqual(@as(u64, 2), skipped_service.id);
    try std.testing.expectEqual(@as(u64, 2), skipped_service.isolation_domain_id);
    try std.testing.expectEqual(@as(u64, 3), supervisor.next_service_id);
    try std.testing.expectEqual(@as(u64, 3), supervisor.next_isolation_domain_id);
    try std.testing.expect(supervisor.find(0) == null);
}

test "supervisor service ids do not advance when the table is full" {
    var supervisor = Supervisor.init();
    for (0..MAX_SERVICES) |index| {
        _ = try supervisor.register(.task_runtime, .{ .kind = .service, .serial = @intCast(index + 100) });
    }

    const next_service_before = supervisor.next_service_id;
    const next_isolation_before = supervisor.next_isolation_domain_id;
    try std.testing.expectError(error.ServiceTableFull, supervisor.register(.session_manager, .{ .kind = .service, .serial = 200 }));
    try std.testing.expectEqual(next_service_before, supervisor.next_service_id);
    try std.testing.expectEqual(next_isolation_before, supervisor.next_isolation_domain_id);
    try std.testing.expectEqual(MAX_SERVICES, supervisor.serviceCount());
}

test "supervisor diagnostic sequences wrap without zero and skip retained diagnostics" {
    var supervisor = Supervisor.init();

    supervisor.next_diagnostic_sequence = std.math.maxInt(u64);
    const service = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 20 });
    try std.testing.expectEqual(std.math.maxInt(u64), supervisor.latestDiagnostic(service.id).?.sequence);
    try std.testing.expectEqual(@as(u64, 1), supervisor.next_diagnostic_sequence);

    try std.testing.expect(supervisor.markHealthy(service.id, 10));
    try std.testing.expectEqual(@as(u64, 1), supervisor.latestDiagnostic(service.id).?.sequence);
    try std.testing.expectEqual(@as(u64, 2), supervisor.next_diagnostic_sequence);

    supervisor.next_diagnostic_sequence = 1;
    try std.testing.expect(supervisor.recordCrash(service.id, 11, 0xD1));
    try std.testing.expectEqual(@as(u64, 2), supervisor.latestDiagnostic(service.id).?.sequence);
    try std.testing.expectEqual(@as(u64, 3), supervisor.next_diagnostic_sequence);

    for (supervisor.diagnostics[0..supervisor.diagnostic_count]) |event| {
        try std.testing.expect(event.sequence != 0);
    }
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

test "supervisor keeps diagnostics indexed while recycling the bounded ring" {
    var supervisor = Supervisor.init();
    const network = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 40 });
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .registered));

    var index: usize = 0;
    while (index < MAX_DIAGNOSTICS) : (index += 1) {
        try std.testing.expect(supervisor.markHealthy(network.id, 100 + @as(u64, @intCast(index))));
    }

    try std.testing.expectEqual(MAX_DIAGNOSTICS, supervisor.diagnostic_count);
    try std.testing.expectEqual(@as(usize, 1), supervisor.next_diagnostic_slot);
    try std.testing.expectEqual(MAX_DIAGNOSTICS, supervisor.diagnostic_service_index.count(diagnosticServiceKey(network.id)));
    try std.testing.expectEqual(@as(usize, 0), supervisor.diagnostic_service_kind_index.count(diagnosticServiceKindKey(network.id, .registered)));
    try std.testing.expectEqual(MAX_DIAGNOSTICS, supervisor.diagnostic_service_kind_index.count(diagnosticServiceKindKey(network.id, .healthy)));
    try std.testing.expect(!supervisor.hasDiagnostic(network.id, .registered));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .healthy));
    try std.testing.expectEqual(@as(u64, 100 + MAX_DIAGNOSTICS - 1), supervisor.latestDiagnostic(network.id).?.tick);
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
            .format = manifest.SIGNATURE_FORMAT_ED25519,
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

test "driver hot-swap rebinds authority and restarts only the owning service" {
    const FakeRuntime = struct {
        const ActivationMode = enum(u8) {
            control_only,
            userspace_brokered_data_plane,
        };
        const ActivationRecord = struct {
            activation_generation: u32,
            dma_domain_id: u64,
            exclusive_claim: bool,
            mode: ActivationMode,
        };

        deactivation_count: usize = 0,
        activation_count: usize = 0,
        last_deactivated_service_id: u64 = 0,
        last_activated_service_id: u64 = 0,
        last_dma_domain_id: u64 = 0,

        pub fn deactivate(self: *@This(), service_id: u64) bool {
            self.deactivation_count += 1;
            self.last_deactivated_service_id = service_id;
            return true;
        }

        pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, _: u64) !ActivationRecord {
            self.activation_count += 1;
            self.last_activated_service_id = driver.service_id;
            self.last_dma_domain_id = driver.dma_domain_id;
            return .{
                .activation_generation = @intCast(self.activation_count),
                .dma_domain_id = driver.dma_domain_id,
                .exclusive_claim = true,
                .mode = .userspace_brokered_data_plane,
            };
        }
    };

    var supervisor = Supervisor.init();
    const compositor = try supervisor.register(.compositor_ui_session, .{ .kind = .service, .serial = 21 });
    const storage = try supervisor.register(.storage_object, .{ .kind = .service, .serial = 22 });
    try std.testing.expect(supervisor.markHealthy(compositor.id, 1));
    try std.testing.expect(supervisor.markHealthy(storage.id, 1));

    var directory = driver_service.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const device_id: u64 = 0x1234_1111_0021;
    const first_authority = try driverAuthority(
        &capabilities,
        compositor.owner,
        501,
        device_id,
        .graphics_adapter,
    );
    const first_driver = try directory.registerSigned(.{
        .service_id = compositor.id,
        .owner_task_id = 501,
        .device_id = device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = first_authority.id,
        .capability_table = &capabilities,
        .requester = compositor.owner,
        .now_ticks = 1,
        .signer = "graphics-v1",
    });
    const first_dma_domain = first_driver.dma_domain_id;
    const second_authority = try driverAuthority(
        &capabilities,
        compositor.owner,
        501,
        device_id,
        .graphics_adapter,
    );

    var runtime = FakeRuntime{};
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    const report = try supervisor.hotSwapDriver(.{
        .service_id = compositor.id,
        .owner_task_id = 501,
        .device_id = device_id,
        .device_class = .graphics_adapter,
        .authority_capability_id = second_authority.id,
        .capability_table = &capabilities,
        .requester = compositor.owner,
        .now_ticks = 10,
        .signer = "graphics-v2",
    }, &directory, &runtime, &notifications, &ledger, 10, "display driver hot-swapped");

    const swapped = directory.findByService(compositor.id).?;
    try std.testing.expect(report.visible_impact);
    try std.testing.expect(report.notification_id != null);
    try std.testing.expectEqual(@as(u32, 1), report.previous_restart_generation);
    try std.testing.expectEqual(@as(u32, 2), report.next_restart_generation);
    try std.testing.expectEqual(first_dma_domain, report.previous_dma_domain_id);
    try std.testing.expect(swapped.dma_domain_id != first_dma_domain);
    try std.testing.expectEqual(swapped.dma_domain_id, report.next_dma_domain_id);
    try std.testing.expect(report.runtime_activation_observed);
    try std.testing.expectEqual(@as(u32, 1), report.runtime_activation_generation);
    try std.testing.expectEqual(swapped.dma_domain_id, report.runtime_dma_domain_id);
    try std.testing.expect(report.runtime_exclusive_claim);
    try std.testing.expect(report.userspace_brokered_data_plane);
    try std.testing.expectEqual(second_authority.id, swapped.authority_capability_id);
    try std.testing.expectEqualStrings("graphics-v2", swapped.signerSlice());
    try std.testing.expectEqual(@as(usize, 1), runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 1), runtime.activation_count);
    try std.testing.expectEqual(compositor.id, runtime.last_deactivated_service_id);
    try std.testing.expectEqual(compositor.id, runtime.last_activated_service_id);
    try std.testing.expectEqual(swapped.dma_domain_id, runtime.last_dma_domain_id);
    try std.testing.expectEqual(ServiceState.healthy, compositor.state);
    try std.testing.expectEqual(@as(u16, 1), compositor.restart_count);
    try std.testing.expectEqual(ServiceState.healthy, storage.state);
    try std.testing.expectEqual(@as(u16, 0), storage.restart_count);
    try std.testing.expect(supervisor.hasDiagnostic(compositor.id, .driver_attached));
    try std.testing.expect(supervisor.hasDiagnostic(compositor.id, .restart_completed));
    try std.testing.expectEqual(notification_center.Reason.driver_restart, notifications.latestVisible(20).?.reason);
    try std.testing.expectEqual(second_authority.id, ledger.latestKind(.driver_restart).?.related_id);

    try std.testing.expectError(error.DriverAttachmentDenied, supervisor.hotSwapDriver(.{
        .service_id = compositor.id,
        .owner_task_id = 501,
        .device_id = device_id,
        .device_class = .storage_controller,
        .authority_capability_id = second_authority.id,
        .capability_table = &capabilities,
        .requester = compositor.owner,
        .now_ticks = 11,
        .signer = "storage-v1",
    }, &directory, &runtime, null, null, 11, ""));
}
