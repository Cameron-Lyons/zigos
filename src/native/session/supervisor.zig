const builtin = @import("builtin");
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
const root = @import("root");

pub const MAX_SERVICES: usize = 24;
pub const MAX_DIAGNOSTICS: usize = 64;
pub const COMPACT_DIAGNOSTIC_RING_METADATA = true;
pub const ACTIONABLE_DIAGNOSTICS_ONLY = true;
pub const HEAP_BACKED_ACTIONABLE_DIAGNOSTICS_ON_FREESTANDING = true;
pub const DIAGNOSTIC_EVENT_SIZE_CEILING_BYTES: usize = 32;
pub const DIAGNOSTIC_HANDLE_SIZE_CEILING_BYTES: usize = 8;
pub const SCHEMA_DERIVED_SERVICE_METADATA = true;
pub const SERVICE_ID_IS_ISOLATION_DOMAIN = true;
pub const OMITS_UNOBSERVED_SERVICE_TRANSITION_TIMESTAMPS = true;
pub const SERVICE_RECORD_SIZE_CEILING_BYTES: usize = 40;
pub const SUPERVISOR_SIZE_CEILING_BYTES: usize = 4_408;
const SERVICE_INDEX_CAPACITY: usize = MAX_SERVICES * 2;

comptime {
    if (MAX_DIAGNOSTICS > std.math.maxInt(u8)) {
        @compileError("supervisor diagnostic ring metadata exceeds u8 capacity");
    }
}

pub const ServiceState = enum(u8) {
    registered,
    healthy,
    restarting,
    failed,
};

pub const ServiceRecord = struct {
    id: u64,
    class: contract.ServiceClass,
    owner: principal.PrincipalId,
    contract_endpoint_id: u64,
    state: ServiceState,
    restart_count: u16,

    pub fn isolationDomainId(self: *const ServiceRecord) u64 {
        return self.id;
    }

    pub fn descriptor(self: *const ServiceRecord) contract.ServiceDescriptor {
        return contract.serviceDescriptor(self.class) orelse
            native_util.impossibleByInvariant("registered supervisor services retain a schema descriptor");
    }

    comptime {
        if (@sizeOf(@This()) > SERVICE_RECORD_SIZE_CEILING_BYTES) {
            @compileError("supervisor service record exceeds its compact dynamic layout");
        }
    }
};

pub const DiagnosticKind = enum(u8) {
    crash,
    restart_requested,
    restart_completed,
};

pub const DiagnosticEvent = struct {
    sequence: u64,
    service_id: u64,
    tick: u64,
    detail: u32 = 0,
    kind: DiagnosticKind,
};

const DiagnosticArray = [MAX_DIAGNOSTICS]DiagnosticEvent;
const heap_backed_actionable_diagnostics = builtin.target.os.tag == .freestanding and HEAP_BACKED_ACTIONABLE_DIAGNOSTICS_ON_FREESTANDING;
const DiagnosticBacking = if (heap_backed_actionable_diagnostics) ?*DiagnosticArray else DiagnosticArray;
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    root.kernel_memory
else
    struct {};

pub const actionable_diagnostic_layout = .{
    .event_bytes = @sizeOf(DiagnosticEvent),
    .ring_bytes = @sizeOf(DiagnosticArray),
    .resident_backing_bytes = @sizeOf(DiagnosticBacking),
    .heap_backed_on_freestanding = heap_backed_actionable_diagnostics,
};

pub const Error = error{
    ServiceTableFull,
    UnknownServiceClass,
};

pub const DriverRecoveryReport = struct {
    notification_id: ?u64 = null,
    visible_impact: bool = false,
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
    runtime_activation_generation: u32 = 0,
    runtime_dma_domain_id: u64 = 0,
    runtime_exclusive_claim: bool = false,
    userspace_brokered_data_plane: bool = false,
};

const DriverActivationState = struct {
    activation_generation: u32,
    dma_domain_id: u64,
    exclusive_claim: bool,
    userspace_brokered_data_plane: bool,
};

const ServiceSlot = struct {
    in_use: bool = false,
    service: ServiceRecord = zeroService(),
};

const ServiceArena = indexed_arena.IndexedArena(ServiceSlot, MAX_SERVICES, SERVICE_INDEX_CAPACITY, serviceSlotId);
const ServiceClassIndex = indexed_arena.UniqueIndex(SERVICE_INDEX_CAPACITY);

pub const supervisor_indexing = .{
    .uses_service_arena = @hasDecl(ServiceArena, "reserveIndex"),
    .uses_service_class_index = @hasDecl(ServiceClassIndex, "lookup"),
    .scans_bounded_diagnostic_ring = true,
    .scans_diagnostics_newest_first = true,
};

pub const Supervisor = struct {
    next_service_id: u64 = 1,
    service_arena: ServiceArena = ServiceArena.init(),
    service_class_index: ServiceClassIndex = ServiceClassIndex.init(),
    next_diagnostic_sequence: u64 = 1,
    diagnostics: DiagnosticBacking = if (heap_backed_actionable_diagnostics) null else [_]DiagnosticEvent{zeroDiagnostic()} ** MAX_DIAGNOSTICS,
    diagnostic_count: u8 = 0,
    next_diagnostic_slot: u8 = 0,

    pub fn init() Supervisor {
        return Supervisor{};
    }

    comptime {
        if (@sizeOf(@This()) > SUPERVISOR_SIZE_CEILING_BYTES) {
            @compileError("supervisor exceeds its compact resident layout");
        }
        if (@sizeOf(DiagnosticEvent) > DIAGNOSTIC_EVENT_SIZE_CEILING_BYTES) {
            @compileError("supervisor diagnostic event exceeds its compact layout");
        }
        if (heap_backed_actionable_diagnostics and @sizeOf(DiagnosticBacking) > DIAGNOSTIC_HANDLE_SIZE_CEILING_BYTES) {
            @compileError("heap-backed supervisor diagnostics exceed their handle size ceiling");
        }
    }

    pub fn deinit(self: *Supervisor) void {
        if (comptime heap_backed_actionable_diagnostics) {
            if (self.diagnostics) |diagnostics| {
                @memset(std.mem.asBytes(diagnostics), 0);
                kernel_memory.kfree(@ptrCast(diagnostics));
                self.diagnostics = null;
            }
        } else {
            self.diagnostics = [_]DiagnosticEvent{zeroDiagnostic()} ** MAX_DIAGNOSTICS;
        }
        self.next_diagnostic_sequence = 1;
        self.diagnostic_count = 0;
        self.next_diagnostic_slot = 0;
    }

    pub fn register(self: *Supervisor, class: contract.ServiceClass, owner: principal.PrincipalId) Error!*ServiceRecord {
        if (contract.serviceDescriptor(class) == null) return error.UnknownServiceClass;

        const service_id = self.nextReservableServiceId() orelse return error.ServiceTableFull;
        const slot_index = self.service_arena.reserveIndex(service_id) orelse return error.ServiceTableFull;
        const slot = &self.service_arena.slots[slot_index];

        slot.service = .{
            .id = service_id,
            .class = class,
            .owner = owner,
            .contract_endpoint_id = 0,
            .state = .registered,
            .restart_count = 0,
        };
        self.service_class_index.insert(serviceClassKey(class), slot_index);
        self.advanceNextServiceIdFrom(service_id);
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
        return left.isolationDomainId() != right.isolationDomainId();
    }

    pub fn markHealthy(self: *Supervisor, service_id: u64) bool {
        const service = self.find(service_id) orelse return false;
        service.state = .healthy;
        return true;
    }

    pub fn isReady(self: *const Supervisor, service_id: u64) bool {
        const service = self.findConst(service_id) orelse return false;
        return service.state == .healthy and service.contract_endpoint_id != 0;
    }

    pub fn recordCrash(self: *Supervisor, service_id: u64, tick: u64, code: u32) bool {
        const service = self.find(service_id) orelse return false;
        self.recordCrashForService(service, tick, code);
        return true;
    }

    pub fn requestRestart(self: *Supervisor, service_id: u64, tick: u64) bool {
        const service = self.find(service_id) orelse return false;
        return self.requestRestartForService(service, tick);
    }

    pub fn completeRestart(self: *Supervisor, service_id: u64, tick: u64) bool {
        const service = self.find(service_id) orelse return false;
        self.completeRestartForService(service, tick);
        return true;
    }

    pub fn noteContractBound(self: *Supervisor, service_id: u64, endpoint_id: u64) bool {
        if (endpoint_id == 0) return false;
        const service = self.find(service_id) orelse return false;
        service.contract_endpoint_id = endpoint_id;
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
        if (!service.descriptor().restartable) return error.ServiceNotRestartable;

        const restart_detail = if (detail.len != 0)
            detail
        else
            defaultDriverRestartDetail(driver.device_class);
        const visible_impact = driverImpactIsVisible(driver.device_class);

        self.recordCrashForService(service, tick, crash_code);
        if (ledger) |recording| {
            try recording.recordProcessCrash(service.class, service.owner, tick, crash_code, restart_detail);
        }

        if (!self.requestRestartForService(service, tick + 1)) return error.ServiceNotRestartable;
        if (!directory.markRestarted(driver)) return error.DriverRestartFailed;
        if (!runtime.deactivateDriver(driver.service_id, driver.device_class)) {
            return error.DriverDeactivationFailed;
        }
        const activation = try activateRuntimeDriver(runtime, driver, tick + 2);
        self.completeRestartForService(service, tick + 2);

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
        if (!service.descriptor().restartable) return error.ServiceNotRestartable;
        if (!contract.allowsDriverClass(service.class, request.device_class)) {
            return error.DriverAttachmentDenied;
        }
        const previous = (directory.findByServiceAndClass(request.service_id, request.device_class) orelse return error.DriverNotFound).*;

        const swap_detail = if (detail.len != 0)
            detail
        else
            defaultDriverRestartDetail(request.device_class);
        const visible_impact = driverImpactIsVisible(request.device_class);

        if (!self.requestRestartForService(service, tick)) return error.ServiceNotRestartable;
        if (!runtime.deactivateDriver(request.service_id, request.device_class)) {
            return error.DriverDeactivationFailed;
        }

        const swapped = try directory.hotSwapSigned(request);
        if (previous.authority_capability_id != request.authority_capability_id and
            !(try runtime.revokeCapability(previous.owner_task_id, previous.authority_capability_id)))
        {
            return error.CapabilityRevokeFailed;
        }

        const activation = try activateRuntimeDriver(runtime, swapped, tick + 1);
        self.completeRestartForService(service, tick + 1);

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
            .runtime_activation_generation = activation.activation_generation,
            .runtime_dma_domain_id = activation.dma_domain_id,
            .runtime_exclusive_claim = activation.exclusive_claim,
            .userspace_brokered_data_plane = activation.userspace_brokered_data_plane,
        };
    }

    pub fn hasDiagnostic(self: *const Supervisor, service_id: u64, kind: DiagnosticKind) bool {
        return self.newestDiagnostic(service_id, kind) != null;
    }

    pub fn latestDiagnostic(self: *const Supervisor, service_id: u64) ?DiagnosticEvent {
        return self.newestDiagnostic(service_id, null);
    }

    fn newestDiagnostic(self: *const Supervisor, service_id: u64, kind: ?DiagnosticKind) ?DiagnosticEvent {
        if (self.diagnostic_count == 0) return null;
        const diagnostics = self.diagnosticsConst() orelse
            native_util.impossibleByInvariant("retained supervisor diagnostics have backing storage");
        var remaining: usize = self.diagnostic_count;
        var slot_index = (@as(usize, self.next_diagnostic_slot) + MAX_DIAGNOSTICS - 1) % MAX_DIAGNOSTICS;
        while (remaining != 0) : (remaining -= 1) {
            const event = diagnostics[slot_index];
            if (event.service_id == service_id and (kind == null or event.kind == kind.?)) return event;
            slot_index = if (slot_index == 0) MAX_DIAGNOSTICS - 1 else slot_index - 1;
        }
        return null;
    }

    fn nextReservableServiceId(self: *const Supervisor) ?u64 {
        if (self.serviceCount() >= MAX_SERVICES or self.next_service_id == 0) return null;
        if (self.findConst(self.next_service_id) != null) {
            native_util.impossibleByInvariant("monotonic supervisor service ids are never reused");
        }
        return self.next_service_id;
    }

    fn recordCrashForService(self: *Supervisor, service: *ServiceRecord, tick: u64, code: u32) void {
        service.state = .failed;
        self.record(service.id, .crash, tick, code);
    }

    fn requestRestartForService(self: *Supervisor, service: *ServiceRecord, tick: u64) bool {
        if (!service.descriptor().restartable) return false;
        service.state = .restarting;
        service.restart_count += 1;
        self.record(service.id, .restart_requested, tick, service.restart_count);
        return true;
    }

    fn completeRestartForService(self: *Supervisor, service: *ServiceRecord, tick: u64) void {
        service.state = .healthy;
        self.record(service.id, .restart_completed, tick, service.restart_count);
    }

    fn advanceNextServiceIdFrom(self: *Supervisor, service_id: u64) void {
        self.next_service_id = service_id +% 1;
    }

    fn record(
        self: *Supervisor,
        service_id: u64,
        kind: DiagnosticKind,
        tick: u64,
        detail: u32,
    ) void {
        const diagnostics = self.ensureDiagnostics() orelse return;
        const event = DiagnosticEvent{
            .sequence = self.nextDiagnosticSequence(),
            .service_id = service_id,
            .tick = tick,
            .detail = detail,
            .kind = kind,
        };

        const slot_index = self.nextDiagnosticSlot();
        if (slot_index >= self.diagnostic_count) self.diagnostic_count = @intCast(slot_index + 1);
        diagnostics[slot_index] = event;
    }

    fn diagnosticsPtr(self: *Supervisor) ?*DiagnosticArray {
        if (comptime heap_backed_actionable_diagnostics) return self.diagnostics;
        return &self.diagnostics;
    }

    fn diagnosticsConst(self: *const Supervisor) ?*const DiagnosticArray {
        if (comptime heap_backed_actionable_diagnostics) return self.diagnostics;
        return &self.diagnostics;
    }

    fn ensureDiagnostics(self: *Supervisor) ?*DiagnosticArray {
        if (self.diagnosticsPtr()) |diagnostics| return diagnostics;
        if (comptime heap_backed_actionable_diagnostics) {
            const allocation = kernel_memory.kmalloc(@sizeOf(DiagnosticArray)) orelse return null;
            const diagnostics: *DiagnosticArray = @ptrCast(@alignCast(allocation));
            @memset(std.mem.asBytes(diagnostics), 0);
            self.diagnostics = diagnostics;
            return diagnostics;
        }
        return &self.diagnostics;
    }

    fn nextDiagnosticSlot(self: *Supervisor) usize {
        const slot_index: usize = self.next_diagnostic_slot;
        self.next_diagnostic_slot = @intCast((slot_index + 1) % MAX_DIAGNOSTICS);
        return slot_index;
    }

    fn nextDiagnosticSequence(self: *Supervisor) u64 {
        const sequence = self.next_diagnostic_sequence;
        if (sequence == 0) {
            native_util.impossibleByInvariant("supervisor diagnostic sequence exhausted");
        }
        self.next_diagnostic_sequence = sequence +% 1;
        return sequence;
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

fn zeroService() ServiceRecord {
    return .{
        .id = 0,
        .class = .task_runtime,
        .owner = .{ .kind = .service, .serial = 0 },
        .contract_endpoint_id = 0,
        .state = .registered,
        .restart_count = 0,
    };
}

fn zeroDiagnostic() DiagnosticEvent {
    return .{
        .sequence = 0,
        .service_id = 0,
        .tick = 0,
        .detail = 0,
        .kind = .crash,
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
) !DriverActivationState {
    const result = try runtime.activateAt(driver, tick);
    return .{
        .activation_generation = result.activation_generation,
        .dma_domain_id = result.dma_domain_id,
        .exclusive_claim = result.hasExclusiveClaim(),
        .userspace_brokered_data_plane = result.mode == .userspace_brokered_data_plane,
    };
}

test "supervisor registers services using the contract boundary map" {
    var supervisor = Supervisor.init();
    const service = try supervisor.register(.session_manager, .{ .kind = .service, .serial = 1 });

    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, service.descriptor().boundary);
    try std.testing.expectEqual(contract.UiPrivilege.session_surface, service.descriptor().isolation.ui);
    try std.testing.expectEqual(@as(u64, 1), service.isolationDomainId());
    try std.testing.expect(service.descriptor().restartable);
    try std.testing.expect(supervisor.markHealthy(service.id));
    try std.testing.expectEqual(ServiceState.healthy, service.state);
}

test "supervisor service identifiers stop at exhaustion" {
    var supervisor = Supervisor.init();

    supervisor.next_service_id = std.math.maxInt(u64);
    const max_service = try supervisor.register(.session_manager, .{ .kind = .service, .serial = 10 });
    try std.testing.expectEqual(std.math.maxInt(u64), max_service.id);
    try std.testing.expectEqual(std.math.maxInt(u64), max_service.isolationDomainId());
    try std.testing.expectEqual(@as(u64, 0), supervisor.next_service_id);
    try std.testing.expect(supervisor.find(0) == null);
    try std.testing.expectError(error.ServiceTableFull, supervisor.register(.task_runtime, .{ .kind = .service, .serial = 11 }));
}

test "supervisor service ids do not advance when the table is full" {
    var supervisor = Supervisor.init();
    for (0..MAX_SERVICES) |index| {
        _ = try supervisor.register(.task_runtime, .{ .kind = .service, .serial = @intCast(index + 100) });
    }

    const next_service_before = supervisor.next_service_id;
    try std.testing.expectError(error.ServiceTableFull, supervisor.register(.session_manager, .{ .kind = .service, .serial = 200 }));
    try std.testing.expectEqual(next_service_before, supervisor.next_service_id);
    try std.testing.expectEqual(MAX_SERVICES, supervisor.serviceCount());
}

test "supervisor diagnostic sequences stop at exhaustion" {
    var supervisor = Supervisor.init();

    supervisor.next_diagnostic_sequence = std.math.maxInt(u64);
    const service = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 20 });
    try std.testing.expect(supervisor.recordCrash(service.id, 1, 0xD1));
    try std.testing.expectEqual(std.math.maxInt(u64), supervisor.latestDiagnostic(service.id).?.sequence);
    try std.testing.expectEqual(@as(u64, 0), supervisor.next_diagnostic_sequence);
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

    try std.testing.expect(supervisor.noteContractBound(network.id, 101));
    try std.testing.expect(supervisor.allowsDriverAttachment(network.id, .network_adapter));
    try std.testing.expectEqual(@as(u8, 0), supervisor.diagnostic_count);
    try std.testing.expect(supervisor.recordCrash(network.id, 7, 0xD1));
    try std.testing.expect(supervisor.requestRestart(network.id, 8));
    try std.testing.expect(supervisor.completeRestart(network.id, 9));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .crash));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .restart_requested));
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .restart_completed));
    try std.testing.expectEqual(@as(u8, 3), supervisor.diagnostic_count);
    try std.testing.expectEqual(ServiceState.healthy, network.state);
    try std.testing.expectEqual(@as(u16, 1), network.restart_count);
    try std.testing.expectEqual(@as(u64, 9), supervisor.latestDiagnostic(network.id).?.tick);
}

test "supervisor keeps diagnostics queryable while recycling the bounded ring" {
    var supervisor = Supervisor.init();
    const network = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 40 });
    try std.testing.expect(supervisor.latestDiagnostic(network.id) == null);

    var index: usize = 0;
    while (index < MAX_DIAGNOSTICS) : (index += 1) {
        try std.testing.expect(supervisor.recordCrash(network.id, 100 + @as(u64, @intCast(index)), @intCast(index)));
    }

    try std.testing.expectEqual(@as(u8, MAX_DIAGNOSTICS), supervisor.diagnostic_count);
    try std.testing.expectEqual(@as(u8, 0), supervisor.next_diagnostic_slot);
    try std.testing.expect(supervisor.hasDiagnostic(network.id, .crash));
    try std.testing.expectEqual(@as(u64, 100 + MAX_DIAGNOSTICS - 1), supervisor.latestDiagnostic(network.id).?.tick);
}

test "supervisor keeps bounded diagnostic metadata compact" {
    try std.testing.expectEqual(u8, @FieldType(Supervisor, "diagnostic_count"));
    try std.testing.expectEqual(u8, @FieldType(Supervisor, "next_diagnostic_slot"));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(DiagnosticEvent));
    try std.testing.expectEqual(@as(usize, 2_048), actionable_diagnostic_layout.ring_bytes);
    try std.testing.expect(OMITS_UNOBSERVED_SERVICE_TRANSITION_TIMESTAMPS);
    try std.testing.expect(!@hasField(ServiceRecord, "last_transition_tick"));
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(ServiceRecord));
    try std.testing.expectEqual(@as(usize, 4_408), @sizeOf(Supervisor));
}

test "supervisor deinit clears retained diagnostics and sequence state" {
    var supervisor = Supervisor.init();
    const network = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 44 });
    try std.testing.expect(supervisor.recordCrash(network.id, 10, 1));
    try std.testing.expectEqual(@as(u8, 1), supervisor.diagnostic_count);

    supervisor.deinit();

    try std.testing.expectEqual(@as(u8, 0), supervisor.diagnostic_count);
    try std.testing.expectEqual(@as(u8, 0), supervisor.next_diagnostic_slot);
    try std.testing.expectEqual(@as(u64, 1), supervisor.next_diagnostic_sequence);
    try std.testing.expect(supervisor.latestDiagnostic(network.id) == null);
}

test "supervisor diagnostic ring scan selects the newest event per service" {
    var supervisor = Supervisor.init();
    const network = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 42 });
    const storage = try supervisor.register(.storage_object, .{ .kind = .service, .serial = 43 });

    try std.testing.expect(supervisor.recordCrash(storage.id, 10, 1));
    try std.testing.expect(supervisor.recordCrash(network.id, 11, 2));
    try std.testing.expectEqual(@as(u64, 11), supervisor.latestDiagnostic(network.id).?.tick);
    try std.testing.expectEqual(@as(u64, 10), supervisor.latestDiagnostic(storage.id).?.tick);
    try std.testing.expect(supervisor.hasDiagnostic(storage.id, .crash));
}

test "service readiness is live state independent of diagnostic retention" {
    var supervisor = Supervisor.init();
    const network = try supervisor.register(.network_stack, .{ .kind = .service, .serial = 41 });

    try std.testing.expect(!supervisor.isReady(network.id));
    try std.testing.expect(!supervisor.noteContractBound(network.id, 0));
    try std.testing.expect(supervisor.noteContractBound(network.id, 101));
    try std.testing.expect(!supervisor.isReady(network.id));
    try std.testing.expect(supervisor.markHealthy(network.id));
    try std.testing.expect(supervisor.isReady(network.id));
    try std.testing.expectEqual(@as(u8, 0), supervisor.diagnostic_count);
    try std.testing.expect(supervisor.isReady(network.id));
    try std.testing.expect(supervisor.recordCrash(network.id, 100, 0xBAD));
    try std.testing.expect(!supervisor.isReady(network.id));
    try std.testing.expect(supervisor.completeRestart(network.id, 101));
    try std.testing.expect(supervisor.isReady(network.id));
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
        const ActivationMode = enum(u8) { userspace_brokered_data_plane };
        const ActivationRecord = struct {
            activation_generation: u32,
            dma_domain_id: u64,
            mode: ActivationMode,

            pub fn hasExclusiveClaim(_: *const @This()) bool {
                return true;
            }
        };

        deactivation_count: usize = 0,
        activation_count: usize = 0,
        last_service_id: u64 = 0,

        pub fn deactivateDriver(self: *@This(), _: u64, _: driver_service.DeviceClass) bool {
            self.deactivation_count += 1;
            return true;
        }

        pub fn activateAt(self: *@This(), driver: *const driver_service.DriverRecord, _: u64) !ActivationRecord {
            self.activation_count += 1;
            self.last_service_id = driver.service_id;
            return .{
                .activation_generation = @intCast(self.activation_count),
                .dma_domain_id = driver.dma_domain_id,
                .mode = .userspace_brokered_data_plane,
            };
        }
    };

    var supervisor = Supervisor.init();
    const compositor = try supervisor.register(.compositor_ui_session, .{ .kind = .service, .serial = 11 });
    const storage = try supervisor.register(.storage_object, .{ .kind = .service, .serial = 12 });
    try std.testing.expect(supervisor.markHealthy(compositor.id));
    try std.testing.expect(supervisor.markHealthy(storage.id));

    var directory = driver_service.Directory.init();
    var capabilities = capability.CapabilityTable.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.runtime",
        .display_name = "Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = .ed25519,
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
    try std.testing.expectEqual(@as(usize, 1), runtime.deactivation_count);
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

    directory.next_dma_domain_id = 0;
    try std.testing.expectError(error.DriverRestartFailed, supervisor.recoverDriverCrash(
        compositor.id,
        &directory,
        &runtime,
        &notifications,
        &ledger,
        20,
        0xD2,
        "display driver restart without DMA isolation",
    ));
    try std.testing.expectEqual(ServiceState.restarting, compositor.state);
    try std.testing.expectEqual(@as(usize, 1), runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 1), runtime.activation_count);
    try std.testing.expectEqual(@as(u32, 2), graphics_driver.restart_generation);
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
            mode: ActivationMode,

            pub fn hasExclusiveClaim(self: *const @This()) bool {
                return self.mode != .control_only;
            }
        };

        deactivation_count: usize = 0,
        activation_count: usize = 0,
        last_deactivated_service_id: u64 = 0,
        last_activated_service_id: u64 = 0,
        last_dma_domain_id: u64 = 0,
        revoked_task_id: u64 = 0,
        revoked_capability_id: u64 = 0,

        pub fn deactivateDriver(self: *@This(), service_id: u64, _: driver_service.DeviceClass) bool {
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
                .mode = .userspace_brokered_data_plane,
            };
        }

        pub fn revokeCapability(self: *@This(), task_id: u64, capability_id: u64) !bool {
            self.revoked_task_id = task_id;
            self.revoked_capability_id = capability_id;
            return true;
        }
    };

    var supervisor = Supervisor.init();
    const compositor = try supervisor.register(.compositor_ui_session, .{ .kind = .service, .serial = 21 });
    const storage = try supervisor.register(.storage_object, .{ .kind = .service, .serial = 22 });
    try std.testing.expect(supervisor.markHealthy(compositor.id));
    try std.testing.expect(supervisor.markHealthy(storage.id));

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
    try std.testing.expectEqual(@as(u32, 1), report.runtime_activation_generation);
    try std.testing.expectEqual(swapped.dma_domain_id, report.runtime_dma_domain_id);
    try std.testing.expect(report.runtime_exclusive_claim);
    try std.testing.expect(report.userspace_brokered_data_plane);
    try std.testing.expectEqual(second_authority.id, swapped.authority_capability_id);
    try std.testing.expect(swapped.signerMatches("graphics-v2"));
    try std.testing.expect(!swapped.signerMatches("graphics-v1"));
    try std.testing.expectEqual(@as(usize, 1), runtime.deactivation_count);
    try std.testing.expectEqual(@as(usize, 1), runtime.activation_count);
    try std.testing.expectEqual(compositor.id, runtime.last_deactivated_service_id);
    try std.testing.expectEqual(compositor.id, runtime.last_activated_service_id);
    try std.testing.expectEqual(swapped.dma_domain_id, runtime.last_dma_domain_id);
    try std.testing.expectEqual(@as(u64, 501), runtime.revoked_task_id);
    try std.testing.expectEqual(first_authority.id, runtime.revoked_capability_id);
    try std.testing.expectEqual(ServiceState.healthy, compositor.state);
    try std.testing.expectEqual(@as(u16, 1), compositor.restart_count);
    try std.testing.expectEqual(ServiceState.healthy, storage.state);
    try std.testing.expectEqual(@as(u16, 0), storage.restart_count);
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
