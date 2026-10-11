const std = @import("std");
const builtin = @import("builtin");
const abi = @import("../../core/abi.zig");
const boot_markers = @import("../../../kernel/boot/markers.zig");
const capability = @import("../../kernel_api/capability.zig");
const component_port = @import("../../kernel_api/component_port.zig");
const driver_service = @import("../../drivers/driver_service.zig");
const endpoint = @import("../../kernel_api/endpoint.zig");
const manifest = @import("../../policy/manifest.zig");
const native_kernel = @import("../../kernel_api/native_kernel.zig");
const principal = @import("../../core/principal.zig");
const shared_memory = @import("../../kernel_api/shared_memory.zig");
const units = @import("../../core/units.zig");
const userspace_bootstrap_mailbox = @import("../../task/userspace_bootstrap_mailbox.zig");
const userspace_loader = @import("../../task/userspace_loader.zig");
const userspace_scheduler = @import("../../task/userspace_scheduler.zig");
const task_runtime = @import("../../task/task_runtime.zig");
const task_runtime_service = @import("../../task/task_runtime_service.zig");
const network_policy = @import("../../sync/network_policy.zig");
const kernel_memory = if (builtin.target.os.tag == .freestanding)
    @import("../../../kernel/memory/memory.zig")
else
    struct {};

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const paging = if (builtin.target.os.tag == .freestanding)
    @import("../../../kernel/memory/paging64.zig")
else
    struct {
        pub const FrameStats = struct {
            total: u32 = 0,
            reserved: u32 = 0,
            allocated: u32 = 0,
            free: u32 = 0,
        };

        pub fn frameStats() FrameStats {
            return .{};
        }
    };

const MMU_PROOF_BUNDLE_ID = "zigos.proof.mmu-isolation";
const GP_PROOF_BUNDLE_ID = "zigos.system.termination-probe";
const USER_PAGE_FAULT_VECTOR: u8 = 14;
const PAGE_FAULT_USER_MODE_BIT: u32 = 1 << 2;
const HEAP_BACKED_PROOF_FIXTURES = builtin.target.os.tag == .freestanding;

const FreestandingProofFixtures = struct {
    runtime: task_runtime.Runtime,
    restarted_runtime: task_runtime.Runtime,
    capabilities: capability.CapabilityTable,
    endpoints: endpoint.Table,
};

const HostProofFixtures = if (HEAP_BACKED_PROOF_FIXTURES) struct {} else struct {
    var runtime: task_runtime.Runtime = task_runtime.Runtime.init();
    var restarted_runtime: task_runtime.Runtime = task_runtime.Runtime.init();
    var capabilities: capability.CapabilityTable = capability.CapabilityTable.init();
    var endpoints: endpoint.Table = endpoint.Table.init();
};

var reboot_proof_checkpoint_store: task_runtime_service.CheckpointStore = .{};
var freestanding_proof_fixtures: ?*FreestandingProofFixtures = null;
var proof_shared: shared_memory.Table = shared_memory.Table.init();

fn allocateFreestandingProofFixtures() bool {
    if (comptime !HEAP_BACKED_PROOF_FIXTURES) return true;
    if (freestanding_proof_fixtures != null) return false;
    const allocation = kernel_memory.kmalloc(@sizeOf(FreestandingProofFixtures)) orelse return false;
    const fixtures: *FreestandingProofFixtures = @ptrCast(@alignCast(allocation));
    fixtures.runtime.initializeAllocated();
    fixtures.restarted_runtime.initializeAllocated();
    fixtures.capabilities.initializeAllocated();
    fixtures.endpoints.initializeAllocated();
    freestanding_proof_fixtures = fixtures;
    return true;
}

fn releaseFreestandingProofFixtures() void {
    if (comptime !HEAP_BACKED_PROOF_FIXTURES) return;
    const fixtures = freestanding_proof_fixtures orelse return;
    fixtures.runtime.reset();
    fixtures.restarted_runtime.reset();
    fixtures.endpoints.reset();
    proof_shared.deinit();
    proof_shared = shared_memory.Table.init();
    @memset(std.mem.asBytes(fixtures), 0);
    kernel_memory.kfree(@ptrCast(fixtures));
    freestanding_proof_fixtures = null;
}

fn proofRuntime() *task_runtime.Runtime {
    if (comptime HEAP_BACKED_PROOF_FIXTURES) return &freestanding_proof_fixtures.?.runtime;
    return &HostProofFixtures.runtime;
}

fn restartedProofRuntime() *task_runtime.Runtime {
    if (comptime HEAP_BACKED_PROOF_FIXTURES) return &freestanding_proof_fixtures.?.restarted_runtime;
    return &HostProofFixtures.restarted_runtime;
}

fn proofCapabilities() *capability.CapabilityTable {
    if (comptime HEAP_BACKED_PROOF_FIXTURES) return &freestanding_proof_fixtures.?.capabilities;
    return &HostProofFixtures.capabilities;
}

fn proofEndpoints() *endpoint.Table {
    if (comptime HEAP_BACKED_PROOF_FIXTURES) return &freestanding_proof_fixtures.?.endpoints;
    return &HostProofFixtures.endpoints;
}

fn resetProofFixtures() void {
    proofRuntime().reset();
    proofCapabilities().initializeAllocated();
    proofEndpoints().reset();
    proof_shared.deinit();
    proof_shared = shared_memory.Table.init();
}

pub fn runAndPrint() bool {
    if (comptime HEAP_BACKED_PROOF_FIXTURES) {
        if (!allocateFreestandingProofFixtures()) return false;
    }
    defer if (comptime HEAP_BACKED_PROOF_FIXTURES) releaseFreestandingProofFixtures();
    if (!processIsolationBlocksForeignSharedMemory()) return false;
    common.printBootMarker(boot_markers.runtime_proof_process_isolation);

    if (!syscallSubjectSpoofingIsRejected()) return false;
    common.printBootMarker(boot_markers.runtime_proof_syscall_subject_spoof);

    if (!rawNetworkSendBypassIsDenied()) return false;
    common.printBootMarker(boot_markers.runtime_proof_raw_network_bypass);

    if (!driverAuthorityEscapeIsRejected()) return false;
    common.printBootMarker(boot_markers.runtime_proof_driver_authority_escape);

    if (!checkpointAuthorityIsNotReplayed()) return false;
    common.printBootMarker(boot_markers.runtime_proof_checkpoint_authority);

    return true;
}

pub fn runFreestandingAndPrint(
    catalog: *userspace_loader.Catalog,
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
    kernel: *native_kernel.Kernel,
) bool {
    if (builtin.target.os.tag != .freestanding) return true;
    if (!sharedDirectoryRangeReclamation()) return false;
    const launched = catalog.launchDirect(runtime, MMU_PROOF_BUNDLE_ID, .{
        .owner = app(60),
        .budget = budget(),
        .local_only = true,
    }) catch return false;
    const task_id = launched.id;
    const proof_image = catalog.findById(launched.launch.image_id) orelse return false;
    const nx_probe_address = std.math.cast(u32, proof_image.bootstrap_mailbox_address) orelse return false;

    const baseline_frames = paging.frameStats().allocated;
    const baseline_mappings = scheduler.executor.materializedCount();
    if (!scheduler.executor.materializeTaskForProof(catalog, runtime, task_id)) return false;

    const materialized_frames = paging.frameStats().allocated;
    if (materialized_frames <= baseline_frames) return false;
    const frame_footprint = materialized_frames - baseline_frames;
    if (scheduler.executor.materializedCount() != baseline_mappings + 1) return false;

    if (!scheduler.executor.rehostActiveTaskForProof(runtime, task_id, 1)) return false;
    if (scheduler.executor.materializedCount() != baseline_mappings) return false;
    if (paging.frameStats().allocated != baseline_frames) return false;
    if (!scheduler.executor.materializeTaskForProof(catalog, runtime, task_id)) return false;
    if (scheduler.executor.materializedCount() != baseline_mappings + 1) return false;
    if (paging.frameStats().allocated != baseline_frames + frame_footprint) return false;

    var rehost_iteration: usize = 0;
    while (rehost_iteration < task_runtime.MAX_TASKS + 1) : (rehost_iteration += 1) {
        const before = runtime.find(task_id) orelse return false;
        const retired_address_space_id = before.address_space_id;
        if (!(runtime.rehostTask(task_id, rehost_iteration + 2) catch return false)) return false;

        const rehosted = runtime.find(task_id) orelse return false;
        if (rehosted.address_space_id == retired_address_space_id) return false;
        if (scheduler.executor.materializedCount() != baseline_mappings) return false;
        if (paging.frameStats().allocated != baseline_frames) return false;

        if (!scheduler.executor.materializeTaskForProof(catalog, runtime, task_id)) return false;
        if (scheduler.executor.materializedCount() != baseline_mappings + 1) return false;
        if (paging.frameStats().allocated != baseline_frames + frame_footprint) return false;
    }

    var saw_syscall_pointer_denial = false;
    var saw_user_nx_fault = false;
    var attempt: usize = 0;
    while (attempt < 8) : (attempt += 1) {
        const outcome = scheduler.executeTask(task_id, attempt);
        const current = runtime.findConst(task_id) orelse return false;

        if (!saw_syscall_pointer_denial and
            scheduler.executor.observedUserCounterStagePulse(
                current.address_space_id,
                .syscall_ready,
                userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE,
            ))
        {
            common.printBootMarker(boot_markers.runtime_proof_syscall_pointer_isolation);
            saw_syscall_pointer_denial = true;
        }

        if (!saw_user_nx_fault and scheduler.executor.consumeUserExecuteFault(
            task_id,
            current.address_space_id,
            nx_probe_address,
        )) {
            common.printBootMarker(boot_markers.runtime_proof_user_nx_fault);
            saw_user_nx_fault = true;
        }

        if (outcome == .faulted) {
            const exception = scheduler.executor.lastUserException() orelse return false;
            if (exception.vector != USER_PAGE_FAULT_VECTOR or
                (exception.error_code & PAGE_FAULT_USER_MODE_BIT) == 0)
            {
                return false;
            }
            if (exception.fault_address != userspace_bootstrap_mailbox.FOREIGN_SHARED_MEMORY_PROBE_ADDR) return false;
            if (current.state != .terminated) return false;
            if (!saw_syscall_pointer_denial or !saw_user_nx_fault) return false;
            common.printBootMarker(boot_markers.runtime_proof_mmu_user_fault);
            if (scheduler.executor.materializedCount() != baseline_mappings) return false;
            if (paging.frameStats().allocated != baseline_frames) return false;
            common.printBootMarker(boot_markers.runtime_proof_address_space_reclamation);
            if (!userGeneralProtectionFaultIsContained(catalog, runtime, scheduler, kernel)) return false;
            common.printBootMarker(boot_markers.runtime_proof_user_gp_contained);
            return true;
        }

        if (!outcome.handedOff()) return false;
    }

    return false;
}

fn sharedDirectoryRangeReclamation() bool {
    if (builtin.target.os.tag != .freestanding) return true;
    var space = paging.createUserAddressSpace() catch return false;
    defer paging.destroyUserAddressSpace(&space) catch unreachable;
    const retired_start = 0x4000_0000;
    const survivor_start = 0x4200_0000;
    const huge_bytes = 0x20_0000;
    paging.mapOwnedUserRange(&space, retired_start, huge_bytes, .{ .writable = true }) catch return false;
    paging.mapOwnedUserRange(&space, survivor_start, 0x1000, .{ .writable = true }) catch return false;
    const before = paging.frameStats().allocated;

    // Partial huge-page retirement must reject without deleting either peer.
    if (paging.releaseUserRange(&space, retired_start, 0x1000)) |_| {
        return false;
    } else |err| {
        if (err != error.InvalidRange) return false;
    }
    if (paging.frameStats().allocated != before) return false;

    paging.releaseUserRange(&space, retired_start, huge_bytes) catch return false;
    if (paging.frameStats().allocated + huge_bytes / 0x1000 != before) return false;
    if (paging.ownedUserPageIsExecutable(&space, retired_start) != null) return false;
    if (paging.ownedUserPageIsExecutable(&space, survivor_start) == null) return false;
    // A rehost must be able to reuse the retired image's virtual addresses.
    paging.mapOwnedUserRange(&space, retired_start, huge_bytes, .{ .writable = true }) catch return false;
    return paging.frameStats().allocated == before;
}

fn userGeneralProtectionFaultIsContained(
    catalog: *userspace_loader.Catalog,
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
    kernel: *native_kernel.Kernel,
) bool {
    const baseline_mappings = scheduler.executor.materializedCount();
    const baseline_grants = kernel.capability_table.activeCount();
    const baseline_endpoints = kernel.endpoint_table.activeCount();
    const baseline_objects = kernel.shared_memory_table.activeCount();
    const launched = catalog.launchDirect(runtime, GP_PROOF_BUNDLE_ID, .{
        .owner = app(61),
        .budget = budget(),
        .local_only = true,
    }) catch return false;

    const resources = createGeneralProtectionProofResources(runtime, kernel, launched.id, launched.owner, NativeProofFrameCounter{}) orelse return false;
    if (!scheduler.executor.materializeTaskForProof(catalog, runtime, launched.id)) return false;
    _ = kernel.sharedMemoryMap(.{
        .caller_task_id = launched.id,
        .presented_capability_id = resources.memory_capability_id,
        .target = .none,
    }, launched.id, 0) catch return false;

    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        const outcome = scheduler.executeTask(launched.id, task_runtime.MAX_TASKS + 20 + attempt);
        if (outcome == .faulted) break;
        if (!outcome.handedOff()) return false;
    } else return false;

    const exception = scheduler.executor.lastUserException() orelse return false;
    if (exception.vector != 13 or exception.error_code != 0) return false;
    const terminated = runtime.findConst(launched.id) orelse return false;
    if (terminated.state != .terminated) return false;
    const provenance = terminated.latestProvenanceEvent() orelse return false;
    if (provenance.kind != .crash_report) return false;
    if (terminated.capability_count != 0) return false;
    if (kernel.capability_table.query(resources.authority_id) != null or
        kernel.capability_table.query(resources.endpoint_capability_id) != null or
        kernel.capability_table.query(resources.memory_capability_id) != null) return false;
    if (kernel.capability_table.activeCount() != baseline_grants or
        kernel.endpoint_table.activeCount() != baseline_endpoints or
        kernel.shared_memory_table.activeCount() != baseline_objects) return false;
    if (kernel.shared_memory_table.mappingsForTask(@import("../../core/ids.zig").task(launched.id)) != 0) return false;
    if (scheduler.executor.materializedCount() != baseline_mappings) return false;
    if (paging.frameStats().allocated != resources.baseline_frames) return false;
    return true;
}

const GeneralProtectionProofResources = struct {
    baseline_frames: u32,
    authority_id: u64,
    endpoint_capability_id: u64,
    memory_capability_id: u64,
};

const NativeProofFrameCounter = struct {
    fn allocated(_: @This()) u32 {
        return paging.frameStats().allocated;
    }
};

fn createGeneralProtectionProofResources(
    runtime: *task_runtime.Runtime,
    kernel: *native_kernel.Kernel,
    task_id: u64,
    owner: principal.PrincipalId,
    frame_counter: anytype,
) ?GeneralProtectionProofResources {
    // Fault retirement releases both the image and its owned shared memory.
    // Capture the frame baseline before either allocation, including in hosted
    // fixtures that own real backing instead of metadata-only physical IDs.
    const baseline_frames = frame_counter.allocated();
    const authority = kernel.capability_table.mintBootRoot(.{
        .holder = owner,
        .issuer = kernel.policy_authority,
        .target = .{ .kind = .service, .id = 0xF047 },
        .rights = .{ .service = .{ .endpoint_create = true, .shared_memory_create = true } },
        .scope = .{ .task_id = task_id, .local_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = std.math.maxInt(u64) },
    }) catch return null;
    runtime.grantCapability(task_id, authority.id) catch return null;
    const context = native_kernel.KernelCallContext{
        .caller_task_id = task_id,
        .presented_capability_id = authority.id,
        .target = .none,
    };
    const owned_endpoint = kernel.endpointCreate(context, task_id, "fault-owned", .{ .local_only = true }, 0) catch return null;
    const owned_memory = kernel.sharedMemoryCreate(context, task_id, shared_memory.PAGE_SIZE, 0) catch return null;
    return .{
        .baseline_frames = baseline_frames,
        .authority_id = authority.id,
        .endpoint_capability_id = owned_endpoint.capability_id,
        .memory_capability_id = owned_memory.capability_id,
    };
}

pub fn processIsolationBlocksForeignSharedMemory() bool {
    resetProofFixtures();
    const runtime = proofRuntime();
    const capabilities = proofCapabilities();
    var kernel: native_kernel.Kernel = undefined;
    kernel.initInPlace(policyAuthority(1), runtime, capabilities, proofEndpoints(), &proof_shared);
    defer kernel.deinit();
    var port = component_port.KernelPort.init(&kernel);

    const owner = runtime.createTask(.{
        .owner = app(10),
        .component_class = .app_component,
        .budget = budget(),
        .local_only = true,
    }) catch return false;
    const attacker = runtime.createTask(.{
        .owner = app(11),
        .component_class = .app_component,
        .budget = budget(),
        .local_only = true,
    }) catch return false;
    const authority = capabilities.mintBootRoot(.{
        .holder = owner.owner,
        .issuer = policyAuthority(1),
        .target = .{ .kind = .service, .id = 10 },
        .rights = .{ .service = .{ .shared_memory_create = true } },
        .scope = .{ .task_id = owner.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    }) catch return false;
    runtime.grantCapability(owner.id, authority.id) catch return false;

    const object = port.sharedMemoryCreate(.{
        .header = component_port.makeHeader(.shared_memory_create, owner.id),
        .authority_capability_id = authority.id,
        .owner_task_id = owner.id,
        .size_bytes = shared_memory.PAGE_SIZE,
    }, 1) catch return false;

    _ = port.sharedMemoryMap(.{
        .header = component_port.makeHeader(.shared_memory_map, attacker.id),
        .shared_memory_capability_id = object.capability_id,
        .task_id = attacker.id,
    }, 2) catch |err| return err == error.CapabilityNotFound or err == error.ScopeViolation or err == error.SubjectTaskMismatch;
    return false;
}

pub fn syscallSubjectSpoofingIsRejected() bool {
    resetProofFixtures();
    const runtime = proofRuntime();
    const capabilities = proofCapabilities();
    var kernel: native_kernel.Kernel = undefined;
    kernel.initInPlace(policyAuthority(1), runtime, capabilities, proofEndpoints(), &proof_shared);
    defer kernel.deinit();
    var port = component_port.KernelPort.init(&kernel);

    const receiver = runtime.createTask(.{
        .owner = service(20),
        .component_class = .service_component,
        .budget = budget(),
        .local_only = true,
    }) catch return false;
    const attacker = runtime.createTask(.{
        .owner = app(21),
        .component_class = .app_component,
        .budget = budget(),
        .local_only = true,
    }) catch return false;
    const authority = capabilities.mintBootRoot(.{
        .holder = receiver.owner,
        .issuer = policyAuthority(1),
        .target = .{ .kind = .service, .id = 20 },
        .rights = .{ .service = .{ .endpoint_create = true, .endpoint_recv = true } },
        .scope = .{ .task_id = receiver.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    }) catch return false;
    runtime.grantCapability(receiver.id, authority.id) catch return false;

    const receiver_endpoint = port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, receiver.id),
        .authority_capability_id = authority.id,
        .owner_task_id = receiver.id,
        .label = "receiver",
        .flags = .{ .local_only = true },
    }, 1) catch return false;

    var payload: [endpoint.MAX_MESSAGE_BYTES]u8 = undefined;
    var attached_capability = std.mem.zeroes(abi.CapabilityDescriptor);
    _ = port.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, attacker.id),
        .endpoint_capability_id = receiver_endpoint.capability_id,
        .receiver_task_id = receiver.id,
        .payload_out = &payload,
        .attached_capability_out = &attached_capability,
    }, 2) catch |err| return err == error.SubjectTaskMismatch;
    return false;
}

pub fn rawNetworkSendBypassIsDenied() bool {
    var policies = network_policy.Directory.init();
    const internet = policies.create(.{
        .owner = service(30),
        .label = "internet-without-explicit-grant",
        .mode = .unrestricted_internet,
        .explicit_internet_grant = false,
    }) catch return false;

    var capabilities = capability.CapabilityTable.init();
    var broker = network_policy.EgressBroker.init(&policies, &capabilities);
    const no_capability = broker.connect(.{
        .task_id = 30,
        .principal_id = app(30),
        .capability_id = 999,
        .policy_id = internet.id,
        .evidence = .{ .destination = .public_internet },
        .now_ticks = 1,
    }) catch return false;
    if (no_capability.allowed or no_capability.reason != .capability_missing) return false;

    const app_capability = capabilities.mintBootRoot(.{
        .holder = app(30),
        .issuer = policyAuthority(1),
        .target = .{ .kind = .network_policy, .id = internet.id },
        .rights = .{ .network_policy = .{ .network_remote = true } },
        .scope = .{ .task_id = 30, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    }) catch return false;
    const denied_by_policy = broker.connect(.{
        .task_id = 30,
        .principal_id = app(30),
        .capability_id = app_capability.id,
        .policy_id = internet.id,
        .evidence = .{ .destination = .public_internet },
        .now_ticks = 1,
    }) catch return false;
    return !denied_by_policy.allowed and denied_by_policy.reason == .explicit_grant_required;
}

pub fn driverAuthorityEscapeIsRejected() bool {
    var capabilities = capability.CapabilityTable.init();
    var directory = driver_service.Directory.init();
    const audio_driver = service(40);
    const escaped_authority = capabilities.mintBootRoot(.{
        .holder = audio_driver,
        .issuer = policyAuthority(1),
        .target = driver_service.authorityTarget(0xA0D10),
        .rights = .{ .device = .{ .device_use = true, .network_local = true } },
        .scope = .{ .task_id = 40, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
    }) catch return false;

    _ = directory.register(.{
        .service_id = 40,
        .owner_task_id = 40,
        .device_id = 0xA0D10,
        .device_class = .audio_print_io,
        .authority_capability_id = escaped_authority.id,
        .capability_table = &capabilities,
        .requester = audio_driver,
        .now_ticks = 1,
        .bundle = .{
            .bundle_id = "zigos.system.audio-driver",
            .display_name = "Audio Driver",
            .publisher = "zigos.spec",
            .signature = .{ .format = .ed25519, .signer = "zigos-spec-driver" },
        },
    }) catch |err| return err == error.AuthorityRightsEscalation;
    return false;
}

pub fn checkpointAuthorityIsNotReplayed() bool {
    const runtime = proofRuntime();
    const restarted_runtime = restartedProofRuntime();
    reboot_proof_checkpoint_store.reset();
    runtime.reset();
    restarted_runtime.reset();

    var service_instance = task_runtime_service.Service.initWithStore(runtime, &reboot_proof_checkpoint_store);
    service_instance.bind(50, service(50));
    const task = runtime.createTask(.{
        .owner = app(50),
        .component_class = .app_component,
        .budget = budget(),
        .local_only = true,
    }) catch return false;
    const task_id = task.id;
    runtime.grantCapability(task_id, 91) catch return false;
    runtime.grantCapability(task_id, 92) catch return false;
    service_instance.checkpoint(1) catch return false;
    if (!(runtime.revokeCapability(task_id, 91) catch return false)) return false;
    runtime.grantCapability(task_id, 93) catch return false;
    // Restore the older checkpoint after revocation and a new grant. Only
    // authority still attached to the live task may survive the rollback.
    if (!service_instance.restartFromCheckpoint(2)) return false;
    if (runtime.hasCapability(task_id, 91) or
        !runtime.hasCapability(task_id, 92) or
        !runtime.hasCapability(task_id, 93)) return false;

    var restarted = task_runtime_service.Service.initWithStore(restarted_runtime, &reboot_proof_checkpoint_store);
    restarted.bind(50, service(50));
    if (!restarted.restartFromCheckpoint(3)) return false;
    const restored = restarted_runtime.find(task_id) orelse return false;
    // A new runtime has no authority to inherit from execution metadata.
    return restored.capability_count == 0;
}

fn budget() task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = 10_000,
        .memory_bytes = units.kibibytes(256),
        .endpoint_slots = 8,
        .shared_memory_bytes = units.kibibytes(16),
        .background_allowed = false,
    };
}

fn app(serial: u64) principal.PrincipalId {
    return .{ .kind = .app, .serial = serial };
}

fn service(serial: u64) principal.PrincipalId {
    return .{ .kind = .service, .serial = serial };
}

fn policyAuthority(serial: u64) principal.PrincipalId {
    return .{ .kind = .policy_authority, .serial = serial };
}

test "runtime negative proofs reject modeled bypasses" {
    try std.testing.expect(processIsolationBlocksForeignSharedMemory());
    try std.testing.expect(syscallSubjectSpoofingIsRejected());
    try std.testing.expect(rawNetworkSendBypassIsDenied());
    try std.testing.expect(driverAuthorityEscapeIsRejected());
    try std.testing.expect(checkpointAuthorityIsNotReplayed());
}

test "GP proof frame baseline includes owned shared memory retirement after execution collection" {
    const frame_allocator = @import("../../../kernel/memory/frame_allocator.zig");
    const cpu_identity = @import("../../../kernel/cpu_identity.zig");
    const ids = @import("../../core/ids.zig");
    const Frames = struct {
        const Allocator = frame_allocator.Fixed(8 * shared_memory.PAGE_SIZE, shared_memory.PAGE_SIZE);
        const physical_base: u64 = 0x400000;
        storage: Allocator.Storage = undefined,
        allocator: Allocator = undefined,
        memory: [8 * shared_memory.PAGE_SIZE]u8 = @splat(0xa5),
        releases: u32 = 0,

        fn allocated(self: *const @This()) u32 {
            return self.allocator.stats().allocated;
        }

        fn allocate(raw: *anyopaque, count: u32) ?u64 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const run = self.allocator.allocate(count) orelse return null;
            return physical_base + run.base;
        }

        fn bytes(raw: *anyopaque, address: u64, count: u32) ?[]u8 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (address < physical_base) return null;
            const start: usize = @intCast(address - physical_base);
            const end = start + count * shared_memory.PAGE_SIZE;
            if (end > self.memory.len) return null;
            return self.memory[start..end];
        }

        fn release(raw: *anyopaque, address: u64, count: u32) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            std.debug.assert(std.mem.allEqual(u8, bytes(raw, address, count).?, 0));
            self.allocator.release(.{ .base = address - physical_base, .count = count }) catch unreachable;
            self.releases += 1;
        }
    };
    const previous_cpu = cpu_identity.currentIndex();
    defer cpu_identity.setIndexForTest(previous_cpu);
    cpu_identity.setIndexForTest(0);
    var frames = Frames{};
    frames.allocator = Frames.Allocator.init(&frames.storage);
    var runtime = task_runtime.Runtime.init();
    defer runtime.reset();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    defer endpoints.deinit();
    var shared = shared_memory.Table.initWithHostedPhysicalBacking(.{
        .context = &frames,
        .allocate = Frames.allocate,
        .bytes = Frames.bytes,
        .release = Frames.release,
    }, null);
    defer shared.deinit();
    var kernel: native_kernel.Kernel = undefined;
    kernel.initInPlace(policyAuthority(1), &runtime, &capabilities, &endpoints, &shared);
    defer kernel.deinit();
    const peer = try shared.create(ids.task(999), shared_memory.PAGE_SIZE);
    const task = try runtime.createTask(.{ .owner = app(61), .component_class = .app_component, .budget = budget(), .local_only = true });
    const resources = createGeneralProtectionProofResources(&runtime, &kernel, task.id, task.owner, &frames) orelse return error.ProofResourceCreationFailed;
    try std.testing.expectEqual(@as(u32, 1), resources.baseline_frames);
    try std.testing.expectEqual(resources.baseline_frames + 1, frames.allocated());
    _ = try kernel.sharedMemoryMap(.{ .caller_task_id = task.id, .presented_capability_id = resources.memory_capability_id, .target = .none }, task.id, 0);
    const object_id = ids.sharedMemory(capabilities.query(resources.memory_capability_id).?.target.id);
    const mapping = try shared.freestandingTaskMappingDescriptor(object_id, ids.task(task.id));
    @memset(Frames.bytes(&frames, mapping.physical_base, @intCast(mapping.page_count)).?, 0xa5);
    Frames.bytes(&frames, peer.page_base, 1).?[0] = 0x5a;
    const ticket = try runtime.reserveExecution(task, 0);
    try runtime.execution.bindOwnedRoot(ticket, 1, 0x1000);
    _ = try runtime.execution.start(ticket);
    runtime.recordCrashReportForResolved(task, 0xf047, 1, 13, 1, 0x13, true);
    try std.testing.expect(runtime.terminateResolvedTask(task, 1));
    try std.testing.expectEqual(resources.baseline_frames + 1, frames.allocated());
    try std.testing.expectEqual(@as(u32, 0), frames.releases);
    try runtime.execution.acknowledgeOwnedRootReturn(ticket);
    try runtime.collectExecution(ticket);
    try std.testing.expectEqual(resources.baseline_frames, frames.allocated());
    try std.testing.expectEqual(@as(u32, 1), frames.releases);
    try std.testing.expectEqual(@as(u16, 0), shared.mappingsForTask(ids.task(task.id)));
    try std.testing.expectEqual(@as(usize, 1), shared.activeCount());
    _ = try shared.descriptor(peer.id);
    try std.testing.expectEqual(@as(u8, 0x5a), Frames.bytes(&frames, peer.page_base, 1).?[0]);
    try std.testing.expect(capabilities.query(resources.authority_id) == null);
    try std.testing.expect(capabilities.query(resources.endpoint_capability_id) == null);
    try std.testing.expect(capabilities.query(resources.memory_capability_id) == null);
    try std.testing.expectEqual(@as(u16, 0), endpoints.activeForTask(ids.task(task.id)));
}
