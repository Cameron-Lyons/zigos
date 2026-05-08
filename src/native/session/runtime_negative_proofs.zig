const std = @import("std");
const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const capability = @import("../kernel_api/capability.zig");
const component_port = @import("../kernel_api/component_port.zig");
const driver_service = @import("../drivers/driver_service.zig");
const endpoint = @import("../kernel_api/endpoint.zig");
const native_kernel = @import("../kernel_api/native_kernel.zig");
const principal = @import("../core/principal.zig");
const shared_memory = @import("../kernel_api/shared_memory.zig");
const userspace_bootstrap_mailbox = @import("../task/userspace_bootstrap_mailbox.zig");
const userspace_loader = @import("../task/userspace_loader.zig");
const userspace_scheduler = @import("../task/userspace_scheduler.zig");
const task_runtime = @import("../task/task_runtime.zig");
const task_runtime_service = @import("../task/task_runtime_service.zig");
const network_policy = @import("../sync/network_policy.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

const MMU_PROOF_BUNDLE_ID = "zigos.proof.mmu-isolation";

var reboot_proof_checkpoint_store: task_runtime_service.CheckpointStore = .{};
var reboot_proof_runtime: task_runtime.Runtime = task_runtime.Runtime.init();
var reboot_proof_restarted_runtime: task_runtime.Runtime = task_runtime.Runtime.init();

pub fn runAndPrint() bool {
    if (!processIsolationBlocksForeignSharedMemory()) return false;
    common.printBootMarker(boot_markers.runtime_proof_process_isolation);

    if (!syscallSubjectSpoofingIsRejected()) return false;
    common.printBootMarker(boot_markers.runtime_proof_syscall_subject_spoof);

    if (!rawNetworkSendBypassIsDenied()) return false;
    common.printBootMarker(boot_markers.runtime_proof_raw_network_bypass);

    if (!driverAuthorityEscapeIsRejected()) return false;
    common.printBootMarker(boot_markers.runtime_proof_driver_authority_escape);

    if (!rebootGrantAndRevocationStatePersists()) return false;
    common.printBootMarker(boot_markers.runtime_proof_reboot_grant_revocation);

    return true;
}

pub fn runFreestandingAndPrint(
    catalog: *userspace_loader.Catalog,
    runtime: *task_runtime.Runtime,
    scheduler: *userspace_scheduler.Scheduler,
) bool {
    if (builtin.target.os.tag != .freestanding) return true;
    const launched = catalog.launchDirect(runtime, MMU_PROOF_BUNDLE_ID, .{
        .owner = app(60),
        .budget = budget(),
        .local_only = true,
    }) catch return false;

    var saw_syscall_pointer_denial = false;
    var attempt: usize = 0;
    while (attempt < 8) : (attempt += 1) {
        const yielded = scheduler.executeTask(launched.id, attempt);

        if (!saw_syscall_pointer_denial and
            scheduler.executor.observedUserCounterStagePulse(
                launched.address_space_id,
                .syscall_ready,
                userspace_bootstrap_mailbox.PROOF_SYSCALL_POINTER_DENIED_PULSE,
            ))
        {
            common.printBootMarker(boot_markers.runtime_proof_syscall_pointer_isolation);
            saw_syscall_pointer_denial = true;
        }

        if (scheduler.executor.consumeUserPageFault(launched.id, userspace_bootstrap_mailbox.FOREIGN_SHARED_MEMORY_PROBE_ADDR)) {
            if (!saw_syscall_pointer_denial) return false;
            common.printBootMarker(boot_markers.runtime_proof_mmu_user_fault);
            return true;
        }

        if (!yielded) return false;
    }

    return false;
}

pub fn processIsolationBlocksForeignSharedMemory() bool {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(policyAuthority(1), &runtime, &capabilities, &endpoints, &shared);
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
        .header = component_port.makeHeader(.shared_memory_create, 1, owner.id),
        .authority_capability_id = authority.id,
        .owner_task_id = owner.id,
        .size_bytes = 4096,
    }, 1) catch return false;

    _ = port.sharedMemoryMap(.{
        .header = component_port.makeHeader(.shared_memory_map, 2, attacker.id),
        .shared_memory_capability_id = object.capability_id,
        .task_id = attacker.id,
    }, 2) catch |err| return err == error.CapabilityNotFound or err == error.ScopeViolation or err == error.SubjectTaskMismatch;
    return false;
}

pub fn syscallSubjectSpoofingIsRejected() bool {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var kernel = native_kernel.Kernel.init(policyAuthority(1), &runtime, &capabilities, &endpoints, &shared);
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
        .header = component_port.makeHeader(.endpoint_create, 1, receiver.id),
        .authority_capability_id = authority.id,
        .owner_task_id = receiver.id,
        .label = "receiver",
        .flags = .{ .local_only = true },
    }, 1) catch return false;

    _ = port.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, 2, attacker.id),
        .endpoint_capability_id = receiver_endpoint.capability_id,
        .receiver_task_id = receiver.id,
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
            .signature = .{ .format = "ed25519", .signer = "zigos-spec-driver" },
        },
    }) catch |err| return err == error.AuthorityRightsEscalation;
    return false;
}

pub fn rebootGrantAndRevocationStatePersists() bool {
    reboot_proof_checkpoint_store.reset();
    reboot_proof_runtime.reset();
    reboot_proof_restarted_runtime.reset();

    var service_instance = task_runtime_service.Service.initWithStore(&reboot_proof_runtime, &reboot_proof_checkpoint_store);
    service_instance.bind(50, service(50));
    const task = reboot_proof_runtime.createTask(.{
        .owner = app(50),
        .component_class = .app_component,
        .budget = budget(),
        .local_only = true,
    }) catch return false;
    const task_id = task.id;
    reboot_proof_runtime.grantCapability(task_id, 91) catch return false;
    reboot_proof_runtime.grantCapability(task_id, 92) catch return false;
    service_instance.checkpoint(1);
    if (!(reboot_proof_runtime.revokeCapability(task_id, 91) catch return false)) return false;
    service_instance.checkpoint(2);

    var restarted = task_runtime_service.Service.initWithStore(&reboot_proof_restarted_runtime, &reboot_proof_checkpoint_store);
    restarted.bind(50, service(50));
    if (!restarted.restartFromCheckpoint(3)) return false;
    const restored = reboot_proof_restarted_runtime.find(task_id) orelse return false;
    return !reboot_proof_restarted_runtime.hasCapability(restored.id, 91) and
        reboot_proof_restarted_runtime.hasCapability(restored.id, 92);
}

fn budget() task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = 10_000,
        .memory_bytes = 256 * 1024,
        .endpoint_slots = 8,
        .shared_memory_bytes = 16 * 1024,
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
    try std.testing.expect(rebootGrantAndRevocationStatePersists());
}
