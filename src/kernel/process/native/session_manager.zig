const builtin = @import("builtin");
const std = @import("std");
const boot_markers = @import("../../boot/markers.zig");
const abi = @import("abi.zig");
const capability = @import("capability.zig");
const component_port = @import("component_port.zig");
const contract = @import("contract.zig");
const driver_runtime_mod = @import("driver_runtime.zig");
const driver_service = @import("driver_service.zig");
const endpoint_mod = @import("endpoint.zig");
const manifest = @import("manifest.zig");
const native_kernel = @import("native_kernel.zig");
const native_service_registry = @import("service_registry.zig");
const permission_review_service = @import("permission_review_service.zig");
const policy_mediation = @import("policy_mediation.zig");
const policy_component_port = @import("policy_component_port.zig");
const principal = @import("principal.zig");
const phase3_bootstrap = @import("phase3_bootstrap.zig");
const review_component_port = @import("review_component_port.zig");
const session_bootstrap = @import("session_bootstrap.zig");
const session_lifecycle_phases = @import("session_lifecycle_phases.zig");
const service_contract = @import("service_contract.zig");
const shared_memory_mod = @import("shared_memory.zig");
const storage_service_mod = @import("storage_service.zig");
const storage_volume_mod = @import("storage_volume.zig");
const supervisor_mod = @import("supervisor.zig");
const sync_service_mod = @import("sync_service.zig");
const task_runtime = @import("task_runtime.zig");
const task_runtime_service_mod = @import("task_runtime_service.zig");
const userspace_boot_registry = @import("userspace_boot_registry.zig");
const userspace_executor = @import("userspace_executor.zig");
const userspace_launch = @import("userspace_launch.zig");
const userspace_loader = @import("userspace_loader.zig");
const userspace_scheduler = @import("userspace_scheduler.zig");
const workspace_mod = @import("workspace.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

var initialized = false;
var capability_table = capability.CapabilityTable.init();
var endpoint_table = endpoint_mod.Table.init();
var runtime = task_runtime.Runtime.init();
var runtime_service = task_runtime_service_mod.Service.init(&runtime);
var service_directory = native_service_registry.Registry.init();
var shared_memory_table = shared_memory_mod.Table.init();
var userspace_catalog = userspace_loader.Catalog.init();
var kernel_instance: native_kernel.Kernel = undefined;
var kernel_port_instance: component_port.KernelPort = undefined;
var kernel_port_ready = false;
var driver_directory = driver_service.Directory.init();
var driver_runtime = driver_runtime_mod.Runtime.init();
var supervisor = supervisor_mod.Supervisor.init();
var phase4_storage_service = emptyStorageService();
var phase4_export_package = workspace_mod.emptyExportPackage();
const bootstrap_storage_interface = manifest.InterfaceDecl{ .name = "zigos.bootstrap.workspace" };
const compatibility_portal_interface = manifest.InterfaceDecl{ .name = "zigos.compat.portal" };

fn emptyStorageService() storage_service_mod.Service {
    return .{
        .service_id = 0,
        .task_id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .store = undefined,
        .workspaces = undefined,
    };
}

fn resetStateForTest() void {
    initialized = false;
    capability_table = capability.CapabilityTable.init();
    endpoint_table = endpoint_mod.Table.init();
    runtime = task_runtime.Runtime.init();
    runtime_service = task_runtime_service_mod.Service.init(&runtime);
    service_directory = native_service_registry.Registry.init();
    shared_memory_table = shared_memory_mod.Table.init();
    userspace_catalog = userspace_loader.Catalog.init();
    kernel_instance = native_kernel.Kernel.init(
        .{ .kind = .policy_authority, .serial = 0 },
        runtime_service.runtimePtr(),
        &capability_table,
        &endpoint_table,
        &shared_memory_table,
        &service_directory,
    );
    kernel_port_instance = component_port.KernelPort.init(&kernel_instance);
    kernel_port_ready = false;
    driver_directory = driver_service.Directory.init();
    driver_runtime = driver_runtime_mod.Runtime.init();
    supervisor = supervisor_mod.Supervisor.init();
    phase4_storage_service = emptyStorageService();
    phase4_export_package = workspace_mod.emptyExportPackage();
    userspace_scheduler.reset();
    storage_service_mod.Service.resetPersistentState();
    sync_service_mod.Service.resetPersistentState();
}

pub const testing = struct {
    pub fn resetState() void {
        resetStateForTest();
    }

    pub fn isInitialized() bool {
        return initialized;
    }

    pub fn countTasks() usize {
        var count: usize = 0;
        for (runtime.tasks) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn countTasksInState(state: task_runtime.TaskState) usize {
        var count: usize = 0;
        for (runtime.tasks) |slot| {
            if (slot.in_use and slot.task.state == state) count += 1;
        }
        return count;
    }

    pub fn countServices() usize {
        var count: usize = 0;
        for (supervisor.services) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    pub fn findTask(label: []const u8) ?*task_runtime.TaskRecord {
        var match: ?*task_runtime.TaskRecord = null;
        for (&runtime.tasks) |*slot| {
            if (!slot.in_use or slot.task.execution_component_count == 0) continue;
            if (std.mem.eql(u8, slot.task.execution_components[0].labelSlice(), label)) {
                match = &slot.task;
            }
        }
        return match;
    }

    pub fn runtimePtr() *task_runtime.Runtime {
        return &runtime;
    }

    pub fn runtimeServicePtr() *task_runtime_service_mod.Service {
        return &runtime_service;
    }

    pub fn serviceDirectoryPtr() *native_service_registry.Registry {
        return &service_directory;
    }

    pub fn driverDirectoryPtr() *driver_service.Directory {
        return &driver_directory;
    }

    pub fn driverRuntimePtr() *driver_runtime_mod.Runtime {
        return &driver_runtime;
    }

    pub fn supervisorPtr() *supervisor_mod.Supervisor {
        return &supervisor;
    }

    pub fn storageServicePtr() *storage_service_mod.Service {
        return &phase4_storage_service;
    }

    pub fn compatibilityPortalInterface() manifest.InterfaceDecl {
        return compatibility_portal_interface;
    }
};

pub fn kernelPort() ?*component_port.KernelPort {
    if (!kernel_port_ready) return null;
    return &kernel_port_instance;
}

fn executeUserspaceProbe(task_id: u64) void {
    _ = userspace_executor.executeTask(&userspace_catalog, &runtime, task_id);
}

fn scheduleUserspaceTask(task_id: u64) bool {
    return userspace_scheduler.registerTask(task_id);
}

pub fn runUserspaceScheduler(now_ticks: u64) bool {
    return userspace_scheduler.runNext(now_ticks);
}

pub fn boot() void {
    if (initialized) return;
    initialized = true;
    kernel_port_ready = false;

    common.printBootMarker(boot_markers.native_bootstrap);
    common.printBootMarker(boot_markers.tcb_defined);

    const ids = session_bootstrap.principals();
    const policy_authority = ids.policy_authority;
    const session_service = ids.session_service;
    const session_user = ids.session_user;
    const network_service_principal = ids.network_service;
    const compositor_service_principal = ids.compositor_service;
    const storage_service_principal = ids.storage_service;
    const review_service_principal = ids.review_service;
    const package_service_principal = ids.package_service;
    const indexing_service_principal = ids.indexing_service;
    const sync_service_principal = ids.sync_service;
    const media_service_principal = ids.media_service;
    const compatibility_service_principal = ids.compatibility_service;

    session_bootstrap.initializeUserspace(&userspace_catalog, &runtime);
    const services = session_bootstrap.registerCoreServices(&supervisor, &runtime_service, ids);
    const service_registry = services.service_registry;
    const policy_service = services.policy_service;
    const session = services.session;
    const review_service_record = services.review_service_record;
    const compatibility_service = services.compatibility_service;
    const network_service = services.network_service;
    const compositor_service = services.compositor_service;
    const storage_service = services.storage_service;
    const package_service = services.package_service;
    const indexing_service = services.indexing_service;
    const sync_service = services.sync_service;
    const media_service = services.media_service;

    const session_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "zigos.system.session-manager",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 50_000,
                .memory_bytes = 8 * 1024 * 1024,
                .endpoint_slots = 16,
                .shared_memory_bytes = 256 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 1,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    common.printBootMarker(boot_markers.policy_ready);

    const review_service_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "zigos.system.permission-review",
        .{
            .owner = review_service_principal,
            .budget = .{
                .cpu_time_ticks = 10_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 16 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    common.printBootMarker(boot_markers.phase2_ui_service_ready);
    common.printBootMarker(boot_markers.phase2_ui_service_task_ready);

    const session_capability = capability_table.mint(.{
        .holder = session_service,
        .issuer = policy_authority,
        .target = .{ .kind = .service, .id = session.id },
        .rights = .{
            .task_create = true,
            .endpoint_create = true,
            .endpoint_connect = true,
            .endpoint_send = true,
            .endpoint_recv = true,
            .capability_query = true,
            .shared_memory_create = true,
            .shared_memory_map = true,
            .shared_memory_unmap = true,
            .shared_memory_revoke = true,
            .time_query = true,
            .resource_query = true,
            .accounting_query = true,
            .ipc_peer = true,
        },
        .scope = .{
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = session_task.id,
            .broker_service_id = policy_service.id,
        },
    }) catch unreachable;

    runtime.grantCapability(session_task.id, session_capability.id) catch unreachable;
    runtime.audit(session_task.id, .{
        .kind = .created,
        .tick = 0,
    }) catch unreachable;
    runtime.audit(session_task.id, .{
        .kind = .capability_granted,
        .capability_id = session_capability.id,
        .tick = 0,
    }) catch unreachable;

    const policy_capability = capability_table.mint(.{
        .holder = policy_authority,
        .issuer = policy_authority,
        .target = .{ .kind = .policy, .id = policy_service.id },
        .rights = .{
            .capability_mint = true,
            .capability_query = true,
            .capability_revoke = true,
        },
        .scope = .{
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .audit = .{
            .policy_generation = 1,
            .source_task_id = session_task.id,
            .broker_service_id = policy_service.id,
        },
    }) catch unreachable;

    var mediator = policy_mediation.PolicyMediator.init(
        policy_authority,
        &capability_table,
        runtime_service.runtimePtr(),
        .{
            .network_service_id = network_service.id,
            .compositor_service_id = compositor_service.id,
            .policy_service_id = policy_service.id,
            .service_registry_id = service_registry.id,
        },
    );
    kernel_instance = native_kernel.Kernel.init(
        policy_authority,
        runtime_service.runtimePtr(),
        &capability_table,
        &endpoint_table,
        &shared_memory_table,
        &service_directory,
    );
    kernel_port_instance = component_port.KernelPort.init(&kernel_instance);
    const kernel_port = &kernel_port_instance;
    kernel_port_ready = true;
    executeUserspaceProbe(session_task.id);
    common.printBootMarker(boot_markers.phase1_native_kernel_ready);
    common.printBootMarker(boot_markers.phase1_no_root);
    common.printBootMarker(boot_markers.phase1_component_abi_ready);

    const bootstrap_review_inputs = [_][]const u8{
        "allow local lease=400",
        "allow local lease=50",
        "deny",
        "allow lease=10",
        "allow local lease=30",
        "allow local lease=35",
        "deny",
        "allow local lease=25",
        "allow local lease=15",
    };
    var review_service = permission_review_service.Service.init(
        review_service_record.id,
        review_service_task.id,
        &runtime,
        &bootstrap_review_inputs,
    );
    var review_port = review_component_port.Port.init(&review_service);
    var policy_port = policy_component_port.Port.init(&mediator);
    common.printBootMarker(boot_markers.phase2_review_port_ready);
    common.printBootMarker(boot_markers.phase2_policy_port_ready);

    const storage_task_desc = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 1,
            .now_ticks = 1,
        },
        "zigos.system.workspace-storage",
        .{
            .owner = storage_service_principal,
            .budget = .{
                .cpu_time_ticks = 8_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 6,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    executeUserspaceProbe(storage_task_desc.task_id);
    const phase1_client_task_desc = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 2,
            .now_ticks = 2,
        },
        "zigos.system.phase1-client",
        .{
            .owner = .{ .kind = .app, .serial = 10 },
            .budget = .{
                .cpu_time_ticks = 6_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 6,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    common.printBootMarker(boot_markers.phase1_task_create_ok);

    const storage_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 3, storage_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .owner_task_id = storage_task_desc.task_id,
        .label = bootstrap_storage_interface.name,
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, 3) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:ENDPOINT_CREATE:OK");
    kernel_port.serviceRegister(.{
        .header = component_port.makeHeader(.service_register, 4, storage_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .service_id = storage_service.id,
        .owner_task_id = storage_task_desc.task_id,
        .endpoint_capability_id = storage_endpoint.capability_id,
        .interface = bootstrap_storage_interface,
    }, 3) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:SERVICE_REGISTER:OK");

    const phase1_client_endpoint = kernel_port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 5, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .owner_task_id = phase1_client_task_desc.task_id,
        .label = "phase1.client",
        .flags = .{ .local_only = true },
    }, 4) catch unreachable;
    _ = kernel_port.serviceConnect(.{
        .header = component_port.makeHeader(.service_connect, 6, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .endpoint_capability_id = phase1_client_endpoint.capability_id,
        .interface = bootstrap_storage_interface,
    }, 4) catch unreachable;
    common.printBootMarker(boot_markers.phase1_service_connect_ok);

    const phase1_shm = kernel_port.sharedMemoryCreate(.{
        .header = component_port.makeHeader(.shared_memory_create, 7, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .owner_task_id = phase1_client_task_desc.task_id,
        .size_bytes = 4096,
    }, 5) catch unreachable;
    _ = kernel_port.sharedMemoryMap(.{
        .header = component_port.makeHeader(.shared_memory_map, 8, phase1_client_task_desc.task_id),
        .shared_memory_capability_id = phase1_shm.capability_id,
        .task_id = phase1_client_task_desc.task_id,
    }, 5) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:SHM:MAP_OK");

    kernel_port.endpointSend(.{
        .header = component_port.makeHeader(.endpoint_send, 41, phase1_client_task_desc.task_id),
        .endpoint_capability_id = phase1_client_endpoint.capability_id,
        .payload = "workspace-open",
        .attached_capability_id = phase1_shm.capability_id,
        .move_attached_capability = false,
    }, 6) catch unreachable;
    const phase1_received = kernel_port.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, 9, storage_task_desc.task_id),
        .endpoint_capability_id = storage_endpoint.capability_id,
        .receiver_task_id = storage_task_desc.task_id,
    }, 7) catch unreachable orelse unreachable;
    if (std.mem.eql(u8, phase1_received.payload[0..phase1_received.payload_len], "workspace-open") and
        phase1_received.attached_capability != null)
    {
        common.printBootMarker(boot_markers.phase1_cap_pass_ok);
    }

    const phase1_resources = kernel_port.resourceQuery(.{
        .header = component_port.makeHeader(.resource_query, 10, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .task_id = phase1_client_task_desc.task_id,
    }, 7) catch unreachable;
    if (phase1_resources.endpoint_count == 1) {
        common.printBootMarker("ZIGOS:PHASE1:RESOURCE_QUERY:OK");
    }
    const phase1_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 11, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .task_id = phase1_client_task_desc.task_id,
    }, 7) catch unreachable;
    if (phase1_accounting.audit_event_count != 0) {
        common.printBootMarker("ZIGOS:PHASE1:ACCOUNTING_QUERY:OK");
    }
    if ((kernel_port.timeQuery(.{
        .header = component_port.makeHeader(.time_query, 12, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
    }, 7) catch unreachable) == 7) {
        common.printBootMarker("ZIGOS:PHASE1:TIME_QUERY:OK");
    }

    const derivable_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 13, phase1_client_task_desc.task_id),
        .policy_capability_id = policy_capability.id,
        .request = .{
            .holder = runtime.find(phase1_client_task_desc.task_id).?.owner,
            .issuer = policy_authority,
            .target = .{ .kind = .object, .id = 0xCAFE },
            .rights = .{
                .object_read = true,
                .object_write = true,
                .capability_derive = true,
                .capability_query = true,
                .capability_revoke = true,
                .capability_pass = true,
            },
            .scope = .{
                .task_id = phase1_client_task_desc.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 7,
                .expires_at_ticks = 100,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_client_task_desc.task_id,
                .broker_service_id = policy_service.id,
            },
        },
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_MINT:OK");
    _ = kernel_port.capabilityQuery(.{
        .header = component_port.makeHeader(.capability_query, 14, phase1_client_task_desc.task_id),
        .authority_capability_id = session_capability.id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_QUERY:OK");

    _ = kernel_port.capabilityDerive(.{
        .header = component_port.makeHeader(.capability_derive, 15, phase1_client_task_desc.task_id),
        .request = .{
            .parent_capability_id = derivable_capability.capability_id,
            .holder = runtime.find(phase1_client_task_desc.task_id).?.owner,
            .rights = .{ .object_read = true },
            .scope = .{
                .task_id = phase1_client_task_desc.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 7,
                .expires_at_ticks = 60,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_client_task_desc.task_id,
                .broker_service_id = policy_service.id,
            },
        },
    }) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_DERIVE:OK");
    kernel_port.capabilityRevoke(.{
        .header = component_port.makeHeader(.capability_revoke, 16, phase1_client_task_desc.task_id),
        .authority_capability_id = policy_capability.id,
        .capability_id = derivable_capability.capability_id,
    }, 7) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:CAP_REVOKE:OK");

    const phase1_temp_task = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 17,
            .now_ticks = 8,
        },
        "zigos.system.phase1-temp",
        .{
            .owner = .{ .kind = .app, .serial = 11 },
            .budget = .{
                .cpu_time_ticks = 1_000,
                .memory_bytes = 128 * 1024,
                .endpoint_slots = 2,
                .shared_memory_bytes = 32 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    const phase1_temp_capability = kernel_port.capabilityMint(.{
        .header = component_port.makeHeader(.capability_mint, 18, phase1_temp_task.task_id),
        .policy_capability_id = policy_capability.id,
        .request = .{
            .holder = runtime.find(phase1_temp_task.task_id).?.owner,
            .issuer = policy_authority,
            .target = .{ .kind = .task, .id = phase1_temp_task.task_id },
            .rights = .{ .task_terminate = true },
            .scope = .{
                .task_id = phase1_temp_task.task_id,
                .local_only = true,
                .broker_only = true,
            },
            .lease = .{
                .issued_at_ticks = 8,
                .expires_at_ticks = 50,
                .renewable = false,
            },
            .audit = .{
                .policy_generation = 1,
                .source_task_id = phase1_temp_task.task_id,
                .broker_service_id = policy_service.id,
            },
        },
    }, 8) catch unreachable;
    _ = kernel_port.taskTerminate(.{
        .header = component_port.makeHeader(.task_terminate, 19, phase1_temp_task.task_id),
        .task_capability_id = phase1_temp_capability.capability_id,
    }, 9) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE1:TASK_TERMINATE:OK");

    const viewer_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 20,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };
    const viewer_bundle = userspace_boot_registry.manifestFor("app.viewer") catch unreachable;
    const viewer_manifest = manifest.BundleManifest{
        .bundle_id = viewer_bundle.bundle_id,
        .display_name = viewer_bundle.display_name,
        .publisher = viewer_bundle.publisher,
        .requested_permissions = &viewer_permissions,
    };
    manifest.validate(viewer_manifest) catch unreachable;
    common.printBootMarker(boot_markers.phase2_manifest_valid);

    const viewer_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.viewer",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 15_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 8,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 2,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    const viewer_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 20, viewer_task.id),
        .task_id = viewer_task.id,
        .bundle = viewer_manifest,
        .grants = &.{},
    }, 10) catch unreachable;
    if (viewer_summary.decisionForKind(.network_egress)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_zero_authority_deny_network);
        }
    }
    if (viewer_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_zero_authority_deny_clipboard);
        }
    }

    const notes_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_local = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
        },
        .{
            .kind = .clipboard,
            .resource = "clipboard",
            .rights = .{ .clipboard_read = true, .clipboard_write = true },
            .required = false,
        },
    };
    const notes_bundle = userspace_boot_registry.manifestFor("app.notes") catch unreachable;
    const notes_manifest = manifest.BundleManifest{
        .bundle_id = notes_bundle.bundle_id,
        .display_name = notes_bundle.display_name,
        .publisher = notes_bundle.publisher,
        .provided_interfaces = &[_]manifest.InterfaceDecl{
            .{ .name = "zigos.workspace.document" },
        },
        .consumed_interfaces = &[_]manifest.InterfaceDecl{
            .{ .name = "zigos.object.workspace" },
        },
        .requested_permissions = &notes_permissions,
        .ai_metadata = .{
            .model_family = "tiny-embed",
            .locality = .local_only,
            .offline_required = true,
        },
        .update_channel = .beta,
        .signature = notes_bundle.signature,
    };
    manifest.validate(notes_manifest) catch unreachable;

    const notes_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.notes",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 30_000,
                .memory_bytes = 4 * 1024 * 1024,
                .endpoint_slots = 8,
                .shared_memory_bytes = 128 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 3,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var notes_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const notes_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 21, notes_task.id),
        .app_task_id = notes_task.id,
        .bundle = notes_manifest,
        .output = &notes_grants_buffer,
    }, 10) catch unreachable;
    if (hasGrantForKind(notes_grants, .object_access)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_OBJECT");
    }
    if (hasGrantForKind(notes_grants, .network_egress)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_NETWORK");
    }
    if (!hasGrantForKind(notes_grants, .clipboard)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:DENY_CLIPBOARD");
    }

    const notes_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 22, notes_task.id),
        .task_id = notes_task.id,
        .bundle = notes_manifest,
        .grants = notes_grants,
    }, 10) catch unreachable;
    const notes_object_capability = capability_table.query(
        notes_summary.decisionForKind(.object_access).?.capability_id.?,
    ).?;
    if (notes_summary.decisionForKind(.object_access)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_object_local);
        }
    }
    if (notes_summary.decisionForKind(.network_egress)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_network_local);
        }
    }
    if (notes_summary.decisionForKind(.clipboard)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_deny_clipboard);
        }
    }

    _ = runtime.attachComponent(notes_task.id, .{
        .substrate = .early_elf_runner,
        .label = "notes-sync-helper",
        .entry = "/system/components/notes-sync.elf",
    }, 11) catch unreachable;
    const notes_accounting = kernel_port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 221, notes_task.id),
        .authority_capability_id = session_capability.id,
        .task_id = notes_task.id,
    }, 11) catch unreachable;
    if (notes_accounting.component_count == 2) {
        common.printBootMarker(boot_markers.phase2_elf_substrate_ok);
    }

    const sync_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "sync",
            .rights = .{ .background_run = true },
        },
    };
    const sync_background_tasks = [_]manifest.BackgroundTaskDecl{
        .{
            .id = "sync",
            .trigger = .sync_completion,
            .expected_duration_seconds = 30,
            .budget = .{
                .cpu_time_ticks = 2_000,
                .memory_bytes = 128 * 1024,
                .shared_memory_bytes = 8 * 1024,
            },
            .network = .local_network_only,
            .visibility = .status_only,
        },
    };
    const sync_bundle = userspace_boot_registry.manifestFor("app.sync") catch unreachable;
    const sync_manifest = manifest.BundleManifest{
        .bundle_id = sync_bundle.bundle_id,
        .display_name = sync_bundle.display_name,
        .publisher = sync_bundle.publisher,
        .requested_permissions = &sync_permissions,
        .background_tasks = &sync_background_tasks,
    };
    manifest.validate(sync_manifest) catch unreachable;

    const sync_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.sync",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 4,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var sync_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const sync_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 23, sync_task.id),
        .app_task_id = sync_task.id,
        .bundle = sync_manifest,
        .output = &sync_grants_buffer,
    }, 20) catch unreachable;
    common.printBootMarker("ZIGOS:PHASE2:UI:REVIEW_SYNC");
    const sync_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 24, sync_task.id),
        .task_id = sync_task.id,
        .bundle = sync_manifest,
        .grants = sync_grants,
    }, 20) catch unreachable;
    if (sync_summary.decisionForKind(.background_execution)) |decision| {
        if (!decision.allowed and decision.reason == .budget_exhausted) {
            common.printBootMarker("ZIGOS:PHASE2:DENY:BACKGROUND");
        }
    }

    const capture_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .device_access,
            .resource = "capture.card0",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 30,
            .target_id = 700,
        },
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 701,
        },
        .{
            .kind = .mic,
            .resource = "mic.array",
            .rights = .{ .device_use = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 35,
            .target_id = 702,
        },
        .{
            .kind = .sensor,
            .resource = "sensor.lid",
            .rights = .{ .sensor_read = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 25,
            .target_id = 703,
        },
        .{
            .kind = .peer_ipc,
            .resource = "zigos.peer.share",
            .rights = .{ .ipc_peer = true },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 15,
        },
    };
    const capture_bundle = userspace_boot_registry.manifestFor("app.capture") catch unreachable;
    const capture_manifest = manifest.BundleManifest{
        .bundle_id = capture_bundle.bundle_id,
        .display_name = capture_bundle.display_name,
        .publisher = capture_bundle.publisher,
        .requested_permissions = &capture_permissions,
        .signature = capture_bundle.signature,
    };

    const capture_task = userspace_launch.launchRegisteredDirect(
        &userspace_catalog,
        &runtime,
        "app.capture",
        .{
            .owner = session_user,
            .budget = .{
                .cpu_time_ticks = 20_000,
                .memory_bytes = 2 * 1024 * 1024,
                .endpoint_slots = 4,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .ui_surface_id = 5,
            .local_only = true,
        },
        scheduleUserspaceTask,
    );

    var capture_grants_buffer: [permission_review_service.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const capture_grants = review_port.reviewBundle(.{
        .header = review_component_port.makeHeader(.review_bundle, 26, capture_task.id),
        .app_task_id = capture_task.id,
        .bundle = capture_manifest,
        .output = &capture_grants_buffer,
    }, 30) catch unreachable;
    if (hasGrantForKind(capture_grants, .device_access)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_DEVICE");
    }
    if (hasGrantForKind(capture_grants, .camera)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_CAMERA");
    }
    if (!hasGrantForKind(capture_grants, .mic)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:DENY_MIC");
    }
    if (hasGrantForKind(capture_grants, .sensor)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_SENSOR");
    }
    if (hasGrantForKind(capture_grants, .peer_ipc)) {
        common.printBootMarker("ZIGOS:PHASE2:UI:APPROVE_PEER_IPC");
    }

    const capture_summary = policy_port.applyManifest(.{
        .header = policy_component_port.makeHeader(.apply_manifest, 27, capture_task.id),
        .task_id = capture_task.id,
        .bundle = capture_manifest,
        .grants = capture_grants,
    }, 30) catch unreachable;
    if (capture_summary.decisionForKind(.device_access)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_device_local);
        }
    }
    if (capture_summary.decisionForKind(.camera)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_camera);
        }
    }
    if (capture_summary.decisionForKind(.mic)) |decision| {
        if (!decision.allowed and decision.reason == .policy_denied) {
            common.printBootMarker(boot_markers.phase2_deny_mic);
        }
    }
    if (capture_summary.decisionForKind(.sensor)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_sensor_local);
        }
    }
    if (capture_summary.decisionForKind(.peer_ipc)) |decision| {
        if (decision.allowed and decision.local_only) {
            common.printBootMarker(boot_markers.phase2_grant_peer_ipc_local);
        }
    }

    const expired_network_decision = policy_port.authorizeRequest(.{
        .header = policy_component_port.makeHeader(.authorize_request, 28, notes_task.id),
        .task_id = notes_task.id,
        .request = notes_permissions[1],
        .grants = notes_grants,
    }, 80) catch unreachable;
    if (!expired_network_decision.allowed and expired_network_decision.reason == .capability_expired) {
        common.printBootMarker(boot_markers.phase2_lease_expired);
    }

    const phase3_launch_specs: [service_contract.ordered_phase3_contracts.len]struct {
        owner: principal.PrincipalId,
        service_id: u64,
        correlation_base: u64,
        now_ticks: u64,
    } = .{
        .{ .owner = policy_authority, .service_id = policy_service.id, .correlation_base = 301, .now_ticks = 31 },
        .{ .owner = network_service_principal, .service_id = network_service.id, .correlation_base = 304, .now_ticks = 34 },
        .{ .owner = storage_service_principal, .service_id = storage_service.id, .correlation_base = 307, .now_ticks = 35 },
        .{ .owner = package_service_principal, .service_id = package_service.id, .correlation_base = 310, .now_ticks = 38 },
        .{ .owner = compositor_service_principal, .service_id = compositor_service.id, .correlation_base = 313, .now_ticks = 41 },
        .{ .owner = indexing_service_principal, .service_id = indexing_service.id, .correlation_base = 316, .now_ticks = 44 },
        .{ .owner = sync_service_principal, .service_id = sync_service.id, .correlation_base = 319, .now_ticks = 47 },
        .{ .owner = media_service_principal, .service_id = media_service.id, .correlation_base = 322, .now_ticks = 50 },
    };
    var phase3_bindings: [service_contract.ordered_phase3_contracts.len]phase3_bootstrap.ServiceBinding = undefined;
    for (service_contract.ordered_phase3_contracts, phase3_launch_specs, 0..) |entry, spec, index| {
        phase3_bindings[index] = phase3_bootstrap.launchContractService(
            &userspace_catalog,
            kernel_port,
            &supervisor,
            session_capability.id,
            session_task.id,
            scheduleUserspaceTask,
            spec.owner,
            spec.service_id,
            entry,
            spec.correlation_base,
            spec.now_ticks,
        );
    }

    const network_binding = phase3_bindings[service_contract.orderedIndex(.network_stack).?];
    const storage_binding = phase3_bindings[service_contract.orderedIndex(.storage_object).?];
    const compositor_binding = phase3_bindings[service_contract.orderedIndex(.compositor_ui_session).?];
    const sync_binding = phase3_bindings[service_contract.orderedIndex(.sync_replication).?];
    const media_binding = phase3_bindings[service_contract.orderedIndex(.media_print_helpers).?];

    _ = phase3_bootstrap.launchBundleService(
        &userspace_catalog,
        kernel_port,
        &supervisor,
        session_capability.id,
        session_task.id,
        scheduleUserspaceTask,
        compatibility_service_principal,
        compatibility_service.id,
        "zigos.system.compatibility-portal",
        compatibility_portal_interface,
        phase3_bootstrap.serviceBudget(.compatibility_portal),
        325,
        51,
    );
    common.printBootMarker("ZIGOS:PHASE3:COMPAT_PORTAL:READY");

    const phase3_driver_specs = [_]struct {
        service_id: u64,
        task_id: u64,
        owner: principal.PrincipalId,
        device_class: driver_service.DeviceClass,
        now_ticks: u64,
    }{
        .{ .service_id = network_service.id, .task_id = network_binding.task_id, .owner = network_service_principal, .device_class = .network_adapter, .now_ticks = 52 },
        .{ .service_id = storage_service.id, .task_id = storage_binding.task_id, .owner = storage_service_principal, .device_class = .storage_controller, .now_ticks = 53 },
        .{ .service_id = compositor_service.id, .task_id = compositor_binding.task_id, .owner = compositor_service_principal, .device_class = .graphics_adapter, .now_ticks = 54 },
        .{ .service_id = media_service.id, .task_id = media_binding.task_id, .owner = media_service_principal, .device_class = .audio_print_io, .now_ticks = 55 },
    };
    var phase3_drivers: [phase3_driver_specs.len]*driver_service.DriverRecord = undefined;
    for (phase3_driver_specs, 0..) |spec, index| {
        phase3_drivers[index] = phase3_bootstrap.attachDriver(
            kernel_port,
            &capability_table,
            &driver_directory,
            &supervisor,
            policy_authority,
            policy_capability.id,
            spec.service_id,
            spec.task_id,
            spec.owner,
            spec.device_class,
            spec.now_ticks,
        );
    }
    const network_driver = phase3_drivers[0];
    const storage_driver = phase3_drivers[1];
    const network_activation = driver_runtime.activate(network_driver) catch unreachable;
    const storage_activation = driver_runtime.activate(storage_driver) catch unreachable;
    _ = driver_runtime.activate(driver_directory.findByClass(.graphics_adapter).?) catch unreachable;
    _ = driver_runtime.activate(driver_directory.findByClass(.audio_print_io).?) catch unreachable;
    if ((network_activation.mode == .published_data_plane or driver_directory.findByClass(.network_adapter) != null) and
        (storage_activation.mode == .published_data_plane or storage_driver.restart_generation == 1))
    {
        common.printBootMarker(boot_markers.phase3_driver_service_nic_ready);
    }
    if (storage_activation.mode == .published_data_plane and storage_volume_mod.hasAttachedDevice()) {
        common.printBootMarker("ZIGOS:PHASE3:DRIVER_SERVICE:STORAGE_READY");
    }

    if (phase3_bootstrap.contractsReady(&service_directory)) {
        common.printBootMarker(boot_markers.phase3_service_contracts_ready);
    }

    const phase3_client_task = userspace_launch.launchRegisteredKernel(
        &userspace_catalog,
        .{
            .port = kernel_port,
            .authority_capability_id = session_capability.id,
            .controller_task_id = session_task.id,
            .correlation_id = 330,
            .now_ticks = 56,
        },
        "zigos.system.phase3-client",
        .{
            .owner = .{ .kind = .app, .serial = 20 },
            .budget = .{
                .cpu_time_ticks = 6_000,
                .memory_bytes = 512 * 1024,
                .endpoint_slots = 16,
                .shared_memory_bytes = 64 * 1024,
                .background_allowed = false,
            },
            .local_only = true,
        },
        scheduleUserspaceTask,
    );
    var phase3_connect_count: usize = 0;
    for (service_contract.ordered_phase3_contracts, 0..) |entry, index| {
        const endpoint_request_id = 331 + @as(u64, @intCast(index * 2));
        const connect_request_id = endpoint_request_id + 1;
        const client_endpoint = kernel_port.endpointCreate(.{
            .header = component_port.makeHeader(.endpoint_create, endpoint_request_id, phase3_client_task.task_id),
            .authority_capability_id = session_capability.id,
            .owner_task_id = phase3_client_task.task_id,
            .label = entry.interface.name,
            .flags = .{ .local_only = true },
        }, 57 + @as(u64, @intCast(index))) catch unreachable;
        const registry_connection = service_directory.connect(entry.interface) catch unreachable;
        _ = kernel_port.endpointConnect(.{
            .header = component_port.makeHeader(.endpoint_connect, connect_request_id, phase3_client_task.task_id),
            .endpoint_capability_id = client_endpoint.capability_id,
            .peer_endpoint_id = phase3_bindings[index].endpoint_id,
        }, 57 + @as(u64, @intCast(index))) catch unreachable;
        runtime.audit(phase3_client_task.task_id, .{
            .kind = .service_connected,
            .detail = @truncate(registry_connection.service_id),
            .tick = 57 + @as(u64, @intCast(index)),
        }) catch unreachable;
        if (registry_connection.service_id == supervisor.findByClass(entry.class).?.id) {
            phase3_connect_count += 1;
        }
    }
    if (phase3_connect_count == service_contract.ordered_phase3_contracts.len) {
        common.printBootMarker(boot_markers.phase3_ipc_connect_all_ok);
    }

    _ = supervisor.recoverDriverCrash(
        network_service.id,
        &driver_directory,
        &driver_runtime,
        null,
        null,
        70,
        0x4E,
        "network driver restarted",
    ) catch unreachable;
    if (supervisor.hasDiagnostic(network_service.id, .crash)) {
        common.printBootMarker("ZIGOS:PHASE3:SUPERVISOR:CRASH_RECORDED");
    }
    runtime.audit(network_binding.task_id, .{
        .kind = .service_restarted,
        .detail = @truncate(network_service.id),
        .tick = 72,
    }) catch unreachable;
    if (supervisor.hasDiagnostic(network_service.id, .restart_completed) and
        driver_directory.findByService(network_service.id).?.restart_generation == 2)
    {
        common.printBootMarker(boot_markers.phase3_supervisor_restart_ok);
    }
    var lifecycle_context = session_lifecycle_phases.Context{
        .runtime = &runtime,
        .runtime_service = &runtime_service,
        .supervisor = &supervisor,
        .driver_directory = &driver_directory,
        .storage_service_instance = &phase4_storage_service,
        .export_package = &phase4_export_package,
        .policy_authority = policy_authority,
        .session_service = session_service,
        .session_user = session_user,
        .storage_service_id = storage_service.id,
        .storage_task_id = storage_binding.task_id,
        .storage_service_principal = storage_service_principal,
        .sync_service_id = sync_service.id,
        .sync_task_id = sync_binding.task_id,
        .sync_service_principal = sync_service_principal,
        .policy_service_id = policy_service.id,
        .network_service_id = network_service.id,
        .compositor_service_id = compositor_service.id,
        .package_service_id = package_service.id,
        .package_service_principal = package_service_principal,
        .notes_object_capability = notes_object_capability,
    };
    session_lifecycle_phases.run(&lifecycle_context);

    console.print("Zigos native session manager online\n");
    console.print("Native ABI: capability-ipc-v");
    printNumber(abi.ABI_VERSION);
    console.print("\n");
    console.print("Native-only platform ready\n");
}
fn printNumber(value: u64) void {
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{value}) catch return;
    console.print(text);
}

fn hasGrantForKind(grants: []const policy_mediation.UserGrant, kind: manifest.PermissionKind) bool {
    for (grants) |grant| {
        if (grant.kind == kind and grant.allow) {
            return true;
        }
    }
    return false;
}
