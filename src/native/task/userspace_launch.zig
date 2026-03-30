const abi = @import("../core/abi.zig");
const manifest = @import("../policy/manifest.zig");
const contract_registry = @import("userspace_contract_registry.zig");
const package_service = @import("../services/package_service.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_boot_registry = @import("userspace_boot_registry.zig");
const userspace_loader = @import("userspace_loader.zig");

pub fn launchRegisteredDirect(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) *task_runtime.TaskRecord {
    const bundle = userspace_boot_registry.manifestFor(bundle_id) catch unreachable;
    return launchDirectBundle(
        catalog,
        runtime_ptr,
        bundle,
        userspace_boot_registry.componentClassFor(bundle_id) catch unreachable,
        userspace_boot_registry.initialComponentFor(bundle_id) catch unreachable,
        request,
        schedule_task,
    );
}

pub fn launchRegisteredKernel(
    catalog: *userspace_loader.Catalog,
    authority: userspace_loader.KernelLaunchAuthority,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) abi.TaskDescriptor {
    const bundle = userspace_boot_registry.manifestFor(bundle_id) catch unreachable;
    return launchKernelBundle(
        catalog,
        authority,
        bundle,
        userspace_boot_registry.componentClassFor(bundle_id) catch unreachable,
        userspace_boot_registry.initialComponentFor(bundle_id) catch unreachable,
        request,
        schedule_task,
    );
}

pub fn launchDirectBundle(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle: manifest.BundleManifest,
    component_class: task_runtime.ComponentClass,
    initial_component: task_runtime.ExecutionComponentSpec,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) *task_runtime.TaskRecord {
    if (catalog.findByBundleId(bundle.bundle_id) == null) {
        const contract = contractFor(bundle.bundle_id);
        _ = catalog.register(.{
            .bundle = bundle,
            .component_class = component_class,
            .initial_component = initial_component,
            .role_tag = contract.role_tag,
            .heartbeat_increment = contract.heartbeat_increment,
            .contract_flags = contract.contract_flags,
        }) catch unreachable;
    }
    const task = catalog.launchDirect(runtime_ptr, bundle.bundle_id, request) catch unreachable;
    _ = schedule_task(task.id);
    return task;
}

pub fn launchKernelBundle(
    catalog: *userspace_loader.Catalog,
    authority: userspace_loader.KernelLaunchAuthority,
    bundle: manifest.BundleManifest,
    component_class: task_runtime.ComponentClass,
    initial_component: task_runtime.ExecutionComponentSpec,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) abi.TaskDescriptor {
    if (catalog.findByBundleId(bundle.bundle_id) == null) {
        const contract = contractFor(bundle.bundle_id);
        _ = catalog.register(.{
            .bundle = bundle,
            .component_class = component_class,
            .initial_component = initial_component,
            .role_tag = contract.role_tag,
            .heartbeat_increment = contract.heartbeat_increment,
            .contract_flags = contract.contract_flags,
        }) catch unreachable;
    }
    const task = catalog.launchViaKernel(authority, bundle.bundle_id, request) catch unreachable;
    _ = schedule_task(task.task_id);
    return task;
}

fn contractFor(bundle_id: []const u8) contract_registry.ContractSpec {
    return if (contract_registry.find(bundle_id)) |contract|
        contract.*
    else
        .{
            .bundle_id = bundle_id,
            .role_tag = 0,
            .heartbeat_increment = 0,
            .contract_flags = 0,
        };
}

pub fn launchInstalledDirect(
    packages: *const package_service.Service,
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    component_class: task_runtime.ComponentClass,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) *task_runtime.TaskRecord {
    var resolved: package_service.ResolvedManifest = undefined;
    const bundle = packages.resolveCurrentManifest(bundle_id, &resolved) catch unreachable;
    const launch_plan = packages.buildLaunchPlan(bundle_id) catch unreachable;
    if (launch_plan.component_count == 0) unreachable;

    return launchDirectBundle(
        catalog,
        runtime_ptr,
        bundle,
        component_class,
        .{
            .label = launch_plan.components[0].idSlice(),
            .entry = launch_plan.components[0].entrySlice(),
        },
        request,
        schedule_task,
    );
}
