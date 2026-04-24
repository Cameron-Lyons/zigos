const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const manifest = @import("../policy/manifest.zig");
const package_service = @import("../services/package_service.zig");
const registry = @import("userspace_registry.zig");
const task_runtime = @import("task_runtime.zig");
const userspace_boot_registry = @import("userspace_boot_registry.zig");
const userspace_loader = @import("userspace_loader.zig");
const console = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub const Error = userspace_boot_registry.Error || userspace_loader.Error || package_service.Error;

pub fn launchRegisteredDirect(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!*task_runtime.TaskRecord {
    const bundle = try userspace_boot_registry.manifestFor(bundle_id);
    return launchDirectBundle(
        catalog,
        runtime_ptr,
        bundle,
        try userspace_boot_registry.componentClassFor(bundle_id),
        try userspace_boot_registry.initialComponentFor(bundle_id),
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
) Error!abi.TaskDescriptor {
    const bundle = try userspace_boot_registry.manifestFor(bundle_id);
    return launchKernelBundle(
        catalog,
        authority,
        bundle,
        try userspace_boot_registry.componentClassFor(bundle_id),
        try userspace_boot_registry.initialComponentFor(bundle_id),
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
) Error!*task_runtime.TaskRecord {
    if (catalog.findByBundleId(bundle.bundle_id) == null) {
        const contract = contractFor(bundle.bundle_id);
        _ = catalog.register(.{
            .bundle = bundle,
            .component_class = component_class,
            .initial_component = initial_component,
            .role_tag = contract.role_tag,
            .heartbeat_increment = contract.heartbeat_increment,
            .contract_flags = contract.contract_flags,
        }) catch |err| {
            logLaunchFailure(bundle.bundle_id, "register-direct", err);
            return err;
        };
    }
    const task = catalog.launchDirect(runtime_ptr, bundle.bundle_id, request) catch |err| {
        logLaunchFailure(bundle.bundle_id, "launch-direct", err);
        return err;
    };
    scheduleTask(schedule_task, task.id);
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
) Error!abi.TaskDescriptor {
    if (catalog.findByBundleId(bundle.bundle_id) == null) {
        const contract = contractFor(bundle.bundle_id);
        _ = catalog.register(.{
            .bundle = bundle,
            .component_class = component_class,
            .initial_component = initial_component,
            .role_tag = contract.role_tag,
            .heartbeat_increment = contract.heartbeat_increment,
            .contract_flags = contract.contract_flags,
        }) catch |err| {
            logLaunchFailure(bundle.bundle_id, "register-kernel", err);
            return err;
        };
    }
    const task = catalog.launchViaKernel(authority, bundle.bundle_id, request) catch |err| {
        logLaunchFailure(bundle.bundle_id, "launch-kernel", err);
        return err;
    };
    scheduleTask(schedule_task, task.task_id);
    return task;
}

fn contractFor(bundle_id: []const u8) registry.ContractSpec {
    return registry.contractFor(bundle_id) orelse .{
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
) Error!*task_runtime.TaskRecord {
    var resolved: package_service.ResolvedManifest = undefined;
    const bundle = try packages.resolveCurrentManifest(bundle_id, &resolved);
    const launch_plan = try packages.buildLaunchPlan(bundle_id);
    if (launch_plan.component_count == 0) unreachable;

    return launchDirectBundle(
        catalog,
        runtime_ptr,
        bundle,
        component_class,
        .{
            .substrate = userspace_loader.substrateForComponentAbi(launch_plan.components[0].abi),
            .label = launch_plan.components[0].idSlice(),
            .entry = launch_plan.components[0].entrySlice(),
        },
        request,
        schedule_task,
    );
}

fn scheduleTask(schedule_target: anytype, task_id: u64) void {
    switch (@typeInfo(@TypeOf(schedule_target))) {
        .pointer => |pointer| {
            if (@hasDecl(pointer.child, "registerTask")) {
                _ = schedule_target.registerTask(task_id);
                return;
            }
        },
        .@"fn" => {
            _ = schedule_target(task_id);
            return;
        },
        else => {},
    }
    @compileError("schedule target must be a scheduler pointer or fn(u64) bool");
}

fn logLaunchFailure(bundle_id: []const u8, phase: []const u8, err: anytype) void {
    if (builtin.target.os.tag == .freestanding) {
        console.print("ZIGOS:USERSPACE:LAUNCH:FAIL ");
        console.print(phase);
        console.print(" ");
        console.print(bundle_id);
        console.print(" ");
        console.print(@errorName(err));
        console.print("\n");
    }
}
