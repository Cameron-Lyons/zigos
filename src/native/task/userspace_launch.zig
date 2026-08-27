const builtin = @import("builtin");
const abi = @import("../core/abi.zig");
const manifest = @import("../policy/manifest.zig");
const package_service = @import("../services/package_service.zig");
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
pub const REGISTERED_LAUNCH_MANIFEST_SIGNATURES_PER_CALL: u8 = 0;

pub fn launchRegisteredDirect(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!*task_runtime.TaskRecord {
    try ensureRegisteredBundle(catalog, bundle_id, "register-direct");
    return launchDirectImage(
        catalog,
        runtime_ptr,
        bundle_id,
        request,
        schedule_task,
        "launch-direct",
    );
}

pub fn launchRegisteredKernel(
    catalog: *userspace_loader.Catalog,
    authority: userspace_loader.KernelLaunchAuthority,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!abi.TaskDescriptor {
    try ensureRegisteredBundle(catalog, bundle_id, "register-kernel");
    return launchKernelImage(
        catalog,
        authority,
        bundle_id,
        request,
        schedule_task,
        "launch-kernel",
    );
}

pub fn launchDirectBundle(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle: manifest.BundleManifest,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!*task_runtime.TaskRecord {
    try ensureRegisteredBundle(catalog, bundle.bundle_id, "register-direct");
    return launchDirectImage(catalog, runtime_ptr, bundle.bundle_id, request, schedule_task, "launch-direct");
}

fn launchDirectImage(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
    failure_phase: []const u8,
) Error!*task_runtime.TaskRecord {
    const task = catalog.launchDirect(runtime_ptr, bundle_id, request) catch |err| {
        logLaunchFailure(bundle_id, failure_phase, err);
        return err;
    };
    scheduleTask(schedule_task, task.id);
    return task;
}

pub fn launchKernelBundle(
    catalog: *userspace_loader.Catalog,
    authority: userspace_loader.KernelLaunchAuthority,
    bundle: manifest.BundleManifest,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!abi.TaskDescriptor {
    try ensureRegisteredBundle(catalog, bundle.bundle_id, "register-kernel");
    return launchKernelImage(catalog, authority, bundle.bundle_id, request, schedule_task, "launch-kernel");
}

fn launchKernelImage(
    catalog: *userspace_loader.Catalog,
    authority: userspace_loader.KernelLaunchAuthority,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
    failure_phase: []const u8,
) Error!abi.TaskDescriptor {
    const task = catalog.launchViaKernel(authority, bundle_id, request) catch |err| {
        logLaunchFailure(bundle_id, failure_phase, err);
        return err;
    };
    scheduleTask(schedule_task, task.task_id);
    return task;
}

fn ensureRegisteredBundle(
    catalog: *userspace_loader.Catalog,
    bundle_id: []const u8,
    failure_phase: []const u8,
) Error!void {
    if (catalog.findByBundleId(bundle_id)) |image| {
        if (!image.embedsElf()) {
            return error.EmbeddedArtifactRequired;
        }
        return;
    }

    if (userspace_boot_registry.find(bundle_id) != null) {
        try userspace_boot_registry.registerAll(catalog);
        const image = catalog.findByBundleId(bundle_id) orelse return error.ImageNotFound;
        if (!image.embedsElf()) return error.EmbeddedArtifactRequired;
        return;
    }

    logLaunchFailure(bundle_id, failure_phase, error.EmbeddedArtifactRequired);
    return error.EmbeddedArtifactRequired;
}

pub fn launchInstalledDirect(
    packages: *const package_service.Service,
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!*task_runtime.TaskRecord {
    var resolved: package_service.ResolvedManifest = undefined;
    const bundle = try packages.resolveCurrentManifest(bundle_id, &resolved);
    const launch_plan = try packages.buildLaunchPlan(bundle_id);
    if (launch_plan.components.len == 0) return error.MissingBundleComponent;
    var launch_request = request;
    launch_request.source_identity = launch_plan.provenance.source_identity;
    launch_request.release_transparency_sequence = launch_plan.provenance.release_transparency.sequence;
    launch_request.release_transparency_root = launch_plan.provenance.release_transparency.root;
    launch_request.release_transparency_log_head = launch_plan.provenance.release_transparency.log_head;

    return launchDirectBundle(
        catalog,
        runtime_ptr,
        bundle,
        launch_request,
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
