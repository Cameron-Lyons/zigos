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

pub const Error = userspace_boot_registry.Error || userspace_loader.Error || package_service.Error || error{SchedulerUnavailable};
pub const REGISTERED_LAUNCH_MANIFEST_SIGNATURES_PER_CALL: u8 = 0;

pub const SINGLE_KERNEL_CONTRACT_LAUNCH = true;

// Creation deliberately leaves the task out of the run queue. The session
// provisions task-scoped authority and initial resources before activation.
pub fn prepareRegisteredDirect(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
) Error!*task_runtime.TaskRecord {
    try ensureRegisteredBundle(catalog, bundle_id, "register-prepared");
    return catalog.launchDirect(runtime_ptr, bundle_id, request);
}

pub fn launchFromKernel(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!*task_runtime.TaskRecord {
    try ensureRegisteredBundle(catalog, bundle_id, "register-kernel");
    return launchDirectImage(
        catalog,
        runtime_ptr,
        bundle_id,
        request,
        schedule_task,
        "launch-kernel",
    );
}

pub fn launchRegisteredDirect(
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
    schedule_task: anytype,
) Error!*task_runtime.TaskRecord {
    return launchFromKernel(catalog, runtime_ptr, bundle_id, request, schedule_task);
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
    errdefer _ = runtime_ptr.terminateTask(task.id, 0) catch false;
    if (!scheduleTask(schedule_task, task.id)) return error.SchedulerUnavailable;
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
    errdefer _ = authority.port.kernel.runtime.terminateTask(task.task_id, authority.now_ticks) catch false;
    if (!scheduleTask(schedule_task, task.task_id)) return error.SchedulerUnavailable;
    return task;
}

fn ensureRegisteredBundle(
    catalog: *userspace_loader.Catalog,
    bundle_id: []const u8,
    failure_phase: []const u8,
) Error!void {
    if (catalog.resolveLaunchImage(bundle_id)) |image| {
        if (!image.embedsElf()) {
            return error.EmbeddedArtifactRequired;
        }
        return;
    }

    if (userspace_boot_registry.find(bundle_id) != null) {
        try userspace_boot_registry.registerAll(catalog);
        const image = catalog.resolveLaunchImage(bundle_id) orelse return error.ImageNotFound;
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
    const task = try prepareInstalledDirect(packages, catalog, runtime_ptr, bundle_id, request);
    errdefer _ = runtime_ptr.terminateTask(task.id, 0) catch false;
    if (!scheduleTask(schedule_task, task.id)) return error.SchedulerUnavailable;
    return task;
}

pub fn prepareInstalledDirect(
    packages: *const package_service.Service,
    catalog: *userspace_loader.Catalog,
    runtime_ptr: *task_runtime.Runtime,
    bundle_id: []const u8,
    request: userspace_loader.LaunchRequest,
) Error!*task_runtime.TaskRecord {
    var resolved: package_service.ResolvedManifest = undefined;
    const bundle = try packages.resolveCurrentManifest(bundle_id, &resolved);
    const launch_plan = try packages.buildLaunchPlan(bundle_id);
    if (launch_plan.components.len == 0) return error.MissingBundleComponent;
    var launch_request = request;
    if (launch_request.component_label.len == 0 and bundle.components.len != 0) {
        launch_request.component_label = bundle.components[0].id;
    }
    launch_request.source_identity = launch_plan.provenance.source_identity;
    launch_request.release_transparency_sequence = launch_plan.provenance.release_transparency.sequence;
    launch_request.release_transparency_root = launch_plan.provenance.release_transparency.root;
    launch_request.release_transparency_log_head = launch_plan.provenance.release_transparency.log_head;

    return prepareRegisteredDirect(catalog, runtime_ptr, bundle.bundle_id, launch_request);
}

fn scheduleTask(schedule_target: anytype, task_id: u64) bool {
    switch (@typeInfo(@TypeOf(schedule_target))) {
        .pointer => |pointer| {
            if (@hasDecl(pointer.child, "registerTask")) {
                return schedule_target.registerTask(task_id);
            }
        },
        .@"fn" => {
            return schedule_target(task_id);
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

test "scheduler rejection retires a newly created userspace task and address space" {
    const std = @import("std");
    var catalog = userspace_loader.Catalog.init();
    var runtime = task_runtime.Runtime.init();
    const RejectingScheduler = struct {
        runtime: *task_runtime.Runtime,
        task_id: u64 = 0,
        address_space_id: u64 = 0,

        pub fn registerTask(self: *@This(), task_id: u64) bool {
            self.task_id = task_id;
            self.address_space_id = self.runtime.find(task_id).?.address_space_id;
            return false;
        }
    };
    var scheduler = RejectingScheduler{ .runtime = &runtime };
    try std.testing.expectError(error.SchedulerUnavailable, launchRegisteredDirect(&catalog, &runtime, "app.notes", .{
        .owner = .{ .kind = .app, .serial = 71 },
        .budget = .{ .cpu_time_ticks = 1000, .memory_bytes = 256 * 1024, .endpoint_slots = 2, .shared_memory_bytes = 0 },
        .ui_surface_id = 71,
    }, &scheduler));
    try std.testing.expect(scheduler.task_id != 0);
    try std.testing.expectEqual(task_runtime.TaskState.terminated, runtime.find(scheduler.task_id).?.state);
    try std.testing.expect(runtime.findAddressSpaceConst(scheduler.address_space_id) == null);
    try std.testing.expectEqual(@as(usize, 0), runtime.countTasksInState(.active));
}
