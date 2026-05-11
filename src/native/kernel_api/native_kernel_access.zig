const capability = @import("capability.zig");
const task_runtime = @import("../task/task_runtime.zig");

pub fn validateTaskCreateRequest(
    ErrorSet: type,
    request: task_runtime.TaskCreateRequest,
) ErrorSet!void {
    if (request.launch.boundary == .userspace_process and
        (request.userspace_image == null or !request.userspace_image.?.isPresent()))
    {
        return error.InvalidUserspaceImage;
    }
    switch (request.component_class) {
        .session_manager => {},
        .app_component, .service_component => {
            if (request.launch.boundary != .userspace_process) return error.UserspaceLaunchRequired;
            if (request.launch.image_id == 0 or
                request.launch.component_abi_version == 0 or
                !request.launch.signed or
                request.launch.bundle_id.len == 0 or
                request.launch.bundle_id.len >= task_runtime.MAX_TASK_BUNDLE_ID_BYTES)
            {
                return error.InvalidUserspaceImage;
            }
        },
    }
}

pub fn requireCapability(
    ErrorSet: type,
    kernel: anytype,
    capability_id: u64,
    now_ticks: u64,
    needed_rights: capability.CapabilityRights,
) ErrorSet!capability.Capability {
    const owned = kernel.capability_table.query(capability_id) orelse return error.CapabilityNotFound;
    if (!kernel.capability_table.isUsable(owned, now_ticks)) return error.CapabilityRevoked;
    if (!owned.rights.containsAll(needed_rights)) return error.PermissionDenied;
    return owned;
}

pub fn requireTargetedCapability(
    ErrorSet: type,
    kernel: anytype,
    capability_id: u64,
    now_ticks: u64,
    needed_rights: capability.CapabilityRights,
    target_kind: capability.CapabilityTargetKind,
) ErrorSet!capability.Capability {
    const owned = try requireCapability(ErrorSet, kernel, capability_id, now_ticks, needed_rights);
    if (owned.target.kind != target_kind) return error.InvalidCapabilityTarget;
    return owned;
}

pub fn retargetTaskScope(original: capability.CapabilityScope, receiver_task_id: u64) capability.CapabilityScope {
    var next = original;
    if (original.task_id != null) {
        next.task_id = receiver_task_id;
    }
    return next;
}
