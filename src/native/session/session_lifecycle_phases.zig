const sync_service_mod = @import("../sync/sync_service.zig");
const support = @import("session_lifecycle_support.zig");
const phase4_storage = @import("session_phase4_storage.zig");
const phase5_sync = @import("session_phase5_sync.zig");
const phase6_lifecycle = @import("session_phase6_lifecycle.zig");

pub const Context = support.Context;

pub fn run(context: *Context) void {
    const phase4 = phase4_storage.run(context);
    var phase5_sync_service = sync_service_mod.Service.initWithStorage(
        context.sync_service_id,
        context.sync_task_id,
        context.sync_service_principal,
        context.storage_service_instance,
    ) catch unreachable;
    const phase5 = phase5_sync.run(context, &phase5_sync_service, phase4);
    phase6_lifecycle.run(context, &phase5_sync_service, phase4, phase5);
}
