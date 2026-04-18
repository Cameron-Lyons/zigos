const event_ledger = @import("../platform/event_ledger.zig");
const sync_service_mod = @import("../sync/sync_service.zig");
const support = @import("scenario_support.zig");
const storage_scenarios = @import("storage_scenarios.zig");
const sync_scenarios = @import("sync_scenarios.zig");
const platform_scenarios = @import("platform_scenarios.zig");

pub const Context = support.Context;

pub fn run(context: *Context) void {
    const storage_state = storage_scenarios.run(context);
    const early_boot_ledger = context.update_ledger.*;
    context.update_ledger.* = event_ledger.Ledger.initPersistent(
        context.storage_service_instance,
        context.package_service_principal,
        support.diagnostic_ledger_signer,
    ) catch unreachable;
    context.update_ledger.absorb(&early_boot_ledger) catch unreachable;
    var sync_service = sync_service_mod.Service.initWithStorage(
        context.sync_service_id,
        context.sync_task_id,
        context.sync_service_principal,
        context.storage_service_instance,
        context.sync_resident_state,
    ) catch unreachable;
    const sync_state = sync_scenarios.run(context, &sync_service, storage_state);
    platform_scenarios.run(context, &sync_service, storage_state, sync_state);
}
