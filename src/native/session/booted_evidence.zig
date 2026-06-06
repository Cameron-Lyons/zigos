const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const bootstrap_packages = @import("../demo/bootstrap_packages.zig");
const compositor_session = @import("../platform/compositor_session.zig");
const permission_flows = @import("../demo/permission_flows.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_component_port = @import("../policy/policy_component_port.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const review_component_port = @import("../policy/review_component_port.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const scenario_support = @import("../demo/scenario_support.zig");
const storage_scenarios = @import("../demo/storage_scenarios.zig");
const sync_scenarios = @import("../demo/sync_scenarios.zig");
const sync_service_mod = @import("../sync/sync_service.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

pub fn runProduction(manager: anytype, graph: anytype) bool {
    bootstrap_packages.seed(
        manager.packageServicePtr(),
        manager.capabilityTablePtr(),
        graph.state.services.package_service.id,
        graph.state.ids.package_service,
        graph.state.session_task.id,
        graph.state.ids.session_service,
        graph.state.ids.policy_authority,
    );

    var mediator = policy_mediation.PolicyMediator.init(
        graph.state.ids.policy_authority,
        manager.capabilityTablePtr(),
        manager.runtimeServicePtr().runtimePtr(),
        .{
            .network_service_id = graph.state.services.network_service.id,
            .compositor_service_id = graph.state.services.compositor_service.id,
            .policy_service_id = graph.state.services.policy_service.id,
            .service_registry_id = graph.state.services.service_registry.id,
        },
    );
    mediator.attachLedger(manager.updateLedgerPtr());

    var review_service = permission_review_service.Service.initProfiled(
        graph.state.services.review_service_record.id,
        graph.state.review_service_task.id,
        manager.runtimePtr(),
        &[_][]const u8{},
        @import("../policy/bootstrap_review_profile.zig").rules[0..],
        manager.compositorSessionPtr(),
        manager.reviewUxControllerPtr(),
    );
    var compositor_checkpoint_store = compositor_session.CheckpointStore{};
    var compositor_service = compositor_session.Service.initWithCheckpoint(
        graph.state.services.compositor_service.id,
        graph.service_bindings.bindingFor(.compositor_ui_session).task_id,
        manager.runtimePtr(),
        manager.compositorSessionPtr(),
        &compositor_checkpoint_store,
    );
    review_service.bindCompositorService(&compositor_service);

    var review_port = review_component_port.Port.init(&review_service);
    var policy_port = policy_component_port.Port.init(&mediator);
    common.printBootMarker(boot_markers.permission_review_port_ready);
    common.printBootMarker(boot_markers.permission_policy_port_ready);

    const notes_review = permission_flows.run(
        &graph.env,
        &graph.state,
        graph.kernel_port,
        &review_port,
        &policy_port,
    );

    if (manager.storageServicePtr().findWorkspace(graph.state.ids.session_user, "notes-workspace") != null) {
        return true;
    }

    var lifecycle_context = scenario_support.Context{
        .capability_table = manager.capabilityTablePtr(),
        .runtime = manager.runtimePtr(),
        .runtime_service = manager.runtimeServicePtr(),
        .userspace_catalog = manager.userspaceCatalogPtr(),
        .supervisor = manager.supervisorPtr(),
        .compositor = manager.compositorSessionPtr(),
        .driver_directory = manager.driverDirectoryPtr(),
        .storage_service_instance = manager.storageServicePtr(),
        .storage_checkpoint_store = manager.storageCheckpointStorePtr(),
        .export_package = manager.exportPackagePtr(),
        .policy_authority = graph.state.ids.policy_authority,
        .session_service = graph.state.ids.session_service,
        .session_user = graph.state.ids.session_user,
        .storage_service_id = graph.state.services.storage_service.id,
        .storage_task_id = graph.service_bindings.bindingFor(.storage_object).task_id,
        .storage_service_principal = graph.state.ids.storage_service,
        .sync_service_id = graph.state.services.sync_service.id,
        .sync_task_id = graph.service_bindings.bindingFor(.sync_replication).task_id,
        .sync_service_principal = graph.state.ids.sync_service,
        .sync_resident_state = manager.syncResidentStatePtr(),
        .policy_service_id = graph.state.services.policy_service.id,
        .network_service_id = graph.state.services.network_service.id,
        .compositor_service_id = graph.state.services.compositor_service.id,
        .package_service_id = graph.state.services.package_service.id,
        .package_service_principal = graph.state.ids.package_service,
        .update_ledger = manager.updateLedgerPtr(),
        .notes_task_id = notes_review.task_id,
        .notes_object_capability = notes_review.object_capability,
    };
    const storage_state = storage_scenarios.run(&lifecycle_context);
    const early_boot_ledger = lifecycle_context.update_ledger.*;
    lifecycle_context.update_ledger.* = event_ledger.Ledger.initPersistent(
        lifecycle_context.storage_service_instance,
        lifecycle_context.package_service_principal,
        scenario_support.diagnostic_ledger_signer,
    ) catch unreachable;
    lifecycle_context.update_ledger.absorb(&early_boot_ledger) catch unreachable;
    var sync_service = sync_service_mod.Service.initWithStorage(
        lifecycle_context.sync_service_id,
        lifecycle_context.sync_task_id,
        lifecycle_context.sync_service_principal,
        lifecycle_context.storage_service_instance,
        lifecycle_context.sync_resident_state,
    ) catch unreachable;
    _ = sync_scenarios.run(&lifecycle_context, &sync_service, storage_state);
    return true;
}
