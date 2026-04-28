const builtin = @import("builtin");
const boot_markers = @import("../../kernel/boot/markers.zig");
const bootstrap_packages = @import("bootstrap_packages.zig");
const bootstrap_review_profile = @import("../policy/bootstrap_review_profile.zig");
const permission_flows = @import("permission_flows.zig");
const permission_review_service = @import("../policy/permission_review_service.zig");
const policy_component_port = @import("../policy/policy_component_port.zig");
const policy_mediation = @import("../policy/policy_mediation.zig");
const principal = @import("../core/principal.zig");
const review_component_port = @import("../policy/review_component_port.zig");
const scenario_world = @import("scenario_world.zig");
const session_bootstrap = @import("../session/session_bootstrap.zig");
const session_boot_flow = @import("../session/session_manager_boot_flow.zig");
const session_service_bootstrap = @import("../session/session_service_bootstrap.zig");
const session_support = @import("../session/session_manager_support.zig");
const transport_checks = @import("transport_checks.zig");

const common = if (builtin.target.os.tag == .freestanding)
    @import("../../kernel/boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
    };

pub fn bootScenarioWorld(manager: *session_boot_flow.SessionManager) void {
    var graph = manager.beginServiceGraph() orelse return;
    bootstrap_packages.seed(&manager.package_service_instance);

    var mediator = initPolicyMediator(manager, graph.state.ids.policy_authority, graph.state.services);
    if (!session_service_bootstrap.bootRegistryService(&graph.env, &graph.state, graph.kernel_port, &graph.service_bindings)) {
        manager.failBoot();
        return;
    }

    var review_service = initReviewService(
        manager,
        graph.state.services.review_service_record.id,
        graph.state.review_service_task.id,
    );
    var review_port = review_component_port.Port.init(&review_service);
    var policy_port = policy_component_port.Port.init(&mediator);
    common.printBootMarker(boot_markers.permission_review_port_ready);
    common.printBootMarker(boot_markers.permission_policy_port_ready);

    transport_checks.run(&graph.env, &graph.state, graph.kernel_port);
    const notes_review = permission_flows.run(&graph.env, &graph.state, graph.kernel_port, &review_port, &policy_port);
    if (!session_service_bootstrap.run(&graph.env, &graph.state, graph.kernel_port, &graph.service_bindings)) {
        manager.failBoot();
        return;
    }
    runSessionLifecycle(manager, &graph.state, &graph.service_bindings, notes_review);
    session_boot_flow.printReadyBanner();
}

fn initPolicyMediator(
    manager: *session_boot_flow.SessionManager,
    policy_authority: principal.PrincipalId,
    services: session_bootstrap.CoreServices,
) policy_mediation.PolicyMediator {
    return policy_mediation.PolicyMediator.init(
        policy_authority,
        &manager.capability_table,
        manager.runtime_service.runtimePtr(),
        .{
            .network_service_id = services.network_service.id,
            .compositor_service_id = services.compositor_service.id,
            .policy_service_id = services.policy_service.id,
            .service_registry_id = services.service_registry.id,
        },
    );
}

fn initReviewService(
    manager: *session_boot_flow.SessionManager,
    review_service_id: u64,
    review_task_id: u64,
) permission_review_service.Service {
    return permission_review_service.Service.initProfiled(
        review_service_id,
        review_task_id,
        &manager.runtime,
        &[_][]const u8{},
        bootstrap_review_profile.rules[0..],
        &manager.review_compositor_session,
        &manager.review_ux_controller,
    );
}

fn runSessionLifecycle(
    manager: *session_boot_flow.SessionManager,
    state: *const session_boot_flow.BootstrapState,
    service_bindings: *const session_boot_flow.ServiceBindings,
    notes_review: session_support.NotesReviewState,
) void {
    var lifecycle_context = scenario_world.Context{
        .capability_table = &manager.capability_table,
        .runtime = &manager.runtime,
        .runtime_service = &manager.runtime_service,
        .userspace_catalog = &manager.userspace_catalog,
        .supervisor = &manager.supervisor,
        .compositor = &manager.review_compositor_session,
        .driver_directory = &manager.driver_directory,
        .storage_service_instance = &manager.storage_service_instance,
        .storage_checkpoint_store = &manager.storage_checkpoint_store,
        .export_package = &manager.export_package_buffer,
        .policy_authority = state.ids.policy_authority,
        .session_service = state.ids.session_service,
        .session_user = state.ids.session_user,
        .storage_service_id = state.services.storage_service.id,
        .storage_task_id = service_bindings.bindingFor(.storage_object).task_id,
        .storage_service_principal = state.ids.storage_service,
        .sync_service_id = state.services.sync_service.id,
        .sync_task_id = service_bindings.bindingFor(.sync_replication).task_id,
        .sync_service_principal = state.ids.sync_service,
        .sync_resident_state = &manager.sync_resident_state,
        .policy_service_id = state.services.policy_service.id,
        .network_service_id = state.services.network_service.id,
        .compositor_service_id = state.services.compositor_service.id,
        .package_service_id = state.services.package_service.id,
        .package_service_principal = state.ids.package_service,
        .update_ledger = &manager.diagnostic_ledger,
        .notes_task_id = notes_review.task_id,
        .notes_object_capability = notes_review.object_capability,
    };
    scenario_world.run(&lifecycle_context);
}
