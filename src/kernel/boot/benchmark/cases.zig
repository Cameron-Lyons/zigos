pub const BenchmarkCase = struct {
    name: []const u8,
    iterations: u32,
    operations_per_iteration: u32 = 1,
    runIteration: *const fn (iteration: u32) u64,
};

pub const QualityGateCase = struct {
    name: []const u8,
    run: *const fn () u64,
};

pub const SECRET_STORE_OPERATIONS_PER_ITERATION: u32 = 16;

pub fn benchmarkCases(handlers: anytype) [28]BenchmarkCase {
    return .{
        .{ .name = "capability.derive.workspace_object", .iterations = 40_000, .runIteration = handlers.capability_derive },
        .{ .name = "capability.mint_reuse_free_slot", .iterations = 4_000, .runIteration = handlers.capability_mint_reuse_free_slot },
        .{ .name = "capability.target_generation_lookup", .iterations = 4_000, .runIteration = handlers.capability_target_generation_lookup },
        .{ .name = "permission.review.render_grants", .iterations = 12_000, .runIteration = handlers.permission_review_render },
        .{ .name = "network_policy.authorize_connection", .iterations = 60_000, .runIteration = handlers.network_policy_authorize },
        .{ .name = "background_dispatch.allowed_sync", .iterations = 8_000, .runIteration = handlers.background_dispatch },
        .{ .name = "service_supervisor.ready_lookup", .iterations = 60_000, .runIteration = handlers.supervisor_ready_lookup },
        .{ .name = "task_runtime.checkpoint.write_restore", .iterations = 8_000, .runIteration = handlers.task_checkpoint_write_restore },
        .{ .name = "task_runtime.checkpoint.write_low_occupancy", .iterations = 8_000, .runIteration = handlers.task_checkpoint_write_low_occupancy },
        .{ .name = "paging.address_space_roundtrip", .iterations = 50_000, .runIteration = handlers.address_space_roundtrip },
        .{ .name = "memory.heap_allocate_free", .iterations = 20_000, .operations_per_iteration = 2, .runIteration = handlers.heap_allocate_free },
        .{ .name = "memory.frame_allocate_release", .iterations = 20_000, .operations_per_iteration = 2, .runIteration = handlers.frame_allocate_release },
        .{ .name = "syscall.fast_entry_roundtrip", .iterations = 64_000, .operations_per_iteration = 64, .runIteration = handlers.syscall_fast_entry_roundtrip },
        .{ .name = "accelerator_scheduler.claim_release", .iterations = 25_000, .runIteration = handlers.accelerator_claim_release },
        .{ .name = "storage.file_bridge.resolve_shared_view", .iterations = 40_000, .runIteration = handlers.file_bridge_resolve },
        .{ .name = "storage.workspace.commit_overlay", .iterations = 128, .runIteration = handlers.workspace_commit_overlay },
        .{ .name = "storage.volume.replay_segmented_log", .iterations = 24, .runIteration = handlers.storage_volume_replay_segmented_log },
        .{ .name = "storage.volume.compact_checkpoint", .iterations = 1, .runIteration = handlers.storage_volume_compact_checkpoint },
        .{ .name = "package_revision.rollforward_rollback", .iterations = 20_000, .runIteration = handlers.package_revision },
        .{ .name = "indexing_service.query_ranked", .iterations = 20_000, .runIteration = handlers.indexing_query },
        .{ .name = "media_print.submit_complete", .iterations = 8_000, .runIteration = handlers.media_print_submit_complete },
        .{ .name = "event_ledger.export_redacted", .iterations = 4_000, .runIteration = handlers.event_ledger_export },
        .{ .name = "secret_store.import_handle_export", .iterations = 20_000, .operations_per_iteration = SECRET_STORE_OPERATIONS_PER_ITERATION, .runIteration = handlers.secret_store_import_handle_export },
        .{ .name = "denial_explanation.render_policy_hint", .iterations = 32_000, .runIteration = handlers.denial_explanation_render },
        .{ .name = "sync_service.overlay_session_flow", .iterations = 8_000, .runIteration = handlers.overlay_session_flow },
        .{ .name = "recovery_environment.reinstall_restore_repair", .iterations = 4, .runIteration = handlers.recovery_lifecycle },
        .{ .name = "update_health.validate_pending_activation", .iterations = 8, .runIteration = handlers.update_health_validation },
        .{ .name = "driver_recovery.restart_driver", .iterations = 512, .runIteration = handlers.driver_recovery_restart },
    };
}

pub fn qualityGateCases(handlers: anytype) [10]QualityGateCase {
    return .{
        .{ .name = "battery_saver.batch_delay", .run = handlers.battery_saver_batch_delay },
        .{ .name = "thermal_critical.background_delay", .run = handlers.thermal_critical_background_delay },
        .{ .name = "memory_pressure.batch_delay", .run = handlers.memory_pressure_batch_delay },
        .{ .name = "scheduler_fairness.max_min_dispatch_ratio_percent", .run = handlers.scheduler_fairness_ratio_percent },
        .{ .name = "starvation_resistance.min_dispatches_after_pressure", .run = handlers.starvation_resistance_after_pressure },
        .{ .name = "lower_class_service_debt.batch_tie_dispatch", .run = handlers.lower_class_service_debt_batch_tie_dispatch },
        .{ .name = "accelerator_claims.deadline_priority", .run = handlers.accelerator_claim_deadline_priority },
        .{ .name = "brokered_accelerator_queue.completion_release", .run = handlers.brokered_accelerator_queue_completion_release },
        .{ .name = "background_throttling.delayed_dispatches", .run = handlers.background_throttling_delayed_dispatches },
        .{ .name = "latency_under_load.max_foreground_wait_ticks", .run = handlers.latency_under_load_max_wait_ticks },
    };
}
