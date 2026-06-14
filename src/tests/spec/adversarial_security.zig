const std = @import("std");
const spec_support = @import("support.zig");
const abi = @import("../../native/core/abi.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const component_port = @import("../../native/kernel_api/component_port.zig");
const endpoint = @import("../../native/kernel_api/endpoint.zig");
const manifest = @import("../../native/policy/manifest.zig");
const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
const object_store = @import("../../native/storage/object_store.zig");
const storage_volume = @import("../../native/storage/storage_volume.zig");
const supervisor = @import("../../native/session/supervisor.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const userspace_manifest_signing = @import("../../native/task/userspace_manifest_signing.zig");
const workspace = @import("../../native/storage/workspace.zig");

pub fn revokedCapabilitiesFailDuringIpc() !void {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = @import("../../native/kernel_api/shared_memory.zig").Table.init();
    var kernel = native_kernel.Kernel.init(
        spec_support.policyAuthority(1),
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var port = component_port.KernelPort.init(&kernel);

    const sender = try runtime.createTask(.{
        .owner = spec_support.app(101),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const receiver = try runtime.createTask(.{
        .owner = spec_support.service(102),
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const sender_authority = try mintServiceAuthority(&capabilities, sender.owner, sender.id, 10, .{
        .endpoint_create = true,
        .endpoint_connect = true,
        .endpoint_send = true,
        .capability_pass = true,
        .capability_revoke = true,
    }, 0, 100);
    const receiver_authority = try mintServiceAuthority(&capabilities, receiver.owner, receiver.id, 11, .{
        .endpoint_create = true,
        .endpoint_connect = true,
        .endpoint_recv = true,
    }, 0, 100);
    try runtime.grantCapability(sender.id, sender_authority.id);
    try runtime.grantCapability(receiver.id, receiver_authority.id);

    const sender_endpoint = try port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 1, sender.id),
        .authority_capability_id = sender_authority.id,
        .owner_task_id = sender.id,
        .label = "sender",
        .flags = .{ .local_only = true },
    }, 1);
    const receiver_endpoint = try port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 2, receiver.id),
        .authority_capability_id = receiver_authority.id,
        .owner_task_id = receiver.id,
        .label = "receiver",
        .flags = .{ .local_only = true },
    }, 1);
    _ = try port.endpointConnect(.{
        .header = component_port.makeHeader(.endpoint_connect, 3, sender.id),
        .endpoint_capability_id = sender_endpoint.capability_id,
        .peer_endpoint_capability_id = receiver_endpoint.capability_id,
        .peer_endpoint_id = receiver_endpoint.endpoint.endpoint_id,
    }, 2);

    const transferable = try capabilities.mintBootRoot(.{
        .holder = sender.owner,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .object, .id = 77 },
        .rights = .{ .object = .{ .capability_derive = true, .capability_pass = true, .object_read = true } },
        .scope = .{ .task_id = sender.id, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100, .renewable = false },
    });
    try runtime.grantCapability(sender.id, transferable.id);
    const stale_transfer = try capabilities.derive(.{
        .parent_capability_id = transferable.id,
        .holder = sender.owner,
        .rights = .{ .object = .{ .capability_pass = true, .object_read = true } },
        .scope = transferable.scope,
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 90, .renewable = false },
    });
    try runtime.grantCapability(sender.id, stale_transfer.id);
    try capabilities.revokeTargetAuthority(transferable.id);

    try std.testing.expectError(error.CapabilityRevoked, port.endpointSend(.{
        .header = component_port.makeHeader(.endpoint_send, 4, sender.id),
        .endpoint_capability_id = sender_endpoint.capability_id,
        .payload = "revoked-attach",
        .attached_capability_id = stale_transfer.id,
    }, 3));
    try std.testing.expect((try port.endpointRecv(.{
        .header = component_port.makeHeader(.endpoint_recv, 5, receiver.id),
        .endpoint_capability_id = receiver_endpoint.capability_id,
        .receiver_task_id = receiver.id,
    }, 4)) == null);
}

pub fn expiredLeasesFailAtKernelServiceBoundaries() !void {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = @import("../../native/kernel_api/shared_memory.zig").Table.init();
    var kernel = native_kernel.Kernel.init(
        spec_support.policyAuthority(1),
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var port = component_port.KernelPort.init(&kernel);

    const task = try runtime.createTask(.{
        .owner = spec_support.service(201),
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const expired = try mintServiceAuthority(&capabilities, task.owner, task.id, 20, .{
        .endpoint_create = true,
        .shared_memory_create = true,
        .time_query = true,
        .resource_query = true,
        .accounting_query = true,
    }, 0, 10);
    try runtime.grantCapability(task.id, expired.id);

    try std.testing.expectError(error.CapabilityRevoked, port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 1, task.id),
        .authority_capability_id = expired.id,
        .owner_task_id = task.id,
        .label = "expired",
        .flags = .{ .local_only = true },
    }, 11));
    try std.testing.expectError(error.CapabilityRevoked, port.sharedMemoryCreate(.{
        .header = component_port.makeHeader(.shared_memory_create, 2, task.id),
        .authority_capability_id = expired.id,
        .owner_task_id = task.id,
        .size_bytes = 128,
    }, 11));
    try std.testing.expectError(error.CapabilityRevoked, port.timeQuery(.{
        .header = component_port.makeHeader(.time_query, 3, task.id),
        .authority_capability_id = expired.id,
    }, 11));
    try std.testing.expectError(error.CapabilityRevoked, port.resourceQuery(.{
        .header = component_port.makeHeader(.resource_query, 4, task.id),
        .authority_capability_id = expired.id,
        .task_id = task.id,
    }, 11));
    try std.testing.expectError(error.CapabilityRevoked, port.accountingQuery(.{
        .header = component_port.makeHeader(.accounting_query, 5, task.id),
        .authority_capability_id = expired.id,
        .task_id = task.id,
    }, 11));
}

pub fn malformedManifestsStayRejected() !void {
    const invalid_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .background_execution,
            .resource = "orphan-background",
            .rights = .{ .task = .{ .background_run = true } },
        },
    };
    try std.testing.expectError(error.MissingBackgroundTask, manifest.validate(.{
        .bundle_id = "app.bad.background",
        .display_name = "Bad Background",
        .publisher = "zigos.spec",
        .requested_permissions = &invalid_permissions,
    }));

    const duplicate_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "main", .entry = "app.bad.main" },
        .{ .id = "main", .entry = "app.bad.other" },
    };
    try std.testing.expectError(error.DuplicateComponentId, manifest.validate(.{
        .bundle_id = "app.bad.duplicate",
        .display_name = "Bad Duplicate",
        .publisher = "zigos.spec",
        .components = &duplicate_components,
    }));

    const remote_ai_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "remote.model",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .local_only = false,
            .egress_intent = .{
                .kind = .call_service,
                .service = "remote.model",
            },
        },
    };
    try std.testing.expectError(error.LocalOnlyAiRequiresLocalNetwork, manifest.validate(.{
        .bundle_id = "app.bad.ai",
        .display_name = "Bad AI",
        .publisher = "zigos.spec",
        .requested_permissions = &remote_ai_permissions,
        .ai_metadata = .{ .model_family = "spec-local", .locality = .local_only },
    }));

    const smuggled_rights_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .camera,
            .resource = "camera.front",
            .rights = .{ .object = .{ .object_read = true } },
            .required = false,
        },
    };
    try std.testing.expectError(error.PermissionRightsTargetMismatch, manifest.validate(.{
        .bundle_id = "app.bad.permission-rights",
        .display_name = "Bad Permission Rights",
        .publisher = "zigos.spec",
        .requested_permissions = &smuggled_rights_permissions,
    }));

    const local_only_remote_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .network_egress,
            .resource = "remote.sync",
            .rights = .{ .network_policy = .{ .network_remote = true } },
            .required = false,
            .local_only = true,
            .egress_intent = .{
                .kind = .call_service,
                .service = "remote.sync",
            },
        },
    };
    try std.testing.expectError(error.LocalOnlyPermissionRequestsRemoteNetwork, manifest.validate(.{
        .bundle_id = "app.bad.local-only-remote",
        .display_name = "Bad Local Remote",
        .publisher = "zigos.spec",
        .requested_permissions = &local_only_remote_permissions,
    }));

    const duplicate_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_read = true } },
            .required = false,
            .local_only = true,
        },
        .{
            .kind = .object_access,
            .resource = "workspace:notes",
            .rights = .{ .object = .{ .object_write = true } },
            .required = false,
            .local_only = true,
        },
    };
    try std.testing.expectError(error.DuplicatePermissionRequest, manifest.validate(.{
        .bundle_id = "app.bad.duplicate-permissions",
        .display_name = "Bad Duplicate Permissions",
        .publisher = "zigos.spec",
        .requested_permissions = &duplicate_permissions,
    }));
}

pub fn corruptedStorageLogsDoNotReplay() !void {
    const image = try std.testing.allocator.alloc(u8, storage_volume.image_bytes);
    defer std.testing.allocator.free(image);
    @memset(image, 0);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const signer = spec_support.signer("spec.storage.corrupt", 0x71);
    _ = try store.putVersion(.{
        .preferred_object_id = object_store.ids.object(301),
        .object_type = .document,
        .payload = "clean",
        .metadata = try object_store.signMetadata(signer, "clean", "text/plain", .document, "clean", 1),
    });
    _ = try storage_volume.saveToImage(image, &store, &workspaces);

    image[storage_volume.sector_size * 2 + 3] ^= 0xFF;

    var loaded_store = object_store.Store.init();
    var loaded_workspaces = workspace.Directory.init();
    try std.testing.expectError(error.CorruptImage, storage_volume.loadFromImage(image, &loaded_store, &loaded_workspaces));
    try std.testing.expectEqual(@as(usize, 0), loaded_store.objectCount());
}

pub fn serviceCrashLoopsRemainDiagnosableAndBounded() !void {
    var monitor = supervisor.Supervisor.init();
    const service = try monitor.register(.network_stack, spec_support.service(401));
    const service_id = service.id;

    var attempt: u16 = 0;
    while (attempt < 3) : (attempt += 1) {
        const tick = @as(u64, attempt) * 10 + 1;
        try std.testing.expect(monitor.recordCrash(service_id, tick, 0xC0DE + attempt));
        try std.testing.expect(monitor.requestRestart(service_id, tick + 1));
        try std.testing.expect(monitor.completeRestart(service_id, tick + 2));
    }

    const restarted = monitor.find(service_id).?;
    try std.testing.expectEqual(@as(u16, 3), restarted.restart_count);
    try std.testing.expectEqual(supervisor.ServiceState.healthy, restarted.state);
    try std.testing.expect(monitor.hasDiagnostic(service_id, .crash));
    try std.testing.expect(monitor.hasDiagnostic(service_id, .restart_requested));
    try std.testing.expect(monitor.hasDiagnostic(service_id, .restart_completed));
    try std.testing.expectEqual(@as(u32, 3), monitor.latestDiagnostic(service_id).?.detail);
}

pub fn downgradeAndRollbackAttacksNeedFreshSignedMetadata() !void {
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "main", .entry = "app.writer.main" },
    };
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "writer.document/v1" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    var signed_v2 = manifest.BundleManifest{
        .bundle_id = "app.writer",
        .display_name = "Writer",
        .publisher = "zigos.spec",
        .version_major = 2,
        .components = &components,
        .provided_interfaces = &interfaces,
        .assets = &assets,
    };
    signed_v2.signature = try userspace_manifest_signing.signBundle(signed_v2);
    try std.testing.expect(userspace_manifest_signing.verifyBundle(signed_v2));

    var replayed_downgrade = signed_v2;
    replayed_downgrade.version_major = 1;
    try std.testing.expect(!userspace_manifest_signing.verifyBundle(replayed_downgrade));

    var replayed_rollback = signed_v2;
    replayed_rollback.update_channel = .pinned;
    try std.testing.expect(!userspace_manifest_signing.verifyBundle(replayed_rollback));
}

fn mintServiceAuthority(
    table: *capability.CapabilityTable,
    holder: @import("../../native/core/principal.zig").PrincipalId,
    task_id: u64,
    target_id: u64,
    rights: capability.CapabilityRights.SystemRights,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
) !capability.Capability {
    return table.mintBootRoot(.{
        .holder = holder,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .service, .id = target_id },
        .rights = .{ .service = rights },
        .scope = .{ .task_id = task_id, .local_only = true, .broker_only = true },
        .lease = .{
            .issued_at_ticks = issued_at_ticks,
            .expires_at_ticks = expires_at_ticks,
            .renewable = false,
        },
    });
}
