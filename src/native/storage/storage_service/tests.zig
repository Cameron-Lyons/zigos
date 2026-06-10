const std = @import("std");

const capability = @import("../../kernel_api/capability.zig");
const debug_contract = @import("../../security/debug_contract.zig");
const humane_permissions = @import("../../policy/humane_permissions.zig");
const ids = @import("../../core/ids.zig");
const object_store = @import("../object_store.zig");
const principal = @import("../../core/principal.zig");
const shared_memory = @import("../../kernel_api/shared_memory.zig");
const signing = @import("../../core/signing.zig");
const storage_volume = @import("../storage_volume.zig");
const workspace = @import("../workspace.zig");
const storage_service = @import("service.zig");

const AuthorityContext = storage_service.AuthorityContext;
const CheckpointStore = storage_service.CheckpointStore;
const Service = storage_service.Service;
const StorageCore = storage_service.StorageCore;
const StoragePort = storage_service.StoragePort;

const FakeStorageVolumeBackend = struct {
    var image: []u8 = &.{};

    fn attach(image_buffer: []u8) void {
        image = image_buffer;
        storage_volume.attachBackend(.{
            .sector_count = storage_volume.required_device_sectors,
            .read = read,
            .write = write,
        });
    }

    fn read(start_lba: u64, buffer_ptr: [*]u8, buffer_len: usize) callconv(.c) bool {
        const buffer = buffer_ptr[0..buffer_len];
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(buffer, image[start..end]);
        return true;
    }

    fn write(start_lba: u64, buffer_ptr: [*]const u8, buffer_len: usize) callconv(.c) bool {
        const buffer = buffer_ptr[0..buffer_len];
        const start = @as(usize, @intCast(start_lba)) * storage_volume.sector_size;
        const end = start + buffer.len;
        if (end > image.len) return false;
        @memcpy(image[start..end], buffer);
        return true;
    }
};

test "storage port requires authority context for protected mutations" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 47 };
    const actor = principal.PrincipalId{ .kind = .user, .serial = 7 };
    var core = StorageCore.initWithStore(703, 20, owner, &checkpoint_store);
    var capabilities = capability.CapabilityTable.init();
    var port = StoragePort.init(&core, &capabilities);

    const read_only = try capabilities.mintBootRoot(.{
        .holder = actor,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = core.service_id },
        .rights = .{ .service = .{ .object_read = true } },
        .scope = .{ .task_id = 20, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const writer = try capabilities.mintBootRoot(.{
        .holder = actor,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = core.service_id },
        .rights = .{ .service = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = 20, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA7} ** 32,
    };
    const request = object_store.PutRequest{
        .preferred_object_id = ids.object(953),
        .object_type = .document,
        .payload = "authorized",
        .metadata = try object_store.signMetadata(signer, "authorized", "text/plain", .document, "authorized", 10),
    };

    var read_only_trace = debug_contract.ProvenanceRecord{};
    try std.testing.expectError(error.PermissionDenied, port.putVersion(.{
        .task_id = 20,
        .principal = actor,
        .capability_id = read_only.id,
        .now_ticks = 10,
        .operation = "storage-put-version",
        .trace = &read_only_trace,
    }, request));
    try std.testing.expectEqual(debug_contract.ProvenanceKind.service_call, read_only_trace.kind);
    try std.testing.expectEqual(debug_contract.Decision.denied, read_only_trace.decision);
    try std.testing.expectEqualStrings("storage-put-version", read_only_trace.operationSlice());
    try std.testing.expectEqualStrings("object_write", read_only_trace.detailSlice());
    try std.testing.expect(read_only_trace.denial.fingerprint != 0);

    var allowed_trace = debug_contract.ProvenanceRecord{};
    const result = try port.putVersion(.{
        .task_id = 20,
        .principal = actor,
        .capability_id = writer.id,
        .now_ticks = 10,
        .operation = "storage-put-version",
        .trace = &allowed_trace,
    }, request);
    try std.testing.expectEqual(ids.object(953), result.object_id);
    try std.testing.expectEqual(debug_contract.Decision.allowed, allowed_trace.decision);
    try std.testing.expectEqual(@as(u64, core.service_id), allowed_trace.service_id);

    var scope_trace = debug_contract.ProvenanceRecord{};
    try std.testing.expectError(error.PermissionDenied, port.createWorkspace(.{
        .task_id = 21,
        .principal = actor,
        .capability_id = writer.id,
        .now_ticks = 10,
        .operation = "storage-create-workspace",
        .trace = &scope_trace,
    }, .{
        .owner = actor,
        .label = "denied-task",
    }));
    try std.testing.expectEqual(debug_contract.Decision.denied, scope_trace.decision);
    try std.testing.expectEqualStrings("task-scope-policy", scope_trace.denial.blockingPolicySlice());
}

test "storage port derives shared workspace capabilities and blocks unauthorized reshares" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 49 };
    const owner_user = principal.PrincipalId{ .kind = .user, .serial = 40 };
    const team = principal.PrincipalId{ .kind = .team, .serial = 41 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 42 };
    const viewer = principal.PrincipalId{ .kind = .app, .serial = 43 };
    const device = principal.PrincipalId{ .kind = .device, .serial = 44 };
    var core = StorageCore.initWithStore(704, 30, storage_owner, &checkpoint_store);
    var capabilities = capability.CapabilityTable.init();
    var port = StoragePort.init(&core, &capabilities);

    const service_writer = try capabilities.mintBootRoot(.{
        .holder = storage_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = core.service_id },
        .rights = .{ .service = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = 30, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const storage_authority = AuthorityContext{
        .task_id = 30,
        .principal = storage_owner,
        .capability_id = service_writer.id,
        .now_ticks = 10,
    };
    const signer = signing.SignerIdentity{
        .label = "zigos-share-storage-key",
        .seed = [_]u8{0xB4} ** 32,
    };
    const object = try port.putVersion(storage_authority, .{
        .preferred_object_id = ids.object(954),
        .object_type = .document,
        .payload = "shared document",
        .metadata = try object_store.signMetadata(signer, "shared", "text/markdown", .document, "shared document", 10),
    });
    const notes = try port.createWorkspace(storage_authority, .{
        .owner = owner_user,
        .label = "shared-notes",
    });
    try port.beginTransaction(storage_authority, notes.id);
    try port.stagePut(storage_authority, notes.id, "documents/shared.md", object.object_id, object.version_id, .document);
    _ = try port.commit(storage_authority, notes.id);
    try std.testing.expectError(error.WorkspaceScopeViolation, port.shareWorkspace(storage_authority, notes.id, .{
        .principal_id = team,
        .can_read = true,
        .expires_at_ticks = 90,
        .network_scope = .trusted_overlay,
        .reshare_policy = .owner_only,
        .audit_visibility = .shared_participants,
    }));

    const owner_workspace_authority = try capabilities.mintBootRoot(.{
        .holder = owner_user,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .workspace, .id = notes.id.raw() },
        .rights = .{ .workspace = .{
            .object_read = true,
            .object_write = true,
            .capability_derive = true,
            .capability_query = true,
        } },
        .scope = .{ .workspace_id = notes.id.raw(), .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const owner_authority = AuthorityContext{
        .task_id = 31,
        .principal = owner_user,
        .capability_id = owner_workspace_authority.id,
        .now_ticks = 20,
    };

    const team_share = try port.grantWorkspaceShare(&capabilities, owner_authority, notes.id, .{
        .principal_id = team,
        .can_read = true,
        .can_write = false,
        .can_admin = false,
        .can_export = false,
        .expires_at_ticks = 90,
        .network_scope = .trusted_overlay,
        .reshare_policy = .owner_only,
        .audit_visibility = .shared_participants,
    });
    try std.testing.expect(team_share.grant.principal_id.eql(team));
    try std.testing.expectEqual(capability.CapabilityTargetKind.workspace, team_share.capability.target.kind);
    try std.testing.expectEqual(notes.id.raw(), team_share.capability.target.id);
    try std.testing.expect(team_share.capability.rights.has(.object_read));
    try std.testing.expect(!team_share.capability.rights.has(.object_write));
    try std.testing.expectEqual(core.service_id, team_share.capability.audit.broker_service_id);
    try std.testing.expectEqual(@as(u64, 31), team_share.capability.audit.source_task_id);

    const team_view = try port.resolve(.{
        .task_id = 41,
        .principal = team,
        .capability_id = team_share.capability.id,
        .now_ticks = 40,
    }, .{
        .workspace_id = notes.id.raw(),
        .path = "documents/shared.md",
        .access = .read,
    });
    try std.testing.expectEqual(object.object_id.raw(), team_view.object_id);
    try std.testing.expectEqualStrings("documents/shared.md", team_view.pathSlice());
    try std.testing.expectError(error.PermissionDenied, port.resolve(.{
        .task_id = 41,
        .principal = team,
        .capability_id = team_share.capability.id,
        .now_ticks = 40,
    }, .{
        .workspace_id = notes.id.raw(),
        .path = "documents/shared.md",
        .access = .write,
    }));

    const app_share = try port.grantWorkspaceShare(&capabilities, owner_authority, notes.id, .{
        .principal_id = app,
        .can_read = true,
        .can_write = true,
        .can_admin = true,
        .can_export = false,
        .expires_at_ticks = 80,
        .network_scope = .trusted_overlay,
        .reshare_policy = .admin_only,
        .audit_visibility = .shared_participants,
    });
    try std.testing.expect(app_share.capability.rights.has(.capability_derive));
    try std.testing.expectEqual(@as(u64, 80), app_share.capability.lease.expires_at_ticks);
    try std.testing.expectError(error.CapabilityRevoked, port.resolve(.{
        .task_id = 42,
        .principal = app,
        .capability_id = app_share.capability.id,
        .now_ticks = 81,
    }, .{
        .workspace_id = notes.id.raw(),
        .path = "documents/shared.md",
        .access = .read,
    }));

    const app_authority = AuthorityContext{
        .task_id = 42,
        .principal = app,
        .capability_id = app_share.capability.id,
        .now_ticks = 50,
    };
    try std.testing.expectError(error.PermissionDenied, port.grantWorkspaceShare(&capabilities, app_authority, notes.id, .{
        .principal_id = device,
        .can_read = true,
        .can_write = false,
        .can_admin = false,
        .can_export = true,
        .expires_at_ticks = 70,
        .network_scope = .trusted_overlay,
        .reshare_policy = .owner_only,
        .audit_visibility = .shared_participants,
    }));
    try std.testing.expectError(error.PermissionDenied, port.grantWorkspaceShare(&capabilities, app_authority, notes.id, .{
        .principal_id = device,
        .can_read = true,
        .can_write = false,
        .can_admin = false,
        .can_export = false,
        .expires_at_ticks = 70,
        .network_scope = .relay_assisted,
        .reshare_policy = .owner_only,
        .audit_visibility = .shared_participants,
    }));

    const device_share = try port.grantWorkspaceShare(&capabilities, app_authority, notes.id, .{
        .principal_id = device,
        .can_read = true,
        .can_write = false,
        .can_admin = false,
        .can_export = false,
        .expires_at_ticks = 70,
        .network_scope = .trusted_overlay,
        .reshare_policy = .owner_only,
        .audit_visibility = .shared_participants,
    });
    try std.testing.expect(core.workspaceHasAccess(notes.id, .{
        .principal_id = device,
        .network_scope = .trusted_overlay,
        .now_ticks = 60,
    }));
    try std.testing.expect(!core.workspaceHasAccess(notes.id, .{
        .principal_id = device,
        .network_scope = .trusted_overlay,
        .now_ticks = 71,
    }));
    try std.testing.expectEqual(@as(u64, 70), device_share.capability.lease.expires_at_ticks);
    try std.testing.expect(!device_share.capability.rights.has(.capability_derive));

    const viewer_share = try port.grantWorkspaceShare(&capabilities, owner_authority, notes.id, .{
        .principal_id = viewer,
        .can_read = true,
        .can_write = false,
        .can_admin = false,
        .can_export = false,
        .expires_at_ticks = 75,
        .network_scope = .trusted_overlay,
        .reshare_policy = .owner_only,
        .audit_visibility = .owner_only,
    });
    try std.testing.expectError(error.PermissionDenied, port.grantWorkspaceShare(&capabilities, .{
        .task_id = 43,
        .principal = viewer,
        .capability_id = viewer_share.capability.id,
        .now_ticks = 60,
    }, notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 45 },
        .can_read = true,
        .expires_at_ticks = 70,
        .network_scope = .trusted_overlay,
        .reshare_policy = .owner_only,
        .audit_visibility = .owner_only,
    }));
}

test "storage service enforces durable object-scoped workspace shares" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 149 };
    const owner_user = principal.PrincipalId{ .kind = .user, .serial = 140 };
    const viewer = principal.PrincipalId{ .kind = .app, .serial = 141 };
    var core = StorageCore.initWithStore(804, 130, storage_owner, &checkpoint_store);
    var capabilities = capability.CapabilityTable.init();
    var port = StoragePort.init(&core, &capabilities);

    const service_writer = try capabilities.mintBootRoot(.{
        .holder = storage_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = core.service_id },
        .rights = .{ .service = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = 130, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const storage_authority = AuthorityContext{
        .task_id = 130,
        .principal = storage_owner,
        .capability_id = service_writer.id,
        .now_ticks = 10,
    };
    const signer = signing.SignerIdentity{
        .label = "zigos-object-share-storage-key",
        .seed = [_]u8{0xC4} ** 32,
    };
    const shared = try port.putVersion(storage_authority, .{
        .preferred_object_id = ids.object(1_054),
        .object_type = .document,
        .payload = "shared document",
        .metadata = try object_store.signMetadata(signer, "shared", "text/markdown", .document, "shared document", 10),
    });
    const private = try port.putVersion(storage_authority, .{
        .preferred_object_id = ids.object(1_055),
        .object_type = .document,
        .payload = "private document",
        .metadata = try object_store.signMetadata(signer, "private", "text/markdown", .document, "private document", 11),
    });
    const notes = try port.createWorkspace(storage_authority, .{
        .owner = owner_user,
        .label = "object-shared-notes",
    });
    try port.beginTransaction(storage_authority, notes.id);
    try port.stagePut(storage_authority, notes.id, "documents/shared.md", shared.object_id, shared.version_id, .document);
    try port.stagePut(storage_authority, notes.id, "documents/private.md", private.object_id, private.version_id, .document);
    _ = try port.commit(storage_authority, notes.id);

    const owner_workspace_authority = try capabilities.mintBootRoot(.{
        .holder = owner_user,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .workspace, .id = notes.id.raw() },
        .rights = .{ .workspace = .{
            .object_read = true,
            .object_write = true,
            .capability_derive = true,
            .capability_query = true,
        } },
        .scope = .{ .workspace_id = notes.id.raw(), .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const owner_authority = AuthorityContext{
        .task_id = 131,
        .principal = owner_user,
        .capability_id = owner_workspace_authority.id,
        .now_ticks = 20,
    };
    const scoped_request = try (workspace.ShareGrant{
        .principal_id = viewer,
        .can_read = true,
        .network_scope = .local_only,
        .audit_visibility = .shared_participants,
    }).withObjectScope(shared.object_id, "documents/shared.md");
    const scoped_share = try port.grantWorkspaceShare(&capabilities, owner_authority, notes.id, scoped_request);
    try std.testing.expect(scoped_share.grant.isObjectScoped());
    try std.testing.expectEqual(shared.object_id, scoped_share.grant.scope_object_id);
    try std.testing.expectEqualStrings("documents/shared.md", scoped_share.grant.scopePathSlice());

    const viewer_authority = AuthorityContext{
        .task_id = 141,
        .principal = viewer,
        .capability_id = scoped_share.capability.id,
        .now_ticks = 30,
    };
    const shared_view = try port.resolve(viewer_authority, .{
        .workspace_id = notes.id.raw(),
        .path = "documents/shared.md",
        .access = .read,
    });
    try std.testing.expectEqual(shared.object_id.raw(), shared_view.object_id);
    try std.testing.expectError(error.PermissionDenied, port.resolve(viewer_authority, .{
        .workspace_id = notes.id.raw(),
        .path = "documents/private.md",
        .access = .read,
    }));
    try std.testing.expect(core.workspaceHasAccess(notes.id, .{
        .principal_id = viewer,
        .object_id = shared.object_id,
        .path = "documents/shared.md",
        .network_scope = .local_only,
        .now_ticks = 30,
    }));
    try std.testing.expect(!core.workspaceHasAccess(notes.id, .{
        .principal_id = viewer,
        .object_id = private.object_id,
        .path = "documents/private.md",
        .network_scope = .local_only,
        .now_ticks = 30,
    }));

    const reloaded = StorageCore.initWithStore(805, 132, storage_owner, &checkpoint_store);
    const restored = reloaded.findShareGrant(notes.id, viewer).?;
    try std.testing.expect(restored.isObjectScoped());
    try std.testing.expectEqual(shared.object_id, restored.scope_object_id);
    try std.testing.expectEqualStrings("documents/shared.md", restored.scopePathSlice());
}

test "storage port queries object history and grants object capabilities" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 151 };
    const owner_user = principal.PrincipalId{ .kind = .user, .serial = 151 };
    const reviewer = principal.PrincipalId{ .kind = .app, .serial = 152 };
    var core = StorageCore.initWithStore(806, 151, storage_owner, &checkpoint_store);
    var capabilities = capability.CapabilityTable.init();
    var port = StoragePort.init(&core, &capabilities);

    const service_writer = try capabilities.mintBootRoot(.{
        .holder = storage_owner,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .service, .id = core.service_id },
        .rights = .{ .service = .{ .object_read = true, .object_write = true } },
        .scope = .{ .task_id = 151, .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const storage_authority = AuthorityContext{
        .task_id = 151,
        .principal = storage_owner,
        .capability_id = service_writer.id,
        .now_ticks = 10,
    };
    const signer = signing.SignerIdentity{
        .label = "zigos-object-query-storage-key",
        .seed = [_]u8{0xC8} ** 32,
    };
    const first = try port.putVersion(storage_authority, .{
        .preferred_object_id = ids.object(1_060),
        .object_type = .document,
        .payload = "object draft v1",
        .metadata = try object_store.signMetadata(signer, "Object Draft", "text/markdown", .document, "object draft v1", 10),
    });
    const second = try port.putVersion(storage_authority, .{
        .preferred_object_id = ids.object(1_060),
        .object_type = .document,
        .payload = "object draft v2",
        .metadata = try object_store.signMetadata(signer, "Object Draft", "text/markdown", .document, "object draft v2", 11),
        .parent_version_id = first.version_id,
    });
    const workspace_record = try port.createWorkspace(storage_authority, .{
        .owner = owner_user,
        .label = "object-native",
    });
    try port.beginTransaction(storage_authority, workspace_record.id);
    try port.stagePut(storage_authority, workspace_record.id, "exports/object-draft.md", second.object_id, second.version_id, .document);
    _ = try port.commit(storage_authority, workspace_record.id);

    var query_buffer: [object_store.MAX_OBJECT_QUERY_RESULTS]object_store.ObjectQueryResult = undefined;
    const query_results = try port.queryObjects(storage_authority, .{
        .object_type = .document,
        .label_contains = "draft",
    }, &query_buffer);
    try std.testing.expectEqual(@as(usize, 1), query_results.len);
    try std.testing.expectEqual(second.object_id, query_results[0].object_id);
    try std.testing.expectEqual(second.version_id, query_results[0].latest_version_id);
    try std.testing.expectEqualStrings("Object Draft", query_results[0].labelSlice());

    const owner_workspace_authority = try capabilities.mintBootRoot(.{
        .holder = owner_user,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .target = .{ .kind = .workspace, .id = workspace_record.id.raw() },
        .rights = .{ .workspace = .{
            .object_read = true,
            .object_write = true,
            .capability_derive = true,
            .capability_query = true,
        } },
        .scope = .{ .workspace_id = workspace_record.id.raw(), .broker_only = true },
        .lease = .{ .issued_at_ticks = 0, .expires_at_ticks = 100 },
        .audit = .{},
    });
    const object_share = try port.grantObjectShare(&capabilities, .{
        .task_id = 152,
        .principal = owner_user,
        .capability_id = owner_workspace_authority.id,
        .now_ticks = 20,
    }, workspace_record.id, second.object_id, .{
        .principal_id = reviewer,
        .can_read = true,
        .can_write = false,
        .can_export = false,
        .expires_at_ticks = 80,
        .network_scope = .local_only,
        .reshare_policy = .owner_only,
        .audit_visibility = .shared_participants,
    });
    try std.testing.expectEqual(capability.CapabilityTargetKind.object, object_share.capability.target.kind);
    try std.testing.expectEqual(second.object_id.raw(), object_share.capability.target.id);
    try std.testing.expect(object_share.capability.rights.has(.object_read));
    try std.testing.expect(!object_share.capability.rights.has(.object_write));
    try std.testing.expect(object_share.grant.isObjectScoped());
    var share_sheet_buffer: [360]u8 = undefined;
    const share_sheet = try humane_permissions.renderShareSheetToBuffer(
        &share_sheet_buffer,
        workspace_record.id.raw(),
        object_share.grant,
        30,
    );
    try std.testing.expect(std.mem.indexOf(u8, share_sheet, "one object (exports/object-draft.md)") != null);
    try std.testing.expect(std.mem.indexOf(u8, share_sheet, "recipient=app:152") != null);
    try std.testing.expect(std.mem.indexOf(u8, share_sheet, "this device only") != null);

    var history_buffer: [object_store.MAX_OBJECT_HISTORY_RESULTS]object_store.ObjectHistoryEntry = undefined;
    const history = try port.objectHistory(.{
        .task_id = 153,
        .principal = reviewer,
        .capability_id = object_share.capability.id,
        .now_ticks = 30,
    }, second.object_id, &history_buffer);
    try std.testing.expectEqual(@as(usize, 2), history.len);
    try std.testing.expectEqual(second.version_id, history[0].version_id);
    try std.testing.expectEqual(first.version_id, history[1].version_id);
    try std.testing.expectEqualStrings("Object Draft", history[0].labelSlice());
}

test "storage service accepts large object payloads through mapped shared memory transfer" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 48 };
    const producer_task_id = ids.task(200);
    const storage_task_id = ids.task(201);
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA8} ** 32,
    };

    var payload: [object_store.PAGE_SIZE_BYTES * 2 + 33]u8 = undefined;
    for (&payload, 0..) |*byte, index| {
        byte.* = @intCast((index * 17) & 0xFF);
    }

    var shared = shared_memory.Table.init();
    const transfer_object = try shared.create(producer_task_id, payload.len);
    try shared.map(transfer_object.id, producer_task_id);
    try shared.map(transfer_object.id, storage_task_id);

    var service = Service.initWithStore(704, storage_task_id.raw(), owner, &checkpoint_store);
    const request = object_store.PutRequest{
        .preferred_object_id = ids.object(954),
        .object_type = .media_asset,
        .payload = &.{},
        .metadata = try object_store.signMetadata(signer, "large", "application/octet-stream", .media_asset, &payload, 12),
    };
    const result = try service.putVersionFromSharedMemoryRef(&request, .{
        .table = &shared,
        .object_id = transfer_object.id,
        .producer_task_id = producer_task_id,
        .storage_task_id = storage_task_id,
        .bytes = &payload,
    });

    const loaded = try service.versionPayload(service.version(result.version_id).?);
    try std.testing.expectEqualSlices(u8, &payload, loaded);

    const consumer_task_id = ids.task(202);
    var read_buffer: [payload.len]u8 = undefined;
    const read_object = try shared.create(consumer_task_id, payload.len);
    try shared.map(read_object.id, consumer_task_id);
    try shared.map(read_object.id, storage_task_id);
    const read_summary = try service.versionPayloadIntoSharedMemory(service.version(result.version_id).?, .{
        .table = &shared,
        .object_id = read_object.id,
        .consumer_task_id = consumer_task_id,
        .storage_task_id = storage_task_id,
        .bytes = &read_buffer,
    });
    try std.testing.expectEqual(payload.len, read_summary.bytes_transferred);
    try std.testing.expectEqualSlices(u8, &payload, read_buffer[0..read_summary.bytes_transferred]);

    const wrong_size = payload[0 .. payload.len - 1];
    try std.testing.expectError(error.SharedMemorySizeMismatch, service.putVersionFromSharedMemoryRef(&request, .{
        .table = &shared,
        .object_id = transfer_object.id,
        .producer_task_id = producer_task_id,
        .storage_task_id = storage_task_id,
        .bytes = wrong_size,
    }));
}

test "storage service retains authoritative object and workspace state across restart" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 44 };
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA4} ** 32,
    };

    var first = Service.initWithStore(700, 17, owner, &checkpoint_store);
    const object = try first.putVersion(.{
        .preferred_object_id = ids.object(950),
        .object_type = .document,
        .payload = "workspace hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "workspace hello", 10),
    });
    const notes = try first.createWorkspace(.{
        .owner = .{ .kind = .user, .serial = 1 },
        .label = "notes",
    });
    try first.shareWorkspace(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 70 },
        .can_read = true,
        .can_write = true,
        .can_admin = true,
        .can_export = true,
        .expires_at_ticks = 90,
        .network_scope = .trusted_overlay,
        .reshare_policy = .admin_only,
        .audit_visibility = .shared_participants,
    });
    try first.beginTransaction(notes.id);
    try first.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try first.commit(notes.id, 11);

    var restarted = Service.initWithStore(700, 18, owner, &checkpoint_store);
    const resolved = try restarted.resolve(notes.id, "documents/notes.md");
    const entries = try restarted.entries(notes.id);
    const grant = restarted.findShareGrant(notes.id, .{ .kind = .app, .serial = 70 }).?;
    try std.testing.expectEqual(object.object_id, resolved.object_id);
    try std.testing.expectEqual(object.version_id, resolved.version_id);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try std.testing.expectEqual(@as(?*object_store.Store, &checkpoint_store.store), restarted.store);
    try std.testing.expectEqual(@as(?*workspace.Directory, &checkpoint_store.workspaces), restarted.workspaces);
    try std.testing.expectEqual(workspace.ShareNetworkScope.trusted_overlay, grant.network_scope);
    try std.testing.expectEqual(workspace.ResharePolicy.admin_only, grant.reshare_policy);
    try std.testing.expectEqual(workspace.AuditVisibility.shared_participants, grant.audit_visibility);
    try std.testing.expect(restarted.workspaceHasAccess(notes.id, .{
        .principal_id = .{ .kind = .app, .serial = 70 },
        .wants_write = true,
        .wants_export = true,
        .wants_admin = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 50,
    }));
    try std.testing.expect(restarted.workspaceCanReshare(notes.id, .{ .kind = .app, .serial = 70 }, .trusted_overlay, 50));

    checkpoint_store.resetPersistent();
}

test "storage service reloads authoritative state from the attached volume after a cold start" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    var image = [_]u8{0} ** storage_volume.image_bytes;
    FakeStorageVolumeBackend.attach(&image);
    defer storage_volume.clearAttachedBackend();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 45 };
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA5} ** 32,
    };

    var first = Service.initWithStore(701, 17, owner, &checkpoint_store);
    const object = try first.putVersion(.{
        .preferred_object_id = ids.object(951),
        .object_type = .document,
        .payload = "cold-start hello",
        .metadata = try object_store.signMetadata(signer, "notes", "text/markdown", .document, "cold-start hello", 10),
    });
    const notes = try first.createWorkspace(.{
        .owner = .{ .kind = .user, .serial = 2 },
        .label = "cold-notes",
    });
    try first.shareWorkspace(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .can_read = true,
        .can_write = false,
        .can_export = true,
        .expires_at_ticks = 80,
        .network_scope = .relay_assisted,
        .reshare_policy = .owner_only,
        .audit_visibility = .organization_policy,
    });
    try first.beginTransaction(notes.id);
    try first.stagePut(notes.id, "documents/notes.md", object.object_id, object.version_id, .document);
    _ = try first.commit(notes.id, 11);

    checkpoint_store.resetPreparedState();

    var reloaded = Service.initWithStore(701, 18, owner, &checkpoint_store);
    const resolved = try reloaded.resolve(notes.id, "documents/notes.md");
    const grant = reloaded.findShareGrant(notes.id, .{ .kind = .device, .serial = 88 }).?;
    try std.testing.expect(reloaded.loaded_from_volume);
    try std.testing.expectEqual(object.object_id, resolved.object_id);
    try std.testing.expectEqual(object.version_id, resolved.version_id);
    try std.testing.expectEqual(workspace.ShareNetworkScope.relay_assisted, grant.network_scope);
    try std.testing.expectEqual(workspace.AuditVisibility.organization_policy, grant.audit_visibility);
    try std.testing.expect(reloaded.workspaceHasAccess(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .wants_export = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 40,
    }));
    try std.testing.expect(!reloaded.workspaceHasAccess(notes.id, .{
        .principal_id = .{ .kind = .device, .serial = 88 },
        .network_scope = .relay_assisted,
        .now_ticks = 120,
    }));
}

test "storage service coalesces checkpoint writes across an explicit batch" {
    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();

    var image = [_]u8{0} ** storage_volume.image_bytes;
    FakeStorageVolumeBackend.attach(&image);
    defer storage_volume.clearAttachedBackend();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 48 };
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA8} ** 32,
    };

    var service = Service.initWithStore(704, 21, owner, &checkpoint_store);
    service.beginCheckpointBatch();
    const object = try service.putVersion(.{
        .preferred_object_id = ids.object(954),
        .object_type = .document,
        .payload = "batched checkpoint",
        .metadata = try object_store.signMetadata(signer, "batched", "text/plain", .document, "batched checkpoint", 10),
    });
    const notes = try service.createWorkspace(.{
        .owner = .{ .kind = .user, .serial = 3 },
        .label = "batched-notes",
    });
    try service.beginTransaction(notes.id);
    try service.stagePut(notes.id, "documents/batched.md", object.object_id, object.version_id, .document);
    _ = try service.commit(notes.id, 11);

    try std.testing.expect(service.pendingCheckpointMutations());
    try std.testing.expectEqual(@as(u64, 0), checkpoint_store.last_checkpoint_generation);

    service.flushCheckpointBatch();
    try std.testing.expect(!service.pendingCheckpointMutations());
    try std.testing.expectEqual(@as(u64, 1), checkpoint_store.last_checkpoint_generation);

    checkpoint_store.resetPreparedState();
    var reloaded = Service.initWithStore(704, 22, owner, &checkpoint_store);
    try std.testing.expect(reloaded.loaded_from_volume);
    const resolved = try reloaded.resolve(notes.id, "documents/batched.md");
    try std.testing.expectEqual(object.version_id, resolved.version_id);
}

test "storage service records checkpoint flush failures" {
    const FailingBackend = struct {
        fn read(_: u64, _: [*]u8, _: usize) callconv(.c) bool {
            return false;
        }

        fn write(_: u64, _: [*]const u8, _: usize) callconv(.c) bool {
            return false;
        }
    };

    var checkpoint_store = CheckpointStore{};
    checkpoint_store.resetPersistent();
    defer checkpoint_store.resetPersistent();
    storage_volume.attachBackend(.{
        .sector_count = storage_volume.required_device_sectors,
        .read = FailingBackend.read,
        .write = FailingBackend.write,
    });
    defer storage_volume.clearAttachedBackend();

    var service = Service.initWithStore(702, 19, .{ .kind = .service, .serial = 46 }, &checkpoint_store);
    const signer = signing.SignerIdentity{
        .label = "zigos-storage-key",
        .seed = [_]u8{0xA6} ** 32,
    };
    _ = try service.putVersion(.{
        .preferred_object_id = ids.object(952),
        .object_type = .document,
        .payload = "checkpoint failure",
        .metadata = try object_store.signMetadata(signer, "failure", "text/plain", .document, "checkpoint failure", 10),
    });

    try std.testing.expect(checkpoint_store.dirty);
    try std.testing.expect(!checkpoint_store.checkpointHealthy());
    try std.testing.expectEqual(storage_volume.Error.CorruptImage, checkpoint_store.last_checkpoint_error.?);
}
