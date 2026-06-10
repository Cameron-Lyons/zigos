const std = @import("std");
const spec_support = @import("support.zig");
const accelerator_scheduler = @import("../../native/task/accelerator_scheduler.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const compositor_session = @import("../../native/platform/compositor_session.zig");
const manifest = @import("../../native/policy/manifest.zig");
const package_service = @import("../../native/services/package_service.zig");
const permission_review = @import("../../native/policy/permission_review.zig");
const policy_mediation = @import("../../native/policy/policy_mediation.zig");
const signing = @import("../../native/core/signing.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const workspace = @import("../../native/storage/workspace.zig");

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

fn signBundle(bundle: *manifest.BundleManifest, signer_identity: signing.SignerIdentity) !void {
    bundle.signature = try spec_support.signReleaseBundle(bundle.*, signer_identity);
}

pub fn permissionReviewsAndSharingStayScopedAndInspectable() !void {
    var runtime = task_runtime.Runtime.init();
    const reviewer = try runtime.createTask(.{
        .owner = spec_support.service(200),
        .component_class = .service_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "review-ui",
            .entry = "zigos.review.ui",
        },
    });
    const app_task = try runtime.createTask(.{
        .owner = spec_support.app(201),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .ui_surface_id = 12,
        .local_only = true,
        .initial_component = .{
            .label = "trip-planner",
            .entry = "app.trip",
        },
    });
    const peer_task = try runtime.createTask(.{
        .owner = spec_support.app(202),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .ui_surface_id = 13,
        .local_only = true,
        .initial_component = .{
            .label = "trip-companion",
            .entry = "app.trip.companion",
        },
    });

    try std.testing.expect(runtime.processSeparated(app_task.id, peer_task.id));
    try std.testing.expectEqual(task_runtime.ProcessClass.app_sandbox, app_task.process_class);
    try std.testing.expectEqual(task_runtime.NamespaceClass.app_private, app_task.namespace_class);

    const requests = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://trip/documents/plan.md",
            .rights = .{ .object = .{
                .object_read = true,
                .object_write = true,
            } },
            .local_only = true,
            .max_lease_ticks = 400,
        },
        .{
            .kind = .network_egress,
            .resource = "https://api.example.com",
            .rights = .{ .network_policy = .{
                .network_remote = true,
            } },
            .required = false,
            .max_lease_ticks = 60,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.trip",
        .display_name = "Trip Planner",
        .publisher = "zigos.spec",
        .requested_permissions = &requests,
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-spec-trip",
        },
    };

    const decisions = [_]permission_review.ReviewDecision{
        permission_review.decisionFromCommand(
            requests[0],
            try permission_review.parseCommand("allow local lease=200"),
        ),
        permission_review.decisionFromCommand(
            requests[1],
            try permission_review.parseCommand("allow lease=30"),
        ),
    };

    var grants_buffer: [permission_review.MAX_REVIEW_DECISIONS]policy_mediation.UserGrant = undefined;
    const grants = permission_review.decisionsToGrants(&bundle, &decisions, 50, &grants_buffer);
    try std.testing.expectEqual(@as(usize, 2), grants.len);
    try std.testing.expect(grants[0].local_only);
    try std.testing.expectEqual(@as(?u64, 250), grants[0].expires_at_ticks);
    try std.testing.expectEqual(@as(?u64, 80), grants[1].expires_at_ticks);

    var review_session = permission_review.initSession(app_task.id, &bundle, &decisions);
    var summary_buffer: [2048]u8 = undefined;
    const rendered_summary = try permission_review.renderToBuffer(&summary_buffer, &review_session, &bundle);
    try expectContains(rendered_summary, "Permission review for Trip Planner [app.trip]");
    try expectContains(rendered_summary, "requested lease: 400 ticks");
    try expectContains(rendered_summary, "decision: allow local_only=yes lease=200 ticks");
    try expectContains(rendered_summary, "decision: allow local_only=no lease=30 ticks");

    var session = compositor_session.Session.init();
    const window = try session.beginPermissionReview(reviewer.id, app_task, bundle);
    try std.testing.expectEqual(compositor_session.ViewType.app_panel, window.view_type);

    var ui_buffer: [512]u8 = undefined;
    const rendered_window = try compositor_session.renderWindowToBuffer(&ui_buffer, window);
    try expectContains(rendered_window, "type=app_panel");
    try expectContains(rendered_window, "title=Trip Planner permission review");
    try expectContains(rendered_window, "bundle=app.trip");

    const object_item = try session.ensureReviewItem(window.id, bundle, requests[0]);
    const network_item = try session.ensureReviewItem(window.id, bundle, requests[1]);

    const rendered_object_item = try compositor_session.renderReviewItemToBuffer(&ui_buffer, window.id, object_item);
    try expectContains(rendered_object_item, "resource=workspace://trip/documents/plan.md");
    try expectContains(rendered_object_item, "why=Trip Planner needs access to local task objects");
    try expectContains(rendered_object_item, "object_scope=workspace://trip/documents/plan.md");
    try expectContains(rendered_object_item, "network_path=none");
    try expectContains(rendered_object_item, "requested_local_only=yes");
    try expectContains(rendered_object_item, "requested_lease=400");

    const rendered_network_item = try compositor_session.renderReviewItemToBuffer(&ui_buffer, window.id, network_item);
    try expectContains(rendered_network_item, "resource=https://api.example.com");
    try expectContains(rendered_network_item, "object_scope=none");
    try expectContains(rendered_network_item, "network_path=https://api.example.com");

    const decision_item = try session.recordDecision(window.id, requests[0], true, true, 200);
    const rendered_decision = try compositor_session.renderDecisionToBuffer(&ui_buffer, window.id, decision_item);
    try expectContains(rendered_decision, "decision=allow");
    try expectContains(rendered_decision, "decision_local_only=yes");
    try expectContains(rendered_decision, "decision_lease=200");

    var directory = workspace.Directory.init();
    const trip_workspace = try directory.create(.{
        .owner = spec_support.user(20),
        .label = "trip",
    });
    try directory.share(trip_workspace.id, .{
        .principal_id = app_task.owner,
        .can_read = true,
        .can_write = true,
        .can_admin = true,
        .can_export = true,
        .expires_at_ticks = 40,
        .network_scope = .relay_assisted,
        .reshare_policy = .grantee_allowed,
        .audit_visibility = .organization_policy,
    });

    const share_grant = directory.findShareGrant(trip_workspace.id, app_task.owner).?;
    try std.testing.expect(share_grant.can_read);
    try std.testing.expect(share_grant.can_write);
    try std.testing.expect(share_grant.can_admin);
    try std.testing.expect(share_grant.can_export);
    try std.testing.expectEqual(workspace.ShareNetworkScope.relay_assisted, share_grant.network_scope);
    try std.testing.expectEqual(workspace.ResharePolicy.grantee_allowed, share_grant.reshare_policy);
    try std.testing.expectEqual(workspace.AuditVisibility.organization_policy, share_grant.audit_visibility);
    try std.testing.expect(directory.hasAccess(trip_workspace.id, .{
        .principal_id = app_task.owner,
        .wants_write = true,
        .wants_export = true,
        .wants_admin = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 20,
    }));
    try std.testing.expect(!directory.hasAccess(trip_workspace.id, .{
        .principal_id = app_task.owner,
        .wants_write = true,
        .network_scope = .unrestricted,
        .now_ticks = 20,
    }));
    try std.testing.expect(directory.canReshare(trip_workspace.id, app_task.owner, .relay_assisted, 20));
    try std.testing.expect(!directory.hasAccess(trip_workspace.id, .{
        .principal_id = app_task.owner,
        .network_scope = .local_only,
        .now_ticks = 41,
    }));
}

pub fn taskViewsAndNativeComponentsStayExplicit() !void {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = spec_support.app(210),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .ui_surface_id = 21,
        .local_only = true,
        .initial_component = .{
            .label = "workbench",
            .entry = "app.workbench",
        },
    });

    var session = compositor_session.Session.init();
    const document_window = try session.openDocumentView(task, 91, "documents/brief.md");
    const workspace_window = try session.openWorkspaceView(task, 91, "project-brief");
    const fullscreen_window = try session.openTaskView(task, "Focus Mode");

    try std.testing.expectEqual(compositor_session.ViewType.document_view, document_window.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.workspace_view, workspace_window.view_type);
    try std.testing.expectEqual(compositor_session.ViewType.full_screen_task_view, fullscreen_window.view_type);

    var render_buffer: [512]u8 = undefined;
    const rendered_document = try compositor_session.renderWindowToBuffer(&render_buffer, document_window);
    try expectContains(rendered_document, "type=document_view");
    try expectContains(rendered_document, "workspace=91");
    try expectContains(rendered_document, "detail=documents/brief.md");

    const rendered_workspace = try compositor_session.renderWindowToBuffer(&render_buffer, workspace_window);
    try expectContains(rendered_workspace, "type=workspace_view");
    try expectContains(rendered_workspace, "workspace=91");
    try expectContains(rendered_workspace, "detail=project-brief");

    const rendered_fullscreen = try compositor_session.renderWindowToBuffer(&render_buffer, fullscreen_window);
    try expectContains(rendered_fullscreen, "type=full_screen_task_view");
    try expectContains(rendered_fullscreen, "title=Focus Mode");

    const renderer = try runtime.attachComponent(task.id, .{
        .substrate = .typed_component_abi,
        .label = "workbench-renderer",
        .entry = "app.workbench.renderer",
    }, 31);
    const indexer = try runtime.attachComponent(task.id, .{
        .substrate = .typed_component_abi,
        .label = "workbench-indexer",
        .entry = "app.workbench.indexer",
    }, 32);
    try std.testing.expectEqual(task_runtime.ExecutionSubstrate.typed_component_abi, renderer.substrate);
    try std.testing.expectEqual(task_runtime.ExecutionSubstrate.typed_component_abi, indexer.substrate);
    try std.testing.expectEqual(@as(usize, 3), task.execution_component_count);
}

pub fn thermalPowerAndAppUpdatesStayExplicit() !void {
    var scheduler = accelerator_scheduler.Controller.init();
    scheduler.configure(.{
        .thermal_pressure = .critical,
        .battery_saver = false,
        .privacy_mode = false,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });

    const interactive = scheduler.plan(.{
        .class = .foreground_interactive,
        .wants_gpu = true,
        .shared_memory_bytes = 4096,
    });
    try std.testing.expect(!interactive.delayed);
    try std.testing.expect(interactive.degraded);
    try std.testing.expectEqual(accelerator_scheduler.Engine.gpu, interactive.engine);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, interactive.reason);

    const batch = scheduler.plan(.{
        .class = .batch_compute,
        .wants_npu = true,
    });
    try std.testing.expect(batch.delayed);
    try std.testing.expect(batch.degraded);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.thermal_throttle, batch.reason);

    scheduler.configure(.{
        .thermal_pressure = .nominal,
        .battery_saver = true,
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });

    const media_export = scheduler.plan(.{
        .class = .media_export,
        .wants_media_engine = true,
        .shared_memory_bytes = 4096,
    });
    try std.testing.expect(!media_export.delayed);
    try std.testing.expect(media_export.degraded);
    try std.testing.expect(media_export.zero_copy_allowed);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, media_export.engine);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.battery_preserve, media_export.reason);

    const privacy_sensitive = scheduler.plan(.{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    });
    try std.testing.expect(privacy_sensitive.degraded);
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, privacy_sensitive.engine);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.privacy_mode, privacy_sensitive.reason);

    var packages = package_service.Service.init();
    packages.bind(8_200, spec_support.service(8_200));
    var package_capabilities = capability.CapabilityTable.init();
    const package_capability = try spec_support.serviceAuthority(&package_capabilities, packages.service_id, packages.owner, 8_201);
    var package_port = package_service.PackagePort.init(&packages, &package_capabilities);
    const package_authority = spec_support.serviceAuthorityContext(8_201, packages.owner, package_capability, 1);
    const signer_identity = spec_support.signer("spec.update.bundle", 0xA1);
    try spec_support.trustPackagePublisher(&package_port, package_authority, signer_identity, "Example Software");
    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "zigos.workspace.document" },
        .{ .name = "zigos.object.workspace" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "app.notes.ui" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object = .{
                .object_read = true,
                .object_write = true,
            } },
            .local_only = true,
        },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &components,
        .assets = &assets,
        .requested_permissions = &v1_permissions,
    };
    try signBundle(&v1, signer_identity);

    _ = try package_port.install(package_authority, .{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null);

    const v2_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object = .{
                .object_read = true,
                .object_write = true,
            } },
            .local_only = true,
        },
        .{
            .kind = .notification_post,
            .resource = "notifications://task",
            .rights = .{ .task = .{
                .notification_post = true,
            } },
            .required = false,
        },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_minor = 1,
        .provided_interfaces = interfaces[0..1],
        .consumed_interfaces = interfaces[1..2],
        .components = &components,
        .assets = &assets,
        .requested_permissions = &v2_permissions,
    };
    try signBundle(&v2, signer_identity);

    try std.testing.expectError(package_service.Error.PermissionChangeUndeclared, package_port.install(package_authority, .{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, null));

    const updated = try package_port.install(package_authority, .{
        .bundle = v2,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
        .declared_permission_change = true,
    }, null);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);

    var v3 = v2;
    v3.version_minor = 2;
    try signBundle(&v3, signer_identity);

    var hidden_schema_change = v2;
    hidden_schema_change.version_minor = 1;
    try signBundle(&hidden_schema_change, signer_identity);
    try std.testing.expectError(package_service.Error.SchemaChangeRequiresExplicitVersion, package_port.install(package_authority, .{
        .bundle = hidden_schema_change,
        .source_identity = "store:zigos",
        .data_schema_version = 2,
    }, null));

    const compatible = try package_port.install(package_authority, .{
        .bundle = v3,
        .source_identity = "store:zigos",
        .data_schema_version = 2,
    }, null);
    try std.testing.expect(compatible.updated_existing);
    try std.testing.expectEqual(@as(u32, 2), packages.find("app.notes").?.schemaVersion());

    _ = try package_port.rollback(package_authority, "app.notes");
    try std.testing.expectEqual(@as(u16, 1), packages.find("app.notes").?.versionMinor());
    try std.testing.expectEqual(@as(u32, 1), packages.find("app.notes").?.schemaVersion());
}
