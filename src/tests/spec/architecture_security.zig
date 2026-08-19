const std = @import("std");
const embedded_file = @import("../../native/task/embedded_file.zig");
const spec_support = @import("support.zig");
const abi = @import("../../native/core/abi.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const component_port = @import("../../native/kernel_api/component_port.zig");
const contract = @import("../../native/session/contract.zig");
const device_graph = @import("../../native/sync/device_graph.zig");
const device_inventory = @import("../../native/drivers/device_inventory.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const manifest = @import("../../native/policy/manifest.zig");
const kernel_descriptors = @import("../../native/kernel_api/native_kernel_descriptors.zig");
const generated_image_fixtures = @import("../../native/task/generated_image_fixtures.zig");
const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
const native_util = @import("../../native/core/util.zig");
const package_service = @import("../../native/services/package_service.zig");
const policy_mediation = @import("../../native/policy/policy_mediation.zig");
const policy_object = @import("../../native/policy/policy_object.zig");
const principal = @import("../../native/core/principal.zig");
const service_registry = @import("../../native/services/service_registry.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const syscall_abi = @import("../../native/kernel_api/syscall_abi.zig");
const syscall_surface = @import("../../native/kernel_api/syscall_surface.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const task_runtime_service = @import("../../native/task/task_runtime_service.zig");
const typed_component_abi = @import("../../native/services/typed_component_abi.zig");
const userspace_service_ipc = @import("../../native/services/userspace_service_ipc.zig");
const userspace_loader = @import("../../native/task/userspace_loader.zig");
const userspace_manifest_signing = @import("../../native/task/userspace_manifest_signing.zig");

pub fn designGoalsKeepInstallsDeclarativeAndAuthorityExplicit() !void {
    var runtime = task_runtime.Runtime.init();
    const task = try runtime.createTask(.{
        .owner = spec_support.app(41),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    try std.testing.expect(task.zero_ambient_authority);
    try std.testing.expectEqual(@as(usize, 0), task.capability_count);

    var policies = policy_object.Directory.init();
    const install_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 41,
        .issuer = spec_support.policyAuthority(41),
        .label = "trusted-installs",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{"store:zigos"},
    }, spec_support.signer("spec.design.policy", 0x16));

    const interfaces = [_]manifest.InterfaceDecl{
        .{ .name = "writer.edit/v1" },
    };
    const components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "writer-ui", .entry = "app.writer.ui" },
    };
    const assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    var bundle = manifest.BundleManifest{
        .bundle_id = "app.writer",
        .display_name = "Writer",
        .publisher = "zigos.spec",
        .provided_interfaces = &interfaces,
        .components = &components,
        .assets = &assets,
    };
    bundle.signature = try userspace_manifest_signing.signBundle(bundle);

    var packages = package_service.Service.init();
    packages.bind(8_100, spec_support.service(8_100));
    var package_capabilities = capability.CapabilityTable.init();
    const package_capability = try spec_support.serviceAuthority(&package_capabilities, packages.service_id, packages.owner, 8_101);
    var package_port = package_service.PackagePort.init(&packages, &package_capabilities);
    const package_authority = spec_support.serviceAuthorityContext(8_101, packages.owner, package_capability, 1);
    try spec_support.trustPackagePublisher(&package_port, package_authority, try userspace_manifest_signing.identityForPublisher(bundle.publisher), bundle.publisher);
    _ = try package_port.install(package_authority, .{
        .bundle = bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, install_policy);
    try std.testing.expectError(package_service.Error.InstallSourceDenied, package_port.install(package_authority, .{
        .bundle = bundle,
        .source_identity = "repo:opaque-script",
        .data_schema_version = 1,
    }, install_policy));

    const untyped_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "writer-bridge", .entry = "app.writer.bridge", .abi = .native_sandbox },
    };
    var untyped_bundle = bundle;
    untyped_bundle.bundle_id = "app.writer.bridge";
    untyped_bundle.display_name = "Writer Bridge";
    untyped_bundle.components = &untyped_components;
    untyped_bundle.signature = try userspace_manifest_signing.signBundle(untyped_bundle);
    try std.testing.expectError(error.UntypedApplicationComponent, package_port.install(package_authority, .{
        .bundle = untyped_bundle,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, install_policy));
}

pub fn explicitGrantsRequireAuthority() !void {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    var mediator = policy_mediation.PolicyMediator.init(
        spec_support.policyAuthority(1),
        &capability_table,
        &runtime,
        .{
            .network_service_id = 41,
            .compositor_service_id = 42,
            .policy_service_id = 43,
            .service_registry_id = 44,
        },
    );

    const bundle_requests = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://report-alpha/documents/report.md",
            .rights = .{ .object = .{
                .object_read = true,
                .object_write = true,
            } },
            .target_id = 9_001,
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{ .network_policy = .{
                .network_local = true,
            } },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
            .egress_intent = .{
                .kind = .sync_object,
                .object = "workspace://report-alpha/documents/report.md",
                .principal = "trusted-devices",
            },
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.report.writer",
        .display_name = "Report Writer",
        .publisher = "zigos.spec",
        .requested_permissions = &bundle_requests,
        .signature = .{
            .format = .ed25519,
            .signer = "zigos-spec-bundle",
        },
    };

    const denied_task = try runtime.createTask(.{
        .owner = spec_support.app(1),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    try std.testing.expect(denied_task.zero_ambient_authority);
    try std.testing.expectEqual(@as(usize, 0), denied_task.capability_count);

    const denied = try mediator.applyManifest(denied_task.id, bundle, &.{}, 10);
    try std.testing.expectEqual(@as(usize, 0), denied.granted_count);
    try std.testing.expectEqual(@as(usize, 2), denied.denied_count);
    try std.testing.expectEqual(@as(usize, 1), denied.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.suspended, denied_task.state);
    try std.testing.expectEqual(@as(usize, 0), denied_task.capability_count);

    const grants = [_]policy_mediation.UserGrant{
        .{
            .kind = .object_access,
            .resource = "workspace://report-alpha/documents/report.md",
            .allow = true,
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .allow = true,
            .local_only = true,
            .expires_at_ticks = 70,
        },
    };
    const granted_task = try runtime.createTask(.{
        .owner = spec_support.app(2),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    try std.testing.expect(granted_task.zero_ambient_authority);
    try std.testing.expectEqual(@as(usize, 0), granted_task.capability_count);

    const granted = try mediator.applyManifest(granted_task.id, bundle, &grants, 20);
    try std.testing.expectEqual(@as(usize, 2), granted.granted_count);
    try std.testing.expectEqual(@as(usize, 0), granted.required_denials);
    try std.testing.expectEqual(task_runtime.TaskState.active, granted_task.state);
    try std.testing.expectEqual(@as(usize, 2), granted_task.capability_count);

    const network_decision = granted.decisionForKind(.network_egress).?;
    try std.testing.expect(network_decision.allowed);
    try std.testing.expect(network_decision.local_only);
    try std.testing.expectEqual(@as(u64, 70), network_decision.expires_at_ticks);

    const network_capability = capability_table.query(network_decision.capability_id.?).?;
    try std.testing.expectEqual(granted_task.id, network_capability.scope.task_id.?);
    try std.testing.expect(network_capability.scope.local_only);
    try std.testing.expect(network_capability.scope.broker_only);
    try std.testing.expect(network_capability.rights.has(.network_local));
    try std.testing.expect(!network_capability.rights.has(.network_remote));
    try std.testing.expectEqual(capability.CapabilityTargetKind.network_policy, network_capability.target.kind);
    try std.testing.expectEqual(native_util.fnv1a64("lan.sync"), network_capability.target.id);
}

pub fn capabilityLatticePreservesSecurityInvariants() !void {
    try invariantNoRightsEscalationThroughDeriveOrPass();
    try invariantRevocationAlwaysWins();
    try invariantExpiredLeasesFailEverywhere();
    try invariantTaskScopedCapabilitiesCannotCrossTaskBoundaries();
    try invariantTargetKindsDisambiguateHashedIds();
}

pub fn kernelRemainsTypedAndNativeOnly() !void {
    var registry = service_registry.Service.initWithBootstrap(.{
        .task_id = 1,
        .endpoint_id = 1,
        .endpoint_capability_id = 1,
    });

    try std.testing.expectEqual(@as(usize, 7), contract.kernel_tcb.len);
    try std.testing.expectEqualStrings("ipc_transport", contract.tcbName(.ipc_transport));
    try std.testing.expectEqualStrings("iommu_dma_isolation_hooks", contract.tcbName(.iommu_dma_isolation_hooks));

    const runtime_descriptor = contract.serviceDescriptor(.task_runtime).?;
    const network = contract.serviceDescriptor(.network_stack).?;
    const storage = contract.serviceDescriptor(.storage_object).?;
    const compositor = contract.serviceDescriptor(.compositor_ui_session).?;
    const session = contract.serviceDescriptor(.session_manager).?;
    const registry_service = contract.serviceDescriptor(.service_registry).?;
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, runtime_descriptor.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, session.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, registry_service.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, network.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, storage.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, compositor.boundary);
    try std.testing.expect(runtime_descriptor.restartable);
    try std.testing.expect(session.restartable);
    try std.testing.expect(registry_service.restartable);
    try std.testing.expect(network.restartable);
    try std.testing.expect(storage.restartable);
    try std.testing.expect(compositor.restartable);
    try std.testing.expect(runtime_descriptor.isolation.namespace_isolated);
    try std.testing.expectEqual(contract.NetworkPrivilege.unrestricted_brokered, network.isolation.network);
    try std.testing.expectEqual(contract.StoragePrivilege.object_store_authority, storage.isolation.storage);
    try std.testing.expect(contract.allowsDriverClass(.network_stack, .network_adapter));
    try std.testing.expect(contract.allowsDriverClass(.storage_object, .storage_controller));
    try std.testing.expect(contract.allowsDriverClass(.compositor_ui_session, .usb_controller));
    try std.testing.expect(contract.allowsDriverClass(.compositor_ui_session, .graphics_adapter));
    try std.testing.expect(contract.allowsDriverClass(.compositor_ui_session, .input_device));
    try std.testing.expect(contract.allowsDriverClass(.compositor_ui_session, .compositor_policy));
    try std.testing.expect(contract.allowsDriverClass(.media_print_helpers, .audio_print_io));

    try std.testing.expect(abi.opcode(.task_create) >= 0x100);
    try std.testing.expect(abi.policyOpcode(.authorize_request) >= 0x200);
    try std.testing.expect(abi.reviewOpcode(.review_bundle) >= 0x240);
    try std.testing.expectEqual(@as(u16, 5), abi.ABI_VERSION);
    const storage_interface = typed_component_abi.interfaceForService(.storage_object);
    try registry.register(55, 7, 101, 201, storage_interface, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);
    const connection = try registry.connect(storage_interface);
    try std.testing.expectEqual(@as(u64, 55), connection.service_id);
    try std.testing.expectEqual(@as(u64, 101), connection.endpoint_id);
    try std.testing.expectEqual(@as(u16, @intFromEnum(typed_component_abi.interfaceIdForService(.storage_object))), connection.interface_id);
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expectError(service_registry.Error.VersionMismatch, registry.connect(.{
        .name = storage_interface.name,
        .version_major = 2,
        .version_minor = 0,
    }));

    const network_rights = driver_service.allowedRightsFor(.network_adapter);
    const usb_rights = driver_service.allowedRightsFor(.usb_controller);
    const audio_rights = driver_service.allowedRightsFor(.audio_print_io);
    const input_rights = driver_service.allowedRightsFor(.input_device);
    const compositor_policy_rights = driver_service.allowedRightsFor(.compositor_policy);
    try std.testing.expect(network_rights.has(.device_use));
    try std.testing.expect(network_rights.has(.network_local));
    try std.testing.expect(!network_rights.has(.network_remote));
    try std.testing.expect(usb_rights.has(.device_use));
    try std.testing.expect(!usb_rights.has(.network_local));
    try std.testing.expect(!usb_rights.has(.object_write));
    try std.testing.expect(audio_rights.has(.device_use));
    try std.testing.expect(!audio_rights.has(.network_local));
    try std.testing.expect(!audio_rights.has(.object_write));
    try std.testing.expect(input_rights.has(.device_use));
    try std.testing.expect(!input_rights.has(.network_local));
    try std.testing.expect(!input_rights.has(.object_write));
    try std.testing.expect(compositor_policy_rights.has(.device_use));
    try std.testing.expect(!compositor_policy_rights.has(.network_local));
    try std.testing.expect(!compositor_policy_rights.has(.object_write));

    device_inventory.reset();
    device_inventory.registerDetected(.storage_controller, 0x8086_9A0B_0001, .nvme_pci_inventory, false);
    device_inventory.registerDetected(.network_adapter, 0x8086_15F2_0001, .intel_i225_lm_inventory, false);
    device_inventory.registerDetected(.usb_controller, 0x8086A0ED0001, .xhci_inventory, false);
    device_inventory.registerDetected(.input_device, 0x8086A0ED0001, .xhci_inventory, false);
    const storage_handoff = device_inventory.recordForClass(.storage_controller);
    const network_handoff = device_inventory.recordForClass(.network_adapter);
    const usb_handoff = device_inventory.recordForClass(.usb_controller);
    const input_handoff = device_inventory.recordForClass(.input_device);
    try std.testing.expect(storage_handoff.detected);
    try std.testing.expect(!storage_handoff.kernel_bootstrap);
    try std.testing.expectEqualStrings("nvme_pci_inventory", device_inventory.sourceName(storage_handoff.source));
    try std.testing.expect(network_handoff.detected);
    try std.testing.expect(!network_handoff.kernel_bootstrap);
    try std.testing.expectEqualStrings("intel_i225_lm_inventory", device_inventory.sourceName(network_handoff.source));
    try std.testing.expect(usb_handoff.detected);
    try std.testing.expect(!usb_handoff.kernel_bootstrap);
    try std.testing.expectEqualStrings("xhci_inventory", device_inventory.sourceName(usb_handoff.source));
    try std.testing.expect(input_handoff.detected);
    try std.testing.expect(!input_handoff.kernel_bootstrap);
    try std.testing.expectEqualStrings("xhci_inventory", device_inventory.sourceName(input_handoff.source));

    var runtime_checkpoint_store = task_runtime_service.CheckpointStore{};
    var runtime = task_runtime.Runtime.init();
    var runtime_service_instance = task_runtime_service.Service.initWithStore(&runtime, &runtime_checkpoint_store);
    runtime_service_instance.bind(70, spec_support.service(70));
    _ = try runtime.createTask(.{
        .owner = spec_support.app(30),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "typed-launcher",
            .entry = "app.typed.launcher",
        },
    });
    try runtime_service_instance.checkpoint(12);
    _ = try runtime.createTask(.{
        .owner = spec_support.app(31),
        .component_class = .app_component,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "ephemeral-task",
            .entry = "app.ephemeral",
        },
    });
    try std.testing.expect(runtime_service_instance.restartFromCheckpoint(13));
    try std.testing.expectEqual(@as(u32, 1), runtime_service_instance.restart_generation);
    try std.testing.expect(runtime.find(2) == null);

    const typed_bundle = manifest.BundleManifest{
        .bundle_id = "app.accounting",
        .display_name = "Accounting",
        .publisher = "zigos.spec",
        .provided_interfaces = &.{.{ .name = "zigos.accounting.ledger" }},
        .components = &.{.{ .id = "accounting-ui", .entry = "app.accounting.ui" }},
        .assets = &.{.{ .path = "assets/accounting/icon.svg", .content_type = "image/svg+xml" }},
        .signature = .{
            .format = .ed25519,
            .signer = "zigos-spec-app",
        },
    };
    try manifest.validateApplicationPackaging(typed_bundle);
}

fn invariantNoRightsEscalationThroughDeriveOrPass() !void {
    const parent_rights = capability.CapabilityRights{ .service = .{
        .capability_derive = true,
        .capability_pass = true,
        .capability_query = true,
        .endpoint_send = true,
        .object_read = true,
        .network_local = true,
    } };
    const requested_rights = [_]capability.CapabilityRights{
        .{ .service = .{ .capability_query = true } },
        .{ .service = .{ .endpoint_send = true, .object_read = true } },
        .{ .service = .{ .network_local = true, .network_remote = true } },
        .{ .service = .{ .object_write = true } },
        .{ .service = .{ .task_terminate = true } },
    };

    for (requested_rights, 0..) |rights, index| {
        var table = capability.CapabilityTable.init();
        const parent = try table.mintBootRoot(.{
            .holder = spec_support.service(10),
            .issuer = spec_support.policyAuthority(1),
            .target = .{ .kind = .service, .id = 1_000 + index },
            .rights = parent_rights,
            .scope = .{ .task_id = 40, .workspace_id = 70, .local_only = true, .broker_only = true },
            .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 100, .renewable = true },
        });

        if (parent_rights.containsAll(rights)) {
            const derived = try table.derive(.{
                .parent_capability_id = parent.id,
                .holder = spec_support.app(20 + index),
                .rights = rights,
                .scope = parent.scope,
                .lease = .{ .issued_at_ticks = 11, .expires_at_ticks = 90, .renewable = false },
            });
            try std.testing.expect(parent.rights.containsAll(derived.rights));
        } else {
            try std.testing.expectError(error.RightsEscalation, table.derive(.{
                .parent_capability_id = parent.id,
                .holder = spec_support.app(20 + index),
                .rights = rights,
                .scope = parent.scope,
                .lease = .{ .issued_at_ticks = 11, .expires_at_ticks = 90, .renewable = false },
            }));
        }

        const passed = try table.pass(.{
            .capability_id = parent.id,
            .new_holder = spec_support.app(50 + index),
            .now_ticks = 20,
            .scope = parent.scope,
        });
        try std.testing.expectEqual(parent.rights.toBits(), passed.rights.toBits());
    }
}

fn invariantRevocationAlwaysWins() !void {
    const targets = [_]capability.CapabilityTarget{
        .{ .kind = .object, .id = 901 },
        .{ .kind = .network_policy, .id = 901 },
        .{ .kind = .device, .id = 901 },
    };

    for (targets, 0..) |target, index| {
        var table = capability.CapabilityTable.init();
        const parent_rights = switch (target.kind) {
            .object => capability.CapabilityRights{ .object = .{ .capability_derive = true, .capability_pass = true, .capability_query = true, .object_read = true } },
            .network_policy => capability.CapabilityRights{ .network_policy = .{ .capability_derive = true, .capability_pass = true, .capability_query = true, .network_local = true } },
            .device => capability.CapabilityRights{ .device = .{ .capability_derive = true, .capability_pass = true, .capability_query = true, .device_use = true, .network_local = true } },
            else => unreachable,
        };
        const parent = try table.mintBootRoot(.{
            .holder = spec_support.service(30 + index),
            .issuer = spec_support.policyAuthority(1),
            .target = target,
            .rights = parent_rights,
            .scope = .{ .task_id = 80 + index, .local_only = true, .broker_only = true },
            .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 1_000, .renewable = true },
        });
        const derived = try table.derive(.{
            .parent_capability_id = parent.id,
            .holder = spec_support.app(40 + index),
            .rights = capability.CapabilityRights.single(.capability_query).retarget(target.kind),
            .scope = parent.scope,
            .lease = .{ .issued_at_ticks = 2, .expires_at_ticks = 900, .renewable = false },
        });
        const passed = try table.pass(.{
            .capability_id = parent.id,
            .new_holder = spec_support.app(50 + index),
            .now_ticks = 3,
            .scope = parent.scope,
        });

        try table.revokeTargetAuthority(parent.id);
        try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(derived.id, 4));
        try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(passed.id, 4));
        try std.testing.expectError(error.CapabilityRevoked, table.pass(.{
            .capability_id = passed.id,
            .new_holder = spec_support.app(60 + index),
            .now_ticks = 4,
        }));
    }
}

fn invariantExpiredLeasesFailEverywhere() !void {
    var table = capability.CapabilityTable.init();
    const expiring = try table.mintBootRoot(.{
        .holder = spec_support.service(70),
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .service, .id = 700 },
        .rights = .{ .service = .{ .capability_derive = true, .capability_pass = true, .capability_query = true } },
        .scope = .{ .task_id = 700, .local_only = true },
        .lease = .{ .issued_at_ticks = 10, .expires_at_ticks = 20, .renewable = false },
    });

    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(expiring.id, 9));
    try std.testing.expectError(error.CapabilityRevoked, table.requireUsable(expiring.id, 21));
    try std.testing.expectError(error.CapabilityRevoked, table.derive(.{
        .parent_capability_id = expiring.id,
        .holder = spec_support.app(71),
        .rights = .{ .service = .{ .capability_query = true } },
        .scope = expiring.scope,
        .lease = .{ .issued_at_ticks = 21, .expires_at_ticks = 21, .renewable = false },
    }));
    try std.testing.expectError(error.CapabilityRevoked, table.pass(.{
        .capability_id = expiring.id,
        .new_holder = spec_support.app(72),
        .now_ticks = 21,
    }));
}

fn invariantTaskScopedCapabilitiesCannotCrossTaskBoundaries() !void {
    var table = capability.CapabilityTable.init();
    const parent = try table.mintBootRoot(.{
        .holder = spec_support.service(80),
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .endpoint, .id = 8080 },
        .rights = .{ .endpoint = .{ .capability_derive = true, .capability_pass = true, .endpoint_send = true } },
        .scope = .{ .task_id = 81, .local_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100, .renewable = false },
    });

    try std.testing.expectError(error.ScopeEscalation, table.derive(.{
        .parent_capability_id = parent.id,
        .holder = spec_support.app(82),
        .rights = .{ .endpoint = .{ .endpoint_send = true } },
        .scope = .{ .task_id = 82, .local_only = true },
        .lease = .{ .issued_at_ticks = 2, .expires_at_ticks = 90, .renewable = false },
    }));
    try std.testing.expectError(error.ScopeEscalation, table.pass(.{
        .capability_id = parent.id,
        .new_holder = spec_support.app(82),
        .now_ticks = 2,
        .scope = .{ .task_id = 82, .local_only = true },
    }));
}

fn invariantTargetKindsDisambiguateHashedIds() !void {
    const shared_id = native_util.fnv1a64("shared-target-id");
    var table = capability.CapabilityTable.init();
    const object_cap = try table.mintBootRoot(.{
        .holder = spec_support.app(90),
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .object, .id = shared_id },
        .rights = .{ .object = .{ .object_read = true } },
        .scope = .{ .task_id = 90, .local_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100, .renewable = false },
    });
    const network_cap = try table.mintBootRoot(.{
        .holder = spec_support.app(91),
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .network_policy, .id = shared_id },
        .rights = .{ .network_policy = .{ .network_local = true } },
        .scope = .{ .task_id = 91, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100, .renewable = false },
    });
    const device_cap = try table.mintBootRoot(.{
        .holder = spec_support.app(92),
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .device, .id = shared_id },
        .rights = .{ .device = .{ .device_use = true } },
        .scope = .{ .task_id = 92, .local_only = true, .broker_only = true },
        .lease = .{ .issued_at_ticks = 1, .expires_at_ticks = 100, .renewable = false },
    });

    try std.testing.expect(!object_cap.target.eql(network_cap.target));
    try std.testing.expect(!object_cap.target.eql(device_cap.target));
    try std.testing.expect(!network_cap.target.eql(device_cap.target));

    try table.revokeGrant(object_cap.id);
    try std.testing.expect(table.query(object_cap.id) == null);
    try std.testing.expectError(error.CapabilityNotFound, table.requireUsable(object_cap.id, 2));
    _ = try table.requireUsable(network_cap.id, 2);
    _ = try table.requireUsable(device_cap.id, 2);
}

pub fn kernelMediatedLaunchesCarryUserspaceProvenance() !void {
    try generated_image_fixtures.expectReaderRejectsInvalidGeneratedRecords();

    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = @import("../../native/kernel_api/endpoint.zig").Table.init();
    var shared = shared_memory.Table.init();
    var service_directory = service_registry.Service.initWithBootstrap(.{
        .task_id = 2,
        .endpoint_id = 99,
        .endpoint_capability_id = 100,
    });
    var kernel = native_kernel.Kernel.init(
        spec_support.policyAuthority(1),
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
    );
    var port = component_port.KernelPort.init(&kernel);

    const session_task = try runtime.createTask(.{
        .owner = spec_support.service(2),
        .component_class = .session_manager,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const authority = try capabilities.mintBootRoot(.{
        .holder = session_task.owner,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .service, .id = 99 },
        .rights = .{ .service = .{
            .task_create = true,
            .endpoint_create = true,
            .endpoint_connect = true,
            .capability_derive = true,
            .ipc_peer = true,
        } },
        .scope = .{ .local_only = true },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
            .renewable = true,
        },
    });
    try runtime.grantCapability(session_task.id, authority.id);

    try std.testing.expectError(native_kernel.Error.UserspaceLaunchRequired, port.taskCreate(.{
        .header = component_port.makeHeader(.task_create, 1, session_task.id),
        .authority_capability_id = authority.id,
        .request = .{
            .owner = spec_support.service(3),
            .component_class = .service_component,
            .budget = spec_support.defaultBudget(false),
            .local_only = true,
            .initial_component = .{
                .label = "unsigned-direct",
                .entry = "zigos.service.direct",
            },
        },
    }, 1));

    var catalog = userspace_loader.Catalog.init();
    var storage_bundle = manifest.BundleManifest{
        .bundle_id = "zigos.system.spec-storage",
        .display_name = "Spec Storage",
        .publisher = "zigos.spec",
        .components = &[_]manifest.ExecutionComponentDecl{
            .{ .id = "spec-storage", .entry = "zigos.object.spec-storage" },
        },
    };
    const image_bytes = userspace_loader.makeSyntheticElf32ForTest(0x4000_3000, 2, 2);
    storage_bundle.signature = try userspace_manifest_signing.signBundle(storage_bundle);
    _ = try catalog.registerEmbeddedArtifact(.{
        .bundle = storage_bundle,
        .component_class = .service_component,
        .initial_component = .{
            .label = "spec-storage",
            .entry = "zigos.object.spec-storage",
        },
        .role_tag = 0xC301,
        .heartbeat_increment = 3,
        .contract_flags = 0x11,
        .elf_file = embedded_file.File.fromBytes(&image_bytes),
    });
    try std.testing.expect(catalog.findByBundleId("zigos.system.spec-storage").?.embedsElf());

    const launched = try catalog.launchViaKernel(.{
        .port = &port,
        .authority_capability_id = authority.id,
        .controller_task_id = session_task.id,
        .correlation_id = 2,
        .now_ticks = 2,
    }, "zigos.system.spec-storage", .{
        .owner = spec_support.service(4),
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    try std.testing.expect(abi.taskFlagsHas(launched.flags, abi.TASK_FLAG_USERSPACE_PROCESS));
    try std.testing.expect(runtime.find(launched.task_id).?.hasLoadedExecutable());
    const launched_authority = try port.capabilityDerive(.{
        .header = component_port.makeHeader(.capability_derive, 3, session_task.id),
        .request = .{
            .parent_capability_id = authority.id,
            .holder = runtime.find(launched.task_id).?.owner,
            .rights = .{ .service = .{
                .endpoint_create = true,
                .endpoint_connect = true,
                .ipc_peer = true,
            } },
            .scope = .{
                .task_id = launched.task_id,
                .local_only = true,
            },
            .lease = .{
                .issued_at_ticks = 2,
                .expires_at_ticks = 100,
                .renewable = false,
            },
        },
    });

    const service_endpoint = try port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 4, launched.task_id),
        .authority_capability_id = launched_authority.capability_id,
        .owner_task_id = launched.task_id,
        .label = "zigos.object.spec-storage",
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, 3);
    const launched_record = runtime.find(launched.task_id).?;
    try service_directory.register(
        123,
        launched.task_id,
        service_endpoint.endpoint.endpoint_id,
        service_endpoint.capability_id,
        typed_component_abi.interfaceForService(.storage_object),
        kernel_descriptors.serviceBindingFlags(launched_record),
    );

    const connection = try service_directory.connect(typed_component_abi.interfaceForService(.storage_object));
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE));
}

pub fn modeledKernelClaimsHaveHardEnforcementProofs() !void {
    try mmuStyleAddressSpaceValidationRejectsCrossSpaceRanges();
    try componentAbiDeclarationsCoverEveryTypedOperation();
    try userspace_service_ipc.proveCoreServiceStartupProtocolsUseEndpointSyscalls();
}

fn mmuStyleAddressSpaceValidationRejectsCrossSpaceRanges() !void {
    var app_address_space = std.mem.zeroes(task_runtime.AddressSpaceRecord);
    app_address_space.id = 1;
    app_address_space.owner_task_id = 10;
    app_address_space.region_count = 2;
    app_address_space.regions[0] = .{
        .kind = .load_segment,
        .virtual_address = 0x20000,
        .size_bytes = 0x1000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .execute = true },
    };
    app_address_space.regions[1] = .{
        .kind = .stack,
        .virtual_address = 0x30000,
        .size_bytes = 0x1000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .write = true },
    };

    var peer_address_space = std.mem.zeroes(task_runtime.AddressSpaceRecord);
    peer_address_space.id = 2;
    peer_address_space.owner_task_id = 11;
    peer_address_space.region_count = 1;
    peer_address_space.regions[0] = .{
        .kind = .load_segment,
        .virtual_address = 0x40000,
        .size_bytes = 0x1000,
        .file_offset = 0,
        .file_size = 0,
        .access = .{ .read = true, .write = true },
    };

    try std.testing.expect(syscall_surface.validateAddressSpaceRange(&app_address_space, 0x20020, 0x20080, .read));
    try std.testing.expect(!syscall_surface.validateAddressSpaceRange(&app_address_space, 0x20020, 0x20080, .write));
    try std.testing.expect(syscall_surface.validateAddressSpaceRange(&app_address_space, 0x30020, 0x30080, .write));
    try std.testing.expect(!syscall_surface.validateAddressSpaceRange(&app_address_space, 0x20FF0, 0x30020, .read));
    try std.testing.expect(!syscall_surface.validateAddressSpaceRange(&app_address_space, 0x40020, 0x40080, .read));
    try std.testing.expect(syscall_surface.validateAddressSpaceRange(&peer_address_space, 0x40020, 0x40080, .write));
}

fn componentAbiDeclarationsCoverEveryTypedOperation() !void {
    try std.testing.expectEqual(std.meta.fields(abi.NativeOperation).len, syscall_abi.operations.len);

    inline for (std.meta.fields(abi.NativeOperation)) |field| {
        const operation: abi.NativeOperation = @enumFromInt(field.value);
        const declaration = syscall_abi.declarationFor(operation);
        try std.testing.expectEqual(operation, declaration.operation);
        try std.testing.expect(declaration.requestSize() >= @sizeOf(abi.RequestHeader));
        if (declaration.responseSize() != 0) {
            try std.testing.expect(declaration.responseSize() >= @sizeOf(u8));
        }
    }

    try std.testing.expectEqual(syscall_abi.Domain.task, syscall_abi.declarationFor(.task_create).domain);
    try std.testing.expectEqual(syscall_abi.Domain.endpoint, syscall_abi.declarationFor(.endpoint_send).domain);
    try std.testing.expectEqual(syscall_abi.Domain.capability, syscall_abi.declarationFor(.capability_derive).domain);
    try std.testing.expectEqual(syscall_abi.Domain.shared_memory, syscall_abi.declarationFor(.shared_memory_map).domain);
    try std.testing.expectEqual(syscall_abi.Domain.device, syscall_abi.declarationFor(.device_describe).domain);
    try std.testing.expectEqual(syscall_abi.RequestCopyRule.embedded_user_buffers, syscall_abi.declarationFor(.task_create).request_copy);
    try std.testing.expectEqual(syscall_abi.RequestCopyRule.embedded_user_buffers, syscall_abi.declarationFor(.endpoint_send).request_copy);
    try std.testing.expectEqual(capability.CapabilityRight.task_create, syscall_abi.declarationFor(.task_create).required_right);
    try std.testing.expectEqual(capability.CapabilityRight.device_use, syscall_abi.declarationFor(.device_describe).required_right);
    try std.testing.expect(switch (syscall_abi.declarationFor(.shared_memory_map).target_kind) {
        .fixed => |kind| kind == .shared_memory,
        else => false,
    });
    try std.testing.expect(syscall_abi.declarationFor(.endpoint_create).scope_rule.task_scope_matches_request_task);
    try std.testing.expectEqual(@as(usize, 1), syscall_abi.declarationFor(.endpoint_create).auto_grants.len);
}

pub fn principalIdentityAndAdministrativeScopeStaySplit() !void {
    try std.testing.expect(std.meta.stringToEnum(principal.PrincipalKind, "root") == null);
    try std.testing.expect(std.meta.stringToEnum(principal.PrincipalKind, "admin") == null);

    var graph = device_graph.Graph.init();
    const person = spec_support.user(10);
    const laptop = spec_support.device(101);
    const phone = spec_support.device(102);
    const user_identity = spec_support.signer("spec.identity.user", 0xA1);
    const laptop_identity = spec_support.signer("spec.identity.laptop", 0xA2);
    const phone_identity = spec_support.signer("spec.identity.phone", 0xA3);

    const root = try graph.ensureUserRoot(person, "owner", user_identity);
    const laptop_record = try graph.enrollDevice(person, laptop, "laptop", user_identity, laptop_identity, 1);
    const phone_record = try graph.enrollDevice(person, phone, "phone", user_identity, phone_identity, 2);
    try std.testing.expect(root.root_signature.isComplete());
    try std.testing.expect(laptop_record.device_signature.isComplete());
    try std.testing.expect(laptop_record.enrollment_signature.isComplete());
    try std.testing.expect(phone_record.device_signature.isComplete());
    try std.testing.expect(phone_record.enrollment_signature.isComplete());
    try std.testing.expect(graph.overlayIdFor(laptop) != null);
    try std.testing.expect(graph.overlayIdFor(phone) != null);

    var policies = policy_object.Directory.init();
    const user_policy = try policies.create(.{
        .scope = .user,
        .subject_id = person.serial,
        .issuer = spec_support.policyAuthority(10),
        .label = "user-defaults",
        .network_egress_mode = .local_only,
    }, spec_support.signer("spec.policy.user", 0xA4));
    const device_policy = try policies.create(.{
        .scope = .device,
        .subject_id = laptop.serial,
        .issuer = spec_support.policyAuthority(11),
        .label = "device-hardening",
        .install_source_mode = .platform_store_only,
    }, spec_support.signer("spec.policy.device", 0xA5));
    const workspace_policy = try policies.create(.{
        .scope = .workspace,
        .subject_id = 500,
        .issuer = spec_support.policyAuthority(12),
        .label = "workspace-sharing",
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.spec.zigos"},
    }, spec_support.signer("spec.policy.workspace", 0xA6));
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = spec_support.policyAuthority(13),
        .label = "org-controls",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .audit_export_required = true,
    }, spec_support.signer("spec.policy.org", 0xA7));

    try std.testing.expect(policies.verify(user_policy.id));
    try std.testing.expect(policies.verify(device_policy.id));
    try std.testing.expect(policies.verify(workspace_policy.id));
    try std.testing.expect(policies.verify(org_policy.id));
    try std.testing.expectEqual(policy_object.Scope.user, policies.activeForScope(.user, person.serial).?.scope);
    try std.testing.expectEqual(policy_object.Scope.device, policies.activeForScope(.device, laptop.serial).?.scope);
    try std.testing.expectEqual(policy_object.Scope.workspace, policies.activeForScope(.workspace, 500).?.scope);
    try std.testing.expectEqual(policy_object.Scope.organization, policies.activeForScope(.organization, 77).?.scope);
    try std.testing.expectEqual(policy_object.NetworkEgressMode.local_only, user_policy.network_egress_mode);
    try std.testing.expect(device_policy.allowsInstallSource("store:zigos"));
    try std.testing.expect(!device_policy.allowsInstallSource("repo:unsigned"));
    try std.testing.expect(policies.syncDestinationAllowed(.workspace, 500, "relay.spec.zigos"));
    try std.testing.expect(!policies.syncDestinationAllowed(.workspace, 500, "relay.other"));
    try std.testing.expect(org_policy.audit_export_required);

    const subjects = policy_object.SubjectSet{
        .user_id = person.serial,
        .device_id = laptop.serial,
        .workspace_id = 500,
        .organization_id = 77,
    };
    const store_install = policies.installSourceDecision(subjects, "store:zigos");
    try std.testing.expect(store_install.allowed);
    const personal_install = policies.installSourceDecision(subjects, "repo:corp");
    try std.testing.expect(!personal_install.allowed);
    try std.testing.expectEqual(policy_object.DecisionReason.install_source_denied, personal_install.reason);
    try std.testing.expectEqual(policy_object.Scope.device, personal_install.blocking_scope.?);

    const relay_sync = policies.syncDestinationDecision(subjects, "relay.spec.zigos");
    try std.testing.expect(!relay_sync.allowed);
    try std.testing.expectEqual(policy_object.DecisionReason.sync_destination_denied, relay_sync.reason);
    try std.testing.expectEqual(policy_object.Scope.user, relay_sync.blocking_scope.?);

    const workspace_only = policy_object.SubjectSet{
        .workspace_id = 500,
        .organization_id = 77,
    };
    const workspace_relay = policies.syncDestinationDecision(workspace_only, "relay.spec.zigos");
    try std.testing.expect(workspace_relay.allowed);
    const other_sync = policies.syncDestinationDecision(workspace_only, "relay.other");
    try std.testing.expect(!other_sync.allowed);
    try std.testing.expectEqual(policy_object.Scope.workspace, other_sync.blocking_scope.?);
}
