const std = @import("std");
const spec_support = @import("support.zig");
const abi = @import("../../native/core/abi.zig");
const capability = @import("../../native/kernel_api/capability.zig");
const compatibility_environment = @import("../../native/services/compatibility_environment.zig");
const component_port = @import("../../native/kernel_api/component_port.zig");
const contract = @import("../../native/session/contract.zig");
const device_graph = @import("../../native/sync/device_graph.zig");
const device_inventory = @import("../../native/drivers/device_inventory.zig");
const driver_service = @import("../../native/drivers/driver_service.zig");
const manifest = @import("../../native/policy/manifest.zig");
const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
const policy_mediation = @import("../../native/policy/policy_mediation.zig");
const policy_object = @import("../../native/policy/policy_object.zig");
const principal = @import("../../native/core/principal.zig");
const service_registry = @import("../../native/kernel_api/service_registry.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const task_runtime = @import("../../native/task/task_runtime.zig");
const task_runtime_service = @import("../../native/task/task_runtime_service.zig");
const userspace_loader = @import("../../native/task/userspace_loader.zig");
const userspace_manifest_signing = @import("../../native/task/userspace_manifest_signing.zig");

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
            .rights = .{
                .object_read = true,
                .object_write = true,
            },
            .target_id = 9_001,
            .local_only = true,
        },
        .{
            .kind = .network_egress,
            .resource = "lan.sync",
            .rights = .{
                .network_local = true,
            },
            .required = false,
            .local_only = true,
            .max_lease_ticks = 50,
        },
    };
    const bundle = manifest.BundleManifest{
        .bundle_id = "app.report.writer",
        .display_name = "Report Writer",
        .publisher = "zigos.spec",
        .requested_permissions = &bundle_requests,
        .signature = .{
            .format = "ed25519",
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
    try std.testing.expect(network_capability.rights.network_local);
    try std.testing.expect(!network_capability.rights.network_remote);
    try std.testing.expectEqual(capability.CapabilityTargetKind.service, network_capability.target.kind);
    try std.testing.expectEqual(@as(u64, 41), network_capability.target.id);
}

pub fn kernelRemainsTypedAndIsolatesLegacy() !void {
    try std.testing.expectEqual(@as(usize, 7), contract.kernel_tcb.len);
    try std.testing.expectEqualStrings("ipc_transport", contract.tcbName(.ipc_transport));
    try std.testing.expectEqualStrings("iommu_dma_isolation_hooks", contract.tcbName(.iommu_dma_isolation_hooks));

    const runtime_descriptor = contract.serviceDescriptor(.task_runtime).?;
    const network = contract.serviceDescriptor(.network_stack).?;
    const storage = contract.serviceDescriptor(.storage_object).?;
    const compositor = contract.serviceDescriptor(.compositor_ui_session).?;
    const session = contract.serviceDescriptor(.session_manager).?;
    const registry_service = contract.serviceDescriptor(.service_registry).?;
    const compatibility_service = contract.serviceDescriptor(.compatibility_portal).?;
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, runtime_descriptor.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, session.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, registry_service.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, compatibility_service.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, network.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, storage.boundary);
    try std.testing.expectEqual(contract.ServiceBoundary.userspace_service, compositor.boundary);
    try std.testing.expect(runtime_descriptor.restartable);
    try std.testing.expect(session.restartable);
    try std.testing.expect(registry_service.restartable);
    try std.testing.expect(compatibility_service.restartable);
    try std.testing.expect(network.restartable);
    try std.testing.expect(storage.restartable);
    try std.testing.expect(compositor.restartable);
    try std.testing.expect(runtime_descriptor.isolation.namespace_isolated);
    try std.testing.expectEqual(contract.NetworkPrivilege.unrestricted_brokered, network.isolation.network);
    try std.testing.expectEqual(contract.StoragePrivilege.object_store_authority, storage.isolation.storage);
    try std.testing.expect(contract.allowsDriverClass(.network_stack, .network_adapter));
    try std.testing.expect(contract.allowsDriverClass(.storage_object, .storage_controller));

    try std.testing.expect(abi.opcode(.task_create) >= 0x100);
    try std.testing.expect(abi.policyOpcode(.authorize_request) >= 0x200);
    try std.testing.expect(abi.reviewOpcode(.review_bundle) >= 0x240);
    try std.testing.expectEqual(@as(u16, 1), abi.ABI_VERSION);

    var registry = service_registry.Registry.init();
    try registry.register(55, 7, 101, .{
        .name = "zigos.service.storage",
        .version_major = 1,
        .version_minor = 2,
    }, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);
    const connection = try registry.connect(.{
        .name = "zigos.service.storage",
        .version_major = 1,
        .version_minor = 1,
    });
    try std.testing.expectEqual(@as(u64, 55), connection.service_id);
    try std.testing.expectEqual(@as(u64, 101), connection.endpoint_id);
    try std.testing.expect(connection.interface_hash != 0);
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expectError(service_registry.Error.VersionMismatch, registry.connect(.{
        .name = "zigos.service.storage",
        .version_major = 2,
        .version_minor = 0,
    }));

    const network_rights = driver_service.allowedRightsFor(.network_adapter);
    const audio_rights = driver_service.allowedRightsFor(.audio_print_io);
    try std.testing.expect(network_rights.device_use);
    try std.testing.expect(network_rights.network_local);
    try std.testing.expect(!network_rights.network_remote);
    try std.testing.expect(audio_rights.device_use);
    try std.testing.expect(!audio_rights.network_local);
    try std.testing.expect(!audio_rights.object_write);

    device_inventory.reset();
    device_inventory.registerDetected(.storage_controller, 0x1F001, .ata_bootstrap, true);
    device_inventory.registerDetected(.network_adapter, 0x8086100E0001, .pci_inventory, false);
    const storage_handoff = device_inventory.recordForClass(.storage_controller);
    const network_handoff = device_inventory.recordForClass(.network_adapter);
    try std.testing.expect(storage_handoff.detected);
    try std.testing.expect(storage_handoff.kernel_bootstrap);
    try std.testing.expectEqualStrings("ata_bootstrap", device_inventory.sourceName(storage_handoff.source));
    try std.testing.expect(network_handoff.detected);
    try std.testing.expect(!network_handoff.kernel_bootstrap);
    try std.testing.expectEqualStrings("pci_inventory", device_inventory.sourceName(network_handoff.source));

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
            .label = "legacy-launcher",
            .entry = "app.legacy.launcher",
        },
    });
    runtime_service_instance.checkpoint(12);
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

    var compatibility_manager = compatibility_environment.Manager.init();
    const compatibility_bundle = manifest.BundleManifest{
        .bundle_id = "compat.legacy.accounting",
        .display_name = "Legacy Accounting",
        .publisher = "zigos.spec",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-spec-compat",
        },
    };
    const legacy_environment = try compatibility_manager.launch(.{
        .service_id = 88,
        .owner = spec_support.user(7),
        .kind = .remote_application_session,
        .label = "Legacy Accounting Remote Session",
        .bundle = compatibility_bundle,
        .network_class = .named_service_only,
    });
    try std.testing.expect(legacy_environment.isolated);
    try std.testing.expect(legacy_environment.clearly_labeled);
    try std.testing.expect(legacy_environment.portal_only_host_access);
    try std.testing.expect(legacy_environment.limited_host_integration);
    try compatibility_manager.grantPortal(legacy_environment.id, .{
        .kind = .file_import,
        .capability_id = 401,
        .read_only = true,
        .expires_at_ticks = 99,
    });
    try std.testing.expect(legacy_environment.hasPortal(.file_import));
    try std.testing.expectEqual(@as(usize, 1), compatibility_manager.environmentCount());
    try std.testing.expectError(compatibility_environment.Error.DirectHostAccessForbidden, compatibility_manager.launch(.{
        .service_id = 89,
        .owner = spec_support.user(7),
        .kind = .container,
        .label = "Uncontained Legacy Tool",
        .bundle = compatibility_bundle,
        .portal_only_host_access = false,
    }));
}

pub fn kernelMediatedLaunchesCarryUserspaceProvenance() !void {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = @import("../../native/kernel_api/endpoint.zig").Table.init();
    var shared = shared_memory.Table.init();
    var registry = service_registry.Registry.init();
    var kernel = native_kernel.Kernel.init(
        spec_support.policyAuthority(1),
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
        &registry,
    );
    var port = component_port.KernelPort.init(&kernel);

    const session_task = try runtime.createTask(.{
        .owner = spec_support.service(2),
        .component_class = .session_manager,
        .budget = spec_support.defaultBudget(false),
        .local_only = true,
    });
    const authority = try capabilities.mint(.{
        .holder = session_task.owner,
        .issuer = spec_support.policyAuthority(1),
        .target = .{ .kind = .service, .id = 99 },
        .rights = .{
            .task_create = true,
            .endpoint_create = true,
            .endpoint_connect = true,
            .capability_derive = true,
            .ipc_peer = true,
        },
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
    const image_bytes = userspace_loader.makeSyntheticElf32ForTest(0x403000, 2, 1);
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
        .elf_bytes = &image_bytes,
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
            .rights = .{
                .endpoint_create = true,
                .endpoint_connect = true,
                .ipc_peer = true,
            },
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
    try port.serviceRegister(.{
        .header = component_port.makeHeader(.service_register, 5, launched.task_id),
        .authority_capability_id = launched_authority.capability_id,
        .service_id = 123,
        .owner_task_id = launched.task_id,
        .endpoint_capability_id = service_endpoint.capability_id,
        .interface = .{ .name = "zigos.object.spec-storage" },
    }, 3);

    const connection = try registry.connect(.{ .name = "zigos.object.spec-storage" });
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE));
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
}
