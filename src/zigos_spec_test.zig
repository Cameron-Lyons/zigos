const std = @import("std");
const abi = @import("kernel/process/native/abi.zig");
const accelerator_scheduler = @import("kernel/process/native/accelerator_scheduler.zig");
const attestation_service = @import("kernel/process/native/attestation_service.zig");
const bootstrap_driver_port = @import("kernel/process/native/bootstrap_driver_port.zig");
const capability = @import("kernel/process/native/capability.zig");
const component_port = @import("kernel/process/native/component_port.zig");
const compatibility_environment = @import("kernel/process/native/compatibility_environment.zig");
const contract = @import("kernel/process/native/contract.zig");
const denial_explanation = @import("kernel/process/native/denial_explanation.zig");
const device_graph = @import("kernel/process/native/device_graph.zig");
const device_inventory = @import("kernel/process/native/device_inventory.zig");
const driver_runtime_mod = @import("kernel/process/native/driver_runtime.zig");
const driver_service = @import("kernel/process/native/driver_service.zig");
const endpoint = @import("kernel/process/native/endpoint.zig");
const event_ledger = @import("kernel/process/native/event_ledger.zig");
const file_bridge = @import("kernel/process/native/file_bridge.zig");
const immutable_base = @import("kernel/process/native/immutable_base.zig");
const indexing_service = @import("kernel/process/native/indexing_service.zig");
const manifest = @import("kernel/process/native/manifest.zig");
const media_print_service = @import("kernel/process/native/media_print_service.zig");
const measured_boot = @import("kernel/process/native/measured_boot.zig");
const native_kernel = @import("kernel/process/native/native_kernel.zig");
const native_ux = @import("kernel/process/native/native_ux.zig");
const network_policy = @import("kernel/process/native/network_policy.zig");
const notification_center = @import("kernel/process/native/notification_center.zig");
const object_store = @import("kernel/process/native/object_store.zig");
const package_service = @import("kernel/process/native/package_service.zig");
const policy_mediation = @import("kernel/process/native/policy_mediation.zig");
const policy_object = @import("kernel/process/native/policy_object.zig");
const principal = @import("kernel/process/native/principal.zig");
const recovery_environment = @import("kernel/process/native/recovery_environment.zig");
const secure_secret_store = @import("kernel/process/native/secure_secret_store.zig");
const service_registry = @import("kernel/process/native/service_registry.zig");
const shared_memory = @import("kernel/process/native/shared_memory.zig");
const signing = @import("kernel/process/native/signing.zig");
const storage_service = @import("kernel/process/native/storage_service.zig");
const storage_volume = @import("kernel/process/native/storage_volume.zig");
const supervisor = @import("kernel/process/native/supervisor.zig");
const sync_service = @import("kernel/process/native/sync_service.zig");
const task_runtime = @import("kernel/process/native/task_runtime.zig");
const task_runtime_service = @import("kernel/process/native/task_runtime_service.zig");
const userspace_loader = @import("kernel/process/native/userspace_loader.zig");
const workspace = @import("kernel/process/native/workspace.zig");

fn signer(label: []const u8, fill: u8) signing.SignerIdentity {
    return .{
        .label = label,
        .seed = [_]u8{fill} ** 32,
    };
}

fn user(serial: u64) principal.PrincipalId {
    return .{ .kind = .user, .serial = serial };
}

fn device(serial: u64) principal.PrincipalId {
    return .{ .kind = .device, .serial = serial };
}

fn app(serial: u64) principal.PrincipalId {
    return .{ .kind = .app, .serial = serial };
}

fn service(serial: u64) principal.PrincipalId {
    return .{ .kind = .service, .serial = serial };
}

fn policyAuthority(serial: u64) principal.PrincipalId {
    return .{ .kind = .policy_authority, .serial = serial };
}

fn driverAuthority(
    holder: principal.PrincipalId,
    capability_id: u64,
    task_id: u64,
    device_id: u64,
    device_class: driver_service.DeviceClass,
) capability.Capability {
    return .{
        .id = capability_id,
        .holder = holder,
        .issuer = policyAuthority(1),
        .target = driver_service.authorityTarget(device_id),
        .rights = driver_service.allowedRightsFor(device_class),
        .scope = .{
            .task_id = task_id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = std.math.maxInt(u64),
            .renewable = true,
        },
        .revocation_generation = 1,
        .audit = .{},
    };
}

fn defaultBudget(background_allowed: bool) task_runtime.ResourceBudget {
    return .{
        .cpu_time_ticks = 10_000,
        .memory_bytes = 256 * 1024,
        .endpoint_slots = 8,
        .shared_memory_bytes = 16 * 1024,
        .background_allowed = background_allowed,
    };
}

test "spec 2.1 6.2 and 7 explicit grants are required before a task gains authority" {
    var capability_table = capability.CapabilityTable.init();
    var runtime = task_runtime.Runtime.init();
    var mediator = policy_mediation.PolicyMediator.init(
        policyAuthority(1),
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
        .owner = app(1),
        .component_class = .app_component,
        .budget = defaultBudget(false),
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
        .owner = app(2),
        .component_class = .app_component,
        .budget = defaultBudget(false),
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

test "spec 4 6.3 13 and 17 keep the kernel typed minimal and route legacy support through isolated portals" {
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

    var runtime = task_runtime.Runtime.init();
    var runtime_service_instance = task_runtime_service.Service.init(&runtime);
    runtime_service_instance.bind(70, service(70));
    _ = try runtime.createTask(.{
        .owner = app(30),
        .component_class = .app_component,
        .budget = defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "legacy-launcher",
            .entry = "app.legacy.launcher",
        },
    });
    runtime_service_instance.checkpoint(12);
    _ = try runtime.createTask(.{
        .owner = app(31),
        .component_class = .app_component,
        .budget = defaultBudget(false),
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
        .owner = user(7),
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
        .owner = user(7),
        .kind = .container,
        .label = "Uncontained Legacy Tool",
        .bundle = compatibility_bundle,
        .portal_only_host_access = false,
    }));
}

test "spec 4 and 6.3 require kernel-mediated launches and typed services to carry userspace image provenance" {
    var runtime = task_runtime.Runtime.init();
    var capabilities = capability.CapabilityTable.init();
    var endpoints = endpoint.Table.init();
    var shared = shared_memory.Table.init();
    var registry = service_registry.Registry.init();
    var kernel = native_kernel.Kernel.init(
        policyAuthority(1),
        &runtime,
        &capabilities,
        &endpoints,
        &shared,
        &registry,
    );
    var port = component_port.KernelPort.init(&kernel);

    const session_task = try runtime.createTask(.{
        .owner = service(2),
        .component_class = .session_manager,
        .budget = defaultBudget(false),
        .local_only = true,
    });
    const authority = try capabilities.mint(.{
        .holder = session_task.owner,
        .issuer = policyAuthority(1),
        .target = .{ .kind = .service, .id = 99 },
        .rights = .{
            .task_create = true,
            .endpoint_create = true,
            .endpoint_connect = true,
            .ipc_peer = true,
        },
        .scope = .{ .local_only = true },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
            .renewable = true,
        },
    });

    try std.testing.expectError(native_kernel.Error.UserspaceLaunchRequired, port.taskCreate(.{
        .header = component_port.makeHeader(.task_create, 1, session_task.id),
        .authority_capability_id = authority.id,
        .request = .{
            .owner = service(3),
            .component_class = .service_component,
            .budget = defaultBudget(false),
            .local_only = true,
            .initial_component = .{
                .label = "unsigned-direct",
                .entry = "zigos.service.direct",
            },
        },
    }, 1));

    var catalog = userspace_loader.Catalog.init();
    _ = try catalog.register(.{
        .bundle = .{
            .bundle_id = "zigos.system.spec-storage",
            .display_name = "Spec Storage",
            .publisher = "zigos.spec",
            .signature = .{
                .format = "ed25519",
                .signer = "zigos-spec-key",
            },
        },
        .component_class = .service_component,
        .initial_component = .{
            .label = "spec-storage",
            .entry = "zigos.object.spec-storage",
        },
    });

    const launched = try catalog.launchViaKernel(.{
        .port = &port,
        .authority_capability_id = authority.id,
        .controller_task_id = session_task.id,
        .correlation_id = 2,
        .now_ticks = 2,
    }, "zigos.system.spec-storage", .{
        .owner = service(4),
        .budget = defaultBudget(false),
        .local_only = true,
    });
    try std.testing.expect(abi.taskFlagsHas(launched.flags, abi.TASK_FLAG_USERSPACE_PROCESS));

    const service_endpoint = try port.endpointCreate(.{
        .header = component_port.makeHeader(.endpoint_create, 3, launched.task_id),
        .authority_capability_id = authority.id,
        .owner_task_id = launched.task_id,
        .label = "zigos.object.spec-storage",
        .flags = .{
            .local_only = true,
            .service_port = true,
        },
    }, 3);
    try port.serviceRegister(.{
        .header = component_port.makeHeader(.service_register, 4, launched.task_id),
        .authority_capability_id = authority.id,
        .service_id = 123,
        .owner_task_id = launched.task_id,
        .endpoint_capability_id = service_endpoint.capability_id,
        .interface = .{ .name = "zigos.object.spec-storage" },
    }, 3);

    const connection = try registry.connect(.{ .name = "zigos.object.spec-storage" });
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE));
}

test "spec 4 and 13 activate published nic and storage transports through scoped driver services" {
    const FakeNetworkDevice = struct {
        var activation_count: usize = 0;

        fn send(_: []const u8) void {}

        fn getMacAddress() [6]u8 {
            return .{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
        }

        const published_device = bootstrap_driver_port.NetworkDevice{
            .send = send,
            .getMacAddress = getMacAddress,
        };

        fn activate(device_id: u64) ?*const bootstrap_driver_port.NetworkDevice {
            if (device_id != 0x8086_100E_0001) return null;
            activation_count += 1;
            return &published_device;
        }
    };
    const FakeBackend = struct {
        var image: []u8 = &.{};
        var activation_count: usize = 0;

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

        fn activate(device_id: u64) ?storage_volume.Backend {
            if (device_id != 0x0000_1F00_0001) return null;
            activation_count += 1;
            return .{
                .sector_count = storage_volume.required_device_sectors,
                .read = read,
                .write = write,
            };
        }
    };

    bootstrap_driver_port.reset();
    defer bootstrap_driver_port.reset();

    var image = [_]u8{0} ** storage_volume.image_bytes;
    FakeBackend.image = &image;

    const network_device_id: u64 = 0x8086_100E_0001;
    const storage_device_id: u64 = 0x0000_1F00_0001;
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.runtime",
        .display_name = "Published Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-spec-driver",
        },
    };

    try std.testing.expect(bootstrap_driver_port.publishNetworkActivator(
        network_device_id,
        "e1000",
        FakeNetworkDevice.activate,
        true,
    ));
    try std.testing.expect(bootstrap_driver_port.publishStorageActivator(
        storage_device_id,
        "ata-bootstrap",
        FakeBackend.activate,
        true,
    ));

    var directory = driver_service.Directory.init();
    const network_driver = try directory.register(.{
        .service_id = 91,
        .owner_task_id = 901,
        .device_id = network_device_id,
        .device_class = .network_adapter,
        .authority = driverAuthority(service(91), 501, 901, network_device_id, .network_adapter),
        .bundle = bundle,
    });
    const storage_driver = try directory.register(.{
        .service_id = 92,
        .owner_task_id = 902,
        .device_id = storage_device_id,
        .device_class = .storage_controller,
        .authority = driverAuthority(service(92), 502, 902, storage_device_id, .storage_controller),
        .bundle = bundle,
    });
    const graphics_driver = try directory.register(.{
        .service_id = 93,
        .owner_task_id = 903,
        .device_id = 0x1234_1111_0001,
        .device_class = .graphics_adapter,
        .authority = driverAuthority(service(93), 503, 903, 0x1234_1111_0001, .graphics_adapter),
        .bundle = bundle,
    });

    var runtime = driver_runtime_mod.Runtime.init();
    const network_activation = try runtime.activate(network_driver);
    const storage_activation = try runtime.activate(storage_driver);
    const graphics_activation = try runtime.activate(graphics_driver);

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, network_activation.mode);
    try std.testing.expect(network_activation.exclusive_claim);
    try std.testing.expect(network_activation.kernel_bootstrap);
    try std.testing.expectEqualStrings("e1000", network_activation.publisherSlice());
    try std.testing.expectEqual(@as(usize, 1), FakeNetworkDevice.activation_count);
    try std.testing.expect(bootstrap_driver_port.hasActiveNetworkDevice());
    try std.testing.expectEqual(@as(u64, 91), bootstrap_driver_port.networkPublication().?.active_service_id);
    try std.testing.expect(!bootstrap_driver_port.activateNetworkDevice(network_device_id, 999));
    try std.testing.expect(runtime.deactivate(network_driver.service_id));
    try std.testing.expect(!bootstrap_driver_port.hasActiveNetworkDevice());
    try std.testing.expect(bootstrap_driver_port.activateNetworkDevice(network_device_id, 999));
    try std.testing.expect(bootstrap_driver_port.deactivateNetworkDevice(999));

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.published_data_plane, storage_activation.mode);
    try std.testing.expect(storage_activation.exclusive_claim);
    try std.testing.expect(storage_activation.kernel_bootstrap);
    try std.testing.expectEqualStrings("ata-bootstrap", storage_activation.publisherSlice());
    try std.testing.expectEqual(@as(usize, 1), FakeBackend.activation_count);
    try std.testing.expect(storage_volume.hasAttachedDevice());
    try std.testing.expectEqual(@as(u64, 92), bootstrap_driver_port.storagePublication().?.active_service_id);

    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, graphics_activation.mode);
    try std.testing.expectEqualStrings("e1000", runtime.findByClass(.network_adapter).?.publisherSlice());
    try std.testing.expectEqualStrings("ata-bootstrap", runtime.findByClass(.storage_controller).?.publisherSlice());
    try std.testing.expectEqual(driver_runtime_mod.ActivationMode.control_only, runtime.findByClass(.graphics_adapter).?.mode);
}

test "spec 8 storage stays versioned recoverable signed and exposed through a derived file bridge" {
    storage_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();

    const storage_owner = service(20);
    const writer = user(2);
    const storage_signer = signer("spec.storage", 0x31);

    var storage = storage_service.Service.init(500, 50, storage_owner);
    const draft_v1 = try storage.putVersion(.{
        .preferred_object_id = 1_000,
        .object_type = .document,
        .payload = "report-v1",
        .metadata = try object_store.signMetadata(storage_signer, "report", "text/markdown", .document, "report-v1", 1),
    });
    const draft_v2 = try storage.putVersion(.{
        .preferred_object_id = 1_000,
        .object_type = .document,
        .payload = "report-v2",
        .metadata = try object_store.signMetadata(storage_signer, "report", "text/markdown", .document, "report-v2", 2),
        .parent_version_id = draft_v1.version_id,
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = writer,
        .label = "report-alpha",
    });

    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/report.md", draft_v1.object_id, draft_v1.version_id, .document);
    _ = try storage.commit(workspace_record.id, 3);
    const baseline = try storage.snapshot(workspace_record.id, "baseline", storage_signer);

    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/report.md", draft_v2.object_id, draft_v2.version_id, .document);
    _ = try storage.commit(workspace_record.id, 4);

    try storage.beginTransaction(workspace_record.id);
    try storage.stageDelete(workspace_record.id, "documents/report.md");
    _ = try storage.commit(workspace_record.id, 5);
    try std.testing.expect(try storage.recoverDeleted(workspace_record.id, "documents/report.md", 6));

    const recovered = try storage.resolve(workspace_record.id, "documents/report.md");
    try std.testing.expectEqual(draft_v2.object_id, recovered.object_id);
    try std.testing.expectEqual(draft_v2.version_id, recovered.version_id);
    try std.testing.expectEqual(@as(usize, 1), storage.store.objectCount());
    try std.testing.expectEqual(@as(usize, 2), storage.store.versionCount());

    const exported = try storage.exportSnapshot(workspace_record.id, baseline.id, storage_signer);
    const imported = try storage.importWorkspace(user(3), "report-import", exported, 7);
    const imported_entry = try storage.resolve(imported.id, "documents/report.md");
    try std.testing.expectEqual(draft_v1.version_id, imported_entry.version_id);

    const workspace_capability = capability.Capability{
        .id = 1,
        .holder = writer,
        .issuer = policyAuthority(1),
        .target = .{ .kind = .workspace, .id = workspace_record.id },
        .rights = .{
            .object_read = true,
            .object_write = true,
        },
        .scope = .{
            .task_id = 88,
            .workspace_id = workspace_record.id,
            .local_only = true,
            .broker_only = true,
        },
        .lease = .{
            .issued_at_ticks = 0,
            .expires_at_ticks = 100,
        },
        .revocation_generation = 1,
        .audit = .{},
    };
    const view = try storage.bridgeResolve(.{
        .workspace_id = workspace_record.id,
        .path = "/documents/report.md",
        .access = .read,
    }, workspace_capability, 8);
    try std.testing.expect(!view.authoritative);
    try std.testing.expect(view.readable);
    try std.testing.expect(view.writable);
    try std.testing.expectEqualStrings("documents/report.md", view.pathSlice());
    try std.testing.expectEqual(draft_v2.version_id, view.version_id);
}

test "spec 9 and 10 use a trusted device graph selective sync and policy-gated networking" {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = service(30);
    const sync_owner = service(31);
    const person = user(4);
    const laptop = device(41);
    const tablet = device(42);
    const storage_signer = signer("spec.sync.storage", 0x41);
    const user_signer = signer("spec.sync.user", 0x42);
    const laptop_signer = signer("spec.sync.laptop", 0x43);
    const tablet_signer = signer("spec.sync.tablet", 0x44);
    const contract_signer = signer("spec.sync.contract", 0x45);

    var storage = storage_service.Service.init(600, 60, storage_owner);
    const notes_v1 = try storage.putVersion(.{
        .preferred_object_id = 1_100,
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v1", 1),
    });
    const notes_v2 = try storage.putVersion(.{
        .preferred_object_id = 1_100,
        .object_type = .document,
        .payload = "notes-v2",
        .metadata = try object_store.signMetadata(storage_signer, "notes", "text/plain", .document, "notes-v2", 2),
        .parent_version_id = notes_v1.version_id,
    });
    const cover = try storage.putVersion(.{
        .preferred_object_id = 1_101,
        .object_type = .media_asset,
        .payload = "cover.jpg",
        .metadata = try object_store.signMetadata(storage_signer, "cover", "image/jpeg", .media_asset, "cover.jpg", 3),
    });
    const inbox = try storage.putVersion(.{
        .preferred_object_id = 1_102,
        .object_type = .collection,
        .payload = "inbox",
        .metadata = try object_store.signMetadata(storage_signer, "inbox", "application/zigos-collection", .collection, "inbox", 4),
    });
    const secret = try storage.putVersion(.{
        .preferred_object_id = 1_103,
        .object_type = .secret,
        .payload = "enc:top-secret",
        .metadata = try object_store.signMetadata(storage_signer, "secret", "application/zigos-secret", .secret, "enc:top-secret", 5),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "shared-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes_v1.object_id, notes_v1.version_id, .document);
    try storage.stagePut(workspace_record.id, "assets/cover.jpg", cover.object_id, cover.version_id, .media_asset);
    try storage.stagePut(workspace_record.id, "collections/inbox", inbox.object_id, inbox.version_id, .collection);
    _ = try storage.commit(workspace_record.id, 6);

    var sync = sync_service.Service.init(601, 61, sync_owner);
    _ = try sync.ensureUserRoot(person, "owner", user_signer);
    _ = try sync.enrollTrustedDevice(person, laptop, "laptop", user_signer, laptop_signer, 10);
    _ = try sync.enrollTrustedDevice(person, tablet, "tablet", user_signer, tablet_signer, 11);

    const local_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "local",
        .mode = .local_network,
    });
    const discovery_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "printer-discovery",
        .mode = .local_subnet_discovery,
        .target = "printer",
    });
    const relay_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "relay",
        .mode = .named_domain,
        .target = "relay.spec.zigos",
    });
    const overlay_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.spec",
    });
    const inbound_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "document-review",
        .mode = .inbound_collaborative_session,
        .target = "document-review/v1",
    });
    const collaborator = app(63);
    const prefixes = [_][]const u8{ "documents/", "assets/" };
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = person,
        .offline_first = true,
        .personal_e2ee = true,
        .selective_prefixes = &prefixes,
        .device_to_device_policy_id = local_policy.id,
        .relay_policy_id = relay_policy.id,
        .overlay_policy_id = overlay_policy.id,
        .relay_domain = "relay.spec.zigos",
    });
    _ = try sync.configureOverlay(workspace_record.id, laptop, "overlay.notes.spec", true);
    _ = try sync.publishPrivateService(workspace_record.id, "notes.remote");
    try storage.shareWorkspace(workspace_record.id, .{
        .principal_id = collaborator,
        .can_read = true,
        .can_write = true,
        .can_admin = true,
        .can_export = true,
        .expires_at_ticks = 40,
        .network_scope = .trusted_overlay,
        .reshare_policy = .admin_only,
        .audit_visibility = .shared_participants,
    });
    const share = storage.workspaces.findShareGrant(workspace_record.id, collaborator).?;
    try std.testing.expectEqual(workspace.ShareNetworkScope.trusted_overlay, share.network_scope);
    try std.testing.expectEqual(workspace.ResharePolicy.admin_only, share.reshare_policy);
    try std.testing.expectEqual(workspace.AuditVisibility.shared_participants, share.audit_visibility);
    try std.testing.expect(storage.workspaces.hasAccess(workspace_record.id, .{
        .principal_id = collaborator,
        .wants_write = true,
        .wants_export = true,
        .wants_admin = true,
        .network_scope = .trusted_overlay,
        .now_ticks = 20,
    }));
    try std.testing.expect(storage.workspaces.canReshare(workspace_record.id, collaborator, .trusted_overlay, 20));
    try std.testing.expect(!storage.workspaces.hasAccess(workspace_record.id, .{
        .principal_id = collaborator,
        .network_scope = .relay_assisted,
        .now_ticks = 50,
    }));

    try sync.setReplicaVersion(workspace_record.id, tablet, "documents/notes.md", notes_v1.object_id, notes_v2.version_id);
    const summary = try sync.replicateWorkspace(&storage, workspace_record.id, laptop, tablet, .device_to_device);
    try std.testing.expect(summary.offline_first);
    try std.testing.expect(summary.personal_e2ee);
    try std.testing.expect(summary.used_device_to_device);
    try std.testing.expect(summary.overlay_ready);
    try std.testing.expect(summary.remote_access_ready);
    try std.testing.expect(summary.private_service_published);
    try std.testing.expectEqual(@as(usize, 2), summary.selected_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.skipped_entry_count);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_count);
    try std.testing.expectEqual(@as(usize, 1), summary.snapshot_count);
    try std.testing.expectEqual(@as(usize, 1), summary.conflict_count);
    try std.testing.expect(sync.findConflict(workspace_record.id, tablet, "documents/notes.md") != null);
    try std.testing.expect(sync.isTrustedDevice(laptop));
    try std.testing.expect(sync.isTrustedDevice(tablet));
    try std.testing.expect(try sync.transferSecretObject(storage.store, workspace_record.id, secret.object_id, laptop, tablet, .device_to_device));

    const database_contract = try sync.registerDatabaseContract(workspace_record.id, "app.notes.db", "notes-db", contract_signer);
    try std.testing.expect(try sync.replicateDatabaseContract(database_contract.id, workspace_record.id, laptop, tablet, .relay_assisted));
    try std.testing.expect((try sync.evaluateNetworkPolicy(local_policy.id, .local_network)).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(discovery_policy.id, .{ .discovery_class = "printer" })).allowed);
    try std.testing.expect(!(try sync.evaluateNetworkPolicy(discovery_policy.id, .{ .discovery_class = "camera" })).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(relay_policy.id, .{ .domain = "relay.spec.zigos" })).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(overlay_policy.id, .{ .service_identity = "overlay.notes.spec" })).allowed);
    try std.testing.expect((try sync.evaluateNetworkPolicy(inbound_policy.id, .{ .inbound_session_type = "document-review/v1" })).allowed);
    try std.testing.expect(!(try sync.evaluateNetworkPolicy(inbound_policy.id, .{ .inbound_session_type = "pair-screen/v1" })).allowed);
}

test "spec 5 and 14 keep the base image signed measured atomic and rollback-capable" {
    storage_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();

    const owner = service(40);
    const state_signer = signer("spec.base.state", 0x51);
    const image_signer = signer("spec.base.image", 0x52);

    var storage = storage_service.Service.init(700, 70, owner);
    var manager = try immutable_base.Manager.init(&storage, owner, state_signer);

    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    const first_activation = try manager.activate(0, .{}, 11);
    try std.testing.expectEqual(@as(?usize, 0), first_activation.active_slot);
    try std.testing.expect(!first_activation.rolled_back);
    try std.testing.expect(manager.verifyActiveImage());

    _ = try manager.stageImage(1, "stable-b", "kernel=v2", image_signer, 12);
    const rollback = try manager.activate(1, .{
        .network_ok = false,
    }, 13);
    try std.testing.expect(rollback.rolled_back);
    try std.testing.expectEqual(immutable_base.HealthFailure.network, rollback.failure);
    try std.testing.expectEqual(@as(?usize, 0), rollback.active_slot);
    try std.testing.expectEqual(@as(u64, 1), rollback.rollback_generation);

    const active = manager.activeImage().?;
    try std.testing.expectEqualStrings("stable-a", active.labelSlice());
    try std.testing.expect(manager.verifySlot(0));
    try std.testing.expect(manager.verifySlot(1));

    var recorder = measured_boot.Recorder.init();
    recorder.begin(rollback.activation_generation);
    try recorder.add(.kernel, "kernel-zigos-native", "kernel=v1");
    try recorder.add(.base_image, active.labelSlice(), active.measurement[0..]);
    try recorder.add(.critical_service, "storage", "healthy");
    try recorder.add(.policy, "network-egress", "explicit-grants");
    try recorder.add(.driver_set, "signed-drivers", "network+storage+graphics");
    const boot = recorder.finalize();

    try std.testing.expectEqual(rollback.activation_generation, boot.generation);
    try std.testing.expectEqual(@as(usize, 5), boot.record_count);
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.kernel));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.base_image));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.critical_service));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.policy));
    try std.testing.expectEqual(@as(usize, 1), boot.countKind(.driver_set));
    try std.testing.expect(!std.mem.allEqual(u8, &boot.root_digest, 0));
}

test "spec 5.3 recovery mode can reinstall restore repair rotate and revoke" {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = service(50);
    const sync_owner = service(51);
    const person = user(5);
    const primary = device(51);
    const tablet = device(52);
    const state_signer = signer("spec.recovery.state", 0x61);
    const image_signer = signer("spec.recovery.image", 0x62);
    const object_signer = signer("spec.recovery.object", 0x63);
    const user_signer = signer("spec.recovery.user", 0x64);
    const primary_signer = signer("spec.recovery.primary", 0x65);
    const tablet_signer = signer("spec.recovery.tablet", 0x66);
    const rotated_tablet_signer = signer("spec.recovery.tablet.v2", 0x67);

    var storage = storage_service.Service.init(800, 80, storage_owner);
    var manager = try immutable_base.Manager.init(&storage, storage_owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    _ = try manager.activate(0, .{}, 11);

    const notes = try storage.putVersion(.{
        .preferred_object_id = 1_200,
        .object_type = .document,
        .payload = "incident-v1",
        .metadata = try object_store.signMetadata(object_signer, "incident", "text/plain", .document, "incident-v1", 12),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "incident",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/incident.md", notes.object_id, notes.version_id, .document);
    _ = try storage.commit(workspace_record.id, 13);
    const snapshot = try storage.snapshot(workspace_record.id, "clean", object_signer);

    var sync = sync_service.Service.init(801, 81, sync_owner);
    _ = try sync.ensureUserRoot(person, "owner", user_signer);
    _ = try sync.enrollTrustedDevice(person, primary, "primary", user_signer, primary_signer, 14);
    _ = try sync.enrollTrustedDevice(person, tablet, "tablet", user_signer, tablet_signer, 15);

    const local_policy = try sync.createNetworkPolicy(.{
        .owner = sync_owner,
        .workspace_id = workspace_record.id,
        .label = "local",
        .mode = .local_network,
    });
    _ = try sync.configureWorkspacePolicy(.{
        .workspace_id = workspace_record.id,
        .owner = person,
        .device_to_device_policy_id = local_policy.id,
    });
    try sync.setReplicaVersion(workspace_record.id, tablet, "documents/incident.md", notes.object_id, notes.version_id + 1);
    _ = try sync.replicateWorkspace(&storage, workspace_record.id, primary, tablet, .device_to_device);

    var recovery = recovery_environment.Environment.init(storage_owner);
    try std.testing.expect(try recovery.verifyAndReinstallImage(&manager, "kernel=v2", image_signer, 16));
    try std.testing.expect(try recovery.restoreWorkspaceSnapshot(&storage, workspace_record.id, snapshot.id, 17));
    try std.testing.expect(try recovery.repairSyncMetadata(&sync, &storage, workspace_record.id, tablet));
    try std.testing.expectEqual(@as(u32, 2), try recovery.rotateDeviceKeys(&sync, person, tablet, user_signer, rotated_tablet_signer, 18));
    try std.testing.expect(try recovery.revokeDeviceTrust(&sync, person, tablet, user_signer, 19));

    try std.testing.expect(recovery.report.image_verified);
    try std.testing.expect(recovery.report.image_reinstalled);
    try std.testing.expect(recovery.report.snapshot_restored);
    try std.testing.expect(recovery.report.sync_metadata_repaired);
    try std.testing.expect(recovery.report.device_keys_rotated);
    try std.testing.expect(recovery.report.device_trust_revoked);
    try std.testing.expect(!sync.isTrustedDevice(tablet));
}

test "spec 11 task-first UX records structured task workspace permission and pairing flows" {
    storage_service.Service.resetPersistentState();
    sync_service.Service.resetPersistentState();
    defer storage_service.Service.resetPersistentState();
    defer sync_service.Service.resetPersistentState();

    const storage_owner = service(60);
    const sync_owner = service(61);
    const person = user(6);
    const paired_device = device(61);
    const object_signer = signer("spec.ux.object", 0x71);
    const user_signer = signer("spec.ux.user", 0x72);
    const device_signer = signer("spec.ux.device", 0x73);

    var runtime = task_runtime.Runtime.init();
    var storage = storage_service.Service.init(900, 90, storage_owner);
    const document = try storage.putVersion(.{
        .preferred_object_id = 1_300,
        .object_type = .document,
        .payload = "trip-plan",
        .metadata = try object_store.signMetadata(object_signer, "trip", "text/plain", .document, "trip-plan", 10),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = person,
        .label = "trip",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/plan.md", document.object_id, document.version_id, .document);
    _ = try storage.commit(workspace_record.id, 11);

    var sync = sync_service.Service.init(901, 91, sync_owner);
    _ = try sync.ensureUserRoot(person, "owner", user_signer);

    var controller = native_ux.Controller.init();
    const task = try controller.startTask(&runtime, .{
        .owner = person,
        .component_class = .app_component,
        .budget = defaultBudget(false),
        .local_only = true,
        .initial_component = .{
            .label = "trip-planner",
            .entry = "app.trip",
        },
    });
    const opened = try controller.openWorkspace(&storage, workspace_record.id, "documents/plan.md", person);
    try controller.pairDevice(&sync, person, paired_device, "tablet", user_signer, device_signer, 12);
    try std.testing.expect(try controller.reviewPermissionRequest(task.id, person, .object_access, true));
    try controller.recoverSystem(task.id, person, "recovery-environment");

    try std.testing.expectEqual(@as(usize, 5), controller.flow_count);
    try std.testing.expectEqual(native_ux.FlowKind.start_task, controller.flows[0].kind);
    try std.testing.expectEqual(task.id, controller.flows[0].task_id);
    try std.testing.expectEqual(native_ux.FlowKind.open_workspace, controller.flows[1].kind);
    try std.testing.expectEqual(workspace_record.id, controller.flows[1].workspace_id);
    try std.testing.expectEqualStrings("documents/plan.md", controller.flows[1].detailSlice());
    try std.testing.expectEqual(document.version_id, opened.version_id);
    try std.testing.expectEqual(native_ux.FlowKind.pair_device, controller.flows[2].kind);
    try std.testing.expect(sync.isTrustedDevice(paired_device));
    try std.testing.expect(controller.flows[3].approved);
    try std.testing.expectEqual(native_ux.FlowKind.recover_system, controller.flows[4].kind);
    try std.testing.expectEqualStrings("recovery-environment", controller.flows[4].detailSlice());
}

test "spec 6.1 14.3 and 16 keep package lifecycle declarative signed and policy scoped" {
    var policies = policy_object.Directory.init();
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 1,
        .issuer = policyAuthority(7),
        .label = "org-defaults",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.corp.example"},
        .removable_storage_allowed = false,
        .screen_capture_allowed = false,
        .retention_days = 180,
        .audit_export_required = true,
    }, signer("spec.policy.org", 0x81));

    var packages = package_service.Service.init();
    const bundle_signer = signer("spec.bundle.notes", 0x82);

    const v1_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
    };
    const v1_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
    };
    const v1_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
    };
    var v1 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 0,
        .components = &v1_components,
        .assets = &v1_assets,
        .requested_permissions = &v1_permissions,
    };
    v1.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v1));

    const first = try packages.install(.{
        .bundle = v1,
        .source_identity = "store:zigos",
        .data_schema_version = 1,
    }, org_policy);
    try std.testing.expect(first.installed_new);
    try std.testing.expect(!first.rollback_available);
    try std.testing.expect(policies.installSourceAllowed(.organization, 1, "store:zigos"));
    try std.testing.expect(!policies.installSourceAllowed(.organization, 1, "repo:personal"));
    try std.testing.expect(policies.syncDestinationAllowed(.organization, 1, "relay.corp.example"));

    const v2_permissions = [_]manifest.PermissionRequest{
        .{
            .kind = .object_access,
            .resource = "workspace://notes",
            .rights = .{ .object_read = true, .object_write = true },
            .local_only = true,
        },
        .{
            .kind = .notification_post,
            .resource = "notifications://task",
            .rights = .{ .notification_post = true },
            .required = false,
        },
    };
    const v2_components = [_]manifest.ExecutionComponentDecl{
        .{ .id = "notes-ui", .entry = "zigos.notes.ui" },
        .{ .id = "notes-sync", .entry = "zigos.notes.sync", .abi = .native_sandbox },
    };
    const v2_assets = [_]manifest.AssetDecl{
        .{ .path = "assets/icon.svg", .content_type = "image/svg+xml" },
        .{ .path = "assets/editor.css", .content_type = "text/css" },
    };
    var v2 = manifest.BundleManifest{
        .bundle_id = "app.notes",
        .display_name = "Notes",
        .publisher = "Example Software",
        .version_major = 1,
        .version_minor = 1,
        .components = &v2_components,
        .assets = &v2_assets,
        .requested_permissions = &v2_permissions,
    };
    v2.signature = try signing.sign(bundle_signer, &package_service.digestBundle(v2));

    const updated = try packages.install(.{
        .bundle = v2,
        .source_identity = "repo:corp",
        .data_schema_version = 2,
        .migration_manifest = "notes-v2-migration",
        .declared_permission_change = true,
    }, org_policy);
    try std.testing.expect(updated.updated_existing);
    try std.testing.expect(updated.permissions_changed);
    try std.testing.expect(updated.rollback_available);

    const installed = packages.find("app.notes").?;
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_major);
    try std.testing.expectEqual(@as(u16, 1), installed.current_version_minor);
    try std.testing.expectEqual(@as(u32, 2), installed.current_schema_version);
    try std.testing.expectEqual(@as(usize, 2), installed.current_component_count);
    try std.testing.expectEqualStrings("zigos.notes.sync", installed.current_components[1].entrySlice());
    const launch_plan = try packages.buildLaunchPlan("app.notes");
    try std.testing.expectEqual(@as(usize, 2), launch_plan.component_count);
    try std.testing.expectEqual(@as(usize, 2), launch_plan.asset_count);
    try std.testing.expectEqualStrings("assets/editor.css", launch_plan.assets[1].pathSlice());
    try std.testing.expect(!org_policy.removable_storage_allowed);
    try std.testing.expect(!org_policy.screen_capture_allowed);
    try std.testing.expect(org_policy.audit_export_required);

    _ = try packages.rollback("app.notes");
    try std.testing.expectEqual(@as(u16, 0), packages.find("app.notes").?.current_version_minor);
    try std.testing.expectEqual(@as(usize, 1), packages.find("app.notes").?.current_component_count);
}

test "spec 2.3 11.4 12 and 15 keep indexing notifications media helpers and diagnostics structured" {
    var index = indexing_service.Service.init();
    try index.upsert(11, 500, 1, "Trip Draft", "alpha itinerary and booking checklist");
    try index.upsert(12, 600, 1, "Payroll", "alpha restricted finance details");

    var results_buffer: [indexing_service.MAX_RESULTS]indexing_service.SearchResult = undefined;
    const permitted = [_]u64{11};
    const results = index.query(&permitted, "alpha", &results_buffer);
    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(@as(u64, 500), results[0].object_id);

    var scheduler = accelerator_scheduler.Controller.init();
    var notifications = notification_center.Center.init();
    var media = media_print_service.Service.init();
    const source = app(70);

    const export_job = try media.submit(.{
        .kind = .media_export,
        .task_id = 501,
        .workspace_id = 11,
        .source_principal = source,
        .label = "render reel",
        .visibility = .task,
    }, &scheduler, &notifications, 20);
    const print_job = try media.submit(.{
        .kind = .print_document,
        .task_id = 502,
        .workspace_id = 11,
        .source_principal = source,
        .label = "print itinerary",
        .printer_identity = "printer://lobby",
        .visibility = .user,
    }, &scheduler, &notifications, 21);
    _ = try media.complete(export_job.id, &scheduler, &notifications, 30);
    _ = try media.complete(print_job.id, &scheduler, &notifications, 31);

    try std.testing.expectEqual(accelerator_scheduler.Engine.media, export_job.engine);
    try std.testing.expectEqual(media_print_service.JobState.completed, print_job.state);
    try std.testing.expectEqual(notification_center.Reason.print_complete, notifications.latestVisible(31).?.reason);
    try std.testing.expectEqual(@as(u16, 0), scheduler.activeClaimCount());

    var ledger = event_ledger.Ledger.init();
    try ledger.recordPermissionDecision(user(8), 503, .screen_capture, false, .policy_denied, 31, "screen capture blocked", true);
    try ledger.recordDriverRestart(contract.ServiceClass.media_print_helpers, service(71), 9, 32, "printer helper restart");
    try ledger.recordSyncConflict(user(8), 11, 33, "documents/itinerary.md conflict", true);
    var export_buffer: [1024]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "media_print_helpers") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "missing=screen-capture-capability") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "approval=yes") != null);
}

test "spec 5.2 7.5 and 12 keep attestation secrets and accelerator policy explicit" {
    var recorder = measured_boot.Recorder.init();
    recorder.begin(21);
    try recorder.add(.kernel, "kernel-zigos", "kernel=v3");
    try recorder.add(.base_image, "stable-b", "image=v3");
    try recorder.add(.critical_service, "storage", "healthy");
    try recorder.add(.policy, "org-defaults", "strict");
    try recorder.add(.driver_set, "signed-drivers", "gpu+npu+net");
    const boot = recorder.finalize();

    var attestation = attestation_service.Service.init(device(99));
    attestation.provisionRoot(signer("spec.attest.device", 0x91), .secure_enclave);
    const statement = try attestation.attestWithProvisionedRoot(boot, "attest.example", "nonce-7", true);
    try std.testing.expect(attestation_service.Service.verify(statement));
    try std.testing.expect(statement.user_visible);
    try std.testing.expectEqual(@as(usize, 1), attestation.visible_request_count);
    try std.testing.expect(!std.mem.allEqual(u8, &statement.root_digest, 0));
    try std.testing.expectEqual(attestation_service.KeyOrigin.secure_enclave, statement.key_origin);

    var secrets = secure_secret_store.Store.init();
    const imported = try secrets.importSecret(user(9), "signing-key", "opaque-secret", true, false);
    const handle = try secrets.lendHandle(imported.id, app(90), 700, true);
    try std.testing.expect(handle.hardware_backed);
    try std.testing.expect(!imported.resident_material);
    try std.testing.expect(imported.sealed_digest_present);
    try std.testing.expectError(secure_secret_store.Error.RawExportDenied, secrets.exportRaw(handle.id));

    var policy_directory = network_policy.Directory.init();
    const peer_policy = try policy_directory.create(.{
        .owner = service(99),
        .label = "notes-overlay",
        .mode = .named_service_identity,
        .target = "overlay.notes.sync",
        .require_remote_attestation = true,
        .pinned_root_digest = statement.root_digest,
    });
    try std.testing.expectEqual(network_policy.DecisionReason.attestation_required, (try policy_directory.authorizeConnection(peer_policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
    })).reason);
    const peer_decision = try policy_directory.authorizeConnection(peer_policy.id, .{
        .destination = .{ .service_identity = "overlay.notes.sync" },
        .attested = true,
        .peer_root_digest_present = true,
        .peer_root_digest = statement.root_digest,
    });
    try std.testing.expect(peer_decision.allowed);
    try std.testing.expect(peer_decision.identity_pinned);

    var scheduler = accelerator_scheduler.Controller.init();
    scheduler.configure(.{
        .privacy_mode = true,
        .gpu_available = true,
        .npu_available = true,
        .media_available = true,
    });
    const inference = scheduler.plan(.{
        .class = .background_light,
        .wants_npu = true,
        .privacy_sensitive = true,
    });
    const media_export_plan = scheduler.plan(.{
        .class = .media_export,
        .wants_gpu = true,
        .wants_media_engine = true,
        .shared_memory_bytes = 4096,
    });
    var runtime = task_runtime.Runtime.init();
    const foreground_task = try runtime.createTask(.{
        .owner = app(91),
        .component_class = .app_component,
        .budget = defaultBudget(false),
        .local_only = true,
    });
    var shared = shared_memory.Table.init();
    const zero_copy = try shared.createWithAccess(foreground_task.id, 4096, .{
        .media = true,
    });
    const engine_claim = try scheduler.claimWithSharedMemory(.{
        .task_id = foreground_task.id,
        .request = .{
            .class = .media_export,
            .wants_gpu = true,
            .wants_media_engine = true,
            .shared_memory_bytes = 4096,
        },
        .require_accelerator = true,
        .shared_memory_object_id = zero_copy.id,
    }, &shared);
    const background_task = try runtime.createTask(.{
        .owner = app(92),
        .component_class = .app_component,
        .budget = defaultBudget(true),
        .local_only = true,
    });
    const critical_task = try runtime.createTask(.{
        .owner = service(93),
        .component_class = .service_component,
        .budget = .{
            .cpu_time_ticks = 2_000,
            .memory_bytes = 128 * 1024,
            .endpoint_slots = 4,
            .shared_memory_bytes = 4 * 1024,
            .resource_class = .emergency_system_critical,
        },
        .local_only = true,
    });
    try std.testing.expectEqual(accelerator_scheduler.Engine.cpu, inference.engine);
    try std.testing.expectEqual(accelerator_scheduler.DecisionReason.privacy_mode, inference.reason);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, media_export_plan.engine);
    try std.testing.expect(media_export_plan.zero_copy_allowed);
    try std.testing.expectEqual(accelerator_scheduler.Engine.media, engine_claim.engine);
    try std.testing.expect(engine_claim.zero_copy);
    try std.testing.expect(try shared.isAcceleratorAttached(zero_copy.id, .media));
    try std.testing.expect(try scheduler.releaseClaim(engine_claim.id, &shared));
    try std.testing.expect(!(try shared.isAcceleratorAttached(zero_copy.id, .media)));
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.foreground_interactive, foreground_task.resourceClass());
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.background_light, background_task.resourceClass());
    try std.testing.expectEqual(accelerator_scheduler.ResourceClass.emergency_system_critical, critical_task.resourceClass());
}

test "spec 3 4.3 and 16 keep principal identity signed and administrative scope split" {
    try std.testing.expect(std.meta.stringToEnum(principal.PrincipalKind, "root") == null);
    try std.testing.expect(std.meta.stringToEnum(principal.PrincipalKind, "admin") == null);

    var graph = device_graph.Graph.init();
    const person = user(10);
    const laptop = device(101);
    const phone = device(102);
    const user_identity = signer("spec.identity.user", 0xA1);
    const laptop_identity = signer("spec.identity.laptop", 0xA2);
    const phone_identity = signer("spec.identity.phone", 0xA3);

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
        .issuer = policyAuthority(10),
        .label = "user-defaults",
        .network_egress_mode = .local_only,
    }, signer("spec.policy.user", 0xA4));
    const device_policy = try policies.create(.{
        .scope = .device,
        .subject_id = laptop.serial,
        .issuer = policyAuthority(11),
        .label = "device-hardening",
        .install_source_mode = .platform_store_only,
    }, signer("spec.policy.device", 0xA5));
    const workspace_policy = try policies.create(.{
        .scope = .workspace,
        .subject_id = 500,
        .issuer = policyAuthority(12),
        .label = "workspace-sharing",
        .network_egress_mode = .allow_list,
        .allowed_sync_destinations = &.{"relay.spec.zigos"},
    }, signer("spec.policy.workspace", 0xA6));
    const org_policy = try policies.create(.{
        .scope = .organization,
        .subject_id = 77,
        .issuer = policyAuthority(13),
        .label = "org-controls",
        .install_source_mode = .trusted_sources,
        .allowed_install_sources = &.{ "store:zigos", "repo:corp" },
        .audit_export_required = true,
    }, signer("spec.policy.org", 0xA7));

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

test "spec 13.3 15.2 and 15.3 keep failures explainable restartable and redacted" {
    const denied = denial_explanation.forPermissionDecision(.screen_capture, .policy_denied);
    var explanation_buffer: [256]u8 = undefined;
    const rendered = try denial_explanation.renderToBuffer(&explanation_buffer, denied);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "missing=screen-capture-capability") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "approval=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "retry_safe=no") != null);

    const FakeRuntime = struct {
        activation_count: usize = 0,
        last_service_id: u64 = 0,

        pub fn activate(self: *@This(), driver: *const driver_service.DriverRecord) !void {
            self.activation_count += 1;
            self.last_service_id = driver.service_id;
        }
    };

    var supervisor_instance = supervisor.Supervisor.init();
    const storage_record = try supervisor_instance.register(.storage_object, service(140));
    try std.testing.expect(supervisor_instance.markHealthy(storage_record.id, 1));

    var directory = driver_service.Directory.init();
    const bundle = manifest.BundleManifest{
        .bundle_id = "svc.driver.storage-runtime",
        .display_name = "Storage Driver Runtime",
        .publisher = "zigos.spec",
        .signature = .{
            .format = "ed25519",
            .signer = "zigos-spec-driver",
        },
    };
    const storage_driver = try directory.register(.{
        .service_id = storage_record.id,
        .owner_task_id = 1_401,
        .device_id = 0x0000_1F00_0002,
        .device_class = .storage_controller,
        .authority = driverAuthority(storage_record.owner, 801, 1_401, 0x0000_1F00_0002, .storage_controller),
        .bundle = bundle,
    });

    var runtime = FakeRuntime{};
    var notifications = notification_center.Center.init();
    var ledger = event_ledger.Ledger.init();
    try ledger.recordPermissionDecision(user(12), 700, .screen_capture, false, .policy_denied, 19, "screen capture blocked", true);
    const recovery = try supervisor_instance.recoverDriverCrash(
        storage_record.id,
        &directory,
        &runtime,
        &notifications,
        &ledger,
        20,
        0xDEAD,
        "",
    );

    try std.testing.expect(!recovery.visible_impact);
    try std.testing.expectEqual(@as(?u64, null), recovery.notification_id);
    try std.testing.expectEqual(@as(usize, 1), runtime.activation_count);
    try std.testing.expectEqual(storage_record.id, runtime.last_service_id);
    try std.testing.expectEqual(supervisor.ServiceState.healthy, storage_record.state);
    try std.testing.expectEqual(@as(u16, 1), storage_record.restart_count);
    try std.testing.expectEqual(@as(u32, 2), storage_driver.restart_generation);
    try std.testing.expect(notifications.latestVisible(30) == null);

    var export_buffer: [1024]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "service=storage_object") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "detail=storage driver restarted") != null);
    try std.testing.expectEqual(contract.ServiceClass.storage_object, ledger.latestKind(.process_crash).?.service_class);
    try std.testing.expectEqual(contract.ServiceClass.storage_object, ledger.latestKind(.driver_restart).?.service_class);
}
