const std = @import("std");
const abi = @import("../core/abi.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const typed_component_abi = @import("typed_component_abi.zig");

pub const MAX_BINDINGS: usize = 32;
pub const DERIVES_STATIC_CONTRACT_METADATA = true;

pub const BootstrapEndpoint = struct {
    task_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
};

pub const Binding = struct {
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
    contract: ?*const typed_component_abi.InterfaceContract,
    version_major: u16,
    version_minor: u16,
    flags: u16 = 0,

    pub fn typedContract(self: *const Binding) *const typed_component_abi.InterfaceContract {
        return self.contract orelse
            native_util.impossibleByInvariant("registered service interface retains its typed contract");
    }

    pub fn interfaceId(self: *const Binding) typed_component_abi.InterfaceId {
        return self.typedContract().interface_id;
    }

    comptime {
        if (@sizeOf(@This()) > 48) {
            @compileError("typed service bindings exceed their compact schema-derived layout");
        }
    }
};

pub const Error = error{
    BindingTableFull,
    DuplicateInterface,
    InvalidBootstrapEndpoint,
    InvalidBindingEndpoint,
    InvalidServiceFlags,
    InterfaceNotFound,
    VersionMismatch,
    RegistryNotBootstrapped,
    TypedContractMismatch,
    UnsupportedPlatformInterface,
};

const BindingSlot = struct {
    in_use: bool = false,
    binding: Binding = zeroBinding(),
};

const BindingArena = indexed_arena.IndexedArenaWithKey(u64, BindingSlot, MAX_BINDINGS, MAX_BINDINGS * 2, bindingSlotInterfaceIdKey);

pub const Service = struct {
    bootstrap: ?BootstrapEndpoint = null,
    registry: Registry = Registry.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn initWithBootstrap(bootstrap: BootstrapEndpoint) Service {
        return .{ .bootstrap = bootstrap };
    }

    pub fn bindBootstrap(self: *Service, bootstrap: BootstrapEndpoint) void {
        self.bootstrap = bootstrap;
    }

    pub fn register(
        self: *Service,
        service_id: u64,
        owner_task_id: u64,
        endpoint_id: u64,
        endpoint_capability_id: u64,
        interface: manifest.InterfaceDecl,
        flags: u16,
    ) Error!void {
        try validateBootstrap(self.bootstrap);
        return self.registry.register(service_id, owner_task_id, endpoint_id, endpoint_capability_id, interface, flags);
    }

    pub fn connect(self: *const Service, interface: manifest.InterfaceDecl) Error!abi.ServiceConnectionDescriptor {
        try validateBootstrap(self.bootstrap);
        return self.registry.connect(interface);
    }

    pub fn bindingCount(self: *const Service) usize {
        return self.registry.bindingCount();
    }

    comptime {
        if (@sizeOf(@This()) > 3 * 1024) {
            @compileError("typed service registry exceeds its compact resident layout");
        }
    }
};

fn validateBootstrap(bootstrap: ?BootstrapEndpoint) Error!void {
    const endpoint = bootstrap orelse return error.RegistryNotBootstrapped;
    if (endpoint.task_id == 0 or endpoint.endpoint_id == 0 or endpoint.endpoint_capability_id == 0) {
        return error.InvalidBootstrapEndpoint;
    }
}

pub const Registry = struct {
    bindings: BindingArena = BindingArena.init(),

    pub fn init() Registry {
        return .{};
    }

    pub fn register(
        self: *Registry,
        service_id: u64,
        owner_task_id: u64,
        endpoint_id: u64,
        endpoint_capability_id: u64,
        interface: manifest.InterfaceDecl,
        flags: u16,
    ) Error!void {
        if (service_id == 0 or owner_task_id == 0 or endpoint_id == 0 or endpoint_capability_id == 0) {
            return error.InvalidBindingEndpoint;
        }
        const known_flags = abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER | abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE;
        if ((flags & ~known_flags) != 0) return error.InvalidServiceFlags;
        const interface_id = interfaceIdForRequest(interface) catch |err| switch (err) {
            error.UnsupportedPlatformInterface => return error.UnsupportedPlatformInterface,
            error.TypedContractMismatch => return error.TypedContractMismatch,
        };
        const contract = typed_component_abi.contractForId(interface_id) orelse
            native_util.impossibleByInvariant("validated service interface retains its typed contract");
        if (self.find(interface_id)) |_| return error.DuplicateInterface;

        const slot_index = self.bindings.reserveIndex(interfaceIdKey(interface_id)) orelse return error.BindingTableFull;
        const slot = &self.bindings.slots[slot_index];
        slot.binding.service_id = service_id;
        slot.binding.owner_task_id = owner_task_id;
        slot.binding.endpoint_id = endpoint_id;
        slot.binding.endpoint_capability_id = endpoint_capability_id;
        slot.binding.contract = contract;
        slot.binding.version_major = interface.version_major;
        slot.binding.version_minor = interface.version_minor;
        slot.binding.flags = flags;
    }

    pub fn connect(self: *const Registry, interface: manifest.InterfaceDecl) Error!abi.ServiceConnectionDescriptor {
        const interface_id = interfaceIdForRequest(interface) catch |err| switch (err) {
            error.UnsupportedPlatformInterface => return error.UnsupportedPlatformInterface,
            error.TypedContractMismatch => return error.VersionMismatch,
        };
        const binding = self.find(interface_id) orelse return error.InterfaceNotFound;
        if (binding.version_major != interface.version_major) return error.VersionMismatch;
        if (binding.version_minor < interface.version_minor) return error.VersionMismatch;

        return .{
            .service_id = binding.service_id,
            .endpoint_id = binding.endpoint_id,
            .endpoint_capability_id = binding.endpoint_capability_id,
            .interface_id = @intFromEnum(binding.interfaceId()),
            .version_major = binding.version_major,
            .version_minor = binding.version_minor,
            .flags = binding.flags,
        };
    }

    pub fn bindingCount(self: *const Registry) usize {
        return self.bindings.countInUse();
    }

    fn find(self: *const Registry, interface_id: typed_component_abi.InterfaceId) ?*const Binding {
        const slot = self.bindings.getConst(interfaceIdKey(interface_id)) orelse return null;
        if (slot.binding.interfaceId() != interface_id) native_util.impossibleByInvariant("service registry primary index points at the wrong binding");
        return &slot.binding;
    }

    comptime {
        if (@sizeOf(@This()) > 2_816) {
            @compileError("typed binding arena exceeds its compact resident layout");
        }
    }
};

fn bindingSlotInterfaceIdKey(slot: *const BindingSlot) u64 {
    if (slot.binding.service_id == 0) return 0;
    return interfaceIdKey(slot.binding.interfaceId());
}

fn zeroBinding() Binding {
    return .{
        .service_id = 0,
        .owner_task_id = 0,
        .endpoint_id = 0,
        .endpoint_capability_id = 0,
        .contract = null,
        .version_major = 0,
        .version_minor = 0,
        .flags = 0,
    };
}

fn interfaceIdKey(interface_id: typed_component_abi.InterfaceId) u64 {
    return indexed_arena.nonZeroKey(@intFromEnum(interface_id));
}

fn interfaceIdForRequest(interface: manifest.InterfaceDecl) error{ UnsupportedPlatformInterface, TypedContractMismatch }!typed_component_abi.InterfaceId {
    if (!platformInterfaceNameAllowed(interface.name) or interface.version_major == 0) return error.UnsupportedPlatformInterface;
    const interface_id = typed_component_abi.interfaceIdForDecl(interface) orelse return error.UnsupportedPlatformInterface;
    typed_component_abi.validateInterfaceId(interface_id, interface) catch return error.TypedContractMismatch;
    return interface_id;
}

fn platformInterfaceNameAllowed(name: []const u8) bool {
    if (name.len == 0) return false;
    return !std.mem.startsWith(u8, name, "zigos.internal.") and
        !std.mem.startsWith(u8, name, "kernel.") and
        !std.mem.startsWith(u8, name, "sys.") and
        !std.mem.startsWith(u8, name, "vfs.");
}

test "service registry service requires bootstrap endpoint before discovery" {
    var service = Service.init();
    try std.testing.expectError(error.RegistryNotBootstrapped, service.register(44, 7, 101, 201, .{
        .name = "zigos.object.workspace",
    }, 0));

    service.bindBootstrap(.{
        .task_id = 0,
        .endpoint_id = 99,
        .endpoint_capability_id = 123,
    });
    try std.testing.expectError(error.InvalidBootstrapEndpoint, service.connect(.{
        .name = "zigos.object.workspace",
    }));

    service.bindBootstrap(.{
        .task_id = 2,
        .endpoint_id = 99,
        .endpoint_capability_id = 123,
    });
    try service.register(44, 7, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 2,
    }, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);

    const connection = try service.connect(.{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 44), connection.service_id);
    try std.testing.expectEqual(@as(u64, 101), connection.endpoint_id);
    try std.testing.expectEqual(@as(u64, 201), connection.endpoint_capability_id);
}

test "service registry only connects by typed interface declaration" {
    var registry = Registry.init();
    try registry.register(44, 7, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 2,
    }, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);

    const connection = try registry.connect(.{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 44), connection.service_id);
    try std.testing.expectEqual(@as(u64, 101), connection.endpoint_id);
    try std.testing.expectEqual(@as(u64, 201), connection.endpoint_capability_id);
    try std.testing.expect(connection.interface_id != 0);
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
}

test "service registry rejects duplicate interfaces and incompatible versions" {
    var registry = Registry.init();
    try std.testing.expectError(error.InvalidBindingEndpoint, registry.register(0, 7, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    }, 0));
    try std.testing.expectError(error.InvalidBindingEndpoint, registry.register(44, 0, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    }, 0));
    try std.testing.expectError(error.InvalidServiceFlags, registry.register(44, 7, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    }, 0x8000));
    try std.testing.expectEqual(@as(usize, 0), registry.bindingCount());
    try registry.register(44, 7, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    }, 0);

    try std.testing.expectError(error.DuplicateInterface, registry.register(45, 8, 102, 202, .{
        .name = "zigos.object.workspace",
    }, 0));
    try std.testing.expectError(error.VersionMismatch, registry.connect(.{
        .name = "zigos.object.workspace",
        .version_major = 2,
        .version_minor = 0,
    }));
}

test "service registry does not consume a binding slot for untyped interface names" {
    var registry = Registry.init();
    const too_long = "zigos.object.workspace.interface.name.that.is.definitely.longer.than.sixty.four.bytes";
    try std.testing.expect(too_long.len > 64);

    try std.testing.expectError(error.UnsupportedPlatformInterface, registry.register(44, 7, 101, 201, .{
        .name = too_long,
        .version_major = 1,
        .version_minor = 0,
    }, 0));
    try std.testing.expectEqual(@as(usize, 0), registry.bindingCount());

    try registry.register(45, 7, 102, 202, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    }, 0);
    try std.testing.expectEqual(@as(usize, 1), registry.bindingCount());
}

test "service registry binds native AI inference through typed ABI" {
    var registry = Registry.init();
    try registry.register(91, 8, 191, 291, .{
        .name = "zigos.ai.inference",
        .version_major = 1,
        .version_minor = 0,
    }, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER | abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE);

    const connection = try registry.connect(.{
        .name = "zigos.ai.inference",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 91), connection.service_id);
    try std.testing.expectEqual(@intFromEnum(typed_component_abi.InterfaceId.ai_inference), connection.interface_id);
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE));
}

test "service registry binds privacy and diagnostics contracts through typed ABI" {
    var registry = Registry.init();
    try registry.register(92, 9, 192, 292, typed_component_abi.Interface(.privacy_budget), abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);
    try registry.register(93, 10, 193, 293, typed_component_abi.Interface(.diagnostics_export), abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE);

    const privacy = try registry.connect(.{
        .name = "zigos.privacy.budget",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 92), privacy.service_id);
    try std.testing.expectEqual(@intFromEnum(typed_component_abi.InterfaceId.privacy_budget), privacy.interface_id);

    const diagnostics = try registry.connect(.{
        .name = "zigos.diagnostics.export",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 93), diagnostics.service_id);
    try std.testing.expectEqual(@intFromEnum(typed_component_abi.InterfaceId.diagnostics_export), diagnostics.interface_id);
}

test "service registry binds consent and permission lease contracts through typed ABI" {
    var registry = Registry.init();
    try registry.register(94, 11, 194, 294, typed_component_abi.Interface(.consent_receipts), abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);
    try registry.register(95, 12, 195, 295, typed_component_abi.Interface(.permission_lease), abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE);

    const consent = try registry.connect(.{
        .name = "zigos.consent.receipts",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 94), consent.service_id);
    try std.testing.expectEqual(@intFromEnum(typed_component_abi.InterfaceId.consent_receipts), consent.interface_id);

    const lease = try registry.connect(.{
        .name = "zigos.permission.lease",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 95), lease.service_id);
    try std.testing.expectEqual(@intFromEnum(typed_component_abi.InterfaceId.permission_lease), lease.interface_id);
}

test "service registry rejects internal interface names and unversioned API bypasses" {
    var registry = Registry.init();

    try std.testing.expectError(error.UnsupportedPlatformInterface, registry.register(44, 7, 101, 201, .{
        .name = "zigos.internal.storage.raw",
        .version_major = 1,
        .version_minor = 0,
    }, 0));
    try std.testing.expectError(error.UnsupportedPlatformInterface, registry.register(44, 7, 101, 201, .{
        .name = "kernel.task.table",
        .version_major = 1,
        .version_minor = 0,
    }, 0));
    try std.testing.expectError(error.UnsupportedPlatformInterface, registry.register(44, 7, 101, 201, .{
        .name = "vfs.root",
        .version_major = 1,
        .version_minor = 0,
    }, 0));
    try std.testing.expectError(error.UnsupportedPlatformInterface, registry.register(44, 7, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 0,
        .version_minor = 0,
    }, 0));

    try registry.register(44, 7, 101, 201, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    }, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);
    try std.testing.expectError(error.UnsupportedPlatformInterface, registry.connect(.{
        .name = "sys.raw-process-table",
        .version_major = 1,
        .version_minor = 0,
    }));
}

test "service registry binds known interfaces to generated typed contracts" {
    var registry = Registry.init();
    try registry.register(44, 7, 101, 201, .{
        .name = "zigos.service.registry",
        .version_major = 1,
        .version_minor = 0,
    }, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER);

    const binding = registry.find(typed_component_abi.interfaceIdForService(.service_registry)).?;
    try std.testing.expectEqual(typed_component_abi.interfaceIdForService(.service_registry), binding.interfaceId());
    try std.testing.expect(binding.typedContract().contract_hash != 0);

    _ = try registry.connect(.{
        .name = "zigos.service.registry",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectError(error.VersionMismatch, registry.connect(.{
        .name = "zigos.service.registry",
        .version_major = 2,
        .version_minor = 0,
    }));
    try std.testing.expectError(error.TypedContractMismatch, registry.register(45, 8, 102, 202, .{
        .name = "zigos.task.runtime",
        .version_major = 2,
        .version_minor = 0,
    }, 0));
}

test "service registry derives interface names after mutable request changes" {
    var registry = Registry.init();
    const storage_interface = typed_component_abi.interfaceForService(.storage_object);
    var name_storage: [typed_component_abi.interfaceForService(.storage_object).name.len]u8 = undefined;
    @memcpy(&name_storage, storage_interface.name);
    try registry.register(44, 7, 101, 201, .{
        .name = name_storage[0..storage_interface.name.len],
        .version_major = storage_interface.version_major,
        .version_minor = storage_interface.version_minor,
    }, 0);

    @memset(name_storage[0..storage_interface.name.len], 'x');

    try std.testing.expectError(error.UnsupportedPlatformInterface, registry.connect(.{
        .name = name_storage[0..storage_interface.name.len],
        .version_major = 1,
        .version_minor = 0,
    }));
    const connection = try registry.connect(storage_interface);
    try std.testing.expectEqual(@as(u64, 44), connection.service_id);
    try std.testing.expectEqual(@as(u16, @intFromEnum(typed_component_abi.interfaceIdForService(.storage_object))), connection.interface_id);
}
