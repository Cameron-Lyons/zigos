const std = @import("std");
const abi = @import("../core/abi.zig");
const typed_component_abi = @import("typed_component_abi.zig");

pub const MAX_BINDINGS: usize = typed_component_abi.INTERFACE_COUNT;
pub const DERIVES_STATIC_CONTRACT_METADATA = true;
pub const COMPACT_BINDING_METADATA = true;
pub const DIRECT_INTERFACE_BINDINGS = true;
pub const DERIVES_BINDING_COUNT_FROM_SLOTS = true;
pub const DERIVES_OWNER_FROM_ENDPOINT_CAPABILITY = true;
pub const COMPACT_BOOTSTRAP_VALIDATION_STATE = true;
pub const TYPED_ID_ONLY_API = true;
pub const AUTHENTICATED_BINDINGS_ONLY = true;
pub const REQUIRED_BINDING_FLAGS: u16 = abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER | abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE;
pub const BINDING_SIZE_CEILING_BYTES: usize = 24;
pub const REGISTRY_SIZE_CEILING_BYTES: usize = 744;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 752;

pub const BootstrapEndpoint = struct {
    task_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
};

pub const BootstrapValidationState = enum(u8) {
    unbound,
    invalid,
    ready,
};

pub const Binding = struct {
    service_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,

    comptime {
        if (@sizeOf(@This()) > BINDING_SIZE_CEILING_BYTES) {
            @compileError("typed service bindings exceed their compact schema-derived layout");
        }
    }
};

pub const Error = error{
    DuplicateInterface,
    InvalidBootstrapEndpoint,
    InvalidBindingEndpoint,
    InvalidServiceFlags,
    InterfaceNotFound,
    RegistryNotBootstrapped,
};

pub const Service = struct {
    bootstrap_state: BootstrapValidationState = .unbound,
    registry: Registry = Registry.init(),

    pub fn init() Service {
        return .{};
    }

    pub fn initWithBootstrap(bootstrap: BootstrapEndpoint) Service {
        return .{ .bootstrap_state = bootstrapValidationState(bootstrap) };
    }

    pub fn bindBootstrap(self: *Service, bootstrap: BootstrapEndpoint) void {
        self.bootstrap_state = bootstrapValidationState(bootstrap);
    }

    pub fn register(
        self: *Service,
        service_id: u64,
        endpoint_id: u64,
        endpoint_capability_id: u64,
        interface_id: typed_component_abi.InterfaceId,
        flags: u16,
    ) Error!void {
        try validateBootstrap(self.bootstrap_state);
        return self.registry.register(service_id, endpoint_id, endpoint_capability_id, interface_id, flags);
    }

    pub fn connect(self: *const Service, interface_id: typed_component_abi.InterfaceId) Error!abi.ServiceConnectionDescriptor {
        try validateBootstrap(self.bootstrap_state);
        return self.registry.connect(interface_id);
    }

    pub fn bindingCount(self: *const Service) usize {
        return self.registry.bindingCount();
    }

    comptime {
        if (@sizeOf(@This()) > SERVICE_SIZE_CEILING_BYTES) {
            @compileError("typed service registry exceeds its compact resident layout");
        }
    }
};

fn bootstrapValidationState(bootstrap: BootstrapEndpoint) BootstrapValidationState {
    if (bootstrap.task_id == 0 or bootstrap.endpoint_id == 0 or bootstrap.endpoint_capability_id == 0) return .invalid;
    return .ready;
}

fn validateBootstrap(state: BootstrapValidationState) Error!void {
    return switch (state) {
        .unbound => error.RegistryNotBootstrapped,
        .invalid => error.InvalidBootstrapEndpoint,
        .ready => {},
    };
}

pub const Registry = struct {
    bindings: [MAX_BINDINGS]Binding = [_]Binding{zeroBinding()} ** MAX_BINDINGS,

    pub fn init() Registry {
        return .{};
    }

    pub fn register(
        self: *Registry,
        service_id: u64,
        endpoint_id: u64,
        endpoint_capability_id: u64,
        interface_id: typed_component_abi.InterfaceId,
        flags: u16,
    ) Error!void {
        if (service_id == 0 or endpoint_id == 0 or endpoint_capability_id == 0) {
            return error.InvalidBindingEndpoint;
        }
        if (flags != REQUIRED_BINDING_FLAGS) return error.InvalidServiceFlags;
        const slot_index = typed_component_abi.interfaceIndexForId(interface_id);
        const binding = &self.bindings[slot_index];
        if (binding.service_id != 0) return error.DuplicateInterface;

        binding.* = .{
            .service_id = service_id,
            .endpoint_id = endpoint_id,
            .endpoint_capability_id = endpoint_capability_id,
        };
    }

    pub fn connect(self: *const Registry, interface_id: typed_component_abi.InterfaceId) Error!abi.ServiceConnectionDescriptor {
        const binding = self.find(interface_id) orelse return error.InterfaceNotFound;

        return .{
            .service_id = binding.service_id,
            .endpoint_id = binding.endpoint_id,
            .endpoint_capability_id = binding.endpoint_capability_id,
        };
    }

    pub fn bindingCount(self: *const Registry) usize {
        var count: usize = 0;
        for (self.bindings) |binding| {
            if (binding.service_id != 0) count += 1;
        }
        return count;
    }

    fn find(self: *const Registry, interface_id: typed_component_abi.InterfaceId) ?*const Binding {
        const slot_index = typed_component_abi.interfaceIndexForId(interface_id);
        const binding = &self.bindings[slot_index];
        if (binding.service_id == 0) return null;
        return binding;
    }

    comptime {
        if (@sizeOf(@This()) > REGISTRY_SIZE_CEILING_BYTES) {
            @compileError("typed binding registry exceeds its compact resident layout");
        }
    }
};

fn zeroBinding() Binding {
    return .{
        .service_id = 0,
        .endpoint_id = 0,
        .endpoint_capability_id = 0,
    };
}

test "service registry stores one direct slot per typed interface" {
    try std.testing.expect(DIRECT_INTERFACE_BINDINGS);
    try std.testing.expectEqual(typed_component_abi.INTERFACE_COUNT, MAX_BINDINGS);
    try std.testing.expectEqual(REGISTRY_SIZE_CEILING_BYTES, @sizeOf(Registry));
    try std.testing.expectEqual(SERVICE_SIZE_CEILING_BYTES, @sizeOf(Service));
    try std.testing.expectEqual(
        @as(usize, 0),
        typed_component_abi.interfaceIndexForId(.task_runtime),
    );
    try std.testing.expectEqual(
        MAX_BINDINGS - 1,
        typed_component_abi.interfaceIndexForId(.personal_context),
    );
}

test "service registry service requires bootstrap endpoint before discovery" {
    var service = Service.init();
    try std.testing.expectError(
        error.RegistryNotBootstrapped,
        service.register(44, 101, 201, .object_workspace, 0),
    );

    service.bindBootstrap(.{
        .task_id = 0,
        .endpoint_id = 99,
        .endpoint_capability_id = 123,
    });
    try std.testing.expectError(error.InvalidBootstrapEndpoint, service.connect(.object_workspace));

    service.bindBootstrap(.{
        .task_id = 2,
        .endpoint_id = 99,
        .endpoint_capability_id = 123,
    });
    try service.register(44, 101, 201, .object_workspace, REQUIRED_BINDING_FLAGS);

    const connection = try service.connect(.object_workspace);
    try std.testing.expectEqual(@as(u64, 44), connection.service_id);
    try std.testing.expectEqual(@as(u64, 101), connection.endpoint_id);
    try std.testing.expectEqual(@as(u64, 201), connection.endpoint_capability_id);
}

test "service registry connects by exact typed interface id" {
    var registry = Registry.init();
    try registry.register(44, 101, 201, .object_workspace, REQUIRED_BINDING_FLAGS);

    const connection = try registry.connect(.object_workspace);
    try std.testing.expectEqual(@as(u64, 44), connection.service_id);
    try std.testing.expectEqual(@as(u64, 101), connection.endpoint_id);
    try std.testing.expectEqual(@as(u64, 201), connection.endpoint_capability_id);
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(@TypeOf(connection)));
    try std.testing.expectError(error.InterfaceNotFound, registry.connect(.task_runtime));
}

test "service registry rejects invalid endpoints flags and duplicate typed ids" {
    var registry = Registry.init();
    try std.testing.expectError(error.InvalidBindingEndpoint, registry.register(0, 101, 201, .object_workspace, 0));
    try std.testing.expectError(error.InvalidBindingEndpoint, registry.register(44, 0, 201, .object_workspace, 0));
    try std.testing.expectError(error.InvalidBindingEndpoint, registry.register(44, 101, 0, .object_workspace, 0));
    try std.testing.expectError(error.InvalidServiceFlags, registry.register(44, 101, 201, .object_workspace, 0));
    try std.testing.expectError(error.InvalidServiceFlags, registry.register(44, 101, 201, .object_workspace, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
    try std.testing.expectError(error.InvalidServiceFlags, registry.register(44, 101, 201, .object_workspace, abi.SERVICE_CONNECTION_FLAG_SIGNED_IMAGE));
    try std.testing.expectError(error.InvalidServiceFlags, registry.register(44, 101, 201, .object_workspace, 0x8000));
    try std.testing.expectEqual(@as(usize, 0), registry.bindingCount());

    try registry.register(44, 101, 201, .object_workspace, REQUIRED_BINDING_FLAGS);
    try std.testing.expectError(error.DuplicateInterface, registry.register(45, 102, 202, .object_workspace, REQUIRED_BINDING_FLAGS));
    try std.testing.expectEqual(@as(usize, 1), registry.bindingCount());
}

test "service registry binds independent exact interface slots" {
    var registry = Registry.init();
    try registry.register(91, 191, 291, .ai_inference, REQUIRED_BINDING_FLAGS);
    try registry.register(92, 192, 292, .privacy_budget, REQUIRED_BINDING_FLAGS);
    try registry.register(93, 193, 293, .diagnostics_export, REQUIRED_BINDING_FLAGS);
    try registry.register(94, 194, 294, .consent_receipts, REQUIRED_BINDING_FLAGS);
    try registry.register(95, 195, 295, .permission_lease, REQUIRED_BINDING_FLAGS);

    try std.testing.expectEqual(@as(u64, 91), (try registry.connect(.ai_inference)).service_id);
    try std.testing.expectEqual(@as(u64, 92), (try registry.connect(.privacy_budget)).service_id);
    try std.testing.expectEqual(@as(u64, 93), (try registry.connect(.diagnostics_export)).service_id);
    try std.testing.expectEqual(@as(u64, 94), (try registry.connect(.consent_receipts)).service_id);
    try std.testing.expectEqual(@as(u64, 95), (try registry.connect(.permission_lease)).service_id);
    try std.testing.expectEqual(@as(usize, 5), registry.bindingCount());
}

test "service registry rejects internal interface names and unversioned API bypasses" {
    try std.testing.expect(typed_component_abi.interfaceIdForDecl(.{
        .name = "zigos.internal.storage.raw",
        .version_major = 1,
        .version_minor = 0,
    }) == null);
    try std.testing.expect(typed_component_abi.interfaceIdForDecl(.{
        .name = "kernel.task.table",
        .version_major = 1,
        .version_minor = 0,
    }) == null);
    try std.testing.expect(typed_component_abi.interfaceIdForDecl(.{
        .name = "vfs.root",
        .version_major = 1,
        .version_minor = 0,
    }) == null);

    const unversioned = typed_component_abi.Interface(.object_workspace);
    var invalid_version = unversioned;
    invalid_version.version_major = 0;
    try std.testing.expectError(
        error.UnsupportedInterfaceVersion,
        typed_component_abi.validateInterfaceId(.object_workspace, invalid_version),
    );
}

test "service registry binds known ids to generated typed contracts" {
    var registry = Registry.init();
    try registry.register(44, 101, 201, .service_registry, REQUIRED_BINDING_FLAGS);

    const binding = registry.find(.service_registry).?;
    try std.testing.expectEqual(@as(u64, 44), binding.service_id);
    try std.testing.expect(typed_component_abi.contractForId(.service_registry).contract_hash != 0);
    _ = try registry.connect(.service_registry);
}
