const std = @import("std");
const abi = @import("../core/abi.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");

pub const MAX_BINDINGS: usize = 24;
pub const MAX_INTERFACE_NAME_BYTES: usize = 64;

pub const BootstrapEndpoint = struct {
    task_id: u64,
    endpoint_id: u64,
    endpoint_capability_id: u64,
};

pub const Binding = struct {
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    interface: manifest.InterfaceDecl,
    interface_name_len: usize,
    interface_name: [MAX_INTERFACE_NAME_BYTES]u8,
    flags: u16 = 0,
};

pub const Error = error{
    BindingTableFull,
    DuplicateInterface,
    InterfaceNotFound,
    InterfaceNameTooLong,
    VersionMismatch,
    RegistryNotBootstrapped,
};

const BindingSlot = struct {
    in_use: bool = false,
    binding: Binding = zeroBinding(),
};

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
        interface: manifest.InterfaceDecl,
        flags: u16,
    ) Error!void {
        if (self.bootstrap == null) return error.RegistryNotBootstrapped;
        return self.registry.register(service_id, owner_task_id, endpoint_id, interface, flags);
    }

    pub fn connect(self: *const Service, interface: manifest.InterfaceDecl) Error!abi.ServiceConnectionDescriptor {
        if (self.bootstrap == null) return error.RegistryNotBootstrapped;
        return self.registry.connect(interface);
    }

    pub fn bindingCount(self: *const Service) usize {
        return self.registry.bindingCount();
    }
};

pub const Registry = struct {
    slots: [MAX_BINDINGS]BindingSlot = [_]BindingSlot{BindingSlot{}} ** MAX_BINDINGS,

    pub fn init() Registry {
        return .{};
    }

    pub fn register(
        self: *Registry,
        service_id: u64,
        owner_task_id: u64,
        endpoint_id: u64,
        interface: manifest.InterfaceDecl,
        flags: u16,
    ) Error!void {
        if (self.find(interface.name)) |_| return error.DuplicateInterface;

        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.binding = zeroBinding();
            slot.binding.service_id = service_id;
            slot.binding.owner_task_id = owner_task_id;
            slot.binding.endpoint_id = endpoint_id;
            slot.binding.interface_name_len = native_util.copyTextExact(
                slot.binding.interface_name[0..],
                interface.name,
            ) catch return error.InterfaceNameTooLong;
            slot.binding.interface = .{
                .name = slot.binding.interface_name[0..slot.binding.interface_name_len],
                .version_major = interface.version_major,
                .version_minor = interface.version_minor,
            };
            slot.binding.flags = flags;
            return;
        }

        return error.BindingTableFull;
    }

    pub fn connect(self: *const Registry, interface: manifest.InterfaceDecl) Error!abi.ServiceConnectionDescriptor {
        const binding = self.find(interface.name) orelse return error.InterfaceNotFound;
        if (binding.interface.version_major != interface.version_major) return error.VersionMismatch;
        if (binding.interface.version_minor < interface.version_minor) return error.VersionMismatch;

        return .{
            .service_id = binding.service_id,
            .endpoint_id = binding.endpoint_id,
            .interface_hash = hashInterface(binding.interface.name),
            .version_major = binding.interface.version_major,
            .version_minor = binding.interface.version_minor,
            .flags = binding.flags,
        };
    }

    pub fn bindingCount(self: *const Registry) usize {
        var count: usize = 0;
        for (self.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    fn find(self: *const Registry, name: []const u8) ?*const Binding {
        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;
            if (std.mem.eql(u8, slot.binding.interface.name, name)) return &slot.binding;
        }
        return null;
    }
};

fn zeroBinding() Binding {
    return .{
        .service_id = 0,
        .owner_task_id = 0,
        .endpoint_id = 0,
        .interface = .{ .name = "" },
        .interface_name_len = 0,
        .interface_name = [_]u8{0} ** MAX_INTERFACE_NAME_BYTES,
        .flags = 0,
    };
}

fn hashInterface(name: []const u8) u64 {
    return native_util.fnv1a64(name);
}

test "service registry service requires bootstrap endpoint before discovery" {
    var service = Service.init();
    try std.testing.expectError(error.RegistryNotBootstrapped, service.register(44, 7, 101, .{
        .name = "zigos.object.workspace",
    }, 0));

    service.bindBootstrap(.{
        .task_id = 2,
        .endpoint_id = 99,
        .endpoint_capability_id = 123,
    });
    try service.register(44, 7, 101, .{
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
}

test "service registry only connects by typed interface declaration" {
    var registry = Registry.init();
    try registry.register(44, 7, 101, .{
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
    try std.testing.expect(connection.interface_hash != 0);
    try std.testing.expect(abi.serviceFlagsHas(connection.flags, abi.SERVICE_CONNECTION_FLAG_USERSPACE_OWNER));
}

test "service registry rejects duplicate interfaces and incompatible versions" {
    var registry = Registry.init();
    try registry.register(44, 7, 101, .{
        .name = "zigos.object.workspace",
        .version_major = 1,
        .version_minor = 0,
    }, 0);

    try std.testing.expectError(error.DuplicateInterface, registry.register(45, 8, 102, .{
        .name = "zigos.object.workspace",
    }, 0));
    try std.testing.expectError(error.VersionMismatch, registry.connect(.{
        .name = "zigos.object.workspace",
        .version_major = 2,
        .version_minor = 0,
    }));
}

test "service registry owns interface name bytes" {
    var registry = Registry.init();
    var name = [_]u8{ 'z', 'i', 'g', 'o', 's', '.', 'm', 'u', 't', 'a', 'b', 'l', 'e' };
    try registry.register(44, 7, 101, .{
        .name = name[0..],
        .version_major = 1,
        .version_minor = 0,
    }, 0);

    @memset(name[0..], 'x');

    try std.testing.expectError(error.InterfaceNotFound, registry.connect(.{
        .name = name[0..],
        .version_major = 1,
        .version_minor = 0,
    }));
    const connection = try registry.connect(.{
        .name = "zigos.mutable",
        .version_major = 1,
        .version_minor = 0,
    });
    try std.testing.expectEqual(@as(u64, 44), connection.service_id);
}
