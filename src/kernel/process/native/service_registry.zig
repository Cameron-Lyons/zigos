const std = @import("std");
const abi = @import("abi.zig");
const manifest = @import("manifest.zig");
const native_util = @import("util.zig");

pub const MAX_BINDINGS: usize = 24;

pub const Binding = struct {
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    interface: manifest.InterfaceDecl,
    flags: u16 = 0,
};

pub const Error = error{
    BindingTableFull,
    DuplicateInterface,
    InterfaceNotFound,
    VersionMismatch,
};

const BindingSlot = struct {
    in_use: bool = false,
    binding: Binding = zeroBinding(),
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
            slot.binding = .{
                .service_id = service_id,
                .owner_task_id = owner_task_id,
                .endpoint_id = endpoint_id,
                .interface = interface,
                .flags = flags,
            };
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
        .flags = 0,
    };
}

fn hashInterface(name: []const u8) u64 {
    return native_util.fnv1a64(name);
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
