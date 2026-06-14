const std = @import("std");

pub const WireModules = struct {
    binary_cursor: *std.Build.Module,
    userspace_wire: *std.Build.Module,
};

pub const UserspaceRuntimeModules = struct {
    wire: WireModules,
    descriptor: *std.Build.Module,
    abi: *std.Build.Module,
    bootstrap_mailbox: *std.Build.Module,
    service_protocol: *std.Build.Module,
    runtime: *std.Build.Module,
};

pub fn addWireModules(b: *std.Build) WireModules {
    const binary_cursor = b.createModule(.{
        .root_source_file = b.path("src/native/core/binary_cursor.zig"),
    });
    const userspace_wire = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_wire.zig"),
    });
    userspace_wire.addImport("binary_cursor", binary_cursor);
    return .{
        .binary_cursor = binary_cursor,
        .userspace_wire = userspace_wire,
    };
}

pub fn addHostWireModules(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) WireModules {
    const binary_cursor = b.createModule(.{
        .root_source_file = b.path("src/native/core/binary_cursor.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const userspace_wire = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_wire.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    userspace_wire.addImport("binary_cursor", binary_cursor);
    return .{
        .binary_cursor = binary_cursor,
        .userspace_wire = userspace_wire,
    };
}

pub fn addUserspaceRuntimeModules(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) UserspaceRuntimeModules {
    const wire = addWireModules(b);
    const descriptor = addDescriptorModule(b, wire, null, null);
    const abi = b.createModule(.{
        .root_source_file = b.path("src/native/core/abi.zig"),
    });
    const bootstrap_mailbox = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_bootstrap_mailbox.zig"),
    });
    const service_protocol = addServiceProtocolModule(b, wire, null, null);
    const runtime = b.createModule(.{
        .root_source_file = b.path("src/userspace/runtime.zig"),
        .target = target,
        .optimize = optimize,
    });
    addRuntimeImports(runtime, descriptor, abi, bootstrap_mailbox, service_protocol);
    return .{
        .wire = wire,
        .descriptor = descriptor,
        .abi = abi,
        .bootstrap_mailbox = bootstrap_mailbox,
        .service_protocol = service_protocol,
        .runtime = runtime,
    };
}

pub fn addUserspaceRuntimeHostTestModules(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) UserspaceRuntimeModules {
    const wire = addHostWireModules(b, optimize);
    const descriptor = addDescriptorModule(b, wire, b.graph.host, optimize);
    const abi = b.createModule(.{
        .root_source_file = b.path("src/native/core/abi.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const bootstrap_mailbox = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_bootstrap_mailbox.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    const service_protocol = addServiceProtocolModule(b, wire, b.graph.host, optimize);
    const runtime = b.createModule(.{
        .root_source_file = b.path("src/userspace/runtime.zig"),
        .target = b.graph.host,
        .optimize = optimize,
    });
    addRuntimeImports(runtime, descriptor, abi, bootstrap_mailbox, service_protocol);
    return .{
        .wire = wire,
        .descriptor = descriptor,
        .abi = abi,
        .bootstrap_mailbox = bootstrap_mailbox,
        .service_protocol = service_protocol,
        .runtime = runtime,
    };
}

fn addDescriptorModule(
    b: *std.Build,
    wire: WireModules,
    target: ?std.Build.ResolvedTarget,
    optimize: ?std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_descriptor.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("userspace_wire", wire.userspace_wire);
    return module;
}

fn addServiceProtocolModule(
    b: *std.Build,
    wire: WireModules,
    target: ?std.Build.ResolvedTarget,
    optimize: ?std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_service_protocol.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("userspace_wire", wire.userspace_wire);
    return module;
}

fn addRuntimeImports(
    runtime: *std.Build.Module,
    descriptor: *std.Build.Module,
    abi: *std.Build.Module,
    bootstrap_mailbox: *std.Build.Module,
    service_protocol: *std.Build.Module,
) void {
    runtime.addImport("userspace_descriptor", descriptor);
    runtime.addImport("native_abi", abi);
    runtime.addImport("userspace_bootstrap_mailbox", bootstrap_mailbox);
    runtime.addImport("userspace_service_protocol", service_protocol);
}
