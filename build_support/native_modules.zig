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
    return addWireModulesFor(b, null, null);
}

pub fn addHostWireModules(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) WireModules {
    return addWireModulesFor(b, b.graph.host, optimize);
}

fn addWireModulesFor(
    b: *std.Build,
    target: ?std.Build.ResolvedTarget,
    optimize: ?std.builtin.OptimizeMode,
) WireModules {
    const binary_cursor = b.createModule(.{
        .root_source_file = b.path("src/native/core/binary_cursor.zig"),
        .target = target,
        .optimize = optimize,
    });
    const userspace_wire = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_wire.zig"),
        .target = target,
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
    return addUserspaceRuntimeModulesFor(b, null, null, target, optimize);
}

pub fn addUserspaceRuntimeHostTestModules(
    b: *std.Build,
    optimize: std.builtin.OptimizeMode,
) UserspaceRuntimeModules {
    return addUserspaceRuntimeModulesFor(b, b.graph.host, optimize, b.graph.host, optimize);
}

/// `support_target`/`support_optimize` apply to the wire, descriptor, abi,
/// bootstrap-mailbox, and service-protocol modules; the runtime module always
/// gets an explicit target and optimize mode.
fn addUserspaceRuntimeModulesFor(
    b: *std.Build,
    support_target: ?std.Build.ResolvedTarget,
    support_optimize: ?std.builtin.OptimizeMode,
    runtime_target: std.Build.ResolvedTarget,
    runtime_optimize: std.builtin.OptimizeMode,
) UserspaceRuntimeModules {
    const wire = addWireModulesFor(b, support_target, support_optimize);
    const descriptor = addDescriptorModule(b, wire, support_target, support_optimize);
    const abi = b.createModule(.{
        .root_source_file = b.path("src/native/core/abi.zig"),
        .target = support_target,
        .optimize = support_optimize,
    });
    const bootstrap_mailbox = b.createModule(.{
        .root_source_file = b.path("src/native/task/userspace_bootstrap_mailbox.zig"),
        .target = support_target,
        .optimize = support_optimize,
    });
    const service_protocol = addServiceProtocolModule(b, wire, support_target, support_optimize);
    const runtime = b.createModule(.{
        .root_source_file = b.path("src/userspace/runtime.zig"),
        .target = runtime_target,
        .optimize = runtime_optimize,
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
