const std = @import("std");

const capability = @import("../../native/kernel_api/capability.zig");
const component_port = @import("../../native/kernel_api/component_port.zig");
const device_broker = @import("../../native/kernel_api/device_broker.zig");
const endpoint = @import("../../native/kernel_api/endpoint.zig");
const kernel_operation_descriptor = @import("../../native/kernel_api/kernel_operation_descriptor.zig");
const native_kernel = @import("../../native/kernel_api/native_kernel.zig");
const operation_metadata = @import("../../native/kernel_api/operation_metadata.zig");
const shared_memory = @import("../../native/kernel_api/shared_memory.zig");
const syscall_abi = @import("../../native/kernel_api/syscall_abi.zig");
const syscall_surface = @import("../../native/kernel_api/syscall_surface.zig");

test "kernel api host tests import native kernel api modules" {
    std.testing.refAllDecls(capability);
    std.testing.refAllDecls(component_port);
    std.testing.refAllDecls(device_broker);
    std.testing.refAllDecls(endpoint);
    std.testing.refAllDecls(kernel_operation_descriptor);
    std.testing.refAllDecls(native_kernel);
    std.testing.refAllDecls(operation_metadata);
    std.testing.refAllDecls(shared_memory);
    std.testing.refAllDecls(syscall_abi);
    std.testing.refAllDecls(syscall_surface);
}
