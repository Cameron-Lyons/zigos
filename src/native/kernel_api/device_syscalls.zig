const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .device_describe, .domain = .device, .Request = component_port.DeviceDescribeRequest, .Response = abi.DeviceDescriptor },
    .{ .operation = .device_mmio_window, .domain = .device, .Request = component_port.DeviceMmioWindowRequest, .Response = abi.DeviceMmioWindowDescriptor },
    .{ .operation = .device_port_read, .domain = .device, .Request = component_port.DevicePortReadRequest, .Response = abi.DevicePortReadResponse },
    .{ .operation = .device_port_write, .domain = .device, .Request = component_port.DevicePortWriteRequest, .Response = void },
};
