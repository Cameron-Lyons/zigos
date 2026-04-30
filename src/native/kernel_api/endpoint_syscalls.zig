const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .endpoint_create, .domain = .endpoint, .Request = component_port.EndpointCreateRequest, .Response = abi.EndpointCreateResponse, .request_copy = .embedded_user_buffers },
    .{ .operation = .endpoint_connect, .domain = .endpoint, .Request = component_port.EndpointConnectRequest, .Response = abi.EndpointDescriptor },
    .{ .operation = .endpoint_send, .domain = .endpoint, .Request = component_port.EndpointSendRequest, .Response = void, .request_copy = .embedded_user_buffers },
    .{ .operation = .endpoint_recv, .domain = .endpoint, .Request = component_port.EndpointRecvRequest, .Response = abi.EndpointRecvResponse },
};
