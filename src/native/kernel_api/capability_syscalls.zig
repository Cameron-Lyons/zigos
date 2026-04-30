const abi = @import("../core/abi.zig");
const component_port = @import("component_port.zig");
const syscall_abi = @import("syscall_abi.zig");

pub const operations = [_]syscall_abi.Operation{
    .{ .operation = .capability_mint, .domain = .capability, .Request = component_port.CapabilityMintRequest, .Response = abi.CapabilityDescriptor },
    .{ .operation = .capability_derive, .domain = .capability, .Request = component_port.CapabilityDeriveRequest, .Response = abi.CapabilityDescriptor },
    .{ .operation = .capability_pass, .domain = .capability, .Request = component_port.CapabilityPassRequest, .Response = abi.CapabilityDescriptor },
    .{ .operation = .capability_revoke, .domain = .capability, .Request = component_port.CapabilityRevokeRequest, .Response = void },
    .{ .operation = .capability_query, .domain = .capability, .Request = component_port.CapabilityQueryRequest, .Response = abi.CapabilityDescriptor },
};
