const std = @import("std");
const abi = @import("../core/abi.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");

pub const MAGIC: u32 = 0x54434142; // TCAB
pub const VERSION: u16 = 1;
pub const MAX_OPERATIONS_PER_INTERFACE: usize = 8;

pub const Error = error{
    UnknownInterface,
    UnknownOperation,
    UnsupportedAbiVersion,
    UnsupportedInterfaceVersion,
    InvalidMagic,
    InvalidRequestLength,
    InvalidResponseLength,
    MalformedMessage,
    SubjectTaskRequired,
};

pub const WireHeader = extern struct {
    magic: u32 = MAGIC,
    abi_version: u16 = VERSION,
    interface_major: u16,
    interface_minor: u16,
    operation: u16,
    flags: u16 = 0,
    request_len: u32,
    response_len: u32,
    correlation_id: u64,
    subject_task_id: u64,
};

pub const OperationId = enum(u16) {
    service_register = 0x0101,
    service_connect = 0x0102,
    task_describe = 0x0201,
    workspace_put_version = 0x0301,
    workspace_resolve = 0x0302,
    network_authorize = 0x0401,
    policy_authorize = 0x0501,
};

pub const ServiceRegisterRequest = extern struct {
    header: WireHeader,
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    flags: u16,
    interface_name_len: u16,
    version_major: u16,
    version_minor: u16,
};

pub const ServiceConnectionRequest = extern struct {
    header: WireHeader,
    interface_name_len: u16,
    version_major: u16,
    version_minor: u16,
    _reserved: u16 = 0,
};

pub const TaskDescribeRequest = extern struct {
    header: WireHeader,
    task_id: u64,
};

pub const WorkspacePutVersionRequest = extern struct {
    header: WireHeader,
    workspace_id: u64,
    object_id: u64,
    object_type: u16,
    payload_len: u32,
};

pub const WorkspaceResolveRequest = extern struct {
    header: WireHeader,
    workspace_id: u64,
    path_len: u16,
    _reserved: u16 = 0,
};

pub const NetworkAuthorizeRequest = extern struct {
    header: WireHeader,
    policy_id: u64,
    destination_len: u16,
    flags: u16,
};

pub const PolicyAuthorizeRequest = extern struct {
    header: WireHeader,
    requester_task_id: u64,
    permission_kind: u16,
    resource_len: u16,
};

pub const ServiceRegisterResponse = extern struct {
    accepted: u32,
};

pub const ServiceConnectionResponse = abi.ServiceConnectionDescriptor;
pub const TaskDescribeResponse = abi.TaskDescriptor;
pub const WorkspacePutVersionResponse = extern struct {
    object_id: u64,
    version_id: u64,
};
pub const WorkspaceResolveResponse = extern struct {
    object_id: u64,
    version_id: u64,
    object_type: u16,
};
pub const NetworkAuthorizeResponse = extern struct {
    allowed: u32,
    reason: u16,
};
pub const PolicyAuthorizeResponse = extern struct {
    allowed: u32,
    denial_reason: u16,
};

pub const OperationDecl = struct {
    id: OperationId,
    name: []const u8,
    request_size: u32,
    response_size: u32,
};

pub const InterfaceContract = struct {
    interface: manifest.InterfaceDecl,
    contract_hash: u64,
    operation_count: usize,
    operations: [MAX_OPERATIONS_PER_INTERFACE]OperationDecl,

    pub fn operation(self: *const InterfaceContract, operation_id: OperationId) ?OperationDecl {
        for (self.operations[0..self.operation_count]) |decl| {
            if (decl.id == operation_id) return decl;
        }
        return null;
    }
};

pub fn contractFor(interface_name: []const u8) ?*const InterfaceContract {
    for (&contracts) |*iface_contract| {
        if (std.mem.eql(u8, iface_contract.interface.name, interface_name)) return iface_contract;
    }
    return null;
}

pub fn validateInterface(interface: manifest.InterfaceDecl) Error!void {
    const iface_contract = contractFor(interface.name) orelse return error.UnknownInterface;
    if (iface_contract.interface.version_major != interface.version_major) return error.UnsupportedInterfaceVersion;
    if (interface.version_minor < iface_contract.interface.version_minor) return error.UnsupportedInterfaceVersion;
}

pub fn validateCompatibility(provided: manifest.InterfaceDecl, requested: manifest.InterfaceDecl) Error!void {
    if (!std.mem.eql(u8, provided.name, requested.name)) return error.UnknownInterface;
    try validateInterface(provided);
    try validateInterface(requested);
    if (provided.version_major != requested.version_major) return error.UnsupportedInterfaceVersion;
    if (provided.version_minor < requested.version_minor) return error.UnsupportedInterfaceVersion;
}

pub fn validateMessage(
    interface: manifest.InterfaceDecl,
    operation_id: OperationId,
    header: WireHeader,
    actual_request_len: usize,
    actual_response_len: usize,
) Error!void {
    if (header.magic != MAGIC) return error.InvalidMagic;
    if (header.abi_version != VERSION) return error.UnsupportedAbiVersion;
    if (header.subject_task_id == 0) return error.SubjectTaskRequired;
    if (header.interface_major != interface.version_major or
        header.interface_minor > interface.version_minor)
    {
        return error.UnsupportedInterfaceVersion;
    }
    if (header.operation != @intFromEnum(operation_id)) return error.UnknownOperation;
    if (header.request_len != actual_request_len) return error.MalformedMessage;
    if (header.response_len != actual_response_len) return error.MalformedMessage;

    const iface_contract = contractFor(interface.name) orelse return error.UnknownInterface;
    const operation_decl = iface_contract.operation(operation_id) orelse return error.UnknownOperation;
    if (operation_decl.request_size != actual_request_len) return error.InvalidRequestLength;
    if (operation_decl.response_size != actual_response_len) return error.InvalidResponseLength;
}

fn op(comptime id: OperationId, comptime name: []const u8, comptime Request: type, comptime Response: type) OperationDecl {
    return .{
        .id = id,
        .name = name,
        .request_size = @sizeOf(Request),
        .response_size = @sizeOf(Response),
    };
}

fn contract(
    interface: manifest.InterfaceDecl,
    comptime operations: []const OperationDecl,
) InterfaceContract {
    var result = InterfaceContract{
        .interface = interface,
        .contract_hash = hashContract(interface, operations),
        .operation_count = operations.len,
        .operations = [_]OperationDecl{emptyOperation()} ** MAX_OPERATIONS_PER_INTERFACE,
    };
    for (operations, 0..) |operation_decl, index| {
        result.operations[index] = operation_decl;
    }
    return result;
}

fn hashContract(interface: manifest.InterfaceDecl, comptime operations: []const OperationDecl) u64 {
    @setEvalBranchQuota(4096);
    var hash = native_util.fnv1a64(interface.name);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, interface.version_major);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, interface.version_minor);
    inline for (operations) |operation_decl| {
        hash = native_util.fnv1a64WithSeed(hash, operation_decl.name);
        hash = native_util.fnv1a64WithSeed(hash, @tagName(operation_decl.id));
        hash = native_util.fnv1a64AppendU64LittleEndian(hash, operation_decl.request_size);
        hash = native_util.fnv1a64AppendU64LittleEndian(hash, operation_decl.response_size);
    }
    return hash;
}

fn emptyOperation() OperationDecl {
    return .{
        .id = .service_connect,
        .name = "",
        .request_size = 0,
        .response_size = 0,
    };
}

pub const contracts = [_]InterfaceContract{
    contract(.{ .name = "zigos.service.registry", .version_major = 1, .version_minor = 0 }, &.{
        op(.service_register, "register", ServiceRegisterRequest, ServiceRegisterResponse),
        op(.service_connect, "connect", ServiceConnectionRequest, ServiceConnectionResponse),
    }),
    contract(.{ .name = "zigos.task.runtime", .version_major = 1, .version_minor = 0 }, &.{
        op(.task_describe, "describe", TaskDescribeRequest, TaskDescribeResponse),
    }),
    contract(.{ .name = "zigos.object.workspace", .version_major = 1, .version_minor = 0 }, &.{
        op(.workspace_put_version, "put_version", WorkspacePutVersionRequest, WorkspacePutVersionResponse),
        op(.workspace_resolve, "resolve", WorkspaceResolveRequest, WorkspaceResolveResponse),
    }),
    contract(.{ .name = "zigos.service.network.policy", .version_major = 1, .version_minor = 0 }, &.{
        op(.network_authorize, "authorize", NetworkAuthorizeRequest, NetworkAuthorizeResponse),
    }),
    contract(.{ .name = "zigos.policy.mediation", .version_major = 1, .version_minor = 0 }, &.{
        op(.policy_authorize, "authorize", PolicyAuthorizeRequest, PolicyAuthorizeResponse),
    }),
};

test "typed component ABI validates generated core service contracts" {
    const registry = contractFor("zigos.service.registry").?;
    try std.testing.expect(registry.contract_hash != 0);
    try std.testing.expect(registry.operation(.service_register) != null);
    try validateInterface(.{ .name = "zigos.object.workspace", .version_major = 1, .version_minor = 0 });
}

test "typed component ABI rejects incompatible interfaces and malformed messages" {
    try std.testing.expectError(Error.UnknownInterface, validateInterface(.{ .name = "zigos.unknown" }));
    try std.testing.expectError(Error.UnsupportedInterfaceVersion, validateInterface(.{
        .name = "zigos.service.registry",
        .version_major = 2,
        .version_minor = 0,
    }));

    const iface = manifest.InterfaceDecl{ .name = "zigos.service.registry", .version_major = 1, .version_minor = 0 };
    var header = WireHeader{
        .interface_major = 1,
        .interface_minor = 0,
        .operation = @intFromEnum(OperationId.service_connect),
        .request_len = @sizeOf(ServiceConnectionRequest),
        .response_len = @sizeOf(ServiceConnectionResponse),
        .correlation_id = 1,
        .subject_task_id = 44,
    };
    try validateMessage(
        iface,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    );

    header.magic = 0;
    try std.testing.expectError(Error.InvalidMagic, validateMessage(
        iface,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    ));
    header.magic = MAGIC;
    header.request_len -= 1;
    try std.testing.expectError(Error.MalformedMessage, validateMessage(
        iface,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    ));
    header.request_len += 1;
    header.subject_task_id = 0;
    try std.testing.expectError(Error.SubjectTaskRequired, validateMessage(
        iface,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    ));
}
