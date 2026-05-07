const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const schema = @import("component_abi_schema.zig");

pub const MAGIC = schema.MAGIC;
pub const VERSION = schema.VERSION;
pub const Error = schema.Error;
pub const WireHeader = schema.WireHeader;

pub const InterfaceKey = schema.InterfaceKey;
pub const ServiceBinding = schema.ServiceBinding;
pub const OperationId = schema.OperationId;
pub const OperationDecl = schema.OperationDecl;
pub const InterfaceContract = schema.InterfaceContract;
pub const ServiceCatalogBinding = schema.ServiceCatalogBinding;
pub const CoverageReference = schema.CoverageReference;
pub const CoverageReferenceKind = schema.CoverageReferenceKind;
pub const MAX_OPERATIONS_PER_INTERFACE = schema.MAX_OPERATIONS_PER_INTERFACE;

pub const ServiceRegisterRequest = schema.requestType(.service_register);
pub const ServiceConnectionRequest = schema.requestType(.service_connect);
pub const TaskDescribeRequest = schema.requestType(.task_describe);
pub const WorkspacePutVersionRequest = schema.requestType(.workspace_put_version);
pub const WorkspaceResolveRequest = schema.requestType(.workspace_resolve);
pub const NetworkAuthorizeRequest = schema.requestType(.network_authorize);
pub const PolicyAuthorizeRequest = schema.requestType(.policy_authorize);

pub const ServiceRegisterResponse = schema.responseType(.service_register);
pub const ServiceConnectionResponse = schema.responseType(.service_connect);
pub const TaskDescribeResponse = schema.responseType(.task_describe);
pub const WorkspacePutVersionResponse = schema.responseType(.workspace_put_version);
pub const WorkspaceResolveResponse = schema.responseType(.workspace_resolve);
pub const NetworkAuthorizeResponse = schema.responseType(.network_authorize);
pub const PolicyAuthorizeResponse = schema.responseType(.policy_authorize);

pub const contracts = schema.contracts;
pub const manifest_interfaces = schema.manifest_interfaces;
pub const service_catalog_bindings = schema.service_catalog_bindings;
pub const coverage_references = schema.coverage_references;

pub fn Interface(comptime key: InterfaceKey) manifest.InterfaceDecl {
    return schema.interfaceDecl(key);
}

pub fn interfaceForService(comptime service: ServiceBinding) manifest.InterfaceDecl {
    return schema.interfaceForService(service);
}

pub fn Request(comptime operation_id: OperationId) type {
    return schema.requestType(operation_id);
}

pub fn Response(comptime operation_id: OperationId) type {
    return schema.responseType(operation_id);
}

pub fn contractFor(interface_name: []const u8) ?*const InterfaceContract {
    return schema.contractFor(interface_name);
}

pub fn validateInterface(interface: manifest.InterfaceDecl) Error!void {
    return schema.validateInterface(interface);
}

pub fn validateCompatibility(provided: manifest.InterfaceDecl, requested: manifest.InterfaceDecl) Error!void {
    return schema.validateCompatibility(provided, requested);
}

pub fn validateMessage(
    interface: manifest.InterfaceDecl,
    operation_id: OperationId,
    header: WireHeader,
    actual_request_len: usize,
    actual_response_len: usize,
) Error!void {
    return schema.validateMessage(interface, operation_id, header, actual_request_len, actual_response_len);
}

pub fn coverageReferenceCountForRequirement(requirement_id: []const u8) usize {
    return schema.coverageReferenceCountForRequirement(requirement_id);
}

test "typed component ABI derives operation IDs, wire types, and validators from schema" {
    const registry = contractFor("zigos.service.registry").?;
    try std.testing.expect(registry.contract_hash != 0);
    try std.testing.expect(registry.operation(.service_register) != null);
    try validateInterface(Interface(.object_workspace));
    try std.testing.expectEqual(@as(u16, 0x0102), @intFromEnum(OperationId.service_connect));
    try std.testing.expectEqual(@sizeOf(ServiceConnectionRequest), @sizeOf(Request(.service_connect)));
    try std.testing.expectEqual(@sizeOf(ServiceConnectionResponse), @sizeOf(Response(.service_connect)));
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(WorkspacePutVersionRequest))), contractFor("zigos.object.workspace").?.operation(.workspace_put_version).?.request_size);
}

test "typed component ABI rejects incompatible interfaces and malformed messages" {
    try std.testing.expectError(Error.UnknownInterface, validateInterface(.{ .name = "zigos.unknown" }));
    try std.testing.expectError(Error.UnsupportedInterfaceVersion, validateInterface(.{
        .name = "zigos.service.registry",
        .version_major = 2,
        .version_minor = 0,
    }));

    const iface = Interface(.service_registry);
    var header = WireHeader{
        .interface_major = iface.version_major,
        .interface_minor = iface.version_minor,
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
