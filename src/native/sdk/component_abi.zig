const std = @import("std");
const idl = @import("idl.zig");
const manifest = @import("../policy/manifest.zig");
const schema = @import("../services/component_abi_schema.zig");

pub const MAGIC = schema.MAGIC;
pub const VERSION = schema.VERSION;
pub const InterfaceKey = schema.InterfaceKey;
pub const InterfaceId = schema.InterfaceId;
pub const OperationId = schema.OperationId;
pub const OperationDecl = schema.OperationDecl;
pub const InterfaceContract = schema.InterfaceContract;
pub const WireHeader = schema.WireHeader;
pub const PackageInstallRequest = schema.Request(.package_install);
pub const PackageInstallResponse = schema.Response(.package_install);
pub const PackageUpdateRequest = schema.Request(.package_update);
pub const PackageUpdateResponse = schema.Response(.package_update);
pub const BINDING_SIZE_CEILING_BYTES: usize = 40;
pub const Error = schema.Error || idl.Error || error{
    InterfaceNotDeclared,
    OperationNotInInterface,
};

pub const Binding = struct {
    interface_id: InterfaceId,
    interface: manifest.InterfaceDecl,
    contract_hash: u64,
    operation_count: u8,

    pub fn matches(self: Binding, decl: manifest.InterfaceDecl) bool {
        return std.mem.eql(u8, self.interface.name, decl.name) and
            self.interface.version_major == decl.version_major and
            self.interface.version_minor == decl.version_minor;
    }

    comptime {
        if (@sizeOf(@This()) > BINDING_SIZE_CEILING_BYTES) {
            @compileError("SDK component binding exceeds its compact size ceiling");
        }
    }
};

pub fn binding(comptime key: InterfaceKey) Binding {
    const abi_contract = schema.contractForId(schema.interfaceId(key));
    return .{
        .interface_id = abi_contract.interface_id,
        .interface = abi_contract.interface,
        .contract_hash = abi_contract.contract_hash,
        .operation_count = abi_contract.operation_count,
    };
}

pub fn contract(comptime key: InterfaceKey) *const InterfaceContract {
    return schema.contractForId(schema.interfaceId(key));
}

pub fn operation(comptime key: InterfaceKey, operation_id: OperationId) Error!OperationDecl {
    return contract(key).operation(operation_id) orelse error.OperationNotInInterface;
}

pub fn header(
    comptime key: InterfaceKey,
    operation_id: OperationId,
    correlation_id: u64,
    subject_task_id: u64,
) Error!WireHeader {
    _ = try operation(key, operation_id);
    return .{
        .operation = @backingInt(operation_id),
        .correlation_id = correlation_id,
        .subject_task_id = subject_task_id,
    };
}

pub fn validateHeader(
    comptime key: InterfaceKey,
    operation_id: OperationId,
    wire_header: WireHeader,
    actual_request_len: usize,
    actual_response_len: usize,
) Error!void {
    return schema.validateMessage(
        schema.interfaceId(key),
        operation_id,
        wire_header,
        actual_request_len,
        actual_response_len,
    );
}

test "SDK component ABI exposes typed bindings and validates real wire headers" {
    const bind = binding(.package_install);
    try std.testing.expectEqual(u8, @FieldType(Binding, "operation_count"));
    try std.testing.expect(@sizeOf(Binding) <= BINDING_SIZE_CEILING_BYTES);
    try std.testing.expectEqual(InterfaceId.package_install, bind.interface_id);
    try std.testing.expect(bind.contract_hash != 0);
    try std.testing.expect(bind.operation_count >= 3);

    const wire_header = try header(.package_install, .package_update, 44, 9);
    try validateHeader(
        .package_install,
        .package_update,
        wire_header,
        @sizeOf(PackageUpdateRequest),
        @sizeOf(PackageUpdateResponse),
    );

    var malformed = wire_header;
    malformed.subject_task_id = 0;
    try std.testing.expectError(error.SubjectTaskRequired, validateHeader(
        .package_install,
        .package_update,
        malformed,
        @sizeOf(PackageUpdateRequest),
        @sizeOf(PackageUpdateResponse),
    ));
}
