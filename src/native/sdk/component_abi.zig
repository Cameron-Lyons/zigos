const std = @import("std");
const idl = @import("idl.zig");
const manifest = @import("../policy/manifest.zig");
const typed_component_abi = @import("../services/typed_component_abi.zig");

pub const MAGIC = typed_component_abi.MAGIC;
pub const VERSION = typed_component_abi.VERSION;
pub const InterfaceKey = typed_component_abi.InterfaceKey;
pub const InterfaceId = typed_component_abi.InterfaceId;
pub const OperationId = typed_component_abi.OperationId;
pub const OperationDecl = typed_component_abi.OperationDecl;
pub const InterfaceContract = typed_component_abi.InterfaceContract;
pub const WireHeader = typed_component_abi.WireHeader;
pub const PackageInstallRequest = typed_component_abi.PackageInstallRequest;
pub const PackageInstallResponse = typed_component_abi.PackageInstallResponse;
pub const PackageUpdateRequest = typed_component_abi.PackageUpdateRequest;
pub const PackageUpdateResponse = typed_component_abi.PackageUpdateResponse;
pub const COMPACT_COMPONENT_BINDING_METADATA = true;
pub const BINDING_SIZE_CEILING_BYTES: usize = 40;
pub const Error = typed_component_abi.Error || idl.Error || error{
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
    const abi_contract = typed_component_abi.contractForId(typed_component_abi.interfaceId(key));
    return .{
        .interface_id = abi_contract.interface_id,
        .interface = abi_contract.interface,
        .contract_hash = abi_contract.contract_hash,
        .operation_count = abi_contract.operation_count,
    };
}

pub fn contract(comptime key: InterfaceKey) *const InterfaceContract {
    return typed_component_abi.contractForId(typed_component_abi.interfaceId(key));
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
        .operation = @intFromEnum(operation_id),
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
    return typed_component_abi.validateMessage(
        typed_component_abi.interfaceId(key),
        operation_id,
        wire_header,
        actual_request_len,
        actual_response_len,
    );
}

test "SDK component ABI exposes typed bindings and validates real wire headers" {
    const bind = binding(.package_install);
    try std.testing.expect(COMPACT_COMPONENT_BINDING_METADATA);
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
        @sizeOf(typed_component_abi.PackageUpdateRequest),
        @sizeOf(typed_component_abi.PackageUpdateResponse),
    );

    var malformed = wire_header;
    malformed.subject_task_id = 0;
    try std.testing.expectError(error.SubjectTaskRequired, validateHeader(
        .package_install,
        .package_update,
        malformed,
        @sizeOf(typed_component_abi.PackageUpdateRequest),
        @sizeOf(typed_component_abi.PackageUpdateResponse),
    ));
}
