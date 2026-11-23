const std = @import("std");
const abi = @import("../core/abi.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const wire = @import("component_abi_wire.zig");

pub const MAGIC = wire.MAGIC;
pub const VERSION = wire.VERSION;

pub const Error = error{
    UnknownInterface,
    UnknownOperation,
    UnsupportedAbiVersion,
    UnsupportedInterfaceVersion,
    InvalidMagic,
    InvalidRequestLength,
    InvalidResponseLength,
    SubjectTaskRequired,
};

pub const WireHeader = wire.WireHeader;

pub const InterfaceKey = enum(u8) {
    task_runtime,
    session_manager,
    policy_mediation,
    permission_review,
    service_registry,
    network_policy,
    object_workspace,
    bootstrap_workspace,
    package_install,
    ui_session,
    index_search,
    sync_replication,
    media_print,
    secure_pasteboard,
    object_resilience,
    sensitive_capture,
    secret_vault,
    attention_broker,
    task_lifecycle,
    personal_context,
};

pub const InterfaceId = enum(u16) {
    task_runtime = 0x1001,
    session_manager = 0x1002,
    policy_mediation = 0x1003,
    permission_review = 0x1004,
    service_registry = 0x1005,
    network_policy = 0x1006,
    object_workspace = 0x1007,
    bootstrap_workspace = 0x1008,
    package_install = 0x1009,
    ui_session = 0x100A,
    index_search = 0x100B,
    sync_replication = 0x100C,
    media_print = 0x100D,
    secure_pasteboard = 0x100E,
    object_resilience = 0x100F,
    sensitive_capture = 0x1010,
    secret_vault = 0x1011,
    attention_broker = 0x1012,
    task_lifecycle = 0x1013,
    personal_context = 0x1014,
};

pub const OperationId = enum(u16) {
    service_register = 0x0101,
    service_connect = 0x0102,
    task_describe = 0x0201,
    workspace_put_version = 0x0301,
    workspace_resolve = 0x0302,
    network_authorize = 0x0401,
    network_open_session = 0x0402,
    network_record_transfer = 0x0403,
    network_revoke_session = 0x0404,
    policy_authorize = 0x0501,
    package_install = 0x0601,
    package_update = 0x0602,
    package_rollback = 0x0603,
    package_remove = 0x0604,
    pasteboard_offer = 0x0701,
    pasteboard_read = 0x0702,
    pasteboard_revoke = 0x0703,
    object_backup_prepare = 0x0801,
    object_restore_authorize = 0x0802,
    object_backup_revoke = 0x0803,
    index_upsert = 0x0901,
    index_query = 0x0902,
    semantic_index_query = 0x0903,
    sync_device_enroll = 0x0A01,
    sync_workspace_replicate = 0x0A02,
    sync_conflict_review = 0x0A03,
    sync_conflict_resolve = 0x0A04,
    sync_transport_frame = 0x0A05,
    capture_start = 0x0B01,
    capture_sample = 0x0B02,
    capture_stop = 0x0B03,
    secret_import = 0x0C01,
    secret_lend = 0x0C02,
    secret_rotate = 0x0C03,
    secret_revoke = 0x0C04,
    attention_post = 0x0D01,
    attention_dismiss = 0x0D02,
    attention_query = 0x0D03,
    lifecycle_suspend = 0x0E01,
    lifecycle_resume = 0x0E02,
    lifecycle_terminate = 0x0E03,
    personal_context_lease = 0x0F01,
    personal_context_query = 0x0F02,
    personal_context_revoke = 0x0F03,
};

const InterfaceSpec = struct {
    id: InterfaceId,
    key: InterfaceKey,
    name: []const u8,
    version_major: u16 = 1,
    version_minor: u16 = 0,
};

fn iface(comptime key: InterfaceKey, comptime name: []const u8) InterfaceSpec {
    return .{
        .id = @field(InterfaceId, @tagName(key)),
        .key = key,
        .name = name,
    };
}

pub const interface_specs = [_]InterfaceSpec{
    iface(.task_runtime, "zigos.task.runtime"),
    iface(.session_manager, "zigos.session.manager"),
    iface(.policy_mediation, "zigos.policy.mediation"),
    iface(.permission_review, "zigos.permission.review"),
    iface(.service_registry, "zigos.service.registry"),
    iface(.network_policy, "zigos.service.network.policy"),
    iface(.object_workspace, "zigos.object.workspace"),
    iface(.bootstrap_workspace, "zigos.bootstrap.workspace"),
    iface(.package_install, "zigos.package.install"),
    iface(.ui_session, "zigos.ui.session"),
    iface(.index_search, "zigos.index.search"),
    iface(.sync_replication, "zigos.sync.replication"),
    iface(.media_print, "zigos.media.print"),
    iface(.secure_pasteboard, "zigos.secure.pasteboard"),
    iface(.object_resilience, "zigos.object.resilience"),
    iface(.sensitive_capture, "zigos.sensitive.capture"),
    iface(.secret_vault, "zigos.secret.vault"),
    iface(.attention_broker, "zigos.attention.broker"),
    iface(.task_lifecycle, "zigos.task.lifecycle"),
    iface(.personal_context, "zigos.personal.context"),
};

pub const INTERFACE_COUNT: usize = interface_specs.len;
const FIRST_INTERFACE_ID: u16 = @backingInt(interface_specs[0].id);

const OperationSpec = struct {
    id: OperationId,
    interface: InterfaceKey,
    name: []const u8,
    Request: type,
    Response: type,
};

fn op(
    comptime interface: InterfaceKey,
    comptime id: OperationId,
    comptime name: []const u8,
    comptime RequestWire: type,
    comptime ResponseWire: type,
) OperationSpec {
    return .{
        .id = id,
        .interface = interface,
        .name = name,
        .Request = RequestWire,
        .Response = ResponseWire,
    };
}

pub const operation_specs = [_]OperationSpec{
    op(.service_registry, .service_register, "register", wire.ServiceRegisterRequestWire, wire.ServiceRegisterResponseWire),
    op(.service_registry, .service_connect, "connect", wire.ServiceConnectionRequestWire, abi.ServiceConnectionDescriptor),
    op(.task_runtime, .task_describe, "describe", wire.TaskDescribeRequestWire, abi.TaskDescriptor),
    op(.object_workspace, .workspace_put_version, "put_version", wire.WorkspacePutVersionRequestWire, wire.WorkspacePutVersionResponseWire),
    op(.object_workspace, .workspace_resolve, "resolve", wire.WorkspaceResolveRequestWire, wire.WorkspaceResolveResponseWire),
    op(.index_search, .index_upsert, "upsert", wire.IndexUpsertRequestWire, wire.IndexResponseWire),
    op(.index_search, .index_query, "query", wire.IndexQueryRequestWire, wire.IndexResponseWire),
    op(.index_search, .semantic_index_query, "semantic_query", wire.SemanticIndexQueryRequestWire, wire.IndexResponseWire),
    op(.sync_replication, .sync_device_enroll, "device_enroll", wire.SyncDeviceEnrollRequestWire, wire.SyncResponseWire),
    op(.sync_replication, .sync_workspace_replicate, "workspace_replicate", wire.SyncWorkspaceReplicateRequestWire, wire.SyncResponseWire),
    op(.sync_replication, .sync_conflict_review, "conflict_review", wire.SyncConflictReviewRequestWire, wire.SyncResponseWire),
    op(.sync_replication, .sync_conflict_resolve, "conflict_resolve", wire.SyncConflictResolveRequestWire, wire.SyncResponseWire),
    op(.sync_replication, .sync_transport_frame, "transport_frame", wire.SyncTransportFrameRequestWire, wire.SyncResponseWire),
    op(.network_policy, .network_authorize, "authorize", wire.NetworkAuthorizeRequestWire, wire.NetworkAuthorizeResponseWire),
    op(.network_policy, .network_open_session, "open_session", wire.NetworkOpenSessionRequestWire, wire.NetworkSessionResponseWire),
    op(.network_policy, .network_record_transfer, "record_transfer", wire.NetworkRecordTransferRequestWire, wire.NetworkSessionResponseWire),
    op(.network_policy, .network_revoke_session, "revoke_session", wire.NetworkRevokeSessionRequestWire, wire.NetworkSessionResponseWire),
    op(.policy_mediation, .policy_authorize, "authorize", wire.PolicyAuthorizeRequestWire, wire.PolicyAuthorizeResponseWire),
    op(.package_install, .package_install, "install", wire.PackageInstallRequestWire, wire.PackageLifecycleResponseWire),
    op(.package_install, .package_update, "update", wire.PackageUpdateRequestWire, wire.PackageLifecycleResponseWire),
    op(.package_install, .package_rollback, "rollback", wire.PackageRollbackRequestWire, wire.PackageLifecycleResponseWire),
    op(.package_install, .package_remove, "remove", wire.PackageRemoveRequestWire, wire.PackageLifecycleResponseWire),
    op(.attention_broker, .attention_post, "post", wire.AttentionPostRequestWire, wire.AttentionResponseWire),
    op(.attention_broker, .attention_dismiss, "dismiss", wire.AttentionDismissRequestWire, wire.AttentionResponseWire),
    op(.attention_broker, .attention_query, "query", wire.AttentionQueryRequestWire, wire.AttentionResponseWire),
    op(.task_lifecycle, .lifecycle_suspend, "suspend", wire.LifecycleControlRequestWire, wire.LifecycleControlResponseWire),
    op(.task_lifecycle, .lifecycle_resume, "resume", wire.LifecycleControlRequestWire, wire.LifecycleControlResponseWire),
    op(.task_lifecycle, .lifecycle_terminate, "terminate", wire.LifecycleControlRequestWire, wire.LifecycleControlResponseWire),
    op(.personal_context, .personal_context_lease, "lease", wire.PersonalContextLeaseRequestWire, wire.PersonalContextResponseWire),
    op(.personal_context, .personal_context_query, "query", wire.PersonalContextQueryRequestWire, wire.PersonalContextResponseWire),
    op(.personal_context, .personal_context_revoke, "revoke", wire.PersonalContextRevokeRequestWire, wire.PersonalContextResponseWire),
    op(.secure_pasteboard, .pasteboard_offer, "offer", wire.PasteboardOfferRequestWire, wire.PasteboardResponseWire),
    op(.secure_pasteboard, .pasteboard_read, "read", wire.PasteboardReadRequestWire, wire.PasteboardResponseWire),
    op(.secure_pasteboard, .pasteboard_revoke, "revoke", wire.PasteboardRevokeRequestWire, wire.PasteboardResponseWire),
    op(.object_resilience, .object_backup_prepare, "backup_prepare", wire.ObjectBackupPrepareRequestWire, wire.ObjectResilienceResponseWire),
    op(.object_resilience, .object_restore_authorize, "restore_authorize", wire.ObjectRestoreAuthorizeRequestWire, wire.ObjectResilienceResponseWire),
    op(.object_resilience, .object_backup_revoke, "backup_revoke", wire.ObjectBackupRevokeRequestWire, wire.ObjectResilienceResponseWire),
    op(.sensitive_capture, .capture_start, "start", wire.CaptureStartRequestWire, wire.CaptureResponseWire),
    op(.sensitive_capture, .capture_sample, "sample", wire.CaptureSampleRequestWire, wire.CaptureResponseWire),
    op(.sensitive_capture, .capture_stop, "stop", wire.CaptureStopRequestWire, wire.CaptureResponseWire),
    op(.secret_vault, .secret_import, "import", wire.SecretImportRequestWire, wire.SecretVaultResponseWire),
    op(.secret_vault, .secret_lend, "lend", wire.SecretLendRequestWire, wire.SecretVaultResponseWire),
    op(.secret_vault, .secret_rotate, "rotate", wire.SecretRotateRequestWire, wire.SecretVaultResponseWire),
    op(.secret_vault, .secret_revoke, "revoke", wire.SecretRevokeRequestWire, wire.SecretVaultResponseWire),
};

pub const OperationDecl = struct {
    id: OperationId,
    request_size: u32,
    response_size: u32,
};

pub const MAX_OPERATIONS_PER_INTERFACE: usize = maxOperationsPerInterface();
pub const OPERATION_DECL_SIZE_CEILING_BYTES: usize = 12;
pub const INTERFACE_CONTRACT_SIZE_CEILING_BYTES: usize = 96;

comptime {
    if (MAX_OPERATIONS_PER_INTERFACE > std.math.maxInt(u8)) {
        @compileError("component ABI operation capacity exceeds its compact count field");
    }
    // Golden service-registry wire layouts: a size change requires a VERSION bump.
    const golden_layouts = .{
        .{ WireHeader, 24 },
        .{ wire.ServiceRegisterRequestWire, 48 },
        .{ wire.ServiceRegisterResponseWire, 4 },
        .{ wire.ServiceConnectionRequestWire, 32 },
        .{ abi.ServiceConnectionDescriptor, 24 },
    };
    for (golden_layouts) |layout| {
        if (@sizeOf(layout[0]) != layout[1]) {
            @compileError(std.fmt.comptimePrint(
                "component ABI wire layout {s} is {d} bytes, not {d}",
                .{ @typeName(layout[0]), @sizeOf(layout[0]), layout[1] },
            ));
        }
    }
}

pub const InterfaceContract = struct {
    interface_id: InterfaceId,
    interface: manifest.InterfaceDecl,
    contract_hash: u64,
    operation_count: u8,
    operations: [MAX_OPERATIONS_PER_INTERFACE]OperationDecl,

    pub fn operation(self: *const InterfaceContract, operation_id: OperationId) ?OperationDecl {
        const ordinal = @backingInt(operation_id) & 0x00FF;
        if (ordinal == 0) return null;
        const operation_index: usize = @intCast(ordinal - 1);
        if (operation_index >= @as(usize, self.operation_count)) return null;
        const decl = self.operations[operation_index];
        return if (decl.id == operation_id) decl else null;
    }

    comptime {
        if (@sizeOf(OperationDecl) > OPERATION_DECL_SIZE_CEILING_BYTES) {
            @compileError("component ABI operation metadata exceeds its compact size ceiling");
        }
        if (@sizeOf(@This()) > INTERFACE_CONTRACT_SIZE_CEILING_BYTES) {
            @compileError("component ABI interface contract exceeds its compact size ceiling");
        }
    }
};

pub const manifest_interfaces = buildManifestInterfaces();
pub const contracts = buildContracts();

pub fn interfaceDecl(comptime key: InterfaceKey) manifest.InterfaceDecl {
    const spec = interfaceSpec(key);
    return .{
        .name = spec.name,
        .version_major = spec.version_major,
        .version_minor = spec.version_minor,
    };
}

pub fn interfaceId(comptime key: InterfaceKey) InterfaceId {
    return interfaceSpec(key).id;
}

pub fn Request(comptime operation_id: OperationId) type {
    return operationSpec(operation_id).Request;
}

pub fn Response(comptime operation_id: OperationId) type {
    return operationSpec(operation_id).Response;
}

pub fn contractFor(interface_name: []const u8) ?*const InterfaceContract {
    for (&contracts) |*iface_contract| {
        if (std.mem.eql(u8, iface_contract.interface.name, interface_name)) return iface_contract;
    }
    return null;
}

pub fn contractForId(interface_id: InterfaceId) *const InterfaceContract {
    return &contracts[interfaceIndexForId(interface_id)];
}

pub fn interfaceIndexForId(interface_id: InterfaceId) usize {
    return @intCast(@backingInt(interface_id) - FIRST_INTERFACE_ID);
}

pub fn interfaceIdForDecl(interface: manifest.InterfaceDecl) ?InterfaceId {
    const iface_contract = contractFor(interface.name) orelse return null;
    return iface_contract.interface_id;
}

pub fn validateInterface(interface: manifest.InterfaceDecl) Error!void {
    const iface_contract = contractFor(interface.name) orelse return error.UnknownInterface;
    if (iface_contract.interface.version_major != interface.version_major) return error.UnsupportedInterfaceVersion;
    if (iface_contract.interface.version_minor != interface.version_minor) return error.UnsupportedInterfaceVersion;
}

pub fn validateInterfaceId(interface_id: InterfaceId, interface: manifest.InterfaceDecl) Error!void {
    const iface_contract = contractForId(interface_id);
    if (!std.mem.eql(u8, iface_contract.interface.name, interface.name)) return error.UnknownInterface;
    if (iface_contract.interface.version_major != interface.version_major) return error.UnsupportedInterfaceVersion;
    if (iface_contract.interface.version_minor != interface.version_minor) return error.UnsupportedInterfaceVersion;
}

pub fn validateMessage(
    interface_id: InterfaceId,
    operation_id: OperationId,
    header: WireHeader,
    actual_request_len: usize,
    actual_response_len: usize,
) Error!void {
    if (header.magic != MAGIC) return error.InvalidMagic;
    if (header.abi_version != VERSION) return error.UnsupportedAbiVersion;
    if (header.subject_task_id == 0) return error.SubjectTaskRequired;
    const iface_contract = contractForId(interface_id);
    if (header.operation != @backingInt(operation_id)) return error.UnknownOperation;
    const operation_decl = iface_contract.operation(operation_id) orelse return error.UnknownOperation;
    if (operation_decl.request_size != actual_request_len) return error.InvalidRequestLength;
    if (operation_decl.response_size != actual_response_len) return error.InvalidResponseLength;
}

fn interfaceSpec(comptime key: InterfaceKey) InterfaceSpec {
    @setEvalBranchQuota(8192);
    inline for (interface_specs) |spec| {
        if (spec.key == key) return spec;
    }
    @compileError("component ABI interface key is missing a schema entry");
}

fn operationSpec(comptime operation_id: OperationId) OperationSpec {
    @setEvalBranchQuota(4096);
    inline for (operation_specs) |spec| {
        if (spec.id == operation_id) return spec;
    }
    @compileError("component ABI operation id is missing a schema entry");
}

fn operationDecl(comptime spec: OperationSpec) OperationDecl {
    return .{
        .id = spec.id,
        .request_size = @intCast(@sizeOf(spec.Request)),
        .response_size = @intCast(@sizeOf(spec.Response)),
    };
}

fn buildManifestInterfaces() [interface_specs.len]manifest.InterfaceDecl {
    @setEvalBranchQuota(4096);
    var entries: [interface_specs.len]manifest.InterfaceDecl = undefined;
    inline for (interface_specs, 0..) |spec, index| {
        entries[index] = .{
            .name = spec.name,
            .version_major = spec.version_major,
            .version_minor = spec.version_minor,
        };
        comptime var peer_index: usize = 0;
        inline while (peer_index < index) : (peer_index += 1) {
            if (interface_specs[peer_index].key == spec.key) @compileError("duplicate component ABI interface key");
            if (std.mem.eql(u8, interface_specs[peer_index].name, spec.name)) @compileError("duplicate component ABI interface name");
        }
    }
    return entries;
}

fn buildContracts() [interface_specs.len]InterfaceContract {
    @setEvalBranchQuota(65536);
    if (interface_specs.len != @typeInfo(InterfaceId).@"enum".field_names.len) {
        @compileError("every component interface id must have one schema contract");
    }
    var result: [interface_specs.len]InterfaceContract = undefined;
    inline for (interface_specs, 0..) |spec, index| {
        if (@as(usize, @backingInt(spec.id)) != @as(usize, FIRST_INTERFACE_ID) + index) {
            @compileError("component interface ids must remain contiguous for direct indexing");
        }
        result[index] = buildContract(spec);
    }
    return result;
}

fn buildContract(comptime spec: InterfaceSpec) InterfaceContract {
    var result = InterfaceContract{
        .interface_id = spec.id,
        .interface = .{
            .name = spec.name,
            .version_major = spec.version_major,
            .version_minor = spec.version_minor,
        },
        .contract_hash = hashContract(spec),
        .operation_count = 0,
        .operations = @as([MAX_OPERATIONS_PER_INTERFACE]OperationDecl, @splat(emptyOperation())),
    };
    comptime var expected_ordinal: u16 = 1;
    comptime var operation_prefix: ?u16 = null;
    inline for (operation_specs) |operation_spec| {
        _ = interfaceSpec(operation_spec.interface);
        if (operation_spec.interface == spec.key) {
            const raw_id = @backingInt(operation_spec.id);
            if ((raw_id & 0x00FF) != expected_ordinal) {
                @compileError("component ABI operation ids must remain contiguous within each interface");
            }
            const prefix = raw_id >> 8;
            if (operation_prefix) |expected_prefix| {
                if (prefix != expected_prefix) {
                    @compileError("component ABI operations for one interface must retain one id prefix");
                }
            } else {
                operation_prefix = prefix;
            }
            result.operations[@as(usize, result.operation_count)] = operationDecl(operation_spec);
            result.operation_count += 1;
            expected_ordinal += 1;
        }
    }
    return result;
}

fn hashContract(comptime spec: InterfaceSpec) u64 {
    @setEvalBranchQuota(65536);
    var hash = native_util.fnv1a64(spec.name);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, spec.version_major);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, spec.version_minor);
    inline for (operation_specs) |operation_spec| {
        if (operation_spec.interface == spec.key) {
            const decl = operationDecl(operation_spec);
            hash = native_util.fnv1a64WithSeed(hash, operation_spec.name);
            hash = native_util.fnv1a64WithSeed(hash, @tagName(decl.id));
            hash = native_util.fnv1a64AppendU64LittleEndian(hash, decl.request_size);
            hash = native_util.fnv1a64AppendU64LittleEndian(hash, decl.response_size);
        }
    }
    return hash;
}

fn emptyOperation() OperationDecl {
    return .{
        .id = operation_specs[0].id,
        .request_size = 0,
        .response_size = 0,
    };
}

fn maxOperationsPerInterface() usize {
    @setEvalBranchQuota(65536);
    comptime var max_count: usize = 0;
    inline for (interface_specs) |interface_spec| {
        comptime var count: usize = 0;
        inline for (operation_specs) |operation_spec| {
            if (operation_spec.interface == interface_spec.key) count += 1;
        }
        if (count > max_count) max_count = count;
    }
    if (max_count == 0) @compileError("component ABI schema must define at least one operation");
    return max_count;
}

test "component ABI schema emits manifest interfaces and interface contracts" {
    try std.testing.expectEqual(OPERATION_DECL_SIZE_CEILING_BYTES, @sizeOf(OperationDecl));
    try std.testing.expectEqual(INTERFACE_CONTRACT_SIZE_CEILING_BYTES, @sizeOf(InterfaceContract));
    try std.testing.expectEqual(interface_specs.len, manifest_interfaces.len);
    try std.testing.expectEqualStrings("zigos.service.registry", interfaceDecl(.service_registry).name);
    try std.testing.expectEqual(InterfaceId.object_workspace, interfaceIdForDecl(interfaceDecl(.object_workspace)).?);
    try std.testing.expectEqual(InterfaceId.service_registry, contractFor(interfaceDecl(.service_registry).name).?.interface_id);
    try std.testing.expectEqual(@as(usize, 0), interfaceIndexForId(.task_runtime));
    try std.testing.expectEqual(INTERFACE_COUNT - 1, interfaceIndexForId(.personal_context));
    const service_registry_contract = contractForId(.service_registry);
    try std.testing.expectEqual(OperationId.service_register, service_registry_contract.operation(.service_register).?.id);
    try std.testing.expect(service_registry_contract.operation(.network_open_session) == null);
    try std.testing.expect(contractForId(.package_install).operation(.package_remove) != null);
    try std.testing.expect(contractForId(.secret_vault).operation(.secret_revoke) != null);
    try std.testing.expect(contractForId(.personal_context).operation(.personal_context_revoke) != null);

    for (&contracts) |*contract| {
        try std.testing.expect(contract.contract_hash != 0);
        for (contract.operations[0..contract.operation_count]) |decl| {
            try std.testing.expectEqual(decl, contract.operation(decl.id).?);
        }
    }
    for (manifest_interfaces) |interface| {
        try validateInterface(interface);
    }
}

test "component ABI rejects incompatible interfaces and malformed messages" {
    try std.testing.expectError(Error.UnknownInterface, validateInterface(.{ .name = "zigos.unknown" }));
    try std.testing.expectError(Error.UnsupportedInterfaceVersion, validateInterface(.{
        .name = "zigos.service.registry",
        .version_major = 2,
        .version_minor = 0,
    }));
    try std.testing.expectError(Error.UnsupportedInterfaceVersion, validateInterface(.{
        .name = "zigos.service.registry",
        .version_major = 1,
        .version_minor = 1,
    }));

    var header = WireHeader{
        .operation = @backingInt(OperationId.service_connect),
        .correlation_id = 1,
        .subject_task_id = 44,
    };
    const request_len = @sizeOf(Request(.service_connect));
    const response_len = @sizeOf(Response(.service_connect));
    try validateMessage(.service_registry, .service_connect, header, request_len, response_len);
    try std.testing.expectError(Error.UnknownOperation, validateMessage(
        .service_registry,
        .network_open_session,
        .{ .operation = @backingInt(OperationId.network_open_session), .correlation_id = 2, .subject_task_id = 44 },
        @sizeOf(Request(.network_open_session)),
        @sizeOf(Response(.network_open_session)),
    ));
    try std.testing.expectError(Error.UnknownOperation, validateMessage(
        .service_registry,
        .service_register,
        header,
        @sizeOf(Request(.service_register)),
        @sizeOf(Response(.service_register)),
    ));
    header.abi_version = VERSION - 1;
    try std.testing.expectError(Error.UnsupportedAbiVersion, validateMessage(.service_registry, .service_connect, header, request_len, response_len));
    header.abi_version = VERSION;
    header.magic = 0;
    try std.testing.expectError(Error.InvalidMagic, validateMessage(.service_registry, .service_connect, header, request_len, response_len));
    header.magic = MAGIC;
    try std.testing.expectError(Error.InvalidRequestLength, validateMessage(.service_registry, .service_connect, header, request_len - 1, response_len));
    try std.testing.expectError(Error.InvalidResponseLength, validateMessage(.service_registry, .service_connect, header, request_len, response_len + 1));
    header.subject_task_id = 0;
    try std.testing.expectError(Error.SubjectTaskRequired, validateMessage(.service_registry, .service_connect, header, request_len, response_len));
}
