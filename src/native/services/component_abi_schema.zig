const std = @import("std");
const abi = @import("../core/abi.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");

pub const MAGIC: u32 = 0x54434142; // TCAB
pub const VERSION: u16 = 1;

const COMPONENT_MODEL_REQ = "REQ-COMPONENT-MODEL";
const SCHEMA_TEST_FILE = "src/native/services/component_abi_schema.zig";
const ABI_TEST_FILE = "src/native/services/typed_component_abi.zig";
const SCHEMA_TEST_NAME = "component ABI schema emits manifest interfaces and service catalog bindings";
const ABI_TEST_NAME = "typed component ABI derives operation IDs, wire types, and validators from schema";

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
    compat_portal,
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
    compat_portal = 0x100E,
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

pub const ServiceBinding = enum(u8) {
    task_runtime,
    session_manager,
    policy_mediation,
    permission_review_ui,
    service_registry,
    compatibility_portal,
    network_stack,
    storage_object,
    package_install_update,
    compositor_ui_session,
    indexing_search,
    sync_replication,
    media_print_helpers,
};

const ServiceRegisterRequestWire = extern struct {
    header: WireHeader,
    service_id: u64,
    owner_task_id: u64,
    endpoint_id: u64,
    flags: u16,
    interface_id: u16,
    interface_name_len: u16,
    version_major: u16,
    version_minor: u16,
};

const ServiceConnectionRequestWire = extern struct {
    header: WireHeader,
    interface_id: u16,
    version_major: u16,
    version_minor: u16,
    _reserved: u16 = 0,
};

const TaskDescribeRequestWire = extern struct {
    header: WireHeader,
    task_id: u64,
};

const WorkspacePutVersionRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    object_id: u64,
    object_type: u16,
    payload_len: u32,
};

const WorkspaceResolveRequestWire = extern struct {
    header: WireHeader,
    workspace_id: u64,
    path_len: u16,
    _reserved: u16 = 0,
};

const NetworkAuthorizeRequestWire = extern struct {
    header: WireHeader,
    policy_id: u64,
    destination_len: u16,
    flags: u16,
};

const PolicyAuthorizeRequestWire = extern struct {
    header: WireHeader,
    requester_task_id: u64,
    permission_kind: u16,
    resource_len: u16,
};

const ServiceRegisterResponseWire = extern struct {
    accepted: u32,
};

const WorkspacePutVersionResponseWire = extern struct {
    object_id: u64,
    version_id: u64,
};

const WorkspaceResolveResponseWire = extern struct {
    object_id: u64,
    version_id: u64,
    object_type: u16,
};

const NetworkAuthorizeResponseWire = extern struct {
    allowed: u32,
    reason: u16,
};

const PolicyAuthorizeResponseWire = extern struct {
    allowed: u32,
    denial_reason: u16,
};

const InterfaceSpec = struct {
    id: InterfaceId,
    key: InterfaceKey,
    name: []const u8,
    version_major: u16 = 1,
    version_minor: u16 = 0,
    coverage_requirement_id: []const u8 = COMPONENT_MODEL_REQ,
    coverage_file: []const u8 = SCHEMA_TEST_FILE,
    coverage_test_name: []const u8 = SCHEMA_TEST_NAME,
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
    iface(.compat_portal, "zigos.compat.portal"),
};

const OperationSpec = struct {
    id: OperationId,
    interface: InterfaceKey,
    name: []const u8,
    Request: type,
    Response: type,
    coverage_requirement_id: []const u8 = COMPONENT_MODEL_REQ,
    coverage_file: []const u8 = ABI_TEST_FILE,
    coverage_test_name: []const u8 = ABI_TEST_NAME,
};

fn op(
    comptime interface: InterfaceKey,
    comptime id: OperationId,
    comptime name: []const u8,
    comptime Request: type,
    comptime Response: type,
) OperationSpec {
    return .{
        .id = id,
        .interface = interface,
        .name = name,
        .Request = Request,
        .Response = Response,
    };
}

pub const operation_specs = [_]OperationSpec{
    op(.service_registry, .service_register, "register", ServiceRegisterRequestWire, ServiceRegisterResponseWire),
    op(.service_registry, .service_connect, "connect", ServiceConnectionRequestWire, abi.ServiceConnectionDescriptor),
    op(.task_runtime, .task_describe, "describe", TaskDescribeRequestWire, abi.TaskDescriptor),
    op(.object_workspace, .workspace_put_version, "put_version", WorkspacePutVersionRequestWire, WorkspacePutVersionResponseWire),
    op(.object_workspace, .workspace_resolve, "resolve", WorkspaceResolveRequestWire, WorkspaceResolveResponseWire),
    op(.network_policy, .network_authorize, "authorize", NetworkAuthorizeRequestWire, NetworkAuthorizeResponseWire),
    op(.policy_mediation, .policy_authorize, "authorize", PolicyAuthorizeRequestWire, PolicyAuthorizeResponseWire),
};

const ServiceBindingSpec = struct {
    service: ServiceBinding,
    interface: InterfaceKey,
    coverage_requirement_id: []const u8 = COMPONENT_MODEL_REQ,
    coverage_file: []const u8 = SCHEMA_TEST_FILE,
    coverage_test_name: []const u8 = SCHEMA_TEST_NAME,
};

fn binding(comptime service: ServiceBinding, comptime interface: InterfaceKey) ServiceBindingSpec {
    return .{ .service = service, .interface = interface };
}

pub const service_binding_specs = [_]ServiceBindingSpec{
    binding(.task_runtime, .task_runtime),
    binding(.session_manager, .session_manager),
    binding(.policy_mediation, .policy_mediation),
    binding(.permission_review_ui, .permission_review),
    binding(.service_registry, .service_registry),
    binding(.compatibility_portal, .compat_portal),
    binding(.network_stack, .network_policy),
    binding(.storage_object, .object_workspace),
    binding(.package_install_update, .package_install),
    binding(.compositor_ui_session, .ui_session),
    binding(.indexing_search, .index_search),
    binding(.sync_replication, .sync_replication),
    binding(.media_print_helpers, .media_print),
};

pub const OperationDecl = struct {
    id: OperationId,
    name: []const u8,
    request_size: u32,
    response_size: u32,
    coverage_requirement_id: []const u8,
};

pub const MAX_OPERATIONS_PER_INTERFACE: usize = maxOperationsPerInterface();

pub const InterfaceContract = struct {
    interface_id: InterfaceId,
    interface: manifest.InterfaceDecl,
    contract_hash: u64,
    coverage_requirement_id: []const u8,
    operation_count: usize,
    operations: [MAX_OPERATIONS_PER_INTERFACE]OperationDecl,

    pub fn operation(self: *const InterfaceContract, operation_id: OperationId) ?OperationDecl {
        for (self.operations[0..self.operation_count]) |decl| {
            if (decl.id == operation_id) return decl;
        }
        return null;
    }
};

pub const ServiceCatalogBinding = struct {
    service: ServiceBinding,
    interface_id: InterfaceId,
    interface: manifest.InterfaceDecl,
    coverage_requirement_id: []const u8,
};

pub const manifest_interfaces = buildManifestInterfaces();
pub const service_catalog_bindings = buildServiceCatalogBindings();
pub const contracts = buildContracts();

pub const CoverageReferenceKind = enum(u8) {
    manifest_interface,
    service_catalog_binding,
    contract_operation,
};

pub const CoverageReference = struct {
    kind: CoverageReferenceKind,
    requirement_id: []const u8,
    file: []const u8,
    test_name: []const u8,
    service_name: []const u8 = "",
    interface_name: []const u8,
    operation_name: []const u8 = "",
};

pub const coverage_references = buildCoverageReferences();

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

pub fn interfaceForService(comptime service: ServiceBinding) manifest.InterfaceDecl {
    return interfaceDecl(serviceBindingSpec(service).interface);
}

pub fn interfaceIdForService(comptime service: ServiceBinding) InterfaceId {
    return interfaceId(serviceBindingSpec(service).interface);
}

pub fn requestType(comptime operation_id: OperationId) type {
    return operationSpec(operation_id).Request;
}

pub fn responseType(comptime operation_id: OperationId) type {
    return operationSpec(operation_id).Response;
}

pub fn contractFor(interface_name: []const u8) ?*const InterfaceContract {
    for (&contracts) |*iface_contract| {
        if (std.mem.eql(u8, iface_contract.interface.name, interface_name)) return iface_contract;
    }
    return null;
}

pub fn contractForId(interface_id: InterfaceId) ?*const InterfaceContract {
    for (&contracts) |*iface_contract| {
        if (iface_contract.interface_id == interface_id) return iface_contract;
    }
    return null;
}

pub fn interfaceIdForDecl(interface: manifest.InterfaceDecl) ?InterfaceId {
    const iface_contract = contractFor(interface.name) orelse return null;
    return iface_contract.interface_id;
}

pub fn validateInterface(interface: manifest.InterfaceDecl) Error!void {
    const iface_contract = contractFor(interface.name) orelse return error.UnknownInterface;
    if (iface_contract.interface.version_major != interface.version_major) return error.UnsupportedInterfaceVersion;
    if (interface.version_minor < iface_contract.interface.version_minor) return error.UnsupportedInterfaceVersion;
}

pub fn validateInterfaceId(interface_id: InterfaceId, interface: manifest.InterfaceDecl) Error!void {
    const iface_contract = contractForId(interface_id) orelse return error.UnknownInterface;
    if (!std.mem.eql(u8, iface_contract.interface.name, interface.name)) return error.UnknownInterface;
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

pub fn coverageReferenceCountForRequirement(requirement_id: []const u8) usize {
    var count: usize = 0;
    for (coverage_references) |reference| {
        if (std.mem.eql(u8, reference.requirement_id, requirement_id)) count += 1;
    }
    return count;
}

fn interfaceSpec(comptime key: InterfaceKey) InterfaceSpec {
    inline for (interface_specs) |spec| {
        if (spec.key == key) return spec;
    }
    @compileError("component ABI interface key is missing a schema entry");
}

fn serviceBindingSpec(comptime service: ServiceBinding) ServiceBindingSpec {
    inline for (service_binding_specs) |spec| {
        if (spec.service == service) return spec;
    }
    @compileError("component ABI service binding key is missing a schema entry");
}

fn operationSpec(comptime operation_id: OperationId) OperationSpec {
    inline for (operation_specs) |spec| {
        if (spec.id == operation_id) return spec;
    }
    @compileError("component ABI operation id is missing a schema entry");
}

fn operationDecl(comptime spec: OperationSpec) OperationDecl {
    return .{
        .id = spec.id,
        .name = spec.name,
        .request_size = @intCast(@sizeOf(spec.Request)),
        .response_size = @intCast(@sizeOf(spec.Response)),
        .coverage_requirement_id = spec.coverage_requirement_id,
    };
}

fn buildManifestInterfaces() [interface_specs.len]manifest.InterfaceDecl {
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

fn buildServiceCatalogBindings() [service_binding_specs.len]ServiceCatalogBinding {
    var entries: [service_binding_specs.len]ServiceCatalogBinding = undefined;
    inline for (service_binding_specs, 0..) |spec, index| {
        entries[index] = .{
            .service = spec.service,
            .interface_id = interfaceId(spec.interface),
            .interface = interfaceDecl(spec.interface),
            .coverage_requirement_id = spec.coverage_requirement_id,
        };
        comptime var peer_index: usize = 0;
        inline while (peer_index < index) : (peer_index += 1) {
            if (service_binding_specs[peer_index].service == spec.service) @compileError("duplicate component ABI service catalog binding");
        }
    }
    return entries;
}

fn buildContracts() [interface_specs.len]InterfaceContract {
    var result: [interface_specs.len]InterfaceContract = undefined;
    inline for (interface_specs, 0..) |spec, index| {
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
        .coverage_requirement_id = spec.coverage_requirement_id,
        .operation_count = 0,
        .operations = [_]OperationDecl{emptyOperation()} ** MAX_OPERATIONS_PER_INTERFACE,
    };
    inline for (operation_specs) |operation_spec| {
        _ = interfaceSpec(operation_spec.interface);
        if (operation_spec.interface == spec.key) {
            result.operations[result.operation_count] = operationDecl(operation_spec);
            result.operation_count += 1;
        }
    }
    return result;
}

fn hashContract(comptime spec: InterfaceSpec) u64 {
    @setEvalBranchQuota(4096);
    var hash = native_util.fnv1a64(spec.name);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, spec.version_major);
    hash = native_util.fnv1a64AppendU64LittleEndian(hash, spec.version_minor);
    inline for (operation_specs) |operation_spec| {
        if (operation_spec.interface == spec.key) {
            const decl = operationDecl(operation_spec);
            hash = native_util.fnv1a64WithSeed(hash, decl.name);
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
        .name = "",
        .request_size = 0,
        .response_size = 0,
        .coverage_requirement_id = "",
    };
}

fn maxOperationsPerInterface() usize {
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

fn buildCoverageReferences() [interface_specs.len + service_binding_specs.len + operation_specs.len]CoverageReference {
    var refs: [interface_specs.len + service_binding_specs.len + operation_specs.len]CoverageReference = undefined;
    var index: usize = 0;
    inline for (interface_specs) |spec| {
        refs[index] = .{
            .kind = .manifest_interface,
            .requirement_id = spec.coverage_requirement_id,
            .file = spec.coverage_file,
            .test_name = spec.coverage_test_name,
            .interface_name = spec.name,
        };
        index += 1;
    }
    inline for (service_binding_specs) |spec| {
        const iface_spec = interfaceSpec(spec.interface);
        refs[index] = .{
            .kind = .service_catalog_binding,
            .requirement_id = spec.coverage_requirement_id,
            .file = spec.coverage_file,
            .test_name = spec.coverage_test_name,
            .service_name = @tagName(spec.service),
            .interface_name = iface_spec.name,
        };
        index += 1;
    }
    inline for (operation_specs) |spec| {
        const iface_spec = interfaceSpec(spec.interface);
        refs[index] = .{
            .kind = .contract_operation,
            .requirement_id = spec.coverage_requirement_id,
            .file = spec.coverage_file,
            .test_name = spec.coverage_test_name,
            .interface_name = iface_spec.name,
            .operation_name = spec.name,
        };
        index += 1;
    }
    return refs;
}

test "component ABI schema emits manifest interfaces and service catalog bindings" {
    try std.testing.expectEqual(interface_specs.len, manifest_interfaces.len);
    try std.testing.expectEqual(service_binding_specs.len, service_catalog_bindings.len);
    try std.testing.expectEqualStrings("zigos.service.registry", interfaceDecl(.service_registry).name);
    try std.testing.expectEqualStrings("zigos.service.network.policy", interfaceForService(.network_stack).name);
    try std.testing.expectEqualStrings("zigos.object.workspace", interfaceForService(.storage_object).name);
    try std.testing.expectEqual(InterfaceId.service_registry, interfaceId(.service_registry));
    try std.testing.expectEqual(InterfaceId.object_workspace, interfaceIdForService(.storage_object));
    try std.testing.expectEqual(InterfaceId.object_workspace, interfaceIdForDecl(interfaceForService(.storage_object)).?);
    try std.testing.expectEqual(InterfaceId.service_registry, contractFor(interfaceForService(.service_registry).name).?.interface_id);
    try std.testing.expect(contractFor(interfaceForService(.service_registry).name).?.contract_hash != 0);
    try std.testing.expect(contractFor(interfaceForService(.sync_replication).name).?.contract_hash != 0);
    try std.testing.expectEqual(
        interface_specs.len + service_binding_specs.len + operation_specs.len,
        coverageReferenceCountForRequirement(COMPONENT_MODEL_REQ),
    );

    for (service_catalog_bindings) |entry| {
        try validateInterface(entry.interface);
    }
}
