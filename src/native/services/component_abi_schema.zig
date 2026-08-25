const std = @import("std");
const abi = @import("../core/abi.zig");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const wire = @import("component_abi_wire.zig");

pub const MAGIC = wire.MAGIC;
pub const VERSION = wire.VERSION;
pub const EXACT_INTERFACE_VERSIONS = true;
pub const TYPED_ID_ONLY_MESSAGE_VALIDATION = true;

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
    ai_inference,
    ai_model_registry,
    privacy_budget,
    diagnostics_export,
    consent_receipts,
    permission_lease,
    data_rights,
    identity_session,
    agent_delegation,
    accessibility_profile,
    background_activity,
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
    ai_inference = 0x100E,
    ai_model_registry = 0x100F,
    privacy_budget = 0x1010,
    diagnostics_export = 0x1011,
    consent_receipts = 0x1012,
    permission_lease = 0x1013,
    data_rights = 0x1014,
    identity_session = 0x1015,
    agent_delegation = 0x1016,
    accessibility_profile = 0x1017,
    background_activity = 0x1018,
    secure_pasteboard = 0x1019,
    object_resilience = 0x101A,
    sensitive_capture = 0x101B,
    secret_vault = 0x101C,
    attention_broker = 0x101D,
    task_lifecycle = 0x101E,
    personal_context = 0x101F,
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
    ai_authorize = 0x0701,
    ai_run_local = 0x0702,
    ai_model_register = 0x0D01,
    ai_model_attest = 0x0D02,
    ai_model_revoke = 0x0D03,
    privacy_authorize_egress = 0x0801,
    privacy_query_budget = 0x0802,
    diagnostics_prepare_export = 0x0901,
    diagnostics_share_remote = 0x0902,
    consent_record = 0x0A01,
    consent_revoke = 0x0A02,
    permission_lease_issue = 0x0B01,
    permission_lease_renew = 0x0B02,
    permission_lease_expire = 0x0B03,
    data_export_prepare = 0x0C01,
    data_delete_request = 0x0C02,
    data_delete_receipt = 0x0C03,
    identity_session_authorize = 0x0E01,
    identity_session_step_up = 0x0E02,
    identity_session_revoke = 0x0E03,
    identity_credential_register = 0x0E04,
    identity_credential_assert = 0x0E05,
    identity_credential_recover = 0x0E06,
    identity_credential_revoke = 0x0E07,
    agent_authorize = 0x0F01,
    agent_record_action = 0x0F02,
    agent_revoke = 0x0F03,
    agent_bind_session = 0x0F04,
    agent_kill_switch = 0x0F05,
    accessibility_profile_get = 0x1001,
    accessibility_profile_apply = 0x1002,
    accessibility_profile_audit = 0x1003,
    background_authorize = 0x1101,
    background_record = 0x1102,
    background_complete = 0x1103,
    pasteboard_offer = 0x1201,
    pasteboard_read = 0x1202,
    pasteboard_revoke = 0x1203,
    object_backup_prepare = 0x1301,
    object_restore_authorize = 0x1302,
    object_backup_revoke = 0x1303,
    index_upsert = 0x1401,
    index_query = 0x1402,
    semantic_index_query = 0x1403,
    sync_device_enroll = 0x1501,
    sync_workspace_replicate = 0x1502,
    sync_conflict_review = 0x1503,
    sync_conflict_resolve = 0x1504,
    sync_transport_frame = 0x1505,
    capture_start = 0x1601,
    capture_sample = 0x1602,
    capture_stop = 0x1603,
    secret_import = 0x1701,
    secret_lend = 0x1702,
    secret_rotate = 0x1703,
    secret_revoke = 0x1704,
    attention_post = 0x1801,
    attention_dismiss = 0x1802,
    attention_query = 0x1803,
    lifecycle_suspend = 0x1901,
    lifecycle_resume = 0x1902,
    lifecycle_terminate = 0x1903,
    personal_context_lease = 0x1A01,
    personal_context_query = 0x1A02,
    personal_context_revoke = 0x1A03,
};

pub const ServiceBinding = enum(u8) {
    task_runtime,
    session_manager,
    policy_mediation,
    permission_review_ui,
    service_registry,
    network_stack,
    storage_object,
    package_install_update,
    compositor_ui_session,
    indexing_search,
    sync_replication,
    media_print_helpers,
    attention_broker,
    task_lifecycle,
    secure_pasteboard,
    object_resilience,
    sensitive_capture,
    secret_vault,
    personal_context,
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
    iface(.ai_inference, "zigos.ai.inference"),
    iface(.ai_model_registry, "zigos.ai.model.registry"),
    iface(.privacy_budget, "zigos.privacy.budget"),
    iface(.diagnostics_export, "zigos.diagnostics.export"),
    iface(.consent_receipts, "zigos.consent.receipts"),
    iface(.permission_lease, "zigos.permission.lease"),
    iface(.data_rights, "zigos.data.rights"),
    iface(.identity_session, "zigos.identity.session"),
    iface(.agent_delegation, "zigos.agent.delegation"),
    iface(.accessibility_profile, "zigos.accessibility.profile"),
    iface(.background_activity, "zigos.background.activity"),
    iface(.secure_pasteboard, "zigos.secure.pasteboard"),
    iface(.object_resilience, "zigos.object.resilience"),
    iface(.sensitive_capture, "zigos.sensitive.capture"),
    iface(.secret_vault, "zigos.secret.vault"),
    iface(.attention_broker, "zigos.attention.broker"),
    iface(.task_lifecycle, "zigos.task.lifecycle"),
    iface(.personal_context, "zigos.personal.context"),
};

pub const INTERFACE_COUNT: usize = interface_specs.len;
pub const DIRECT_INTERFACE_INDEX = true;
pub const TOTAL_INTERFACE_ID_MAP = true;
const FIRST_INTERFACE_ID: u16 = @intFromEnum(interface_specs[0].id);

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
    op(.ai_inference, .ai_authorize, "authorize", wire.AiAuthorizeRequestWire, wire.AiAuthorizeResponseWire),
    op(.ai_inference, .ai_run_local, "run_local", wire.AiRunLocalRequestWire, wire.AiRunLocalResponseWire),
    op(.ai_model_registry, .ai_model_register, "register", wire.AiModelRegisterRequestWire, wire.AiModelRegistryResponseWire),
    op(.ai_model_registry, .ai_model_attest, "attest", wire.AiModelAttestRequestWire, wire.AiModelRegistryResponseWire),
    op(.ai_model_registry, .ai_model_revoke, "revoke", wire.AiModelRevokeRequestWire, wire.AiModelRegistryResponseWire),
    op(.privacy_budget, .privacy_authorize_egress, "authorize_egress", wire.PrivacyAuthorizeEgressRequestWire, wire.PrivacyAuthorizeEgressResponseWire),
    op(.privacy_budget, .privacy_query_budget, "query_budget", wire.PrivacyQueryBudgetRequestWire, wire.PrivacyQueryBudgetResponseWire),
    op(.diagnostics_export, .diagnostics_prepare_export, "prepare_export", wire.DiagnosticsPrepareExportRequestWire, wire.DiagnosticsExportResponseWire),
    op(.diagnostics_export, .diagnostics_share_remote, "share_remote", wire.DiagnosticsShareRemoteRequestWire, wire.DiagnosticsExportResponseWire),
    op(.consent_receipts, .consent_record, "record", wire.ConsentRecordRequestWire, wire.ConsentReceiptResponseWire),
    op(.consent_receipts, .consent_revoke, "revoke", wire.ConsentRevokeRequestWire, wire.ConsentReceiptResponseWire),
    op(.permission_lease, .permission_lease_issue, "issue", wire.PermissionLeaseIssueRequestWire, wire.PermissionLeaseResponseWire),
    op(.permission_lease, .permission_lease_renew, "renew", wire.PermissionLeaseRenewRequestWire, wire.PermissionLeaseResponseWire),
    op(.permission_lease, .permission_lease_expire, "expire", wire.PermissionLeaseExpireRequestWire, wire.PermissionLeaseResponseWire),
    op(.data_rights, .data_export_prepare, "export_prepare", wire.DataExportPrepareRequestWire, wire.DataRightsResponseWire),
    op(.data_rights, .data_delete_request, "delete_request", wire.DataDeleteRequestWire, wire.DataRightsResponseWire),
    op(.data_rights, .data_delete_receipt, "delete_receipt", wire.DataDeleteReceiptRequestWire, wire.DataRightsResponseWire),
    op(.identity_session, .identity_session_authorize, "authorize", wire.IdentitySessionAuthorizeRequestWire, wire.IdentitySessionResponseWire),
    op(.identity_session, .identity_session_step_up, "step_up", wire.IdentitySessionStepUpRequestWire, wire.IdentitySessionResponseWire),
    op(.identity_session, .identity_session_revoke, "revoke", wire.IdentitySessionRevokeRequestWire, wire.IdentitySessionResponseWire),
    op(.identity_session, .identity_credential_register, "credential_register", wire.IdentityCredentialRegisterRequestWire, wire.IdentityCredentialResponseWire),
    op(.identity_session, .identity_credential_assert, "credential_assert", wire.IdentityCredentialAssertRequestWire, wire.IdentityCredentialResponseWire),
    op(.identity_session, .identity_credential_recover, "credential_recover", wire.IdentityCredentialRecoverRequestWire, wire.IdentityCredentialResponseWire),
    op(.identity_session, .identity_credential_revoke, "credential_revoke", wire.IdentityCredentialRevokeRequestWire, wire.IdentityCredentialResponseWire),
    op(.agent_delegation, .agent_authorize, "authorize", wire.AgentAuthorizeRequestWire, wire.AgentDelegationResponseWire),
    op(.agent_delegation, .agent_record_action, "record_action", wire.AgentRecordActionRequestWire, wire.AgentDelegationResponseWire),
    op(.agent_delegation, .agent_revoke, "revoke", wire.AgentRevokeRequestWire, wire.AgentDelegationResponseWire),
    op(.agent_delegation, .agent_bind_session, "bind_session", wire.AgentBindSessionRequestWire, wire.AgentDelegationResponseWire),
    op(.agent_delegation, .agent_kill_switch, "kill_switch", wire.AgentKillSwitchRequestWire, wire.AgentDelegationResponseWire),
    op(.accessibility_profile, .accessibility_profile_get, "get_profile", wire.AccessibilityProfileGetRequestWire, wire.AccessibilityProfileResponseWire),
    op(.accessibility_profile, .accessibility_profile_apply, "apply_profile", wire.AccessibilityProfileApplyRequestWire, wire.AccessibilityProfileResponseWire),
    op(.accessibility_profile, .accessibility_profile_audit, "audit_profile", wire.AccessibilityProfileAuditRequestWire, wire.AccessibilityProfileResponseWire),
    op(.background_activity, .background_authorize, "authorize", wire.BackgroundAuthorizeRequestWire, wire.BackgroundActivityResponseWire),
    op(.background_activity, .background_record, "record", wire.BackgroundRecordRequestWire, wire.BackgroundActivityResponseWire),
    op(.background_activity, .background_complete, "complete", wire.BackgroundCompleteRequestWire, wire.BackgroundActivityResponseWire),
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
    binding(.network_stack, .network_policy),
    binding(.storage_object, .object_workspace),
    binding(.package_install_update, .package_install),
    binding(.compositor_ui_session, .ui_session),
    binding(.indexing_search, .index_search),
    binding(.sync_replication, .sync_replication),
    binding(.media_print_helpers, .media_print),
    binding(.attention_broker, .attention_broker),
    binding(.task_lifecycle, .task_lifecycle),
    binding(.secure_pasteboard, .secure_pasteboard),
    binding(.object_resilience, .object_resilience),
    binding(.sensitive_capture, .sensitive_capture),
    binding(.secret_vault, .secret_vault),
    binding(.personal_context, .personal_context),
};

pub const OperationDecl = struct {
    id: OperationId,
    request_size: u32,
    response_size: u32,
};

pub const MAX_OPERATIONS_PER_INTERFACE: usize = maxOperationsPerInterface();
pub const COMPACT_INTERFACE_CONTRACT_METADATA = true;
pub const DIRECT_OPERATION_INDEX = true;
pub const OPERATION_DECL_SIZE_CEILING_BYTES: usize = 12;
pub const INTERFACE_CONTRACT_SIZE_CEILING_BYTES: usize = 120;

comptime {
    if (MAX_OPERATIONS_PER_INTERFACE > std.math.maxInt(u8)) {
        @compileError("component ABI operation capacity exceeds its compact count field");
    }
}

pub const InterfaceContract = struct {
    interface_id: InterfaceId,
    interface: manifest.InterfaceDecl,
    contract_hash: u64,
    operation_count: u8,
    operations: [MAX_OPERATIONS_PER_INTERFACE]OperationDecl,

    pub fn operation(self: *const InterfaceContract, operation_id: OperationId) ?OperationDecl {
        const ordinal = @intFromEnum(operation_id) & 0x00FF;
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

pub fn contractForId(interface_id: InterfaceId) *const InterfaceContract {
    return &contracts[interfaceIndexForId(interface_id)];
}

pub fn interfaceIndexForId(interface_id: InterfaceId) usize {
    return @intCast(@intFromEnum(interface_id) - FIRST_INTERFACE_ID);
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
    if (header.operation != @intFromEnum(operation_id)) return error.UnknownOperation;
    if (header.request_len != actual_request_len) return error.MalformedMessage;
    if (header.response_len != actual_response_len) return error.MalformedMessage;

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
    @setEvalBranchQuota(8192);
    inline for (interface_specs) |spec| {
        if (spec.key == key) return spec;
    }
    @compileError("component ABI interface key is missing a schema entry");
}

fn serviceBindingSpec(comptime service: ServiceBinding) ServiceBindingSpec {
    @setEvalBranchQuota(2048);
    inline for (service_binding_specs) |spec| {
        if (spec.service == service) return spec;
    }
    @compileError("component ABI service binding key is missing a schema entry");
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
    @setEvalBranchQuota(65536);
    if (interface_specs.len != std.meta.fields(InterfaceId).len) {
        @compileError("every component interface id must have one schema contract");
    }
    var result: [interface_specs.len]InterfaceContract = undefined;
    inline for (interface_specs, 0..) |spec, index| {
        if (@as(usize, @intFromEnum(spec.id)) != @as(usize, FIRST_INTERFACE_ID) + index) {
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
        .operations = [_]OperationDecl{emptyOperation()} ** MAX_OPERATIONS_PER_INTERFACE,
    };
    comptime var expected_ordinal: u16 = 1;
    comptime var operation_prefix: ?u16 = null;
    inline for (operation_specs) |operation_spec| {
        _ = interfaceSpec(operation_spec.interface);
        if (operation_spec.interface == spec.key) {
            const raw_id = @intFromEnum(operation_spec.id);
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
    try std.testing.expect(DIRECT_INTERFACE_INDEX);
    try std.testing.expect(TOTAL_INTERFACE_ID_MAP);
    try std.testing.expect(COMPACT_INTERFACE_CONTRACT_METADATA);
    try std.testing.expect(DIRECT_OPERATION_INDEX);
    try std.testing.expectEqual(u8, @FieldType(InterfaceContract, "operation_count"));
    try std.testing.expectEqual(OPERATION_DECL_SIZE_CEILING_BYTES, @sizeOf(OperationDecl));
    try std.testing.expectEqual(INTERFACE_CONTRACT_SIZE_CEILING_BYTES, @sizeOf(InterfaceContract));
    try std.testing.expectEqual(interface_specs.len, manifest_interfaces.len);
    try std.testing.expectEqual(interface_specs.len, INTERFACE_COUNT);
    try std.testing.expectEqual(service_binding_specs.len, service_catalog_bindings.len);
    try std.testing.expectEqualStrings("zigos.service.registry", interfaceDecl(.service_registry).name);
    try std.testing.expectEqualStrings("zigos.service.network.policy", interfaceForService(.network_stack).name);
    try std.testing.expectEqualStrings("zigos.object.workspace", interfaceForService(.storage_object).name);
    try std.testing.expectEqual(InterfaceId.service_registry, interfaceId(.service_registry));
    try std.testing.expectEqual(InterfaceId.object_workspace, interfaceIdForService(.storage_object));
    try std.testing.expectEqual(InterfaceId.package_install, interfaceIdForService(.package_install_update));
    try std.testing.expectEqual(InterfaceId.object_workspace, interfaceIdForDecl(interfaceForService(.storage_object)).?);
    try std.testing.expectEqual(InterfaceId.service_registry, contractFor(interfaceForService(.service_registry).name).?.interface_id);
    try std.testing.expectEqual(@as(usize, 0), interfaceIndexForId(.task_runtime));
    try std.testing.expectEqual(INTERFACE_COUNT - 1, interfaceIndexForId(.personal_context));
    const service_registry_contract = contractForId(.service_registry);
    try std.testing.expectEqual(OperationId.service_register, service_registry_contract.operation(.service_register).?.id);
    try std.testing.expect(service_registry_contract.operation(.network_open_session) == null);
    try std.testing.expectEqual(
        OperationId.identity_credential_revoke,
        contractForId(.identity_session).operation(.identity_credential_revoke).?.id,
    );
    try std.testing.expect(contractFor("zigos.service.network.policy").?.operation(.network_open_session) != null);
    try std.testing.expect(contractFor("zigos.index.search").?.operation(.semantic_index_query) != null);
    try std.testing.expect(contractFor("zigos.sync.replication").?.operation(.sync_workspace_replicate) != null);
    try std.testing.expect(contractFor(interfaceForService(.package_install_update).name).?.operation(.package_rollback) != null);
    try std.testing.expect(contractFor(interfaceForService(.package_install_update).name).?.operation(.package_remove) != null);
    try std.testing.expect(contractFor("zigos.ai.inference").?.operation(.ai_run_local) != null);
    try std.testing.expect(contractFor("zigos.ai.model.registry").?.operation(.ai_model_attest) != null);
    try std.testing.expect(contractFor("zigos.privacy.budget").?.operation(.privacy_authorize_egress) != null);
    try std.testing.expect(contractFor("zigos.diagnostics.export").?.operation(.diagnostics_share_remote) != null);
    try std.testing.expect(contractFor("zigos.consent.receipts").?.operation(.consent_record) != null);
    try std.testing.expect(contractFor("zigos.permission.lease").?.operation(.permission_lease_issue) != null);
    try std.testing.expect(contractFor("zigos.data.rights").?.operation(.data_delete_receipt) != null);
    try std.testing.expect(contractFor("zigos.identity.session").?.operation(.identity_session_authorize) != null);
    try std.testing.expect(contractFor("zigos.identity.session").?.operation(.identity_credential_assert) != null);
    try std.testing.expect(contractFor("zigos.agent.delegation").?.operation(.agent_authorize) != null);
    try std.testing.expect(contractFor("zigos.agent.delegation").?.operation(.agent_bind_session) != null);
    try std.testing.expect(contractFor("zigos.agent.delegation").?.operation(.agent_kill_switch) != null);
    try std.testing.expect(contractFor("zigos.accessibility.profile").?.operation(.accessibility_profile_apply) != null);
    try std.testing.expect(contractFor("zigos.background.activity").?.operation(.background_authorize) != null);
    try std.testing.expect(contractFor("zigos.attention.broker").?.operation(.attention_post) != null);
    try std.testing.expect(contractFor("zigos.task.lifecycle").?.operation(.lifecycle_suspend) != null);
    try std.testing.expect(contractFor("zigos.secure.pasteboard").?.operation(.pasteboard_offer) != null);
    try std.testing.expect(contractFor("zigos.object.resilience").?.operation(.object_backup_prepare) != null);
    try std.testing.expect(contractFor("zigos.sensitive.capture").?.operation(.capture_start) != null);
    try std.testing.expect(contractFor("zigos.secret.vault").?.operation(.secret_import) != null);
    try std.testing.expectEqual(InterfaceId.secure_pasteboard, interfaceId(.secure_pasteboard));
    try std.testing.expectEqual(InterfaceId.secure_pasteboard, interfaceIdForService(.secure_pasteboard));
    try std.testing.expectEqual(InterfaceId.object_resilience, interfaceId(.object_resilience));
    try std.testing.expectEqual(InterfaceId.object_resilience, interfaceIdForService(.object_resilience));
    try std.testing.expectEqual(InterfaceId.sensitive_capture, interfaceId(.sensitive_capture));
    try std.testing.expectEqual(InterfaceId.sensitive_capture, interfaceIdForService(.sensitive_capture));
    try std.testing.expectEqual(InterfaceId.secret_vault, interfaceId(.secret_vault));
    try std.testing.expectEqual(InterfaceId.secret_vault, interfaceIdForService(.secret_vault));
    try std.testing.expectEqual(InterfaceId.attention_broker, interfaceId(.attention_broker));
    try std.testing.expectEqual(InterfaceId.attention_broker, interfaceIdForService(.attention_broker));
    try std.testing.expectEqual(InterfaceId.task_lifecycle, interfaceId(.task_lifecycle));
    try std.testing.expectEqual(InterfaceId.task_lifecycle, interfaceIdForService(.task_lifecycle));
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
