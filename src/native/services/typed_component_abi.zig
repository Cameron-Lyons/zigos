const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const schema = @import("component_abi_schema.zig");

pub const MAGIC = schema.MAGIC;
pub const VERSION = schema.VERSION;
pub const Error = schema.Error;
pub const WireHeader = schema.WireHeader;

pub const InterfaceKey = schema.InterfaceKey;
pub const InterfaceId = schema.InterfaceId;
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
pub const PackageInstallRequest = schema.requestType(.package_install);
pub const PackageUpdateRequest = schema.requestType(.package_update);
pub const PackageRollbackRequest = schema.requestType(.package_rollback);
pub const AiAuthorizeRequest = schema.requestType(.ai_authorize);
pub const AiRunLocalRequest = schema.requestType(.ai_run_local);
pub const AiModelRegisterRequest = schema.requestType(.ai_model_register);
pub const AiModelAttestRequest = schema.requestType(.ai_model_attest);
pub const AiModelRevokeRequest = schema.requestType(.ai_model_revoke);
pub const PrivacyAuthorizeEgressRequest = schema.requestType(.privacy_authorize_egress);
pub const PrivacyQueryBudgetRequest = schema.requestType(.privacy_query_budget);
pub const DiagnosticsPrepareExportRequest = schema.requestType(.diagnostics_prepare_export);
pub const DiagnosticsShareRemoteRequest = schema.requestType(.diagnostics_share_remote);
pub const ConsentRecordRequest = schema.requestType(.consent_record);
pub const ConsentRevokeRequest = schema.requestType(.consent_revoke);
pub const PermissionLeaseIssueRequest = schema.requestType(.permission_lease_issue);
pub const PermissionLeaseRenewRequest = schema.requestType(.permission_lease_renew);
pub const PermissionLeaseExpireRequest = schema.requestType(.permission_lease_expire);
pub const DataExportPrepareRequest = schema.requestType(.data_export_prepare);
pub const DataDeleteRequest = schema.requestType(.data_delete_request);
pub const DataDeleteReceiptRequest = schema.requestType(.data_delete_receipt);
pub const IdentitySessionAuthorizeRequest = schema.requestType(.identity_session_authorize);
pub const IdentitySessionStepUpRequest = schema.requestType(.identity_session_step_up);
pub const IdentitySessionRevokeRequest = schema.requestType(.identity_session_revoke);
pub const AgentAuthorizeRequest = schema.requestType(.agent_authorize);
pub const AgentRecordActionRequest = schema.requestType(.agent_record_action);
pub const AgentRevokeRequest = schema.requestType(.agent_revoke);
pub const AgentBindSessionRequest = schema.requestType(.agent_bind_session);
pub const AgentKillSwitchRequest = schema.requestType(.agent_kill_switch);
pub const AccessibilityProfileGetRequest = schema.requestType(.accessibility_profile_get);
pub const AccessibilityProfileApplyRequest = schema.requestType(.accessibility_profile_apply);
pub const AccessibilityProfileAuditRequest = schema.requestType(.accessibility_profile_audit);
pub const BackgroundAuthorizeRequest = schema.requestType(.background_authorize);
pub const BackgroundRecordRequest = schema.requestType(.background_record);
pub const BackgroundCompleteRequest = schema.requestType(.background_complete);
pub const PasteboardOfferRequest = schema.requestType(.pasteboard_offer);
pub const PasteboardReadRequest = schema.requestType(.pasteboard_read);
pub const PasteboardRevokeRequest = schema.requestType(.pasteboard_revoke);

pub const ServiceRegisterResponse = schema.responseType(.service_register);
pub const ServiceConnectionResponse = schema.responseType(.service_connect);
pub const TaskDescribeResponse = schema.responseType(.task_describe);
pub const WorkspacePutVersionResponse = schema.responseType(.workspace_put_version);
pub const WorkspaceResolveResponse = schema.responseType(.workspace_resolve);
pub const NetworkAuthorizeResponse = schema.responseType(.network_authorize);
pub const PolicyAuthorizeResponse = schema.responseType(.policy_authorize);
pub const PackageInstallResponse = schema.responseType(.package_install);
pub const PackageUpdateResponse = schema.responseType(.package_update);
pub const PackageRollbackResponse = schema.responseType(.package_rollback);
pub const AiAuthorizeResponse = schema.responseType(.ai_authorize);
pub const AiRunLocalResponse = schema.responseType(.ai_run_local);
pub const AiModelRegisterResponse = schema.responseType(.ai_model_register);
pub const AiModelAttestResponse = schema.responseType(.ai_model_attest);
pub const AiModelRevokeResponse = schema.responseType(.ai_model_revoke);
pub const PrivacyAuthorizeEgressResponse = schema.responseType(.privacy_authorize_egress);
pub const PrivacyQueryBudgetResponse = schema.responseType(.privacy_query_budget);
pub const DiagnosticsPrepareExportResponse = schema.responseType(.diagnostics_prepare_export);
pub const DiagnosticsShareRemoteResponse = schema.responseType(.diagnostics_share_remote);
pub const ConsentRecordResponse = schema.responseType(.consent_record);
pub const ConsentRevokeResponse = schema.responseType(.consent_revoke);
pub const PermissionLeaseIssueResponse = schema.responseType(.permission_lease_issue);
pub const PermissionLeaseRenewResponse = schema.responseType(.permission_lease_renew);
pub const PermissionLeaseExpireResponse = schema.responseType(.permission_lease_expire);
pub const DataExportPrepareResponse = schema.responseType(.data_export_prepare);
pub const DataDeleteResponse = schema.responseType(.data_delete_request);
pub const DataDeleteReceiptResponse = schema.responseType(.data_delete_receipt);
pub const IdentitySessionAuthorizeResponse = schema.responseType(.identity_session_authorize);
pub const IdentitySessionStepUpResponse = schema.responseType(.identity_session_step_up);
pub const IdentitySessionRevokeResponse = schema.responseType(.identity_session_revoke);
pub const AgentAuthorizeResponse = schema.responseType(.agent_authorize);
pub const AgentRecordActionResponse = schema.responseType(.agent_record_action);
pub const AgentRevokeResponse = schema.responseType(.agent_revoke);
pub const AgentBindSessionResponse = schema.responseType(.agent_bind_session);
pub const AgentKillSwitchResponse = schema.responseType(.agent_kill_switch);
pub const AccessibilityProfileGetResponse = schema.responseType(.accessibility_profile_get);
pub const AccessibilityProfileApplyResponse = schema.responseType(.accessibility_profile_apply);
pub const AccessibilityProfileAuditResponse = schema.responseType(.accessibility_profile_audit);
pub const BackgroundAuthorizeResponse = schema.responseType(.background_authorize);
pub const BackgroundRecordResponse = schema.responseType(.background_record);
pub const BackgroundCompleteResponse = schema.responseType(.background_complete);
pub const PasteboardResponse = schema.responseType(.pasteboard_offer);

pub const contracts = schema.contracts;
pub const manifest_interfaces = schema.manifest_interfaces;
pub const service_catalog_bindings = schema.service_catalog_bindings;
pub const coverage_references = schema.coverage_references;

pub fn Interface(comptime key: InterfaceKey) manifest.InterfaceDecl {
    return schema.interfaceDecl(key);
}

pub fn interfaceId(comptime key: InterfaceKey) InterfaceId {
    return schema.interfaceId(key);
}

pub fn interfaceForService(comptime service: ServiceBinding) manifest.InterfaceDecl {
    return schema.interfaceForService(service);
}

pub fn interfaceIdForService(comptime service: ServiceBinding) InterfaceId {
    return schema.interfaceIdForService(service);
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

pub fn contractForId(interface_id: InterfaceId) ?*const InterfaceContract {
    return schema.contractForId(interface_id);
}

pub fn interfaceIdForDecl(interface: manifest.InterfaceDecl) ?InterfaceId {
    return schema.interfaceIdForDecl(interface);
}

pub fn validateInterface(interface: manifest.InterfaceDecl) Error!void {
    return schema.validateInterface(interface);
}

pub fn validateInterfaceId(interface_id: InterfaceId, interface: manifest.InterfaceDecl) Error!void {
    return schema.validateInterfaceId(interface_id, interface);
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
    try std.testing.expectEqual(@as(u16, 0x0603), @intFromEnum(OperationId.package_rollback));
    try std.testing.expectEqual(@as(u16, 0x0702), @intFromEnum(OperationId.ai_run_local));
    try std.testing.expectEqual(@as(u16, 0x0D02), @intFromEnum(OperationId.ai_model_attest));
    try std.testing.expectEqual(@as(u16, 0x0801), @intFromEnum(OperationId.privacy_authorize_egress));
    try std.testing.expectEqual(@as(u16, 0x0902), @intFromEnum(OperationId.diagnostics_share_remote));
    try std.testing.expectEqual(@as(u16, 0x0A01), @intFromEnum(OperationId.consent_record));
    try std.testing.expectEqual(@as(u16, 0x0B03), @intFromEnum(OperationId.permission_lease_expire));
    try std.testing.expectEqual(@as(u16, 0x0C03), @intFromEnum(OperationId.data_delete_receipt));
    try std.testing.expectEqual(@as(u16, 0x0E01), @intFromEnum(OperationId.identity_session_authorize));
    try std.testing.expectEqual(@as(u16, 0x0F01), @intFromEnum(OperationId.agent_authorize));
    try std.testing.expectEqual(@as(u16, 0x0F04), @intFromEnum(OperationId.agent_bind_session));
    try std.testing.expectEqual(@as(u16, 0x1001), @intFromEnum(OperationId.accessibility_profile_get));
    try std.testing.expectEqual(@as(u16, 0x1101), @intFromEnum(OperationId.background_authorize));
    try std.testing.expectEqual(@as(u16, 0x1201), @intFromEnum(OperationId.pasteboard_offer));
    try std.testing.expectEqual(@as(u16, 0x1202), @intFromEnum(OperationId.pasteboard_read));
    try std.testing.expectEqual(@as(u16, 0x1203), @intFromEnum(OperationId.pasteboard_revoke));
    try std.testing.expectEqual(@sizeOf(ServiceConnectionRequest), @sizeOf(Request(.service_connect)));
    try std.testing.expectEqual(@sizeOf(ServiceConnectionResponse), @sizeOf(Response(.service_connect)));
    try std.testing.expectEqual(@sizeOf(PackageRollbackRequest), @sizeOf(Request(.package_rollback)));
    try std.testing.expectEqual(@sizeOf(PackageRollbackResponse), @sizeOf(Response(.package_rollback)));
    try std.testing.expectEqual(@sizeOf(AiRunLocalRequest), @sizeOf(Request(.ai_run_local)));
    try std.testing.expectEqual(@sizeOf(AiRunLocalResponse), @sizeOf(Response(.ai_run_local)));
    try std.testing.expectEqual(@sizeOf(AiModelAttestRequest), @sizeOf(Request(.ai_model_attest)));
    try std.testing.expectEqual(@sizeOf(AiModelAttestResponse), @sizeOf(Response(.ai_model_attest)));
    try std.testing.expectEqual(@sizeOf(PrivacyAuthorizeEgressRequest), @sizeOf(Request(.privacy_authorize_egress)));
    try std.testing.expectEqual(@sizeOf(PrivacyAuthorizeEgressResponse), @sizeOf(Response(.privacy_authorize_egress)));
    try std.testing.expectEqual(@sizeOf(DiagnosticsShareRemoteRequest), @sizeOf(Request(.diagnostics_share_remote)));
    try std.testing.expectEqual(@sizeOf(DiagnosticsShareRemoteResponse), @sizeOf(Response(.diagnostics_share_remote)));
    try std.testing.expectEqual(@sizeOf(ConsentRecordRequest), @sizeOf(Request(.consent_record)));
    try std.testing.expectEqual(@sizeOf(ConsentRecordResponse), @sizeOf(Response(.consent_record)));
    try std.testing.expectEqual(@sizeOf(PermissionLeaseIssueRequest), @sizeOf(Request(.permission_lease_issue)));
    try std.testing.expectEqual(@sizeOf(PermissionLeaseIssueResponse), @sizeOf(Response(.permission_lease_issue)));
    try std.testing.expectEqual(@sizeOf(DataExportPrepareRequest), @sizeOf(Request(.data_export_prepare)));
    try std.testing.expectEqual(@sizeOf(DataDeleteReceiptResponse), @sizeOf(Response(.data_delete_receipt)));
    try std.testing.expectEqual(@sizeOf(IdentitySessionAuthorizeRequest), @sizeOf(Request(.identity_session_authorize)));
    try std.testing.expectEqual(@sizeOf(IdentitySessionAuthorizeResponse), @sizeOf(Response(.identity_session_authorize)));
    try std.testing.expectEqual(@sizeOf(AgentAuthorizeRequest), @sizeOf(Request(.agent_authorize)));
    try std.testing.expectEqual(@sizeOf(AgentAuthorizeResponse), @sizeOf(Response(.agent_authorize)));
    try std.testing.expectEqual(@sizeOf(AgentBindSessionRequest), @sizeOf(Request(.agent_bind_session)));
    try std.testing.expectEqual(@sizeOf(AgentBindSessionResponse), @sizeOf(Response(.agent_bind_session)));
    try std.testing.expectEqual(@sizeOf(AccessibilityProfileApplyRequest), @sizeOf(Request(.accessibility_profile_apply)));
    try std.testing.expectEqual(@sizeOf(AccessibilityProfileApplyResponse), @sizeOf(Response(.accessibility_profile_apply)));
    try std.testing.expectEqual(@sizeOf(BackgroundAuthorizeRequest), @sizeOf(Request(.background_authorize)));
    try std.testing.expectEqual(@sizeOf(BackgroundAuthorizeResponse), @sizeOf(Response(.background_authorize)));
    try std.testing.expectEqual(@sizeOf(PasteboardOfferRequest), @sizeOf(Request(.pasteboard_offer)));
    try std.testing.expectEqual(@sizeOf(PasteboardReadRequest), @sizeOf(Request(.pasteboard_read)));
    try std.testing.expectEqual(@sizeOf(PasteboardRevokeRequest), @sizeOf(Request(.pasteboard_revoke)));
    try std.testing.expectEqual(@sizeOf(PasteboardResponse), @sizeOf(Response(.pasteboard_read)));
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(WorkspacePutVersionRequest))), contractFor("zigos.object.workspace").?.operation(.workspace_put_version).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PackageUpdateRequest))), contractFor("zigos.package.install").?.operation(.package_update).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AiAuthorizeRequest))), contractFor("zigos.ai.inference").?.operation(.ai_authorize).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AiModelRegisterRequest))), contractFor("zigos.ai.model.registry").?.operation(.ai_model_register).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PrivacyQueryBudgetRequest))), contractFor("zigos.privacy.budget").?.operation(.privacy_query_budget).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(DiagnosticsPrepareExportRequest))), contractFor("zigos.diagnostics.export").?.operation(.diagnostics_prepare_export).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(ConsentRevokeRequest))), contractFor("zigos.consent.receipts").?.operation(.consent_revoke).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PermissionLeaseRenewRequest))), contractFor("zigos.permission.lease").?.operation(.permission_lease_renew).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(DataDeleteRequest))), contractFor("zigos.data.rights").?.operation(.data_delete_request).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(IdentitySessionStepUpRequest))), contractFor("zigos.identity.session").?.operation(.identity_session_step_up).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AgentRecordActionRequest))), contractFor("zigos.agent.delegation").?.operation(.agent_record_action).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AgentKillSwitchRequest))), contractFor("zigos.agent.delegation").?.operation(.agent_kill_switch).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AccessibilityProfileAuditRequest))), contractFor("zigos.accessibility.profile").?.operation(.accessibility_profile_audit).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(BackgroundCompleteRequest))), contractFor("zigos.background.activity").?.operation(.background_complete).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PasteboardReadRequest))), contractFor("zigos.secure.pasteboard").?.operation(.pasteboard_read).?.request_size);
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

    const package_iface = Interface(.package_install);
    const package_header = WireHeader{
        .interface_major = package_iface.version_major,
        .interface_minor = package_iface.version_minor,
        .operation = @intFromEnum(OperationId.package_rollback),
        .request_len = @sizeOf(PackageRollbackRequest),
        .response_len = @sizeOf(PackageRollbackResponse),
        .correlation_id = 902,
        .subject_task_id = 78,
    };
    try validateMessage(
        package_iface,
        .package_rollback,
        package_header,
        @sizeOf(PackageRollbackRequest),
        @sizeOf(PackageRollbackResponse),
    );

    const ai_iface = Interface(.ai_inference);
    const ai_header = WireHeader{
        .interface_major = ai_iface.version_major,
        .interface_minor = ai_iface.version_minor,
        .operation = @intFromEnum(OperationId.ai_run_local),
        .request_len = @sizeOf(AiRunLocalRequest),
        .response_len = @sizeOf(AiRunLocalResponse),
        .correlation_id = 903,
        .subject_task_id = 79,
    };
    try validateMessage(
        ai_iface,
        .ai_run_local,
        ai_header,
        @sizeOf(AiRunLocalRequest),
        @sizeOf(AiRunLocalResponse),
    );

    const privacy_iface = Interface(.privacy_budget);
    const privacy_header = WireHeader{
        .interface_major = privacy_iface.version_major,
        .interface_minor = privacy_iface.version_minor,
        .operation = @intFromEnum(OperationId.privacy_authorize_egress),
        .request_len = @sizeOf(PrivacyAuthorizeEgressRequest),
        .response_len = @sizeOf(PrivacyAuthorizeEgressResponse),
        .correlation_id = 904,
        .subject_task_id = 80,
    };
    try validateMessage(
        privacy_iface,
        .privacy_authorize_egress,
        privacy_header,
        @sizeOf(PrivacyAuthorizeEgressRequest),
        @sizeOf(PrivacyAuthorizeEgressResponse),
    );

    const diagnostics_iface = Interface(.diagnostics_export);
    const diagnostics_header = WireHeader{
        .interface_major = diagnostics_iface.version_major,
        .interface_minor = diagnostics_iface.version_minor,
        .operation = @intFromEnum(OperationId.diagnostics_share_remote),
        .request_len = @sizeOf(DiagnosticsShareRemoteRequest),
        .response_len = @sizeOf(DiagnosticsShareRemoteResponse),
        .correlation_id = 905,
        .subject_task_id = 81,
    };
    try validateMessage(
        diagnostics_iface,
        .diagnostics_share_remote,
        diagnostics_header,
        @sizeOf(DiagnosticsShareRemoteRequest),
        @sizeOf(DiagnosticsShareRemoteResponse),
    );

    const consent_iface = Interface(.consent_receipts);
    const consent_header = WireHeader{
        .interface_major = consent_iface.version_major,
        .interface_minor = consent_iface.version_minor,
        .operation = @intFromEnum(OperationId.consent_record),
        .request_len = @sizeOf(ConsentRecordRequest),
        .response_len = @sizeOf(ConsentRecordResponse),
        .correlation_id = 906,
        .subject_task_id = 82,
    };
    try validateMessage(
        consent_iface,
        .consent_record,
        consent_header,
        @sizeOf(ConsentRecordRequest),
        @sizeOf(ConsentRecordResponse),
    );

    const lease_iface = Interface(.permission_lease);
    const lease_header = WireHeader{
        .interface_major = lease_iface.version_major,
        .interface_minor = lease_iface.version_minor,
        .operation = @intFromEnum(OperationId.permission_lease_expire),
        .request_len = @sizeOf(PermissionLeaseExpireRequest),
        .response_len = @sizeOf(PermissionLeaseExpireResponse),
        .correlation_id = 907,
        .subject_task_id = 83,
    };
    try validateMessage(
        lease_iface,
        .permission_lease_expire,
        lease_header,
        @sizeOf(PermissionLeaseExpireRequest),
        @sizeOf(PermissionLeaseExpireResponse),
    );

    const identity_iface = Interface(.identity_session);
    const identity_header = WireHeader{
        .interface_major = identity_iface.version_major,
        .interface_minor = identity_iface.version_minor,
        .operation = @intFromEnum(OperationId.identity_session_authorize),
        .request_len = @sizeOf(IdentitySessionAuthorizeRequest),
        .response_len = @sizeOf(IdentitySessionAuthorizeResponse),
        .correlation_id = 908,
        .subject_task_id = 84,
    };
    try validateMessage(
        identity_iface,
        .identity_session_authorize,
        identity_header,
        @sizeOf(IdentitySessionAuthorizeRequest),
        @sizeOf(IdentitySessionAuthorizeResponse),
    );
}
