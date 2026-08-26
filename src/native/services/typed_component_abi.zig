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
pub const INTERFACE_COUNT = schema.INTERFACE_COUNT;
pub const DIRECT_INTERFACE_INDEX = schema.DIRECT_INTERFACE_INDEX;
pub const TOTAL_INTERFACE_ID_MAP = schema.TOTAL_INTERFACE_ID_MAP;
pub const COMPACT_INTERFACE_CONTRACT_METADATA = schema.COMPACT_INTERFACE_CONTRACT_METADATA;
pub const INTERFACE_CONTRACT_SIZE_CEILING_BYTES = schema.INTERFACE_CONTRACT_SIZE_CEILING_BYTES;

pub const ServiceRegisterRequest = schema.requestType(.service_register);
pub const ServiceConnectionRequest = schema.requestType(.service_connect);
pub const TaskDescribeRequest = schema.requestType(.task_describe);
pub const WorkspacePutVersionRequest = schema.requestType(.workspace_put_version);
pub const WorkspaceResolveRequest = schema.requestType(.workspace_resolve);
pub const IndexUpsertRequest = schema.requestType(.index_upsert);
pub const IndexQueryRequest = schema.requestType(.index_query);
pub const SemanticIndexQueryRequest = schema.requestType(.semantic_index_query);
pub const SyncDeviceEnrollRequest = schema.requestType(.sync_device_enroll);
pub const SyncWorkspaceReplicateRequest = schema.requestType(.sync_workspace_replicate);
pub const SyncConflictReviewRequest = schema.requestType(.sync_conflict_review);
pub const SyncConflictResolveRequest = schema.requestType(.sync_conflict_resolve);
pub const SyncTransportFrameRequest = schema.requestType(.sync_transport_frame);
pub const NetworkAuthorizeRequest = schema.requestType(.network_authorize);
pub const NetworkOpenSessionRequest = schema.requestType(.network_open_session);
pub const NetworkRecordTransferRequest = schema.requestType(.network_record_transfer);
pub const NetworkRevokeSessionRequest = schema.requestType(.network_revoke_session);
pub const PolicyAuthorizeRequest = schema.requestType(.policy_authorize);
pub const PackageInstallRequest = schema.requestType(.package_install);
pub const PackageUpdateRequest = schema.requestType(.package_update);
pub const PackageRollbackRequest = schema.requestType(.package_rollback);
pub const PackageRemoveRequest = schema.requestType(.package_remove);
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
pub const IdentityCredentialRegisterRequest = schema.requestType(.identity_credential_register);
pub const IdentityCredentialAssertRequest = schema.requestType(.identity_credential_assert);
pub const IdentityCredentialRecoverRequest = schema.requestType(.identity_credential_recover);
pub const IdentityCredentialRevokeRequest = schema.requestType(.identity_credential_revoke);
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
pub const AttentionPostRequest = schema.requestType(.attention_post);
pub const AttentionDismissRequest = schema.requestType(.attention_dismiss);
pub const AttentionQueryRequest = schema.requestType(.attention_query);
pub const LifecycleControlRequest = schema.requestType(.lifecycle_suspend);
pub const PersonalContextLeaseRequest = schema.requestType(.personal_context_lease);
pub const PersonalContextQueryRequest = schema.requestType(.personal_context_query);
pub const PersonalContextRevokeRequest = schema.requestType(.personal_context_revoke);
pub const PasteboardOfferRequest = schema.requestType(.pasteboard_offer);
pub const PasteboardReadRequest = schema.requestType(.pasteboard_read);
pub const PasteboardRevokeRequest = schema.requestType(.pasteboard_revoke);
pub const ObjectBackupPrepareRequest = schema.requestType(.object_backup_prepare);
pub const ObjectRestoreAuthorizeRequest = schema.requestType(.object_restore_authorize);
pub const ObjectBackupRevokeRequest = schema.requestType(.object_backup_revoke);
pub const CaptureStartRequest = schema.requestType(.capture_start);
pub const CaptureSampleRequest = schema.requestType(.capture_sample);
pub const CaptureStopRequest = schema.requestType(.capture_stop);
pub const SecretImportRequest = schema.requestType(.secret_import);
pub const SecretLendRequest = schema.requestType(.secret_lend);
pub const SecretRotateRequest = schema.requestType(.secret_rotate);
pub const SecretRevokeRequest = schema.requestType(.secret_revoke);

pub const ServiceRegisterResponse = schema.responseType(.service_register);
pub const ServiceConnectionResponse = schema.responseType(.service_connect);
pub const TaskDescribeResponse = schema.responseType(.task_describe);
pub const WorkspacePutVersionResponse = schema.responseType(.workspace_put_version);
pub const WorkspaceResolveResponse = schema.responseType(.workspace_resolve);
pub const IndexResponse = schema.responseType(.index_query);
pub const SyncResponse = schema.responseType(.sync_workspace_replicate);
pub const NetworkAuthorizeResponse = schema.responseType(.network_authorize);
pub const NetworkSessionResponse = schema.responseType(.network_open_session);
pub const PolicyAuthorizeResponse = schema.responseType(.policy_authorize);
pub const PackageInstallResponse = schema.responseType(.package_install);
pub const PackageUpdateResponse = schema.responseType(.package_update);
pub const PackageRollbackResponse = schema.responseType(.package_rollback);
pub const PackageRemoveResponse = schema.responseType(.package_remove);
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
pub const IdentityCredentialResponse = schema.responseType(.identity_credential_assert);
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
pub const AttentionResponse = schema.responseType(.attention_post);
pub const LifecycleControlResponse = schema.responseType(.lifecycle_suspend);
pub const PersonalContextResponse = schema.responseType(.personal_context_lease);
pub const PasteboardResponse = schema.responseType(.pasteboard_offer);
pub const ObjectResilienceResponse = schema.responseType(.object_backup_prepare);
pub const CaptureResponse = schema.responseType(.capture_start);
pub const SecretVaultResponse = schema.responseType(.secret_import);

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

pub fn contractForId(interface_id: InterfaceId) *const InterfaceContract {
    return schema.contractForId(interface_id);
}

pub fn interfaceIndexForId(interface_id: InterfaceId) usize {
    return schema.interfaceIndexForId(interface_id);
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

pub fn validateMessage(
    interface_id: InterfaceId,
    operation_id: OperationId,
    header: WireHeader,
    actual_request_len: usize,
    actual_response_len: usize,
) Error!void {
    return schema.validateMessage(interface_id, operation_id, header, actual_request_len, actual_response_len);
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
    try std.testing.expectEqual(@as(u16, 0x0402), @intFromEnum(OperationId.network_open_session));
    try std.testing.expectEqual(@as(u16, 0x0403), @intFromEnum(OperationId.network_record_transfer));
    try std.testing.expectEqual(@as(u16, 0x0404), @intFromEnum(OperationId.network_revoke_session));
    try std.testing.expectEqual(@as(u16, 0x0603), @intFromEnum(OperationId.package_rollback));
    try std.testing.expectEqual(@as(u16, 0x0604), @intFromEnum(OperationId.package_remove));
    try std.testing.expectEqual(@as(u16, 0x0702), @intFromEnum(OperationId.ai_run_local));
    try std.testing.expectEqual(@as(u16, 0x0D02), @intFromEnum(OperationId.ai_model_attest));
    try std.testing.expectEqual(@as(u16, 0x0801), @intFromEnum(OperationId.privacy_authorize_egress));
    try std.testing.expectEqual(@as(u16, 0x0902), @intFromEnum(OperationId.diagnostics_share_remote));
    try std.testing.expectEqual(@as(u16, 0x0A01), @intFromEnum(OperationId.consent_record));
    try std.testing.expectEqual(@as(u16, 0x0B03), @intFromEnum(OperationId.permission_lease_expire));
    try std.testing.expectEqual(@as(u16, 0x0C03), @intFromEnum(OperationId.data_delete_receipt));
    try std.testing.expectEqual(@as(u16, 0x0E01), @intFromEnum(OperationId.identity_session_authorize));
    try std.testing.expectEqual(@as(u16, 0x0E04), @intFromEnum(OperationId.identity_credential_register));
    try std.testing.expectEqual(@as(u16, 0x0E05), @intFromEnum(OperationId.identity_credential_assert));
    try std.testing.expectEqual(@as(u16, 0x0E06), @intFromEnum(OperationId.identity_credential_recover));
    try std.testing.expectEqual(@as(u16, 0x0E07), @intFromEnum(OperationId.identity_credential_revoke));
    try std.testing.expectEqual(@as(u16, 0x0F01), @intFromEnum(OperationId.agent_authorize));
    try std.testing.expectEqual(@as(u16, 0x0F04), @intFromEnum(OperationId.agent_bind_session));
    try std.testing.expectEqual(@as(u16, 0x1001), @intFromEnum(OperationId.accessibility_profile_get));
    try std.testing.expectEqual(@as(u16, 0x1101), @intFromEnum(OperationId.background_authorize));
    try std.testing.expectEqual(@as(u16, 0x1201), @intFromEnum(OperationId.pasteboard_offer));
    try std.testing.expectEqual(@as(u16, 0x1202), @intFromEnum(OperationId.pasteboard_read));
    try std.testing.expectEqual(@as(u16, 0x1203), @intFromEnum(OperationId.pasteboard_revoke));
    try std.testing.expectEqual(@as(u16, 0x1301), @intFromEnum(OperationId.object_backup_prepare));
    try std.testing.expectEqual(@as(u16, 0x1302), @intFromEnum(OperationId.object_restore_authorize));
    try std.testing.expectEqual(@as(u16, 0x1303), @intFromEnum(OperationId.object_backup_revoke));
    try std.testing.expectEqual(@as(u16, 0x1401), @intFromEnum(OperationId.index_upsert));
    try std.testing.expectEqual(@as(u16, 0x1402), @intFromEnum(OperationId.index_query));
    try std.testing.expectEqual(@as(u16, 0x1403), @intFromEnum(OperationId.semantic_index_query));
    try std.testing.expectEqual(@as(u16, 0x1501), @intFromEnum(OperationId.sync_device_enroll));
    try std.testing.expectEqual(@as(u16, 0x1502), @intFromEnum(OperationId.sync_workspace_replicate));
    try std.testing.expectEqual(@as(u16, 0x1503), @intFromEnum(OperationId.sync_conflict_review));
    try std.testing.expectEqual(@as(u16, 0x1504), @intFromEnum(OperationId.sync_conflict_resolve));
    try std.testing.expectEqual(@as(u16, 0x1505), @intFromEnum(OperationId.sync_transport_frame));
    try std.testing.expectEqual(@as(u16, 0x1601), @intFromEnum(OperationId.capture_start));
    try std.testing.expectEqual(@as(u16, 0x1602), @intFromEnum(OperationId.capture_sample));
    try std.testing.expectEqual(@as(u16, 0x1603), @intFromEnum(OperationId.capture_stop));
    try std.testing.expectEqual(@as(u16, 0x1701), @intFromEnum(OperationId.secret_import));
    try std.testing.expectEqual(@as(u16, 0x1702), @intFromEnum(OperationId.secret_lend));
    try std.testing.expectEqual(@as(u16, 0x1703), @intFromEnum(OperationId.secret_rotate));
    try std.testing.expectEqual(@as(u16, 0x1704), @intFromEnum(OperationId.secret_revoke));
    try std.testing.expectEqual(@as(u16, 0x1801), @intFromEnum(OperationId.attention_post));
    try std.testing.expectEqual(@as(u16, 0x1802), @intFromEnum(OperationId.attention_dismiss));
    try std.testing.expectEqual(@as(u16, 0x1803), @intFromEnum(OperationId.attention_query));
    try std.testing.expectEqual(@as(u16, 0x1901), @intFromEnum(OperationId.lifecycle_suspend));
    try std.testing.expectEqual(@as(u16, 0x1902), @intFromEnum(OperationId.lifecycle_resume));
    try std.testing.expectEqual(@as(u16, 0x1903), @intFromEnum(OperationId.lifecycle_terminate));
    try std.testing.expectEqual(@as(u16, 0x1A01), @intFromEnum(OperationId.personal_context_lease));
    try std.testing.expectEqual(@as(u16, 0x1A02), @intFromEnum(OperationId.personal_context_query));
    try std.testing.expectEqual(@as(u16, 0x1A03), @intFromEnum(OperationId.personal_context_revoke));
    try std.testing.expectEqual(@sizeOf(ServiceConnectionRequest), @sizeOf(Request(.service_connect)));
    try std.testing.expectEqual(@sizeOf(ServiceConnectionResponse), @sizeOf(Response(.service_connect)));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(WireHeader));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(ServiceRegisterRequest));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(ServiceConnectionRequest));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(ServiceConnectionResponse));
    try std.testing.expectEqual(@sizeOf(NetworkOpenSessionRequest), @sizeOf(Request(.network_open_session)));
    try std.testing.expectEqual(@sizeOf(NetworkRecordTransferRequest), @sizeOf(Request(.network_record_transfer)));
    try std.testing.expect(@hasField(NetworkRecordTransferRequest, "expected_policy_id"));
    try std.testing.expect(@hasField(NetworkRecordTransferRequest, "expected_capability_id"));
    try std.testing.expectEqual(@sizeOf(NetworkRevokeSessionRequest), @sizeOf(Request(.network_revoke_session)));
    try std.testing.expect(@hasField(NetworkRevokeSessionRequest, "expected_policy_id"));
    try std.testing.expect(@hasField(NetworkRevokeSessionRequest, "expected_capability_id"));
    try std.testing.expectEqual(@sizeOf(NetworkSessionResponse), @sizeOf(Response(.network_revoke_session)));
    try std.testing.expectEqual(@sizeOf(PackageRollbackRequest), @sizeOf(Request(.package_rollback)));
    try std.testing.expect(@hasField(PackageRollbackRequest, "expected_active_digest"));
    try std.testing.expectEqual(@sizeOf(PackageRollbackResponse), @sizeOf(Response(.package_rollback)));
    try std.testing.expectEqual(@sizeOf(PackageRemoveRequest), @sizeOf(Request(.package_remove)));
    try std.testing.expect(@hasField(PackageRemoveRequest, "expected_active_digest"));
    try std.testing.expectEqual(@sizeOf(PackageRemoveResponse), @sizeOf(Response(.package_remove)));
    try std.testing.expect(@hasField(PackageRemoveResponse, "removed_existing"));
    try std.testing.expect(@hasField(PackageRemoveResponse, "removed_revision_count"));
    try std.testing.expect(@hasField(PackageRemoveResponse, "deletion_receipt_id"));
    try std.testing.expect(@hasField(PackageRemoveResponse, "removed_bundle_digest"));
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
    try std.testing.expectEqual(@sizeOf(IdentityCredentialRegisterRequest), @sizeOf(Request(.identity_credential_register)));
    try std.testing.expectEqual(@sizeOf(IdentityCredentialAssertRequest), @sizeOf(Request(.identity_credential_assert)));
    try std.testing.expectEqual(@sizeOf(IdentityCredentialRecoverRequest), @sizeOf(Request(.identity_credential_recover)));
    try std.testing.expectEqual(@sizeOf(IdentityCredentialRevokeRequest), @sizeOf(Request(.identity_credential_revoke)));
    try std.testing.expectEqual(@sizeOf(IdentityCredentialResponse), @sizeOf(Response(.identity_credential_recover)));
    try std.testing.expectEqual(@sizeOf(AgentAuthorizeRequest), @sizeOf(Request(.agent_authorize)));
    try std.testing.expectEqual(@sizeOf(AgentAuthorizeResponse), @sizeOf(Response(.agent_authorize)));
    try std.testing.expectEqual(@sizeOf(AgentRecordActionRequest), @sizeOf(Request(.agent_record_action)));
    try std.testing.expect(@hasField(AgentRecordActionRequest, "expected_subject_serial"));
    try std.testing.expect(@hasField(AgentRecordActionRequest, "expected_subject_kind"));
    try std.testing.expect(@hasField(AgentRecordActionRequest, "expected_task_id"));
    try std.testing.expect(@hasField(AgentRecordActionRequest, "expected_generation"));
    try std.testing.expectEqual(@sizeOf(AgentBindSessionRequest), @sizeOf(Request(.agent_bind_session)));
    try std.testing.expectEqual(@sizeOf(AgentBindSessionResponse), @sizeOf(Response(.agent_bind_session)));
    try std.testing.expectEqual(@sizeOf(AccessibilityProfileApplyRequest), @sizeOf(Request(.accessibility_profile_apply)));
    try std.testing.expectEqual(@sizeOf(AccessibilityProfileApplyResponse), @sizeOf(Response(.accessibility_profile_apply)));
    try std.testing.expectEqual(@sizeOf(BackgroundAuthorizeRequest), @sizeOf(Request(.background_authorize)));
    try std.testing.expectEqual(@sizeOf(BackgroundAuthorizeResponse), @sizeOf(Response(.background_authorize)));
    try std.testing.expectEqual(@sizeOf(BackgroundCompleteRequest), @sizeOf(Request(.background_complete)));
    try std.testing.expect(@hasField(BackgroundCompleteRequest, "record_id"));
    try std.testing.expect(@hasField(BackgroundCompleteRequest, "expected_task_id"));
    try std.testing.expect(@hasField(BackgroundCompleteRequest, "expected_background_task_len"));
    try std.testing.expect(@hasField(BackgroundCompleteRequest, "expected_trigger"));
    try std.testing.expect(@hasField(BackgroundCompleteRequest, "completed_tick"));
    try std.testing.expectEqual(@sizeOf(PasteboardOfferRequest), @sizeOf(Request(.pasteboard_offer)));
    try std.testing.expectEqual(@sizeOf(PasteboardReadRequest), @sizeOf(Request(.pasteboard_read)));
    try std.testing.expectEqual(@sizeOf(PasteboardRevokeRequest), @sizeOf(Request(.pasteboard_revoke)));
    try std.testing.expectEqual(@sizeOf(PasteboardResponse), @sizeOf(Response(.pasteboard_read)));
    try std.testing.expectEqual(@sizeOf(ObjectBackupPrepareRequest), @sizeOf(Request(.object_backup_prepare)));
    try std.testing.expectEqual(@sizeOf(ObjectRestoreAuthorizeRequest), @sizeOf(Request(.object_restore_authorize)));
    try std.testing.expectEqual(@sizeOf(ObjectBackupRevokeRequest), @sizeOf(Request(.object_backup_revoke)));
    try std.testing.expectEqual(@sizeOf(ObjectResilienceResponse), @sizeOf(Response(.object_restore_authorize)));
    try std.testing.expectEqual(@sizeOf(IndexUpsertRequest), @sizeOf(Request(.index_upsert)));
    try std.testing.expectEqual(@sizeOf(IndexQueryRequest), @sizeOf(Request(.index_query)));
    try std.testing.expectEqual(@sizeOf(SemanticIndexQueryRequest), @sizeOf(Request(.semantic_index_query)));
    try std.testing.expectEqual(@sizeOf(IndexResponse), @sizeOf(Response(.semantic_index_query)));
    try std.testing.expect(@hasField(IndexResponse, "index_generation"));
    try std.testing.expectEqual(@sizeOf(SyncDeviceEnrollRequest), @sizeOf(Request(.sync_device_enroll)));
    try std.testing.expectEqual(@sizeOf(SyncWorkspaceReplicateRequest), @sizeOf(Request(.sync_workspace_replicate)));
    try std.testing.expectEqual(@sizeOf(SyncConflictReviewRequest), @sizeOf(Request(.sync_conflict_review)));
    try std.testing.expectEqual(@sizeOf(SyncConflictResolveRequest), @sizeOf(Request(.sync_conflict_resolve)));
    try std.testing.expectEqual(@sizeOf(SyncTransportFrameRequest), @sizeOf(Request(.sync_transport_frame)));
    try std.testing.expectEqual(@sizeOf(SyncResponse), @sizeOf(Response(.sync_conflict_resolve)));
    try std.testing.expectEqual(@sizeOf(CaptureStartRequest), @sizeOf(Request(.capture_start)));
    try std.testing.expectEqual(@sizeOf(CaptureSampleRequest), @sizeOf(Request(.capture_sample)));
    try std.testing.expect(@hasField(CaptureSampleRequest, "expected_device_id"));
    try std.testing.expect(@hasField(CaptureSampleRequest, "expected_foreground_session_id"));
    try std.testing.expect(@hasField(CaptureSampleRequest, "expected_kind"));
    try std.testing.expectEqual(@sizeOf(CaptureStopRequest), @sizeOf(Request(.capture_stop)));
    try std.testing.expect(@hasField(CaptureStopRequest, "expected_device_id"));
    try std.testing.expect(@hasField(CaptureStopRequest, "expected_foreground_session_id"));
    try std.testing.expect(@hasField(CaptureStopRequest, "expected_kind"));
    try std.testing.expectEqual(@sizeOf(CaptureResponse), @sizeOf(Response(.capture_stop)));
    try std.testing.expectEqual(@sizeOf(SecretImportRequest), @sizeOf(Request(.secret_import)));
    try std.testing.expectEqual(@sizeOf(SecretLendRequest), @sizeOf(Request(.secret_lend)));
    try std.testing.expectEqual(@sizeOf(SecretRotateRequest), @sizeOf(Request(.secret_rotate)));
    try std.testing.expectEqual(@sizeOf(SecretRevokeRequest), @sizeOf(Request(.secret_revoke)));
    try std.testing.expect(@hasField(SecretRevokeRequest, "subject_serial"));
    try std.testing.expect(@hasField(SecretRevokeRequest, "subject_kind"));
    try std.testing.expect(@hasField(SecretRevokeRequest, "expected_holder_serial"));
    try std.testing.expect(@hasField(SecretRevokeRequest, "expected_holder_kind"));
    try std.testing.expect(@hasField(SecretRevokeRequest, "expected_holder_task_id"));
    try std.testing.expectEqual(@sizeOf(SecretVaultResponse), @sizeOf(Response(.secret_revoke)));
    try std.testing.expectEqual(@sizeOf(AttentionPostRequest), @sizeOf(Request(.attention_post)));
    try std.testing.expectEqual(@sizeOf(AttentionDismissRequest), @sizeOf(Request(.attention_dismiss)));
    try std.testing.expect(@hasField(AttentionDismissRequest, "expected_source_serial"));
    try std.testing.expect(@hasField(AttentionDismissRequest, "expected_source_kind"));
    try std.testing.expect(@hasField(AttentionDismissRequest, "expected_notification_task_id"));
    try std.testing.expectEqual(@sizeOf(AttentionQueryRequest), @sizeOf(Request(.attention_query)));
    try std.testing.expectEqual(@sizeOf(AttentionResponse), @sizeOf(Response(.attention_query)));
    try std.testing.expectEqual(@sizeOf(LifecycleControlRequest), @sizeOf(Request(.lifecycle_suspend)));
    try std.testing.expect(@hasField(LifecycleControlRequest, "target_owner_serial"));
    try std.testing.expect(@hasField(LifecycleControlRequest, "target_owner_kind"));
    try std.testing.expectEqual(@sizeOf(LifecycleControlResponse), @sizeOf(Response(.lifecycle_terminate)));
    try std.testing.expectEqual(@sizeOf(PersonalContextLeaseRequest), @sizeOf(Request(.personal_context_lease)));
    try std.testing.expectEqual(@sizeOf(PersonalContextQueryRequest), @sizeOf(Request(.personal_context_query)));
    try std.testing.expectEqual(@sizeOf(PersonalContextRevokeRequest), @sizeOf(Request(.personal_context_revoke)));
    try std.testing.expectEqual(@sizeOf(PersonalContextResponse), @sizeOf(Response(.personal_context_query)));
    try std.testing.expect(@hasField(PersonalContextResponse, "result_count"));
    try std.testing.expect(@hasField(PersonalContextResponse, "lease_revocation_generation"));
    try std.testing.expect(@hasField(PersonalContextResponse, "top_score"));
    try std.testing.expect(@hasField(PersonalContextResponse, "top_title_hits"));
    try std.testing.expect(@hasField(PersonalContextResponse, "top_body_hits"));
    try std.testing.expect(@hasField(PersonalContextResponse, "top_sensitivity"));
    try std.testing.expect(@hasField(PersonalContextResponse, "receipt_id"));
    try std.testing.expect(@hasField(PersonalContextResponse, "receipt_index_generation"));
    try std.testing.expect(@hasField(PersonalContextResponse, "receipt_privacy_flags"));
    try std.testing.expect(@hasField(PersonalContextResponse, "receipt_max_pack_sensitivity"));
    try std.testing.expect(@hasField(PersonalContextResponse, "top_object_id"));
    try std.testing.expect(@hasField(PersonalContextResponse, "top_version_id"));
    try std.testing.expect(@hasField(PersonalContextResponse, "top_title_fingerprint"));
    try std.testing.expect(@hasField(PersonalContextResponse, "receipt_issued_at_tick"));
    try std.testing.expect(@hasField(PersonalContextResponse, "request_fingerprint"));
    try std.testing.expect(@hasField(PersonalContextResponse, "query_fingerprint"));
    try std.testing.expect(@hasField(PersonalContextResponse, "pack_digest"));
    try std.testing.expect(@hasField(PersonalContextResponse, "receipt_digest"));
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(WorkspacePutVersionRequest))), contractFor("zigos.object.workspace").?.operation(.workspace_put_version).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PackageUpdateRequest))), contractFor("zigos.package.install").?.operation(.package_update).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PackageRollbackRequest))), contractFor("zigos.package.install").?.operation(.package_rollback).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PackageRemoveRequest))), contractFor("zigos.package.install").?.operation(.package_remove).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AiAuthorizeRequest))), contractFor("zigos.ai.inference").?.operation(.ai_authorize).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AiModelRegisterRequest))), contractFor("zigos.ai.model.registry").?.operation(.ai_model_register).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PrivacyQueryBudgetRequest))), contractFor("zigos.privacy.budget").?.operation(.privacy_query_budget).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(DiagnosticsPrepareExportRequest))), contractFor("zigos.diagnostics.export").?.operation(.diagnostics_prepare_export).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(ConsentRevokeRequest))), contractFor("zigos.consent.receipts").?.operation(.consent_revoke).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PermissionLeaseRenewRequest))), contractFor("zigos.permission.lease").?.operation(.permission_lease_renew).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(DataDeleteRequest))), contractFor("zigos.data.rights").?.operation(.data_delete_request).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(IdentitySessionStepUpRequest))), contractFor("zigos.identity.session").?.operation(.identity_session_step_up).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(IdentityCredentialAssertRequest))), contractFor("zigos.identity.session").?.operation(.identity_credential_assert).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AgentRecordActionRequest))), contractFor("zigos.agent.delegation").?.operation(.agent_record_action).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AgentKillSwitchRequest))), contractFor("zigos.agent.delegation").?.operation(.agent_kill_switch).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AccessibilityProfileAuditRequest))), contractFor("zigos.accessibility.profile").?.operation(.accessibility_profile_audit).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(BackgroundCompleteRequest))), contractFor("zigos.background.activity").?.operation(.background_complete).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PasteboardReadRequest))), contractFor("zigos.secure.pasteboard").?.operation(.pasteboard_read).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(ObjectRestoreAuthorizeRequest))), contractFor("zigos.object.resilience").?.operation(.object_restore_authorize).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(SemanticIndexQueryRequest))), contractFor("zigos.index.search").?.operation(.semantic_index_query).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(SyncWorkspaceReplicateRequest))), contractFor("zigos.sync.replication").?.operation(.sync_workspace_replicate).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(CaptureStartRequest))), contractFor("zigos.sensitive.capture").?.operation(.capture_start).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(SecretImportRequest))), contractFor("zigos.secret.vault").?.operation(.secret_import).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(SecretRevokeRequest))), contractFor("zigos.secret.vault").?.operation(.secret_revoke).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AttentionPostRequest))), contractFor("zigos.attention.broker").?.operation(.attention_post).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(AttentionDismissRequest))), contractFor("zigos.attention.broker").?.operation(.attention_dismiss).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(LifecycleControlRequest))), contractFor("zigos.task.lifecycle").?.operation(.lifecycle_terminate).?.request_size);
    try std.testing.expectEqual(@as(u32, @intCast(@sizeOf(PersonalContextQueryRequest))), contractFor("zigos.personal.context").?.operation(.personal_context_query).?.request_size);
}

test "typed component ABI rejects incompatible interfaces and malformed messages" {
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

    const interface_id = InterfaceId.service_registry;
    var header = WireHeader{
        .operation = @intFromEnum(OperationId.service_connect),
        .correlation_id = 1,
        .subject_task_id = 44,
    };
    try validateMessage(
        interface_id,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    );
    const wrong_interface_header = WireHeader{
        .operation = @intFromEnum(OperationId.network_open_session),
        .correlation_id = 2,
        .subject_task_id = 44,
    };
    try std.testing.expectError(Error.UnknownOperation, validateMessage(
        interface_id,
        .network_open_session,
        wrong_interface_header,
        @sizeOf(NetworkOpenSessionRequest),
        @sizeOf(NetworkSessionResponse),
    ));
    header.abi_version = VERSION - 1;
    try std.testing.expectError(Error.UnsupportedAbiVersion, validateMessage(
        interface_id,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    ));
    header.abi_version = VERSION;
    header.magic = 0;
    try std.testing.expectError(Error.InvalidMagic, validateMessage(
        interface_id,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    ));
    header.magic = MAGIC;
    try std.testing.expectError(Error.InvalidRequestLength, validateMessage(
        interface_id,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest) - 1,
        @sizeOf(ServiceConnectionResponse),
    ));
    header.subject_task_id = 0;
    try std.testing.expectError(Error.SubjectTaskRequired, validateMessage(
        interface_id,
        .service_connect,
        header,
        @sizeOf(ServiceConnectionRequest),
        @sizeOf(ServiceConnectionResponse),
    ));

    const package_header = WireHeader{
        .operation = @intFromEnum(OperationId.package_rollback),
        .correlation_id = 902,
        .subject_task_id = 78,
    };
    try validateMessage(
        .package_install,
        .package_rollback,
        package_header,
        @sizeOf(PackageRollbackRequest),
        @sizeOf(PackageRollbackResponse),
    );

    const ai_header = WireHeader{
        .operation = @intFromEnum(OperationId.ai_run_local),
        .correlation_id = 903,
        .subject_task_id = 79,
    };
    try validateMessage(
        .ai_inference,
        .ai_run_local,
        ai_header,
        @sizeOf(AiRunLocalRequest),
        @sizeOf(AiRunLocalResponse),
    );

    const privacy_header = WireHeader{
        .operation = @intFromEnum(OperationId.privacy_authorize_egress),
        .correlation_id = 904,
        .subject_task_id = 80,
    };
    try validateMessage(
        .privacy_budget,
        .privacy_authorize_egress,
        privacy_header,
        @sizeOf(PrivacyAuthorizeEgressRequest),
        @sizeOf(PrivacyAuthorizeEgressResponse),
    );

    const network_header = WireHeader{
        .operation = @intFromEnum(OperationId.network_open_session),
        .correlation_id = 9041,
        .subject_task_id = 80,
    };
    try validateMessage(
        .network_policy,
        .network_open_session,
        network_header,
        @sizeOf(NetworkOpenSessionRequest),
        @sizeOf(NetworkSessionResponse),
    );

    const diagnostics_header = WireHeader{
        .operation = @intFromEnum(OperationId.diagnostics_share_remote),
        .correlation_id = 905,
        .subject_task_id = 81,
    };
    try validateMessage(
        .diagnostics_export,
        .diagnostics_share_remote,
        diagnostics_header,
        @sizeOf(DiagnosticsShareRemoteRequest),
        @sizeOf(DiagnosticsShareRemoteResponse),
    );

    const consent_header = WireHeader{
        .operation = @intFromEnum(OperationId.consent_record),
        .correlation_id = 906,
        .subject_task_id = 82,
    };
    try validateMessage(
        .consent_receipts,
        .consent_record,
        consent_header,
        @sizeOf(ConsentRecordRequest),
        @sizeOf(ConsentRecordResponse),
    );

    const lease_header = WireHeader{
        .operation = @intFromEnum(OperationId.permission_lease_expire),
        .correlation_id = 907,
        .subject_task_id = 83,
    };
    try validateMessage(
        .permission_lease,
        .permission_lease_expire,
        lease_header,
        @sizeOf(PermissionLeaseExpireRequest),
        @sizeOf(PermissionLeaseExpireResponse),
    );

    const identity_header = WireHeader{
        .operation = @intFromEnum(OperationId.identity_session_authorize),
        .correlation_id = 908,
        .subject_task_id = 84,
    };
    try validateMessage(
        .identity_session,
        .identity_session_authorize,
        identity_header,
        @sizeOf(IdentitySessionAuthorizeRequest),
        @sizeOf(IdentitySessionAuthorizeResponse),
    );
}
