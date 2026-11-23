const std = @import("std");
const manifest = @import("../policy/manifest.zig");
const schema = @import("component_abi_schema.zig");

pub const MAGIC = schema.MAGIC;
pub const VERSION = schema.VERSION;
pub const Error = schema.Error;
pub const WireHeader = schema.WireHeader;

pub const InterfaceKey = schema.InterfaceKey;
pub const InterfaceId = schema.InterfaceId;
pub const OperationId = schema.OperationId;
pub const OperationDecl = schema.OperationDecl;
pub const InterfaceContract = schema.InterfaceContract;
pub const MAX_OPERATIONS_PER_INTERFACE = schema.MAX_OPERATIONS_PER_INTERFACE;
pub const INTERFACE_COUNT = schema.INTERFACE_COUNT;
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

pub fn Interface(comptime key: InterfaceKey) manifest.InterfaceDecl {
    return schema.interfaceDecl(key);
}

pub fn interfaceId(comptime key: InterfaceKey) InterfaceId {
    return schema.interfaceId(key);
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

test "typed component ABI derives operation IDs, wire types, and validators from schema" {
    const registry = contractFor("zigos.service.registry").?;
    try std.testing.expect(registry.contract_hash != 0);
    try std.testing.expect(registry.operation(.service_register) != null);
    try validateInterface(Interface(.object_workspace));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(WireHeader));
    try std.testing.expectEqual(@as(usize, 48), @sizeOf(ServiceRegisterRequest));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(ServiceConnectionRequest));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(ServiceConnectionResponse));
    for (&contracts) |*contract| {
        try std.testing.expect(contract.contract_hash != 0);
        for (contract.operations[0..contract.operation_count]) |decl| {
            try std.testing.expectEqual(decl, contract.operation(decl.id).?);
        }
    }
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
        .operation = @backingInt(OperationId.service_connect),
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
        .operation = @backingInt(OperationId.network_open_session),
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
        .operation = @backingInt(OperationId.package_rollback),
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
        .operation = @backingInt(OperationId.ai_run_local),
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
        .operation = @backingInt(OperationId.privacy_authorize_egress),
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
        .operation = @backingInt(OperationId.network_open_session),
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
        .operation = @backingInt(OperationId.diagnostics_share_remote),
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
        .operation = @backingInt(OperationId.consent_record),
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
        .operation = @backingInt(OperationId.permission_lease_expire),
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
        .operation = @backingInt(OperationId.identity_session_authorize),
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
