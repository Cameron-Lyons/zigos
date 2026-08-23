const std = @import("std");
const event_ledger = @import("event_ledger.zig");
const native_ux = @import("native_ux.zig");
const notification_center = @import("../services/notification_center.zig");
const object_store_mod = @import("../storage/object_store.zig");
const object_store_ids = object_store_mod.ids;
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const units = @import("../core/units.zig");

const Event = event_ledger.Event;
const EventKind = event_ledger.EventKind;
const Ledger = event_ledger.Ledger;
const DIAGNOSTIC_EXPORT_BUFFER_BYTES = units.kibibytes(2);
const REMOTE_SHARE_BUFFER_BYTES = units.kibibytes(1);
const USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES: usize = 4096;
const DOCUMENT_KNOWLEDGE_BUFFER_BYTES: usize = 512;
const DETAIL_PAYLOAD_BUFFER_BYTES: usize = 96;
const QUERY_EVENT_RECORD_CAPACITY: usize = 4;

test "event ledger text metadata stays compact" {
    try std.testing.expectEqual(u8, @FieldType(Event, "policy_label_len"));
    try std.testing.expectEqual(u8, @FieldType(Event, "missing_capability_len"));
    try std.testing.expectEqual(u16, @FieldType(Event, "detail_len"));
    try std.testing.expectEqual(@as(usize, 688), @sizeOf(Event));
    try std.testing.expectEqual(@as(usize, 53_192), @sizeOf(event_ledger.EventBacking));
}

test "event ledger reset clears events indexes and sequence state" {
    var ledger = Ledger.init();
    try ledger.recordProcessCrash(
        .network_stack,
        .{ .kind = .service, .serial = 9 },
        21,
        5001,
        "segfault",
    );
    try std.testing.expectEqual(@as(u64, 2), ledger.next_sequence);

    ledger.reset();
    try std.testing.expectEqual(@as(u64, 1), ledger.next_sequence);
    try std.testing.expectEqual(@as(usize, 0), ledger.countMatching(.{}));
    try std.testing.expect(ledger.latestKind(.process_crash) == null);
}

test "event ledger text export preserves the stable diagnostic wire format" {
    var ledger = Ledger.init();
    try ledger.recordProcessCrash(
        .network_stack,
        .{ .kind = .service, .serial = 9 },
        21,
        5001,
        "segfault",
    );

    var buffer: [256]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expectEqualStrings(
        "#1 tick=21 kind=process_crash subject=service:9 code=5001 service=network_stack detail=segfault\n",
        exported,
    );
}

test "event ledger compact inputs preserve truncation and zeroed tails" {
    var ledger = Ledger.init();
    const subject = principal.PrincipalId{ .kind = .service, .serial = 12 };
    try ledger.recordUpdateTransition(subject, 1, .boot, false, 22, "short detail");

    var events: [1]Event = undefined;
    const matched = ledger.queryEvents(.{ .kind = .update_transition }, &events);
    try std.testing.expectEqual(@as(usize, 1), matched.len);
    try std.testing.expectEqualStrings("short detail", matched[0].detailSlice());
    try std.testing.expect(std.mem.allEqual(u8, matched[0].detail[@as(usize, matched[0].detail_len)..], 0));

    var oversized = [_]u8{'x'} ** (event_ledger.MAX_DETAIL_BYTES + 8);
    try ledger.recordProcessCrash(.network_stack, subject, 23, 5002, &oversized);
    const crash = ledger.latestKind(.process_crash).?;
    try std.testing.expectEqual(@as(u16, event_ledger.MAX_DETAIL_BYTES), crash.detail_len);
    try std.testing.expect(std.mem.allEqual(u8, crash.detailSlice(), 'x'));
}

test "event ledger exports structured redacted diagnostics and audit history" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 7 };
    const app_subject = principal.PrincipalId{ .kind = .app, .serial = 8 };
    const service_subject = principal.PrincipalId{ .kind = .service, .serial = 9 };
    const device_subject = principal.PrincipalId{ .kind = .device, .serial = 42 };

    try ledger.recordPermissionDecision(user, 11, .screen_capture, false, .policy_denied, 20, "org policy denied capture", true);
    try ledger.recordProcessCrash(.network_stack, service_subject, 21, 5001, "segfault");
    try ledger.recordDriverRestart(.media_print_helpers, service_subject, 88, 22, "audio-print restarted");
    try ledger.recordUpdateTransition(service_subject, 1, .boot, true, 23, "rolled back to stable-a");
    try ledger.recordSyncConflict(user, 5, 24, "documents/tax-return.pdf conflict", true);
    try ledger.recordDeviceTrustChange(user, device_subject, false, 25, "device revoked");
    try ledger.recordSuspiciousAppBehavior(app_subject, 33, 26, 9001, "contacts plus network burst", true);

    var buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "service=network_stack") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "slot=1 rollback=yes failure=boot") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "device=42 trusted=no") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "policy=user-grant-policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "approval=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "app_behavior=suspicious") != null);

    const full = try ledger.exportText(&buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "tax-return.pdf") != null);
    try std.testing.expectEqual(EventKind.device_trust_change, ledger.latestKind(.device_trust_change).?.kind);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const summary = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, summary, "user_visible=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "privacy=redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "evidence_of_intrusion_capable=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "capability_denials=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "crashes=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "driver_restarts=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "suspicious_app_behavior=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "sync_conflicts=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "device_trust_changes=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "device_trust_revocations=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "update_health_events=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "update_rollbacks=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "protected_details_redacted=3") != null);
    try std.testing.expect(std.mem.indexOf(u8, summary, "contacts plus network burst") == null);
}

test "event ledger requires explicit opt-in before remote sharing personal device diagnostics" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 17 };

    try ledger.recordSyncConflict(user, 41, 50, "documents/payroll.xlsx conflict", true);

    var buffer: [REMOTE_SHARE_BUFFER_BYTES]u8 = undefined;
    try std.testing.expectError(error.ConsentRequired, ledger.exportRemoteShare(&buffer, .{}));

    const opted_in = try ledger.exportRemoteShare(&buffer, .{
        .user_opted_in = true,
    });
    try std.testing.expect(std.mem.indexOf(u8, opted_in, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, opted_in, "payroll.xlsx") == null);

    const managed = try ledger.exportRemoteShare(&buffer, .{
        .personal_device = false,
        .include_protected_content = true,
    });
    try std.testing.expect(std.mem.indexOf(u8, managed, "payroll.xlsx") != null);
}

test "event ledger records AI inference as protected diagnostic evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 21 };

    try ledger.recordAiInference(user, 2101, false, true, false, 70, "prompt mentions private note title");
    try ledger.recordAiInference(user, 2101, true, false, false, 71, "local model summarized object");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=ai_inference") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "private note title") == null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "private note title") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.ai_inference_events);
    try std.testing.expectEqual(@as(usize, 1), summary.ai_remote_denials);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ai_inference_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ai_remote_denials=1") != null);
}

test "event ledger records semantic memory receipt spends and replay denials" {
    var ledger = Ledger.init();
    const app = principal.PrincipalId{ .kind = .app, .serial = 31 };

    try ledger.recordSemanticMemoryReceipt(app, 3101, 42, 9001, true, true, true, true, 91, "private receipt consumed");
    try ledger.recordSemanticMemoryReceipt(app, 3101, 42, 9001, false, true, true, true, 92, "private receipt replay");
    try ledger.recordSemanticMemoryReceipt(app, 3101, 42, 0, false, true, true, true, 93, "private malformed receipt");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=semantic_memory") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "workspace=42") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "related=9001") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "receipt_audit=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "receipt replay") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "malformed receipt") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "detail=redacted") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 3), summary.semantic_memory_events);
    try std.testing.expectEqual(@as(usize, 2), summary.semantic_memory_denials);
    try std.testing.expectEqual(@as(usize, 0), summary.semantic_memory_remote_denials);
    try std.testing.expectEqual(@as(usize, 3), summary.semantic_memory_receipt_events);
    try std.testing.expectEqual(@as(usize, 2), summary.semantic_memory_receipt_denials);
    try std.testing.expectEqual(@as(usize, 3), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "semantic_memory_receipt_events=3") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "semantic_memory_receipt_denials=2") != null);
}

test "event ledger records AI model attestations as protected diagnostic evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 25 };

    try ledger.recordAiModelAttestation(user, 2501, true, true, true, 75, "sha256:local-model trusted source");
    try ledger.recordAiModelAttestation(user, 2501, false, false, true, 76, "unmeasured local model rejected");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=ai_model_attestation") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "sha256:local-model") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "sha256:local-model") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "unmeasured local model rejected") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.ai_model_attestations);
    try std.testing.expectEqual(@as(usize, 1), summary.ai_model_rejections);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ai_model_attestations=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ai_model_rejections=1") != null);
}

test "event ledger records session posture as protected diagnostic evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 26 };

    try ledger.recordSessionPosture(user, 2601, true, true, true, true, 2, 77, "fresh hardware-backed platform session");
    try ledger.recordSessionPosture(user, 2601, false, false, true, true, 9, 78, "software credential rejected");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=session_posture") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "software credential") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "hardware-backed platform session") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "software credential rejected") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.session_posture_events);
    try std.testing.expectEqual(@as(usize, 1), summary.session_posture_denials);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "session_posture_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "session_posture_denials=1") != null);
}

test "event ledger records private egress and privacy budgets as redacted evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 22 };

    try ledger.recordDataEgress(user, 2201, .private_user_data, 2048, false, 80, "workspace://notes/private.md");
    try ledger.recordPrivacyBudget(user, 2201, false, 81, "private egress budget exhausted");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=data_egress") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=privacy_budget") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "private.md") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "budget exhausted") == null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "private.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "budget exhausted") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 1), summary.data_egress_events);
    try std.testing.expectEqual(@as(usize, 1), summary.private_egress_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.privacy_budget_events);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "data_egress_events=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "private_egress_denials=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "privacy_budget_events=1") != null);
}

test "event ledger records data export deletion and receipts as redacted evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 24 };

    try ledger.recordDataExport(user, 2401, .private_user_data, 1024, true, 100, "export workspace://notes/private.md");
    try ledger.recordDataExport(user, 2401, .private_user_data, 8192, false, 101, "export denied for private archive");
    try ledger.recordDataDeletion(user, 2401, 9101, true, 102, "deleted private note versions", true);
    try ledger.recordDataDeletion(user, 2401, 0, false, 103, "deletion denied without receipt", true);

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=data_export") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=data_deletion") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "private.md") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "private.md") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "deleted private note versions") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.data_export_events);
    try std.testing.expectEqual(@as(usize, 1), summary.data_export_denials);
    try std.testing.expectEqual(@as(usize, 2), summary.data_deletion_events);
    try std.testing.expectEqual(@as(usize, 1), summary.data_deletion_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.data_deletion_receipts);
    try std.testing.expectEqual(@as(usize, 4), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "data_export_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "data_export_denials=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "data_deletion_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "data_deletion_receipts=1") != null);
}

test "event ledger records retention leases and consent receipts as redacted evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 23 };

    try ledger.recordRetentionPolicy(user, 2301, 30, true, 90, "retain private capture for 30 days", true);
    try ledger.recordPermissionLease(user, 2301, .camera, .issued, 300, 91, "camera lease issued for scan", true);
    try ledger.recordPermissionLease(user, 2301, .camera, .expired, 300, 92, "camera lease expired", true);
    try ledger.recordConsentReceipt(user, 2301, 7001, .recorded, 93, "consent for document scan");
    try ledger.recordConsentReceipt(user, 2301, 7001, .revoked, 94, "consent revoked");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=retention_policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=permission_lease") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=consent_receipt") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "document scan") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "document scan") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 1), summary.retention_policy_events);
    try std.testing.expectEqual(@as(usize, 2), summary.permission_lease_events);
    try std.testing.expectEqual(@as(usize, 1), summary.permission_lease_expirations);
    try std.testing.expectEqual(@as(usize, 2), summary.consent_receipt_events);
    try std.testing.expectEqual(@as(usize, 1), summary.consent_receipt_revocations);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "retention_policy_events=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "permission_lease_expirations=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "consent_receipt_revocations=1") != null);
}

test "event ledger records agent delegation as redacted diagnostic evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 27 };

    try ledger.recordAgentDelegation(user, 2701, true, 3, 0, true, true, 110, "agent organized private notes locally");
    try ledger.recordAgentDelegation(user, 2701, false, 5, 2, false, true, 111, "agent remote action denied for customer plan");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=agent_delegation") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "customer plan") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "agent organized private notes locally") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "agent remote action denied") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.agent_delegation_events);
    try std.testing.expectEqual(@as(usize, 1), summary.agent_delegation_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.agent_remote_call_events);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "agent_delegation_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "agent_delegation_denials=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "agent_remote_call_events=1") != null);
}

test "event ledger records agent session boundaries as redacted diagnostic evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 29 };

    try ledger.recordAgentSessionBoundary(user, 2901, true, true, true, false, 5, 112, "agent session bound locally");
    try ledger.recordAgentSessionBoundary(user, 2901, false, true, true, true, 4, 113, "agent session killed for stale generation");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=agent_session") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kill_switch_block=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "stale generation") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "agent session bound locally") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "agent session killed") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.agent_session_events);
    try std.testing.expectEqual(@as(usize, 1), summary.agent_session_denials);
    try std.testing.expectEqual(@as(usize, 1), summary.agent_kill_switch_denials);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "agent_session_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "agent_session_denials=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "agent_kill_switch_denials=1") != null);
}

test "event ledger records attention policy as redacted diagnostic evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 28 };

    try ledger.recordAttentionDecision(user, 2801, true, false, 1, 0, 120, "passive status notice allowed");
    try ledger.recordAttentionDecision(user, 2801, false, true, 3, 1, 121, "agent tried to interrupt quiet hours");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=attention_policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "interruptive=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "active_visible=3") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "quiet hours") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "agent tried to interrupt quiet hours") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.attention_policy_events);
    try std.testing.expectEqual(@as(usize, 1), summary.attention_interruptions_denied);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "attention_policy_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "attention_interruptions_denied=1") != null);
}

test "event ledger records accessibility profile as redacted diagnostic evidence" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 29 };

    try ledger.recordAccessibilityProfile(user, 2901, false, true, false, true, true, 130, "keyboard navigation missing for tremor profile");
    try ledger.recordAccessibilityProfile(user, 2901, true, true, true, true, true, 131, "profile applied");

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const redacted = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, "kind=accessibility_profile") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "accessibility screen_reader=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "tremor profile") == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "redacted") != null);

    const full = try ledger.exportText(&export_buffer, .{ .include_protected_content = true });
    try std.testing.expect(std.mem.indexOf(u8, full, "tremor profile") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 2), summary.accessibility_profile_events);
    try std.testing.expectEqual(@as(usize, 1), summary.accessibility_denials);
    try std.testing.expectEqual(@as(usize, 2), summary.protected_details_redacted);

    var summary_buffer: [USER_DIAGNOSTIC_SUMMARY_BUFFER_BYTES]u8 = undefined;
    const rendered = try ledger.renderUserVisibleDiagnosticsToBuffer(&summary_buffer);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "accessibility_profile_events=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "accessibility_denials=1") != null);
}

test "event ledger remote sharing scrubs protected diagnostics unless explicitly included" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 18 };
    const service_subject = principal.PrincipalId{ .kind = .service, .serial = 19 };

    try ledger.recordProcessCrash(.network_stack, service_subject, 60, 5002, "network service restarted");
    try ledger.recordPermissionDecision(user, 61, .screen_capture, false, .policy_denied, 61, "private customer deck", true);
    try ledger.recordSyncConflict(user, 62, 62, "documents/secrets.md conflict", true);

    var buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    try std.testing.expectError(error.ConsentRequired, ledger.exportRemoteShare(&buffer, .{
        .include_protected_content = true,
    }));

    const personal_redacted = try ledger.exportRemoteShare(&buffer, .{
        .user_opted_in = true,
    });
    try std.testing.expect(std.mem.indexOf(u8, personal_redacted, "network service restarted") != null);
    try std.testing.expect(std.mem.indexOf(u8, personal_redacted, "redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, personal_redacted, "private customer deck") == null);
    try std.testing.expect(std.mem.indexOf(u8, personal_redacted, "secrets.md") == null);

    const managed_full = try ledger.exportRemoteShare(&buffer, .{
        .personal_device = false,
        .include_protected_content = true,
    });
    try std.testing.expect(std.mem.indexOf(u8, managed_full, "private customer deck") != null);
    try std.testing.expect(std.mem.indexOf(u8, managed_full, "secrets.md") != null);
}

test "event ledger indexes structured queries by kind subject and task" {
    var ledger = Ledger.init();
    const alice = principal.PrincipalId{ .kind = .user, .serial = 101 };
    const bob = principal.PrincipalId{ .kind = .user, .serial = 202 };
    const storage_subject = principal.PrincipalId{ .kind = .service, .serial = 303 };

    try ledger.recordPermissionDecision(alice, 44, .screen_capture, false, .policy_denied, 10, "alice protected", true);
    try ledger.recordCapabilityGrant(alice, 44, 700, .object_access, 11, "alice grant");
    try ledger.recordPermissionReview(bob, 55, .camera, true, 12, "bob review", false);
    try ledger.recordDriverRestart(.storage_object, storage_subject, 900, 13, "driver restart");
    try ledger.recordCapabilityRevocation(alice, 66, 700, .object_access, 14, "alice revoke");

    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .kind = .permission_decision }));
    try std.testing.expectEqual(@as(usize, 3), ledger.countMatching(.{ .subject = alice }));
    try std.testing.expectEqual(@as(usize, 2), ledger.countMatching(.{ .task_id = 44 }));
    try std.testing.expectEqual(EventKind.capability_revocation, ledger.latestKind(.capability_revocation).?.kind);

    var records: [QUERY_EVENT_RECORD_CAPACITY]Event = undefined;
    const task_matches = ledger.queryEvents(.{ .task_id = 44 }, &records);
    try std.testing.expectEqual(@as(usize, 2), task_matches.len);
    try std.testing.expectEqual(@as(u64, 1), task_matches[0].sequence);
    try std.testing.expectEqual(@as(u64, 2), task_matches[1].sequence);
    try std.testing.expectEqualStrings("redacted", task_matches[0].detailSlice());

    const subject_and_kind = ledger.queryEvents(.{ .subject = alice, .kind = .capability_revocation }, &records);
    try std.testing.expectEqual(@as(usize, 1), subject_and_kind.len);
    try std.testing.expectEqual(@as(u64, 5), subject_and_kind[0].sequence);

    const protected = ledger.queryEvents(.{ .subject = alice, .task_id = 44, .include_protected_content = true }, &records);
    try std.testing.expectEqual(@as(usize, 2), protected.len);
    try std.testing.expectEqualStrings("alice protected", protected[0].detailSlice());

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "#1 tick=10 kind=permission_decision") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "blocked_help=\"Blocked: This app") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "detail=redacted") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "detail=alice protected") == null);
}

test "event ledger evicts oldest events instead of jamming past MAX_EVENTS" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 7 };

    const total: u64 = event_ledger.MAX_EVENTS * 2 + 5;
    var task_id: u64 = 1;
    while (task_id <= total) : (task_id += 1) {
        try ledger.recordPermissionDecision(user, task_id, .screen_capture, false, .policy_denied, task_id, "denied", true);
    }

    try std.testing.expectEqual(event_ledger.MAX_EVENTS, ledger.countMatching(.{ .kind = .permission_decision }));
    try std.testing.expectEqual(event_ledger.MAX_EVENTS, ledger.countMatching(.{ .subject = user }));

    const oldest_retained = total - event_ledger.MAX_EVENTS + 1;
    try std.testing.expectEqual(oldest_retained, ledger.oldest_retained_sequence);
    try std.testing.expectEqual(@as(usize, 0), ledger.countMatching(.{ .task_id = 1 }));
    try std.testing.expectEqual(@as(usize, 0), ledger.countMatching(.{ .task_id = oldest_retained - 1 }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .task_id = oldest_retained }));
    try std.testing.expectEqual(@as(usize, 1), ledger.countMatching(.{ .task_id = total }));

    const latest = ledger.latestKind(.permission_decision).?;
    try std.testing.expectEqual(total, latest.sequence);
    try std.testing.expectEqual(total, latest.task_id);

    var recycled_task_ledger = Ledger.init();
    const recycled_total: u64 = @as(u64, event_ledger.MAX_EVENTS) + 1;
    var sequence: u64 = 1;
    while (sequence <= recycled_total) : (sequence += 1) {
        const recycled_task_id = if (sequence == recycled_total) 1 else sequence;
        try recycled_task_ledger.recordPermissionDecision(user, recycled_task_id, .screen_capture, false, .policy_denied, sequence, "denied", true);
    }

    try std.testing.expectEqual(@as(u64, 2), recycled_task_ledger.oldest_retained_sequence);
    try std.testing.expectEqual(@as(usize, 1), recycled_task_ledger.countMatching(.{ .task_id = 1 }));
    var records: [QUERY_EVENT_RECORD_CAPACITY]Event = undefined;
    const recycled_matches = recycled_task_ledger.queryEvents(.{ .task_id = 1 }, &records);
    try std.testing.expectEqual(@as(usize, 1), recycled_matches.len);
    try std.testing.expectEqual(recycled_total, recycled_matches[0].sequence);
}

test "event ledger renders what an app knows about a document" {
    var ledger = Ledger.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 303 };
    const task_id: u64 = 77;
    const document = "workspace://trip/documents/plan.md";

    try ledger.recordPermissionReview(user, task_id, .object_access, true, 10, "review resource=workspace://trip/documents/plan.md", false);
    try ledger.recordCapabilityGrant(user, task_id, 700, .object_access, 11, "Permission receipt: granted Object access for workspace://trip/documents/plan.md; data leaves: none; revoke: Permission Review");
    try ledger.recordCapabilityGrant(user, task_id, 701, .network_egress, 12, "Permission receipt: data leaves: sync object workspace://trip/documents/plan.md with trusted-devices; revoke: Permission Review");

    var buffer: [DOCUMENT_KNOWLEDGE_BUFFER_BYTES]u8 = undefined;
    const before_revoke = try ledger.renderAppDocumentKnowledgeToBuffer(&buffer, task_id, document);
    try std.testing.expect(std.mem.indexOf(u8, before_revoke, "knows=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, before_revoke, "active_grants=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, before_revoke, "egress_routes=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, before_revoke, "data_can_leave=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, before_revoke, "object_capability=700") != null);

    try ledger.recordCapabilityRevocation(user, task_id, 700, .object_access, 13, "revoked from Permission Review");
    const after_revoke = try ledger.renderAppDocumentKnowledgeToBuffer(&buffer, task_id, document);
    try std.testing.expect(std.mem.indexOf(u8, after_revoke, "active_grants=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, after_revoke, "revoked=1") != null);

    try ledger.recordCapabilityGrant(user, task_id, 702, .object_access, 14, "Permission receipt: granted Object access for workspace://trip/documents/plan.md; data leaves: none; revoke: Permission Review");
    try ledger.recordCapabilityRevocation(user, task_id, 702, .object_access, 15, "revoked without restating the document path");
    const implicit_revoke = try ledger.renderAppDocumentKnowledgeToBuffer(&buffer, task_id, document);
    try std.testing.expect(std.mem.indexOf(u8, implicit_revoke, "object_grants=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, implicit_revoke, "active_grants=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, implicit_revoke, "revoked=2") != null);
}

test "event ledger persists history across restart" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 44 };
    const signer = signing.SignerIdentity{
        .label = "diagnostic-ledger",
        .seed = signing.seedFromByte(0xA7),
    };

    var storage = storage_service.Service.initWithStore(901, 300, owner, &storage_checkpoint_store);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);
    try ledger.recordUpdateTransition(owner, 1, .none, false, 10, "stable-b activated");
    try ledger.recordDeviceTrustChange(owner, .{ .kind = .device, .serial = 4 }, false, 11, "device revoked");

    var restarted_storage = storage_service.Service.initWithStore(901, 301, owner, &storage_checkpoint_store);
    var restarted = try Ledger.initPersistent(&restarted_storage, owner, signer);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(EventKind.device_trust_change, restarted.latestKind(.device_trust_change).?.kind);

    var buffer: [REMOTE_SHARE_BUFFER_BYTES]u8 = undefined;
    const exported = try restarted.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=update_transition") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=device_trust_change") != null);

    storage_checkpoint_store.resetPersistent();
}

test "event ledger batches durable writes until persistence batch flush" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 47 };
    const signer = signing.SignerIdentity{
        .label = "diagnostic-ledger-batched",
        .seed = signing.seedFromByte(0xAA),
    };

    var storage = storage_service.Service.initWithStore(904, 306, owner, &storage_checkpoint_store);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);
    ledger.beginPersistenceBatch();
    try ledger.recordUpdateTransition(owner, 1, .none, false, 20, "first batched event");
    try ledger.recordDeviceTrustChange(owner, .{ .kind = .device, .serial = 6 }, true, 21, "second batched event");
    try std.testing.expectEqual(@as(usize, 2), ledger.pendingPersistenceCount());
    try std.testing.expectEqual(@as(usize, 0), storage.objectCount());

    var preflush_storage = storage_service.Service.initWithStore(904, 307, owner, &storage_checkpoint_store);
    const preflush = try Ledger.initPersistent(&preflush_storage, owner, signer);
    try std.testing.expect(!preflush.loaded_existing_state);

    try ledger.flushPersistenceBatch();
    try std.testing.expectEqual(@as(usize, 0), ledger.pendingPersistenceCount());
    try std.testing.expectEqual(@as(usize, 3), storage.objectCount());

    var restarted_storage = storage_service.Service.initWithStore(904, 308, owner, &storage_checkpoint_store);
    var restarted = try Ledger.initPersistent(&restarted_storage, owner, signer);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(EventKind.device_trust_change, restarted.latestKind(.device_trust_change).?.kind);

    storage_checkpoint_store.resetPersistent();
}

test "event ledger persists user visible policy ux history across restart and query" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 46 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 8 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 9 };
    const signer = signing.SignerIdentity{
        .label = "policy-ux-history",
        .seed = signing.seedFromByte(0xA9),
    };

    var storage = storage_service.Service.initWithStore(903, 304, owner, &storage_checkpoint_store);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);
    try ledger.recordPermissionReview(user, 503, .screen_capture, false, 30, "screen capture review denied", false);
    try ledger.recordPermissionDecision(user, 503, .screen_capture, false, .policy_denied, 31, "screen capture blocked", true);
    try ledger.recordCapabilityGrant(user, 503, 7001, .object_access, 32, "workspace grant");
    try ledger.recordCapabilityRevocation(user, 503, 7001, .object_access, 33, "workspace grant revoked");

    var notifications = notification_center.Center.init();
    const notification = try notifications.post(.{
        .source = app,
        .reason = .permission_request,
        .urgency = .high,
        .task_id = 503,
        .detail = "app needs screen capture",
    });
    try ledger.recordNotification(notification.*, 34);

    var ux = native_ux.Controller.init();
    const flow = try ux.reviewPermissionDecision(
        503,
        user,
        "app.capture",
        .{
            .kind = .screen_capture,
            .resource = "screen:main",
            .rights = .{ .service = .{} },
            .required = true,
        },
        false,
        false,
        null,
    );
    try ledger.recordTaskFlow(flow.*, 35);

    var restarted_storage = storage_service.Service.initWithStore(903, 305, owner, &storage_checkpoint_store);
    var restarted = try Ledger.initPersistent(&restarted_storage, owner, signer);
    try std.testing.expect(restarted.loaded_existing_state);
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .kind = .permission_review, .task_id = 503 }));
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .kind = .permission_decision, .task_id = 503 }));
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .kind = .capability_grant, .task_id = 503 }));
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .kind = .capability_revocation, .task_id = 503 }));
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .kind = .notification, .task_id = 503 }));
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .kind = .task_flow, .task_id = 503 }));

    var events_buffer: [QUERY_EVENT_RECORD_CAPACITY]Event = undefined;
    const redacted = restarted.queryEvents(.{ .kind = .permission_decision, .task_id = 503 }, &events_buffer);
    try std.testing.expectEqual(@as(usize, 1), redacted.len);
    try std.testing.expectEqualStrings("redacted", redacted[0].detailSlice());
    const full = restarted.queryEvents(.{ .kind = .permission_decision, .task_id = 503, .include_protected_content = true }, &events_buffer);
    try std.testing.expectEqualStrings("screen capture blocked", full[0].detailSlice());

    var export_buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try restarted.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=permission_review") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=capability_grant") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=capability_revocation") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "reason=permission_request") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "flow_kind=review_permission_request") != null);

    storage_checkpoint_store.resetPersistent();
}

test "event ledger rebuilds eviction order across restart" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 48 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 49 };
    const signer = signing.SignerIdentity{
        .label = "diagnostic-ledger-eviction-order",
        .seed = signing.seedFromByte(0xAB),
    };

    var storage = storage_service.Service.initWithStore(905, 309, owner, &storage_checkpoint_store);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);
    ledger.beginPersistenceBatch();
    var sequence: u64 = 1;
    while (sequence <= event_ledger.MAX_EVENTS) : (sequence += 1) {
        try ledger.recordPermissionDecision(user, sequence, .screen_capture, false, .policy_denied, sequence, "denied", true);
    }
    try ledger.flushPersistenceBatch();

    var restarted_storage = storage_service.Service.initWithStore(905, 310, owner, &storage_checkpoint_store);
    var restarted = try Ledger.initPersistent(&restarted_storage, owner, signer);
    try restarted.recordPermissionDecision(user, event_ledger.MAX_EVENTS + 1, .screen_capture, false, .policy_denied, event_ledger.MAX_EVENTS + 1, "denied", true);

    try std.testing.expectEqual(@as(usize, 0), restarted.countMatching(.{ .task_id = 1 }));
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .task_id = 2 }));
    try std.testing.expectEqual(@as(usize, 1), restarted.countMatching(.{ .task_id = event_ledger.MAX_EVENTS + 1 }));
    try std.testing.expectEqual(@as(u64, event_ledger.MAX_EVENTS + 1), restarted.latestKind(.permission_decision).?.sequence);

    storage_checkpoint_store.resetPersistent();
}

test "event ledger persistence retains full in-memory history and detail payloads" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 45 };
    const signer = signing.SignerIdentity{
        .label = "diagnostic-ledger-bounded",
        .seed = signing.seedFromByte(0xA8),
    };

    var storage = storage_service.Service.initWithStore(902, 302, owner, &storage_checkpoint_store);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);

    var tick: u64 = 10;
    while (tick < 18) : (tick += 1) {
        var detail_buffer: [DETAIL_PAYLOAD_BUFFER_BYTES]u8 = undefined;
        const detail = try std.fmt.bufPrint(&detail_buffer, "event-{d}-detail-abcdefghijklmnopqrstuvwxyz-0123456789", .{tick});
        try ledger.recordUpdateTransition(
            owner,
            @as(usize, @intCast(tick % 2)),
            if ((tick % 2) == 0) .storage else .none,
            (tick % 2) == 0,
            tick,
            detail,
        );
    }

    try std.testing.expectEqual(@as(usize, 9), storage.objectCount());

    var restarted_storage = storage_service.Service.initWithStore(902, 303, owner, &storage_checkpoint_store);
    var restarted = try Ledger.initPersistent(&restarted_storage, owner, signer);
    try std.testing.expectEqual(@as(u64, 9), restarted.next_sequence);

    var buffer: [DIAGNOSTIC_EXPORT_BUFFER_BYTES]u8 = undefined;
    const exported = try restarted.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "#1 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "#8 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "abcdefghijklmnopqrstuvwxyz-0123456789") != null);

    storage_checkpoint_store.resetPersistent();
}

test "event ledger persist failure aborts its transaction instead of wedging the workspace" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const owner = principal.PrincipalId{ .kind = .service, .serial = 45 };
    const signer = signing.SignerIdentity{
        .label = "diagnostic-ledger",
        .seed = signing.seedFromByte(0xA8),
    };

    var storage = storage_service.Service.initWithStore(902, 302, owner, &storage_checkpoint_store);
    var ledger = try Ledger.initPersistent(&storage, owner, signer);

    const filler = try storage.putVersion(.{
        .preferred_object_id = object_store_ids.object(950),
        .object_type = .document,
        .payload = "filler",
        .metadata = try object_store_mod.signMetadata(signer, "filler", "text/markdown", .document, "filler", 5),
    });
    try storage.beginTransaction(ledger.workspace_id);
    var filler_index: usize = 0;
    while (true) : (filler_index += 1) {
        var path_buffer: [32]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "filler/{d}", .{filler_index});
        storage.stagePut(ledger.workspace_id, path, filler.object_id, filler.version_id, .document) catch |err| {
            try std.testing.expectEqual(error.EntryTableFull, err);
            break;
        };
    }
    _ = try storage.commit(ledger.workspace_id, 6);

    try std.testing.expectError(
        error.EntryTableFull,
        ledger.recordUpdateTransition(owner, 1, .none, false, 10, "stable-b activated"),
    );
    try std.testing.expectError(
        error.EntryTableFull,
        ledger.recordUpdateTransition(owner, 1, .none, false, 11, "stable-b activated"),
    );

    storage_checkpoint_store.resetPersistent();
}
