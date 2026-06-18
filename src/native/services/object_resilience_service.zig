const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const manifest = @import("../policy/manifest.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_SNAPSHOTS: usize = 16;

pub const Error = event_ledger.Error || error{
    DeviceTrustMismatch,
    PolicyDenied,
    SourceTaskMismatch,
    SnapshotNotFound,
    SnapshotSubjectMismatch,
    SnapshotRevoked,
    SnapshotTableFull,
};

pub const PrepareBackupRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    workspace_id: u64,
    object_id: u64,
    restore_device_id: u64,
    bytes: usize,
    sensitivity: manifest.DataSensitivity = .private_user_data,
    encrypted: bool = false,
    recovery_key_present: bool = false,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const RestoreRequest = struct {
    subject: principal.PrincipalId,
    destination_task_id: u64,
    snapshot_id: u64,
    destination_device_id: u64,
    restore_age_days: u16 = 0,
    device_trust_verified: bool = false,
    migration: bool = false,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const RevokeRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    snapshot_id: u64,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const Snapshot = struct {
    id: u64 = 0,
    subject: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    source_task_id: u64 = 0,
    workspace_id: u64 = 0,
    object_id: u64 = 0,
    restore_device_id: u64 = 0,
    bytes: usize = 0,
    sensitivity: manifest.DataSensitivity = .internal_data,
    encrypted: bool = false,
    recovery_key_present: bool = false,
    revoked: bool = false,
    restore_count: u16 = 0,
};

const Slot = struct {
    in_use: bool = false,
    snapshot: Snapshot = .{},
};

pub const Service = struct {
    next_snapshot_id: u64 = 1,
    slots: [MAX_SNAPSHOTS]Slot = [_]Slot{Slot{}} ** MAX_SNAPSHOTS,

    pub fn init() Service {
        return .{};
    }

    pub fn prepareBackup(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: PrepareBackupRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*Snapshot {
        const decision = policies.objectResilienceDecision(subjects, .{
            .operation = .backup,
            .sensitivity = request.sensitivity,
            .bytes = request.bytes,
            .encrypted = request.encrypted,
            .recovery_key_present = request.recovery_key_present,
        });
        if (!decision.allowed) {
            try recordBackup(ledger, request, 0, false);
            return error.PolicyDenied;
        }

        const slot = self.firstFreeSlot() orelse {
            try recordBackup(ledger, request, 0, false);
            return error.SnapshotTableFull;
        };
        slot.in_use = true;
        slot.snapshot = .{
            .id = self.next_snapshot_id,
            .subject = request.subject,
            .source_task_id = request.task_id,
            .workspace_id = request.workspace_id,
            .object_id = request.object_id,
            .restore_device_id = request.restore_device_id,
            .bytes = request.bytes,
            .sensitivity = request.sensitivity,
            .encrypted = request.encrypted,
            .recovery_key_present = request.recovery_key_present,
        };
        self.next_snapshot_id += 1;
        try recordBackup(ledger, request, slot.snapshot.id, true);
        return &slot.snapshot;
    }

    pub fn restore(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: RestoreRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*Snapshot {
        const snapshot = self.find(request.snapshot_id) orelse {
            try recordRestore(ledger, request, false, false);
            return error.SnapshotNotFound;
        };
        if (snapshot.revoked) {
            try recordRestore(ledger, request, false, snapshot.encrypted);
            return error.SnapshotRevoked;
        }
        if (!snapshot.subject.eql(request.subject)) {
            try recordRestore(ledger, request, false, snapshot.encrypted);
            return error.SnapshotSubjectMismatch;
        }
        if (snapshot.restore_device_id != request.destination_device_id) {
            try recordRestore(ledger, request, false, snapshot.encrypted);
            return error.DeviceTrustMismatch;
        }

        const decision = policies.objectResilienceDecision(subjects, .{
            .operation = if (request.migration) .migrate else .restore,
            .sensitivity = snapshot.sensitivity,
            .bytes = snapshot.bytes,
            .encrypted = snapshot.encrypted,
            .recovery_key_present = snapshot.recovery_key_present,
            .device_trust_verified = request.device_trust_verified,
            .restore_age_days = request.restore_age_days,
        });
        if (!decision.allowed) {
            try recordRestore(ledger, request, false, snapshot.encrypted);
            return error.PolicyDenied;
        }

        snapshot.restore_count += 1;
        try recordRestore(ledger, request, true, snapshot.encrypted);
        return snapshot;
    }

    pub fn revoke(self: *Service, request: RevokeRequest, ledger: ?*event_ledger.Ledger) Error!void {
        const snapshot = self.find(request.snapshot_id) orelse {
            try recordRevoke(ledger, request, false, false);
            return error.SnapshotNotFound;
        };
        if (!snapshot.subject.eql(request.subject)) {
            try recordRevoke(ledger, request, false, snapshot.encrypted);
            return error.SnapshotSubjectMismatch;
        }
        if (snapshot.source_task_id != request.task_id) {
            try recordRevoke(ledger, request, false, snapshot.encrypted);
            return error.SourceTaskMismatch;
        }
        snapshot.revoked = true;
        try recordRevoke(ledger, request, true, snapshot.encrypted);
    }

    pub fn find(self: *Service, snapshot_id: u64) ?*Snapshot {
        for (&self.slots) |*slot| {
            if (!slot.in_use) continue;
            if (slot.snapshot.id == snapshot_id) return &slot.snapshot;
        }
        return null;
    }

    fn firstFreeSlot(self: *Service) ?*Slot {
        for (&self.slots) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }
};

fn recordBackup(
    ledger: ?*event_ledger.Ledger,
    request: PrepareBackupRequest,
    snapshot_id: u64,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordObjectResilience(
            request.subject,
            request.task_id,
            snapshot_id,
            allowed,
            false,
            request.encrypted,
            request.restore_device_id != 0,
            request.now_ticks,
            request.detail,
        );
    }
}

fn recordRestore(
    ledger: ?*event_ledger.Ledger,
    request: RestoreRequest,
    allowed: bool,
    encrypted: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordObjectResilience(
            request.subject,
            request.destination_task_id,
            request.snapshot_id,
            allowed,
            true,
            encrypted,
            request.device_trust_verified,
            request.now_ticks,
            request.detail,
        );
    }
}

fn recordRevoke(
    ledger: ?*event_ledger.Ledger,
    request: RevokeRequest,
    allowed: bool,
    encrypted: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordObjectResilience(
            request.subject,
            request.task_id,
            request.snapshot_id,
            allowed,
            false,
            encrypted,
            false,
            request.now_ticks,
            request.detail,
        );
    }
}

test "object resilience binds restore and revoke to snapshot subject and source task" {
    var directory = policy_object.Directory.init();
    _ = try directory.create(.{
        .scope = .organization,
        .subject_id = 730,
        .issuer = .{ .kind = .policy_authority, .serial = 730 },
        .label = "object resilience policy",
        .object_backup_allowed = true,
        .object_restore_allowed = true,
        .require_encrypted_object_backup = true,
        .require_backup_recovery_key = true,
        .require_restore_device_trust = true,
        .max_object_backup_bytes = 1_048_576,
        .max_object_restore_age_days = 30,
    }, signing.SignerIdentity{
        .label = "object-resilience-policy",
        .seed = signing.seedFromByte(0xb7),
    });
    const subjects = policy_object.SubjectSet{ .organization_id = 730 };
    const owner = principal.PrincipalId{ .kind = .app, .serial = 731 };
    const intruder = principal.PrincipalId{ .kind = .app, .serial = 732 };
    var service = Service.init();
    var ledger = event_ledger.Ledger.init();

    const snapshot = try service.prepareBackup(&directory, subjects, .{
        .subject = owner,
        .task_id = 900,
        .workspace_id = 11,
        .object_id = 22,
        .restore_device_id = 333,
        .bytes = 4096,
        .sensitivity = .private_user_data,
        .encrypted = true,
        .recovery_key_present = true,
        .now_ticks = 10,
        .detail = "private object backup contents",
    }, &ledger);

    try std.testing.expectError(error.SnapshotSubjectMismatch, service.restore(&directory, subjects, .{
        .subject = intruder,
        .destination_task_id = 901,
        .snapshot_id = snapshot.id,
        .destination_device_id = 333,
        .device_trust_verified = true,
        .restore_age_days = 1,
        .now_ticks = 11,
        .detail = "private object backup wrong subject restore",
    }, &ledger));

    const restored = try service.restore(&directory, subjects, .{
        .subject = owner,
        .destination_task_id = 901,
        .snapshot_id = snapshot.id,
        .destination_device_id = 333,
        .device_trust_verified = true,
        .restore_age_days = 1,
        .now_ticks = 12,
        .detail = "private object backup trusted restore",
    }, &ledger);
    try std.testing.expectEqual(@as(u16, 1), restored.restore_count);

    const revocable = try service.prepareBackup(&directory, subjects, .{
        .subject = owner,
        .task_id = 900,
        .workspace_id = 11,
        .object_id = 23,
        .restore_device_id = 333,
        .bytes = 4096,
        .sensitivity = .private_user_data,
        .encrypted = true,
        .recovery_key_present = true,
        .now_ticks = 13,
        .detail = "private revocable object backup",
    }, &ledger);

    try std.testing.expectError(error.SnapshotSubjectMismatch, service.revoke(.{
        .subject = intruder,
        .task_id = 900,
        .snapshot_id = revocable.id,
        .now_ticks = 14,
        .detail = "private revocable object backup wrong subject",
    }, &ledger));
    try std.testing.expectError(error.SourceTaskMismatch, service.revoke(.{
        .subject = owner,
        .task_id = 901,
        .snapshot_id = revocable.id,
        .now_ticks = 15,
        .detail = "private revocable object backup wrong source task",
    }, &ledger));
    try service.revoke(.{
        .subject = owner,
        .task_id = 900,
        .snapshot_id = revocable.id,
        .now_ticks = 16,
        .detail = "private revocable object backup revoked",
    }, &ledger);
    try std.testing.expectError(error.SnapshotRevoked, service.restore(&directory, subjects, .{
        .subject = owner,
        .destination_task_id = 901,
        .snapshot_id = revocable.id,
        .destination_device_id = 333,
        .device_trust_verified = true,
        .restore_age_days = 1,
        .now_ticks = 17,
        .detail = "private revoked object backup restore",
    }, &ledger));

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 8), summary.object_resilience_events);
    try std.testing.expectEqual(@as(usize, 4), summary.object_resilience_denials);
    try std.testing.expectEqual(@as(usize, 3), summary.object_restore_events);
    try std.testing.expect(summary.protected_details_redacted >= summary.object_resilience_events);

    var buffer: [2048]u8 = undefined;
    const exported = try ledger.exportText(&buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private object backup") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=object_resilience") != null);
}
