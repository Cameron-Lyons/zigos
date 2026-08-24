const std = @import("std");
const abi = @import("../core/abi.zig");
const event_ledger = @import("event_ledger.zig");
const immutable_base = @import("immutable_base.zig");
const capability = @import("../kernel_api/capability.zig");
const manifest = @import("../policy/manifest.zig");
const object_store = @import("../storage/object_store.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");
const storage_service = @import("../storage/storage_service.zig");
const sync_service = @import("../sync/sync_service.zig");
const workspace = @import("../storage/workspace.zig");

pub const MAX_BREAK_GLASS_REASON_BYTES: usize = 160;
pub const DERIVES_ACTION_COUNT_FROM_SLICE = true;
pub const ENTRY_SESSION_SIZE_CEILING_BYTES: usize = 48;

pub const RecoveryReport = struct {
    recovery_boot_entered: bool = false,
    image_verified: bool = false,
    image_reinstalled: bool = false,
    image_activated: bool = false,
    device_trust_revoked: bool = false,
    snapshot_restored: bool = false,
    sync_metadata_repaired: bool = false,
    device_keys_rotated: bool = false,
};

pub const BootProfile = enum(u8) {
    normal,
    recovery,
};

pub const RecoveryAction = enum(u8) {
    reinstall_base_image,
    restore_workspace_snapshot,
    restore_workspace_export,
    repair_sync_metadata,
    rotate_device_keys,
    revoke_device_trust,
};

pub const EntryRequest = struct {
    profile: BootProfile,
    requester: principal.PrincipalId,
    actions: []const RecoveryAction = &.{},
};

pub const EntrySession = struct {
    owner: principal.PrincipalId,
    actions: []const RecoveryAction,
    profile: BootProfile = .recovery,
    entered_from_boot_profile: bool = false,
    normal_session_authority: bool = false,
    entry_tick: u64 = 0,

    comptime {
        if (@sizeOf(@This()) > ENTRY_SESSION_SIZE_CEILING_BYTES) {
            @compileError("recovery entry session exceeds its compact size ceiling");
        }
    }

    pub fn actionCount(self: *const EntrySession) usize {
        return self.actions.len;
    }

    pub fn permits(self: *const EntrySession, action: RecoveryAction) bool {
        for (self.actions) |allowed| {
            if (allowed == action) return true;
        }
        return false;
    }
};

pub const RecoveryBootExecution = struct {
    entry: EntrySession,
    boot_tick: u64,
    normal_session_authority: bool = false,
    audited_break_glass: bool = false,
    break_glass_approver: ?principal.PrincipalId = null,
    approval_capability_id: u64 = 0,

    pub fn session(self: *const RecoveryBootExecution) *const EntrySession {
        return &self.entry;
    }
};

pub const BreakGlassRequest = struct {
    profile: BootProfile,
    requester: principal.PrincipalId,
    approver: principal.PrincipalId,
    approval_capability_id: u64 = 0,
    reason: []const u8,
    actions: []const RecoveryAction = &.{},
};

pub const BreakGlassSession = struct {
    entry: EntrySession,
    approver: principal.PrincipalId,
    approval_capability_id: u64,
};

pub const EntryError = error{
    BreakGlassApprovalRequired,
    BreakGlassApproverRequired,
    BreakGlassReasonRequired,
    BreakGlassReasonInvalid,
    BreakGlassReasonTooLong,
    DuplicateRecoveryAction,
    RecoveryActionRequired,
    RecoveryProfileRequired,
    RecoveryTickRequired,
    UnauthorizedRecoveryOwner,
};

pub const OperationError = error{
    RecoveryBootProfileRequired,
    NormalSessionAuthorityNotAllowed,
    RecoveryActionNotAllowed,
    RecoveryOwnerMismatch,
    RecoverySessionRequired,
};

pub const Environment = struct {
    owner: principal.PrincipalId,
    report: RecoveryReport = .{},

    pub fn init(owner: principal.PrincipalId) Environment {
        return .{ .owner = owner };
    }

    pub fn enterRecoveryMode(self: *const Environment, request: EntryRequest) EntryError!EntrySession {
        if (request.profile != .recovery) return error.RecoveryProfileRequired;
        if (!request.requester.eql(self.owner)) return error.UnauthorizedRecoveryOwner;
        if (request.actions.len == 0) return error.RecoveryActionRequired;
        try validateUniqueRecoveryActions(request.actions);
        return .{
            .owner = self.owner,
            .actions = request.actions,
            .profile = request.profile,
        };
    }

    pub fn enterRecoveryBootProfile(
        self: *Environment,
        request: EntryRequest,
        tick: u64,
    ) EntryError!RecoveryBootExecution {
        if (tick == 0) return error.RecoveryTickRequired;
        var entry = try self.enterRecoveryMode(request);
        entry.entered_from_boot_profile = true;
        entry.normal_session_authority = false;
        entry.entry_tick = tick;
        self.report.recovery_boot_entered = true;
        return .{
            .entry = entry,
            .boot_tick = tick,
            .normal_session_authority = false,
        };
    }

    pub fn enterBreakGlassRecoveryBootProfile(
        self: *Environment,
        ledger: *event_ledger.Ledger,
        request: BreakGlassRequest,
        tick: u64,
    ) (EntryError || event_ledger.Error)!RecoveryBootExecution {
        if (tick == 0) return error.RecoveryTickRequired;
        var break_glass = try self.enterBreakGlassRecoveryMode(ledger, request, tick);
        break_glass.entry.entered_from_boot_profile = true;
        break_glass.entry.normal_session_authority = false;
        break_glass.entry.entry_tick = tick;
        self.report.recovery_boot_entered = true;
        return .{
            .entry = break_glass.entry,
            .boot_tick = tick,
            .normal_session_authority = false,
            .audited_break_glass = true,
            .break_glass_approver = break_glass.approver,
            .approval_capability_id = break_glass.approval_capability_id,
        };
    }

    pub fn enterBreakGlassRecoveryMode(
        self: *const Environment,
        ledger: *event_ledger.Ledger,
        request: BreakGlassRequest,
        tick: u64,
    ) (EntryError || event_ledger.Error)!BreakGlassSession {
        if (request.profile != .recovery) {
            try recordBreakGlassDecision(ledger, request, false, "break-glass requires recovery profile", tick);
            return error.RecoveryProfileRequired;
        }
        if (!request.requester.eql(self.owner)) {
            try recordBreakGlassDecision(ledger, request, false, "break-glass requester is not recovery owner", tick);
            return error.UnauthorizedRecoveryOwner;
        }
        if (request.approver.kind != .policy_authority) {
            try recordBreakGlassDecision(ledger, request, false, "break-glass approver must be policy authority", tick);
            return error.BreakGlassApproverRequired;
        }
        if (request.approval_capability_id == 0) {
            try recordBreakGlassDecision(ledger, request, false, "break-glass approval capability required", tick);
            return error.BreakGlassApprovalRequired;
        }
        if (request.reason.len == 0) {
            try recordBreakGlassDecision(ledger, request, false, "break-glass reason required", tick);
            return error.BreakGlassReasonRequired;
        }
        if (request.reason.len > MAX_BREAK_GLASS_REASON_BYTES) {
            try recordBreakGlassDecision(ledger, request, false, "break-glass reason too long", tick);
            return error.BreakGlassReasonTooLong;
        }
        if (!breakGlassReasonIsAuditSafe(request.reason)) {
            try recordBreakGlassDecision(ledger, request, false, "break-glass reason contains invalid audit text", tick);
            return error.BreakGlassReasonInvalid;
        }
        const entry = try self.enterRecoveryMode(.{
            .profile = request.profile,
            .requester = request.requester,
            .actions = request.actions,
        });
        try recordBreakGlassDecision(ledger, request, true, request.reason, tick);
        return .{
            .entry = entry,
            .approver = request.approver,
            .approval_capability_id = request.approval_capability_id,
        };
    }

    pub fn verifyAndReinstallImage(
        self: *Environment,
        session: ?*const EntrySession,
        manager: *immutable_base.Manager,
        payload: []const u8,
        signer: signing.SignerIdentity,
        tick: u64,
    ) (OperationError || immutable_base.Error)!bool {
        try self.requireRecoverySession(session, .reinstall_base_image);
        const verified = manager.verifyActiveImage();
        const target_slot = manager.inactiveSlotIndex();
        _ = try manager.stageImage(target_slot, "recovery-reinstall", payload, signer, tick);
        self.report.image_verified = verified;
        self.report.image_reinstalled = manager.verifySlot(target_slot);
        if (self.report.image_reinstalled) {
            const activation = try manager.activate(target_slot, .{}, tick + 1);
            self.report.image_activated = !activation.rolled_back and
                activation.active_slot != null and
                activation.active_slot.? == target_slot;
        }
        return self.report.image_reinstalled and self.report.image_activated;
    }

    pub fn revokeDeviceTrust(
        self: *Environment,
        session: ?*const EntrySession,
        sync: *sync_service.Service,
        user: principal.PrincipalId,
        device: principal.PrincipalId,
        signer: signing.SignerIdentity,
        tick: u64,
    ) (OperationError || sync_service.AuthorityError || sync_service.Error || capability.Error)!bool {
        try self.requireRecoverySession(session, .revoke_device_trust);
        var capability_table = capability.CapabilityTable.init();
        const authority_capability = try sync_service.mintEndpointConnectAuthority(&capability_table, sync, 0, @max(tick, 1_000));
        var port = sync_service.SyncPort.init(sync, &capability_table);
        const authority = sync_service.authorityContext(sync, authority_capability, tick);
        port.revokeTrustedDevice(authority, user, device, signer, tick) catch |err| switch (err) {
            error.AlreadyRevoked => {},
            else => return err,
        };
        self.report.device_trust_revoked = !sync.isTrustedDevice(device);
        return self.report.device_trust_revoked;
    }

    pub fn restoreWorkspaceSnapshot(
        self: *Environment,
        session: ?*const EntrySession,
        storage: *storage_service.Service,
        workspace_id: anytype,
        snapshot_id: anytype,
        tick: u64,
    ) (OperationError || workspace.Error)!bool {
        try self.requireRecoverySession(session, .restore_workspace_snapshot);
        _ = try storage.restore(workspace_id, snapshot_id, tick);
        self.report.snapshot_restored = true;
        return true;
    }

    pub fn restoreWorkspaceExport(
        self: *Environment,
        session: ?*const EntrySession,
        storage: *storage_service.Service,
        workspace_id: anytype,
        package: *const workspace.ExportPackage,
        tick: u64,
    ) (OperationError || workspace.Error)!bool {
        try self.requireRecoverySession(session, .restore_workspace_export);
        _ = try storage.restoreFromExportPackage(workspace_id, package, tick);
        self.report.snapshot_restored = true;
        return true;
    }

    pub fn repairSyncMetadata(
        self: *Environment,
        session: ?*const EntrySession,
        sync: *sync_service.Service,
        storage: *const storage_service.Service,
        workspace_id: anytype,
        device_id: principal.PrincipalId,
    ) (OperationError || sync_service.AuthorityError || sync_service.Error || capability.Error)!bool {
        try self.requireRecoverySession(session, .repair_sync_metadata);
        var capability_table = capability.CapabilityTable.init();
        const authority_capability = try sync_service.mintEndpointConnectAuthority(&capability_table, sync, 0, 1_000);
        var port = sync_service.SyncPort.init(sync, &capability_table);
        const authority = sync_service.authorityContext(sync, authority_capability, 0);
        self.report.sync_metadata_repaired = try port.repairWorkspaceMetadata(authority, storage, object_store.ids.raw(workspace_id), device_id);
        return self.report.sync_metadata_repaired;
    }

    pub fn rotateDeviceKeys(
        self: *Environment,
        session: ?*const EntrySession,
        sync: *sync_service.Service,
        user: principal.PrincipalId,
        device: principal.PrincipalId,
        signer: signing.SignerIdentity,
        next_signer: signing.SignerIdentity,
        tick: u64,
    ) (OperationError || sync_service.AuthorityError || sync_service.Error || capability.Error)!u32 {
        try self.requireRecoverySession(session, .rotate_device_keys);
        var capability_table = capability.CapabilityTable.init();
        const authority_capability = try sync_service.mintEndpointConnectAuthority(&capability_table, sync, 0, @max(tick, 1_000));
        var port = sync_service.SyncPort.init(sync, &capability_table);
        const authority = sync_service.authorityContext(sync, authority_capability, tick);
        const record = try port.rotateDeviceKey(authority, user, device, signer, next_signer, tick);
        self.report.device_keys_rotated = record.key_rotation_generation >= 2;
        return record.key_rotation_generation;
    }

    fn requireRecoverySession(
        self: *const Environment,
        session: ?*const EntrySession,
        action: RecoveryAction,
    ) OperationError!void {
        const active = session orelse return error.RecoverySessionRequired;
        if (!active.owner.eql(self.owner)) return error.RecoveryOwnerMismatch;
        if (active.profile != .recovery or !active.entered_from_boot_profile) return error.RecoveryBootProfileRequired;
        if (active.normal_session_authority) return error.NormalSessionAuthorityNotAllowed;
        if (!active.permits(action)) return error.RecoveryActionNotAllowed;
    }
};

fn recordBreakGlassDecision(
    ledger: *event_ledger.Ledger,
    request: BreakGlassRequest,
    allowed: bool,
    detail: []const u8,
    tick: u64,
) event_ledger.Error!void {
    try ledger.recordPermissionDecision(
        request.requester,
        request.approval_capability_id,
        .device_access,
        allowed,
        if (allowed) .none else .policy_denied,
        tick,
        detail,
        true,
    );
}

fn breakGlassReasonIsAuditSafe(reason: []const u8) bool {
    for (reason) |byte| {
        if (byte < 0x20 or byte > 0x7E) return false;
    }
    return true;
}

fn validateUniqueRecoveryActions(actions: []const RecoveryAction) EntryError!void {
    for (actions, 0..) |action, action_index| {
        for (actions[action_index + 1 ..]) |other| {
            if (action == other) return error.DuplicateRecoveryAction;
        }
    }
}

test "recovery entry sessions derive action count from their authoritative slice" {
    try std.testing.expect(DERIVES_ACTION_COUNT_FROM_SLICE);
    try std.testing.expect(!@hasField(EntrySession, "action_count"));
    try std.testing.expect(@hasDecl(EntrySession, "actionCount"));
    try std.testing.expect(@sizeOf(EntrySession) <= ENTRY_SESSION_SIZE_CEILING_BYTES);
}

test "recovery environment verifies reinstalls restores repairs and rotates" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 4 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 8 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const primary_device = principal.PrincipalId{ .kind = .device, .serial = 21 };
    const tablet = principal.PrincipalId{ .kind = .device, .serial = 22 };

    const state_signer = signing.SignerIdentity{
        .label = "platform-state",
        .seed = signing.seedFromByte(0x71),
    };
    const image_signer = signing.SignerIdentity{
        .label = "platform-image",
        .seed = signing.seedFromByte(0x72),
    };
    const object_signer = signing.SignerIdentity{
        .label = "platform-storage",
        .seed = signing.seedFromByte(0x73),
    };
    const user_signer = signing.SignerIdentity{
        .label = "platform-user",
        .seed = signing.seedFromByte(0x74),
    };
    const device_signer = signing.SignerIdentity{
        .label = "primary-device",
        .seed = signing.seedFromByte(0x75),
    };
    const tablet_signer = signing.SignerIdentity{
        .label = "tablet-device",
        .seed = signing.seedFromByte(0x76),
    };
    const tablet_rotated_signer = signing.SignerIdentity{
        .label = "tablet-device-v2",
        .seed = signing.seedFromByte(0x77),
    };

    var storage = storage_service.Service.initWithStore(920, 51, storage_owner, &storage_checkpoint_store);
    var manager = try immutable_base.Manager.init(&storage, storage_owner, state_signer);
    _ = try manager.stageImage(0, "stable-a", "kernel=v1", image_signer, 10);
    _ = try manager.activate(0, .{}, 11);

    const notes = try storage.putVersion(.{
        .preferred_object_id = object_store.ids.object(980),
        .object_type = .document,
        .payload = "notes-v1",
        .metadata = try object_store.signMetadata(object_signer, "notes", "text/plain", .document, "notes-v1", 12),
    });
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "recovery-notes",
    });
    try storage.beginTransaction(workspace_record.id);
    try storage.stagePut(workspace_record.id, "documents/notes.md", notes.object_id, notes.version_id, .document);
    _ = try storage.commit(workspace_record.id, 13);
    const snapshot = try storage.snapshot(workspace_record.id, "baseline", object_signer);

    var sync = sync_service.Service.init(921, 52, sync_owner);
    var sync_capabilities = capability.CapabilityTable.init();
    const sync_authority_capability = try sync_service.mintEndpointConnectAuthority(&sync_capabilities, &sync, 0, 1_000);
    var sync_port = sync_service.SyncPort.init(&sync, &sync_capabilities);
    const sync_authority = sync_service.authorityContext(&sync, sync_authority_capability, 16);
    _ = try sync_port.ensureUserRoot(sync_authority, user, "cameron", user_signer);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, primary_device, "primary", user_signer, device_signer, 14);
    _ = try sync_port.enrollTrustedDevice(sync_authority, user, tablet, "tablet", user_signer, tablet_signer, 15);
    const local_policy = try sync_port.createNetworkPolicy(sync_authority, .{
        .owner = sync_owner,
        .workspace_id = workspace_record.id.raw(),
        .label = "local-net",
        .mode = .local_network,
    });
    _ = try sync_port.configureWorkspacePolicy(sync_authority, .{
        .workspace_id = workspace_record.id.raw(),
        .owner = user,
        .device_to_device_policy_id = local_policy.id,
    });
    try sync_port.setReplicaVersion(sync_authority, workspace_record.id.raw(), tablet, "documents/notes.md", notes.object_id.raw(), notes.version_id.raw() + 1);
    _ = try sync_port.replicateWorkspace(sync_authority, &storage, workspace_record.id.raw(), primary_device, tablet, .device_to_device);

    var recovery = Environment.init(storage_owner);
    const recovery_boot = try recovery.enterRecoveryBootProfile(.{
        .profile = .recovery,
        .requester = storage_owner,
        .actions = &.{
            .reinstall_base_image,
            .restore_workspace_snapshot,
            .repair_sync_metadata,
            .rotate_device_keys,
            .revoke_device_trust,
        },
    }, 16);
    try std.testing.expect(recovery_boot.entry.entered_from_boot_profile);
    try std.testing.expect(!recovery_boot.normal_session_authority);
    try std.testing.expect(!recovery_boot.entry.normal_session_authority);
    try std.testing.expectEqual(@as(u64, 16), recovery_boot.boot_tick);
    try std.testing.expect(try recovery.verifyAndReinstallImage(recovery_boot.session(), &manager, "kernel=v2", image_signer, 16));
    try std.testing.expect(try recovery.restoreWorkspaceSnapshot(recovery_boot.session(), &storage, workspace_record.id, snapshot.id, 17));
    try std.testing.expect(try recovery.repairSyncMetadata(recovery_boot.session(), &sync, &storage, workspace_record.id, tablet));
    try std.testing.expectEqual(@as(u32, 2), try recovery.rotateDeviceKeys(recovery_boot.session(), &sync, user, tablet, user_signer, tablet_rotated_signer, 18));
    try std.testing.expect(try recovery.revokeDeviceTrust(recovery_boot.session(), &sync, user, tablet, user_signer, 19));
    try std.testing.expect(try recovery.revokeDeviceTrust(recovery_boot.session(), &sync, user, tablet, user_signer, 20));
    try std.testing.expect(recovery.report.recovery_boot_entered);
    try std.testing.expect(recovery.report.image_verified);
    try std.testing.expect(recovery.report.image_reinstalled);
    try std.testing.expect(recovery.report.image_activated);
    try std.testing.expectEqual(@as(?usize, 1), manager.activeImage().?.slot_index);
    try std.testing.expect(manager.verifyActiveImage());
    try std.testing.expect(recovery.report.snapshot_restored);
    try std.testing.expect(recovery.report.sync_metadata_repaired);
    try std.testing.expect(recovery.report.device_keys_rotated);
    try std.testing.expect(recovery.report.device_trust_revoked);

    storage_checkpoint_store.resetPersistent();
}

test "recovery environment requires boot-profile recovery session gates and refuses missing repair targets" {
    var storage_checkpoint_store = storage_service.CheckpointStore{};
    storage_checkpoint_store.resetPersistent();

    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 5 };
    const sync_owner = principal.PrincipalId{ .kind = .service, .serial = 9 };
    const user = principal.PrincipalId{ .kind = .user, .serial = 3 };
    const intruder = principal.PrincipalId{ .kind = .service, .serial = 500 };
    const untrusted_device = principal.PrincipalId{ .kind = .device, .serial = 44 };
    const user_signer = signing.SignerIdentity{
        .label = "negative-user",
        .seed = signing.seedFromByte(0x91),
    };
    const rotated_signer = signing.SignerIdentity{
        .label = "negative-device-v2",
        .seed = signing.seedFromByte(0x92),
    };

    var storage = storage_service.Service.initWithStore(922, 53, storage_owner, &storage_checkpoint_store);
    const workspace_record = try storage.createWorkspace(.{
        .owner = user,
        .label = "recovery-negative",
    });
    var sync = sync_service.Service.init(923, 54, sync_owner);
    var recovery = Environment.init(storage_owner);

    try std.testing.expectError(error.RecoveryProfileRequired, recovery.enterRecoveryMode(.{
        .profile = .normal,
        .requester = storage_owner,
        .actions = &.{.restore_workspace_snapshot},
    }));
    try std.testing.expectError(error.UnauthorizedRecoveryOwner, recovery.enterRecoveryMode(.{
        .profile = .recovery,
        .requester = intruder,
        .actions = &.{.restore_workspace_snapshot},
    }));
    try std.testing.expectError(error.RecoveryActionRequired, recovery.enterRecoveryMode(.{
        .profile = .recovery,
        .requester = storage_owner,
    }));
    try std.testing.expectError(error.DuplicateRecoveryAction, recovery.enterRecoveryMode(.{
        .profile = .recovery,
        .requester = storage_owner,
        .actions = &.{ .restore_workspace_snapshot, .restore_workspace_snapshot },
    }));

    const entry = try recovery.enterRecoveryMode(.{
        .profile = .recovery,
        .requester = storage_owner,
        .actions = &.{ .restore_workspace_snapshot, .repair_sync_metadata },
    });
    try std.testing.expectEqual(@as(usize, 2), entry.actionCount());
    try std.testing.expect(entry.permits(.restore_workspace_snapshot));
    try std.testing.expect(!entry.permits(.rotate_device_keys));
    try std.testing.expectError(error.RecoveryBootProfileRequired, recovery.restoreWorkspaceSnapshot(&entry, &storage, workspace_record.id, 999, 20));

    const recovery_boot = try recovery.enterRecoveryBootProfile(.{
        .profile = .recovery,
        .requester = storage_owner,
        .actions = &.{ .restore_workspace_snapshot, .repair_sync_metadata },
    }, 20);
    try std.testing.expectError(error.RecoveryTickRequired, recovery.enterRecoveryBootProfile(.{
        .profile = .recovery,
        .requester = storage_owner,
        .actions = &.{.restore_workspace_snapshot},
    }, 0));

    var normal_session_entry = recovery_boot.entry;
    normal_session_entry.normal_session_authority = true;
    try std.testing.expectError(error.NormalSessionAuthorityNotAllowed, recovery.restoreWorkspaceSnapshot(&normal_session_entry, &storage, workspace_record.id, 999, 20));
    try std.testing.expectError(error.RecoverySessionRequired, recovery.restoreWorkspaceSnapshot(null, &storage, workspace_record.id, 999, 20));
    try std.testing.expectError(error.RecoveryActionNotAllowed, recovery.rotateDeviceKeys(recovery_boot.session(), &sync, user, untrusted_device, user_signer, rotated_signer, 20));

    var intruder_recovery = Environment.init(intruder);
    const intruder_entry = try intruder_recovery.enterRecoveryBootProfile(.{
        .profile = .recovery,
        .requester = intruder,
        .actions = &.{.restore_workspace_snapshot},
    }, 20);
    try std.testing.expectError(error.RecoveryOwnerMismatch, recovery.restoreWorkspaceSnapshot(intruder_entry.session(), &storage, workspace_record.id, 999, 20));

    try std.testing.expectError(error.SnapshotNotFound, recovery.restoreWorkspaceSnapshot(recovery_boot.session(), &storage, workspace_record.id, 999, 20));
    try std.testing.expect(!recovery.report.snapshot_restored);
    try std.testing.expectError(error.DeviceNotTrusted, recovery.repairSyncMetadata(recovery_boot.session(), &sync, &storage, workspace_record.id, untrusted_device));
    try std.testing.expect(!recovery.report.sync_metadata_repaired);

    storage_checkpoint_store.resetPersistent();
}

test "recovery environment audits break-glass recovery authorization" {
    const storage_owner = principal.PrincipalId{ .kind = .service, .serial = 6 };
    const policy_authority = principal.PrincipalId{ .kind = .policy_authority, .serial = 6 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 6 };
    var ledger = event_ledger.Ledger.init();
    var recovery = Environment.init(storage_owner);

    try std.testing.expectError(error.BreakGlassApproverRequired, recovery.enterBreakGlassRecoveryMode(&ledger, .{
        .profile = .recovery,
        .requester = storage_owner,
        .approver = app,
        .approval_capability_id = 500,
        .reason = "disk repair",
        .actions = &.{.restore_workspace_snapshot},
    }, 30));
    try std.testing.expectError(error.BreakGlassApprovalRequired, recovery.enterBreakGlassRecoveryMode(&ledger, .{
        .profile = .recovery,
        .requester = storage_owner,
        .approver = policy_authority,
        .reason = "disk repair",
        .actions = &.{.restore_workspace_snapshot},
    }, 31));
    const oversized_reason = [_]u8{'r'} ** (MAX_BREAK_GLASS_REASON_BYTES + 1);
    try std.testing.expectError(error.BreakGlassReasonTooLong, recovery.enterBreakGlassRecoveryMode(&ledger, .{
        .profile = .recovery,
        .requester = storage_owner,
        .approver = policy_authority,
        .approval_capability_id = 501,
        .reason = oversized_reason[0..],
        .actions = &.{.restore_workspace_snapshot},
    }, 32));
    try std.testing.expectError(error.BreakGlassReasonInvalid, recovery.enterBreakGlassRecoveryMode(&ledger, .{
        .profile = .recovery,
        .requester = storage_owner,
        .approver = policy_authority,
        .approval_capability_id = 501,
        .reason = "disk repair\nsecond line",
        .actions = &.{.restore_workspace_snapshot},
    }, 33));
    try std.testing.expectError(error.RecoveryTickRequired, recovery.enterBreakGlassRecoveryBootProfile(&ledger, .{
        .profile = .recovery,
        .requester = storage_owner,
        .approver = policy_authority,
        .approval_capability_id = 501,
        .reason = "disk repair",
        .actions = &.{.restore_workspace_snapshot},
    }, 0));

    const session = try recovery.enterBreakGlassRecoveryBootProfile(&ledger, .{
        .profile = .recovery,
        .requester = storage_owner,
        .approver = policy_authority,
        .approval_capability_id = 501,
        .reason = "disk repair",
        .actions = &.{ .restore_workspace_snapshot, .repair_sync_metadata },
    }, 34);
    try std.testing.expectEqual(@as(usize, 2), session.entry.actionCount());
    try std.testing.expect(session.entry.entered_from_boot_profile);
    try std.testing.expect(!session.entry.normal_session_authority);
    try std.testing.expect(session.audited_break_glass);
    try std.testing.expectEqual(policy_authority, session.break_glass_approver.?);
    try std.testing.expectEqual(@as(u64, 501), session.approval_capability_id);
    try std.testing.expect(session.entry.permits(.repair_sync_metadata));

    var events: [6]event_ledger.Event = undefined;
    const decisions = ledger.queryEvents(.{
        .kind = .permission_decision,
        .subject = storage_owner,
        .include_protected_content = true,
    }, &events);
    try std.testing.expectEqual(@as(usize, 5), decisions.len);
    try std.testing.expect(!decisions[0].allowed);
    try std.testing.expectEqual(abi.DenialReason.policy_denied, decisions[0].denial_reason);
    try std.testing.expectEqualStrings("break-glass approver must be policy authority", decisions[0].detailSlice());
    try std.testing.expect(!decisions[1].allowed);
    try std.testing.expectEqualStrings("break-glass approval capability required", decisions[1].detailSlice());
    try std.testing.expect(!decisions[2].allowed);
    try std.testing.expectEqualStrings("break-glass reason too long", decisions[2].detailSlice());
    try std.testing.expect(!decisions[3].allowed);
    try std.testing.expectEqualStrings("break-glass reason contains invalid audit text", decisions[3].detailSlice());
    try std.testing.expect(decisions[4].allowed);
    try std.testing.expectEqual(manifest.PermissionKind.device_access, decisions[4].permission_kind.?);
    try std.testing.expectEqualStrings("disk repair", decisions[4].detailSlice());
}
