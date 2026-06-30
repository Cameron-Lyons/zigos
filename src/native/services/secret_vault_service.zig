const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const secure_secret_store = @import("../platform/secure_secret_store.zig");

pub const MAX_HANDLES: usize = secure_secret_store.MAX_HANDLES;

pub const Error = secure_secret_store.Error || event_ledger.Error || error{
    HandleExpired,
    HandleHolderMismatch,
    HandleRevoked,
    InvalidLease,
    PolicyDenied,
    SecretRevokeBindingMismatch,
    SecretOwnerMismatch,
    VaultHandleNotFound,
};

pub const ImportRequest = struct {
    owner: principal.PrincipalId,
    task_id: u64,
    label: []const u8,
    raw: []const u8,
    hardware_backed: bool = true,
    exportable: bool = false,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const LendRequest = struct {
    owner: principal.PrincipalId,
    holder: principal.PrincipalId,
    task_id: u64,
    secret_id: u64,
    expires_at_ticks: u64,
    now_ticks: u64,
    allow_raw_export: bool = false,
    hardware_backed: bool = true,
    detail: []const u8 = "",
};

pub const ExportRequest = struct {
    holder: principal.PrincipalId,
    task_id: u64,
    handle_id: u64,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const RotateRequest = struct {
    owner: principal.PrincipalId,
    task_id: u64,
    old_secret_id: u64,
    label: []const u8,
    raw: []const u8,
    hardware_backed: bool = true,
    exportable: bool = false,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const RevokeRequest = struct {
    subject: principal.PrincipalId,
    task_id: u64,
    handle_id: u64 = 0,
    secret_id: u64 = 0,
    expected_holder: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    expected_holder_task_id: u64 = 0,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const VaultHandle = struct {
    id: u64 = 0,
    store_handle_id: u64 = 0,
    secret_id: u64 = 0,
    holder: principal.PrincipalId = .{ .kind = .app, .serial = 0 },
    task_id: u64 = 0,
    expires_at_ticks: u64 = 0,
    hardware_backed: bool = false,
    raw_export_allowed: bool = false,
    revoked: bool = false,
    generation: u32 = 1,

    pub fn expired(self: *const VaultHandle, now_ticks: u64) bool {
        return self.expires_at_ticks != 0 and now_ticks >= self.expires_at_ticks;
    }
};

const HandleSlot = struct {
    in_use: bool = false,
    handle: VaultHandle = .{},
};

const HandleArena = indexed_arena.IndexedArenaWithKey(u64, HandleSlot, MAX_HANDLES, MAX_HANDLES * 2, handleSlotId);
const SecretHandleIndex = indexed_arena.MultimapIndex(MAX_HANDLES, MAX_HANDLES, MAX_HANDLES * 2);
const ActiveHandleIndex = indexed_arena.MultimapIndex(MAX_HANDLES, 1, 2);
const ACTIVE_HANDLE_KEY: u64 = 1;

pub const Service = struct {
    store: secure_secret_store.Store = secure_secret_store.Store.init(),
    next_handle_id: u64 = 1,
    generation: u32 = 1,
    handles: HandleArena = HandleArena.init(),
    secret_handle_index: SecretHandleIndex = SecretHandleIndex.init(),
    active_handle_index: ActiveHandleIndex = ActiveHandleIndex.init(),
    active_handle_count: usize = 0,

    pub fn init() Service {
        return .{};
    }

    pub fn attachHardwareProvider(self: *Service, provider: secure_secret_store.HardwareSealProvider) void {
        self.store.attachHardwareProvider(provider);
    }

    pub fn importSecret(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: ImportRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*secure_secret_store.SecretRecord {
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .import,
            .hardware_backed = request.hardware_backed,
            .raw_export = request.exportable,
        });
        if (!decision.allowed) {
            try recordImport(ledger, request, 0, false);
            return error.PolicyDenied;
        }

        const secret = try self.store.importSecret(
            request.owner,
            request.label,
            request.raw,
            request.hardware_backed,
            request.exportable,
        );
        try recordImport(ledger, request, secret.id, true);
        return secret;
    }

    pub fn lendHandle(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: LendRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*VaultHandle {
        if (request.expires_at_ticks <= request.now_ticks) {
            try recordLend(ledger, request, 0, false);
            return error.InvalidLease;
        }
        const secret = self.store.describeSecret(request.secret_id) orelse {
            try recordLend(ledger, request, 0, false);
            return error.SecretNotFound;
        };
        if (!secret.owner.eql(request.owner)) {
            try recordLend(ledger, request, 0, false);
            return error.SecretOwnerMismatch;
        }
        const lease_ticks = request.expires_at_ticks - request.now_ticks;
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .lend,
            .hardware_backed = request.hardware_backed,
            .raw_export = request.allow_raw_export,
            .lease_ticks = lease_ticks,
        });
        if (!decision.allowed) {
            try recordLend(ledger, request, 0, false);
            return error.PolicyDenied;
        }

        if (self.handles.used_count >= MAX_HANDLES) {
            try recordLend(ledger, request, 0, false);
            return error.HandleTableFull;
        }

        const store_handle = try self.store.lendHandle(
            request.secret_id,
            request.holder,
            request.task_id,
            request.allow_raw_export,
        );
        const handle_id = self.next_handle_id;
        const slot_index = self.handles.reserveIndex(handle_id) orelse return error.HandleTableFull;
        if (!self.secret_handle_index.append(request.secret_id, slot_index)) {
            _ = self.handles.remove(handle_id);
            return error.HandleTableFull;
        }
        const slot = &self.handles.slots[slot_index];
        slot.handle = .{
            .id = handle_id,
            .store_handle_id = store_handle.id,
            .secret_id = request.secret_id,
            .holder = request.holder,
            .task_id = request.task_id,
            .expires_at_ticks = request.expires_at_ticks,
            .hardware_backed = store_handle.hardware_backed,
            .raw_export_allowed = store_handle.export_allowed,
            .generation = self.generation,
        };
        if (!self.active_handle_index.append(ACTIVE_HANDLE_KEY, slot_index)) {
            native_util.impossibleByInvariant("secret vault active-handle index covers handle slots");
        }
        self.next_handle_id += 1;
        self.active_handle_count += 1;
        try recordLend(ledger, request, slot.handle.id, true);
        return &slot.handle;
    }

    pub fn exportRaw(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: ExportRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error![]const u8 {
        const handle = self.findHandle(request.handle_id) orelse {
            try recordExport(ledger, request, 0, false, false);
            return error.VaultHandleNotFound;
        };
        if (!handle.holder.eql(request.holder) or handle.task_id != request.task_id) {
            try recordExportFromHandle(ledger, request, handle, false);
            return error.HandleHolderMismatch;
        }
        if (handle.revoked) {
            try recordExportFromHandle(ledger, request, handle, false);
            return error.HandleRevoked;
        }
        if (handle.expired(request.now_ticks)) {
            try recordExportFromHandle(ledger, request, handle, false);
            return error.HandleExpired;
        }
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .export_raw,
            .hardware_backed = handle.hardware_backed,
            .raw_export = true,
            .lease_ticks = handle.expires_at_ticks - request.now_ticks,
        });
        if (!decision.allowed) {
            try recordExportFromHandle(ledger, request, handle, false);
            return error.PolicyDenied;
        }
        if (!handle.raw_export_allowed) {
            try recordExportFromHandle(ledger, request, handle, false);
            return error.RawExportDenied;
        }
        const raw = try self.store.exportRaw(handle.store_handle_id, .{
            .holder = request.holder,
            .task_id = request.task_id,
        });
        try recordExportFromHandle(ledger, request, handle, true);
        return raw;
    }

    pub fn rotateSecret(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: RotateRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*secure_secret_store.SecretRecord {
        const old_secret = self.store.describeSecret(request.old_secret_id) orelse {
            try recordRotate(ledger, request, 0, false);
            return error.SecretNotFound;
        };
        if (!old_secret.owner.eql(request.owner)) {
            try recordRotate(ledger, request, 0, false);
            return error.SecretOwnerMismatch;
        }
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .rotate,
            .hardware_backed = request.hardware_backed,
            .raw_export = request.exportable,
        });
        if (!decision.allowed) {
            try recordRotate(ledger, request, 0, false);
            return error.PolicyDenied;
        }

        _ = self.revokeSecretHandles(request.old_secret_id);
        self.generation += 1;
        const secret = try self.store.importSecret(
            request.owner,
            request.label,
            request.raw,
            request.hardware_backed,
            request.exportable,
        );
        try recordRotate(ledger, request, secret.id, true);
        return secret;
    }

    pub fn revoke(self: *Service, request: RevokeRequest, ledger: ?*event_ledger.Ledger) Error!void {
        if (request.handle_id != 0) {
            const handle = self.findHandle(request.handle_id) orelse {
                try recordRevoke(ledger, request, false, false);
                return error.VaultHandleNotFound;
            };
            if (request.secret_id == 0 or
                request.expected_holder_task_id == 0 or
                handle.secret_id != request.secret_id or
                handle.task_id != request.expected_holder_task_id or
                !handle.holder.eql(request.expected_holder))
            {
                try recordRevoke(ledger, request, handle.hardware_backed, false);
                return error.SecretRevokeBindingMismatch;
            }
            const secret = self.store.describeSecret(handle.secret_id) orelse {
                try recordRevoke(ledger, request, handle.hardware_backed, false);
                return error.SecretNotFound;
            };
            if (!secret.owner.eql(request.subject)) {
                try recordRevoke(ledger, request, handle.hardware_backed, false);
                return error.SecretOwnerMismatch;
            }
            _ = self.markRevoked(handle);
            try recordRevoke(ledger, request, handle.hardware_backed, true);
            return;
        }
        if (request.secret_id != 0) {
            const secret = self.store.describeSecret(request.secret_id) orelse {
                try recordRevoke(ledger, request, false, false);
                return error.SecretNotFound;
            };
            if (!secret.owner.eql(request.subject)) {
                try recordRevoke(ledger, request, secret.hardware_backed, false);
                return error.SecretOwnerMismatch;
            }
            const revoked_count = self.revokeSecretHandles(request.secret_id);
            try recordRevoke(ledger, request, secret.hardware_backed, revoked_count != 0);
            if (revoked_count == 0) return error.VaultHandleNotFound;
            return;
        }
        try recordRevoke(ledger, request, false, false);
        return error.VaultHandleNotFound;
    }

    pub fn findHandle(self: *Service, handle_id: u64) ?*VaultHandle {
        const slot = self.handles.get(handle_id) orelse return null;
        return &slot.handle;
    }

    pub fn activeHandleCount(self: *const Service) usize {
        return self.active_handle_count;
    }

    pub fn activeHandleCountAt(self: *const Service, now_ticks: u64) usize {
        if (self.active_handle_count == 0) return 0;
        var count: usize = 0;
        var slot_index = self.active_handle_index.head(ACTIVE_HANDLE_KEY);
        while (slot_index != indexed_arena.no_index) : (slot_index = self.active_handle_index.next(slot_index)) {
            const slot = self.activeHandleSlotAt(slot_index);
            if (!slot.handle.expired(now_ticks)) count += 1;
        }
        return count;
    }

    fn revokeSecretHandles(self: *Service, secret_id: u64) usize {
        var revoked_count: usize = 0;
        var slot_index = self.secret_handle_index.head(secret_id);
        while (slot_index != indexed_arena.no_index) : (slot_index = self.secret_handle_index.next(slot_index)) {
            if (slot_index >= self.handles.slots.len) continue;
            const slot = &self.handles.slots[slot_index];
            if (!slot.in_use or slot.handle.secret_id != secret_id) continue;
            if (self.markRevoked(&slot.handle)) revoked_count += 1;
        }
        return revoked_count;
    }

    fn markRevoked(self: *Service, handle: *VaultHandle) bool {
        if (handle.revoked) return false;
        const slot_index = self.handles.slotIndexOf(handle.id) orelse {
            native_util.impossibleByInvariant("secret vault active handle has an arena slot");
        };
        if (!self.active_handle_index.remove(ACTIVE_HANDLE_KEY, slot_index)) {
            native_util.impossibleByInvariant("secret vault active-handle index missing live handle");
        }
        handle.revoked = true;
        if (self.active_handle_count == 0) native_util.impossibleByInvariant("secret vault active handle count underflow");
        self.active_handle_count -= 1;
        return true;
    }

    fn activeHandleSlotAt(self: *const Service, slot_index: usize) *const HandleSlot {
        if (slot_index >= MAX_HANDLES) native_util.impossibleByInvariant("secret vault active-handle index points outside slots");
        const slot = &self.handles.slots[slot_index];
        if (!slot.in_use) native_util.impossibleByInvariant("secret vault active-handle index points at free slot");
        if (slot.handle.revoked) native_util.impossibleByInvariant("secret vault active-handle index points at revoked handle");
        return slot;
    }
};

fn handleSlotId(slot: *const HandleSlot) u64 {
    return slot.handle.id;
}

fn recordImport(
    ledger: ?*event_ledger.Ledger,
    request: ImportRequest,
    secret_id: u64,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSecretVault(
            request.owner,
            request.task_id,
            secret_id,
            0,
            allowed,
            request.hardware_backed,
            request.exportable,
            false,
            false,
            request.now_ticks,
            request.detail,
        );
    }
}

fn recordLend(
    ledger: ?*event_ledger.Ledger,
    request: LendRequest,
    handle_id: u64,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSecretVault(
            request.owner,
            request.task_id,
            request.secret_id,
            handle_id,
            allowed,
            request.hardware_backed,
            request.allow_raw_export,
            false,
            false,
            request.now_ticks,
            request.detail,
        );
    }
}

fn recordExportFromHandle(
    ledger: ?*event_ledger.Ledger,
    request: ExportRequest,
    handle: *const VaultHandle,
    allowed: bool,
) event_ledger.Error!void {
    try recordExport(ledger, request, handle.secret_id, allowed, handle.hardware_backed);
}

fn recordExport(
    ledger: ?*event_ledger.Ledger,
    request: ExportRequest,
    secret_id: u64,
    allowed: bool,
    hardware_backed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSecretVault(
            request.holder,
            request.task_id,
            secret_id,
            request.handle_id,
            allowed,
            hardware_backed,
            true,
            false,
            false,
            request.now_ticks,
            request.detail,
        );
    }
}

fn recordRotate(
    ledger: ?*event_ledger.Ledger,
    request: RotateRequest,
    secret_id: u64,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSecretVault(
            request.owner,
            request.task_id,
            secret_id,
            0,
            allowed,
            request.hardware_backed,
            request.exportable,
            true,
            false,
            request.now_ticks,
            request.detail,
        );
    }
}

fn recordRevoke(
    ledger: ?*event_ledger.Ledger,
    request: RevokeRequest,
    hardware_backed: bool,
    allowed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSecretVault(
            request.subject,
            request.task_id,
            request.secret_id,
            request.handle_id,
            allowed,
            hardware_backed,
            false,
            false,
            true,
            request.now_ticks,
            request.detail,
        );
    }
}

fn testHardwareSeal(label: []const u8, raw: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "secret-vault-test-provider", label);
    crypto_hash.updateBytes(&hasher, "secret-vault-seal", raw);
    return crypto_hash.finalize(&hasher);
}

fn testHardwareProvider() secure_secret_store.HardwareSealProvider {
    return .{
        .available = true,
        .sealFn = testHardwareSeal,
    };
}

test "secret vault brokers sealed leased handles raw export policy rotation and revocation" {
    const signing = @import("../core/signing.zig");

    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 611 };
    const other_user = principal.PrincipalId{ .kind = .user, .serial = 613 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 612 };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "secret vault policy",
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = true,
        .deny_secret_raw_export = true,
        .max_secret_handle_lease_ticks = 25,
    }, signing.SignerIdentity{
        .label = "secret-vault-policy",
        .seed = signing.seedFromByte(0xd7),
    });

    const subjects = policy_object.SubjectSet{ .user_id = user.serial };
    var service = Service.init();
    service.attachHardwareProvider(testHardwareProvider());
    var ledger = event_ledger.Ledger.init();

    try std.testing.expectError(error.PolicyDenied, service.importSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 71,
        .label = "software-token",
        .raw = "private software token",
        .hardware_backed = false,
        .now_ticks = 1,
        .detail = "private software token denied",
    }, &ledger));

    const secret = try service.importSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 71,
        .label = "api-token",
        .raw = "private api token",
        .hardware_backed = true,
        .exportable = false,
        .now_ticks = 2,
        .detail = "private api token imported",
    }, &ledger);
    try std.testing.expect(secret.hardware_backed);
    try std.testing.expect(!secret.resident_material);
    try std.testing.expect(secret.sealed_digest_present);

    try std.testing.expectError(error.SecretOwnerMismatch, service.lendHandle(&policies, subjects, .{
        .owner = other_user,
        .holder = app,
        .task_id = 72,
        .secret_id = secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 3,
        .detail = "private api token wrong owner lend",
    }, &ledger));
    try std.testing.expectError(error.SecretOwnerMismatch, service.rotateSecret(&policies, subjects, .{
        .owner = other_user,
        .task_id = 71,
        .old_secret_id = secret.id,
        .label = "api-token",
        .raw = "private api token wrong owner",
        .hardware_backed = true,
        .now_ticks = 3,
        .detail = "private api token wrong owner rotate",
    }, &ledger));

    try std.testing.expectError(error.PolicyDenied, service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 72,
        .secret_id = secret.id,
        .expires_at_ticks = 80,
        .now_ticks = 3,
        .detail = "private api token long lease",
    }, &ledger));

    const handle = try service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 72,
        .secret_id = secret.id,
        .expires_at_ticks = 20,
        .now_ticks = 4,
        .detail = "private api token lent",
    }, &ledger);
    try std.testing.expect(handle.hardware_backed);
    try std.testing.expect(!handle.raw_export_allowed);
    try std.testing.expectEqual(@as(usize, 1), service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 1), service.active_handle_index.count(ACTIVE_HANDLE_KEY));

    try std.testing.expectError(error.PolicyDenied, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 72,
        .handle_id = handle.id,
        .now_ticks = 5,
        .detail = "private api token raw export denied",
    }, &ledger));

    const rotated = try service.rotateSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 71,
        .old_secret_id = secret.id,
        .label = "api-token",
        .raw = "private api token v2",
        .hardware_backed = true,
        .now_ticks = 6,
        .detail = "private api token rotated",
    }, &ledger);
    try std.testing.expect(rotated.id != secret.id);
    try std.testing.expectEqual(@as(usize, 0), service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 0), service.active_handle_index.count(ACTIVE_HANDLE_KEY));
    try std.testing.expectError(error.HandleRevoked, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 72,
        .handle_id = handle.id,
        .now_ticks = 7,
        .detail = "private api token old handle revoked",
    }, &ledger));

    const rotated_handle = try service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 72,
        .secret_id = rotated.id,
        .expires_at_ticks = 15,
        .now_ticks = 8,
        .detail = "private api token v2 lent",
    }, &ledger);
    try std.testing.expectError(error.SecretRevokeBindingMismatch, service.revoke(.{
        .subject = user,
        .task_id = 71,
        .handle_id = rotated_handle.id,
        .secret_id = secret.id,
        .expected_holder = app,
        .expected_holder_task_id = 72,
        .now_ticks = 9,
        .detail = "private api token wrong secret revoke",
    }, &ledger));
    try std.testing.expectError(error.SecretOwnerMismatch, service.revoke(.{
        .subject = other_user,
        .task_id = 71,
        .handle_id = rotated_handle.id,
        .secret_id = rotated.id,
        .expected_holder = app,
        .expected_holder_task_id = 72,
        .now_ticks = 9,
        .detail = "private api token wrong owner revoke",
    }, &ledger));
    try std.testing.expectError(error.SecretRevokeBindingMismatch, service.revoke(.{
        .subject = user,
        .task_id = 71,
        .handle_id = rotated_handle.id,
        .secret_id = rotated.id,
        .expected_holder = app,
        .expected_holder_task_id = 73,
        .now_ticks = 9,
        .detail = "private api token wrong holder task revoke",
    }, &ledger));
    try std.testing.expectEqual(@as(usize, 1), service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 1), service.active_handle_index.count(ACTIVE_HANDLE_KEY));
    try service.revoke(.{
        .subject = user,
        .task_id = 71,
        .handle_id = rotated_handle.id,
        .secret_id = rotated.id,
        .expected_holder = app,
        .expected_holder_task_id = 72,
        .now_ticks = 9,
        .detail = "private api token v2 revoked",
    }, &ledger);
    try std.testing.expectError(error.HandleRevoked, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 72,
        .handle_id = rotated_handle.id,
        .now_ticks = 10,
        .detail = "private api token v2 raw export denied",
    }, &ledger));
    try std.testing.expectEqual(@as(usize, 0), service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 0), service.active_handle_index.count(ACTIVE_HANDLE_KEY));

    const first_secret_revoke_handle = try service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 72,
        .secret_id = rotated.id,
        .expires_at_ticks = 24,
        .now_ticks = 11,
        .detail = "private api token v2 relend first",
    }, &ledger);
    const second_secret_revoke_handle = try service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 73,
        .secret_id = rotated.id,
        .expires_at_ticks = 24,
        .now_ticks = 12,
        .detail = "private api token v2 relend second",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 2), service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 2), service.active_handle_index.count(ACTIVE_HANDLE_KEY));
    try std.testing.expectEqual(@as(usize, 3), service.secret_handle_index.count(rotated.id));
    try service.revoke(.{
        .subject = user,
        .task_id = 71,
        .secret_id = rotated.id,
        .now_ticks = 13,
        .detail = "private api token v2 secret revoked",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 0), service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 0), service.active_handle_index.count(ACTIVE_HANDLE_KEY));
    try std.testing.expectError(error.HandleRevoked, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 72,
        .handle_id = first_secret_revoke_handle.id,
        .now_ticks = 14,
        .detail = "private api token v2 first raw export denied",
    }, &ledger));
    try std.testing.expectError(error.HandleRevoked, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 73,
        .handle_id = second_secret_revoke_handle.id,
        .now_ticks = 14,
        .detail = "private api token v2 second raw export denied",
    }, &ledger));

    var expiry_service = Service.init();
    expiry_service.attachHardwareProvider(testHardwareProvider());
    var expiry_ledger = event_ledger.Ledger.init();
    const expiring_secret = try expiry_service.importSecret(&policies, subjects, .{
        .owner = user,
        .task_id = 73,
        .label = "expiring-token",
        .raw = "private expiring token",
        .hardware_backed = true,
        .exportable = false,
        .now_ticks = 11,
        .detail = "private expiring token imported",
    }, &expiry_ledger);
    const expiring_handle = try expiry_service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 74,
        .secret_id = expiring_secret.id,
        .expires_at_ticks = 20,
        .now_ticks = 12,
        .detail = "private expiring token lent",
    }, &expiry_ledger);
    try std.testing.expectEqual(@as(usize, 1), expiry_service.active_handle_index.count(ACTIVE_HANDLE_KEY));
    try std.testing.expectEqual(@as(usize, 1), expiry_service.activeHandleCountAt(19));
    try std.testing.expectEqual(@as(usize, 0), expiry_service.activeHandleCountAt(20));
    try std.testing.expectError(error.HandleExpired, expiry_service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 74,
        .handle_id = expiring_handle.id,
        .now_ticks = 20,
        .detail = "private expiring token at boundary",
    }, &expiry_ledger));

    var export_policies = policy_object.Directory.init();
    _ = try export_policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 2 },
        .label = "secret vault raw export policy",
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = true,
        .deny_secret_raw_export = false,
        .max_secret_handle_lease_ticks = 25,
    }, signing.SignerIdentity{
        .label = "secret-vault-export-policy",
        .seed = signing.seedFromByte(0xd8),
    });
    var export_service = Service.init();
    export_service.attachHardwareProvider(testHardwareProvider());
    var export_ledger = event_ledger.Ledger.init();
    const sealed_only = try export_service.importSecret(&export_policies, subjects, .{
        .owner = user,
        .task_id = 75,
        .label = "sealed-only-token",
        .raw = "private sealed-only token",
        .hardware_backed = true,
        .exportable = false,
        .now_ticks = 13,
        .detail = "private sealed-only token imported",
    }, &export_ledger);
    const sealed_only_handle = try export_service.lendHandle(&export_policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 76,
        .secret_id = sealed_only.id,
        .expires_at_ticks = 20,
        .now_ticks = 14,
        .allow_raw_export = true,
        .detail = "private sealed-only token lent",
    }, &export_ledger);
    try std.testing.expect(!sealed_only_handle.raw_export_allowed);
    try std.testing.expectError(error.RawExportDenied, export_service.exportRaw(&export_policies, subjects, .{
        .holder = app,
        .task_id = 76,
        .handle_id = sealed_only_handle.id,
        .now_ticks = 15,
        .detail = "private sealed-only token raw export denied",
    }, &export_ledger));
    const export_summary = export_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 3), export_summary.secret_vault_events);
    try std.testing.expectEqual(@as(usize, 1), export_summary.secret_vault_denials);
    try std.testing.expectEqual(@as(usize, 1), export_summary.secret_vault_raw_export_denials);
    const portable_secret = try export_service.importSecret(&export_policies, subjects, .{
        .owner = user,
        .task_id = 77,
        .label = "portable-token",
        .raw = "private portable token",
        .hardware_backed = true,
        .exportable = true,
        .now_ticks = 16,
        .detail = "private portable token imported",
    }, &export_ledger);
    const portable_handle = try export_service.lendHandle(&export_policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 78,
        .secret_id = portable_secret.id,
        .expires_at_ticks = 24,
        .now_ticks = 17,
        .allow_raw_export = true,
        .detail = "private portable token lent",
    }, &export_ledger);
    try std.testing.expect(portable_handle.raw_export_allowed);
    try std.testing.expectEqualStrings("private portable token", try export_service.exportRaw(&export_policies, subjects, .{
        .holder = app,
        .task_id = 78,
        .handle_id = portable_handle.id,
        .now_ticks = 18,
        .detail = "private portable token raw export allowed",
    }, &export_ledger));
    const export_success_summary = export_ledger.userVisibleDiagnosticSummary();
    try std.testing.expectEqual(@as(usize, 6), export_success_summary.secret_vault_events);
    try std.testing.expectEqual(@as(usize, 1), export_success_summary.secret_vault_denials);
    try std.testing.expectEqual(@as(usize, 1), export_success_summary.secret_vault_raw_export_denials);
    var export_diag_buffer: [2048]u8 = undefined;
    const export_diag = try export_ledger.exportText(&export_diag_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, export_diag, "private portable token") == null);
    try std.testing.expect(std.mem.indexOf(u8, export_diag, "kind=secret_vault") != null);

    const summary = ledger.userVisibleDiagnosticSummary();
    try std.testing.expect(summary.secret_vault_events >= 9);
    try std.testing.expect(summary.secret_vault_denials >= 4);
    try std.testing.expect(summary.secret_vault_raw_export_denials >= 1);
    try std.testing.expect(summary.secret_vault_rotations >= 1);
    try std.testing.expect(summary.secret_vault_revocations >= 1);
    try std.testing.expect(summary.protected_details_redacted >= summary.secret_vault_events);

    var export_buffer: [4096]u8 = undefined;
    const exported = try ledger.exportText(&export_buffer, .{});
    try std.testing.expect(std.mem.indexOf(u8, exported, "private api token") == null);
    try std.testing.expect(std.mem.indexOf(u8, exported, "kind=secret_vault") != null);
}
