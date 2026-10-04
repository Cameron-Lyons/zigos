const std = @import("std");
const event_ledger = @import("../platform/event_ledger.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const policy_object = @import("../policy/policy_object.zig");
const principal = @import("../core/principal.zig");
const secure_secret_store = @import("../platform/secure_secret_store.zig");
const manifest = @import("../policy/manifest.zig");

pub const MAX_HANDLES: usize = secure_secret_store.MAX_HANDLES;
pub const BOUNDED_HANDLE_SCAN = true;
pub const RECLAIMS_TERMINAL_HANDLES = true;
pub const COMPACT_ACTIVE_HANDLE_COUNT_METADATA = true;
pub const DIRECT_HANDLE_LOOKUP = true;
pub const SERVICE_SIZE_CEILING_BYTES: usize = 17_280;

comptime {
    if (MAX_HANDLES > std.math.maxInt(u8)) {
        @compileError("secret vault active handle count cannot represent the handle capacity");
    }
}

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

pub const GenerateSigningKeyRequest = struct {
    owner: principal.PrincipalId,
    task_id: u64,
    label: []const u8,
    now_ticks: u64,
};

pub const LendRequest = struct {
    owner: principal.PrincipalId,
    holder: principal.PrincipalId,
    task_id: u64,
    secret_id: u64,
    expires_at_ticks: u64,
    now_ticks: u64,
    allow_raw_export: bool = false,
    detail: []const u8 = "",
};

pub const ExportRequest = struct {
    holder: principal.PrincipalId,
    task_id: u64,
    handle_id: u64,
    now_ticks: u64,
    detail: []const u8 = "",
};

pub const SignRequest = struct {
    holder: principal.PrincipalId,
    task_id: u64,
    handle_id: u64,
    digest: [32]u8,
    now_ticks: u64,
};

pub const SigningAuthority = struct {
    holder: principal.PrincipalId,
    task_id: u64,
    handle_id: u64,
    now_ticks: u64,
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

pub const RetireRequest = struct {
    owner: principal.PrincipalId,
    task_id: u64,
    secret_id: u64,
    now_ticks: u64,
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

    pub fn expired(self: *const VaultHandle, now_ticks: u64) bool {
        return self.expires_at_ticks != 0 and now_ticks >= self.expires_at_ticks;
    }
};

const HandleSlot = struct {
    in_use: bool = false,
    handle: VaultHandle = .{},
};

pub const HandleId = indexed_arena.GenerationalHandle("SecretVaultHandle");
const HandleArena = indexed_arena.GenerationalArena("SecretVaultHandle", HandleSlot, MAX_HANDLES);

pub const Service = struct {
    store: secure_secret_store.Store = secure_secret_store.Store.init(),
    handles: HandleArena = HandleArena.init(),
    active_handle_count: u8 = 0,
    next_reusable_handle: u8 = 0,

    comptime {
        if (@sizeOf(@This()) > SERVICE_SIZE_CEILING_BYTES) {
            @compileError("secret vault service exceeds its fixed-state size ceiling");
        }
    }

    pub fn init() Service {
        return .{};
    }

    pub fn initializeAllocated(self: *Service) void {
        self.store.initializeAllocated();
        self.handles = HandleArena.init();
        self.active_handle_count = 0;
        self.next_reusable_handle = 0;
    }

    pub fn attachHardwareProvider(self: *Service, provider: secure_secret_store.HardwareSealProvider) void {
        self.store.attachHardwareProvider(provider);
    }

    // Session teardown cannot depend on policy, audit capacity, or hardware.
    // Preserve both arenas' generations across subsequent catalog restores.
    pub fn unload(self: *Service) void {
        self.handles.reset();
        self.active_handle_count = 0;
        self.next_reusable_handle = 0;
        self.store.unload();
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
        errdefer recordImport(ledger, request, 0, false) catch {};
        const slot_index = try self.store.nextSecretSlot();
        const previous_id = self.store.secrets[slot_index].id;
        const secret = try self.store.importSecret(
            request.owner,
            request.label,
            request.raw,
            request.hardware_backed,
            request.exportable,
        );
        errdefer self.discardUnpublishedSecret(slot_index, previous_id);
        try recordImport(ledger, request, secret.id, true);
        return secret;
    }

    pub fn generateSigningKey(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: GenerateSigningKeyRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!*const secure_secret_store.SecretRecord {
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .generate_signing_key,
            .hardware_backed = true,
        });
        if (!decision.allowed) {
            try recordGeneration(ledger, request, 0, false);
            return error.PolicyDenied;
        }
        errdefer recordGeneration(ledger, request, 0, false) catch {};
        if (request.label.len > secure_secret_store.MAX_LABEL_BYTES) return error.LabelTooLong;
        const slot_index = try self.store.nextSecretSlot();
        // Serialized service calls keep this slot private until the audit has
        // succeeded. Roll back on audit failure without consuming a secret id.
        const previous_id = self.store.secrets[slot_index].id;
        const secret = try self.store.generateSigningKey(request.owner, request.label);
        errdefer self.discardUnpublishedSecret(slot_index, previous_id);
        try recordGeneration(ledger, request, secret.id, true);
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
            try recordLend(ledger, request, 0, false, false);
            return error.InvalidLease;
        }
        const secret = self.store.describeSecret(request.secret_id) orelse {
            try recordLend(ledger, request, 0, false, false);
            return error.SecretNotFound;
        };
        if (!secret.owner.eql(request.owner)) {
            try recordLend(ledger, request, 0, false, secret.hardware_backed);
            return error.SecretOwnerMismatch;
        }
        const lease_ticks = request.expires_at_ticks - request.now_ticks;
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .lend,
            .hardware_backed = secret.hardware_backed,
            .raw_export = request.allow_raw_export,
            .lease_ticks = lease_ticks,
        });
        if (!decision.allowed) {
            try recordLend(ledger, request, 0, false, secret.hardware_backed);
            return error.PolicyDenied;
        }

        const retired_slot_index = if (self.handles.previewHandle(null) == null or self.store.handles.previewHandle(null) == null)
            self.terminalHandleSlot(request.now_ticks) orelse {
                try recordLend(ledger, request, 0, false, secret.hardware_backed);
                return error.HandleTableFull;
            }
        else
            null;
        // Both arenas are preflighted before auditing or changing authority.
        // Calls are serialized, so the commits below cannot fail or select a
        // different identity after the audit has accepted these exact IDs.
        const store_id = self.store.handles.previewHandle(if (retired_slot_index) |i| .{ .value = self.handles.slots[i].handle.store_handle_id } else null) orelse
            return if (retired_slot_index != null) error.HandleNotFound else error.HandleTableFull;
        const handle_id = self.handles.previewHandle(if (retired_slot_index) |i| .{ .value = self.handles.slots[i].handle.id } else null) orelse return error.HandleTableFull;
        try recordLend(ledger, request, handle_id.value, true, secret.hardware_backed);
        const store_handle = (if (retired_slot_index) |slot_index|
            self.store.replaceHandle(
                self.handles.slots[slot_index].handle.store_handle_id,
                request.secret_id,
                request.holder,
                request.task_id,
                request.allow_raw_export,
            )
        else
            self.store.lendHandle(
                request.secret_id,
                request.holder,
                request.task_id,
                request.allow_raw_export,
            )) catch |err| native_util.impossibleByInvariantError("preflighted vault store handle commits after audit", err);
        const committed_id = if (retired_slot_index) |retired|
            self.reuseHandleSlot(retired)
        else
            self.handles.reserveHandle() orelse native_util.impossibleByInvariant("preflighted vault handle capacity is unchanged");
        if (!committed_id.eql(handle_id) or store_handle.id != store_id.value)
            native_util.impossibleByInvariant("serialized vault lending preserves previewed identities");
        const slot = self.handles.getByHandle(handle_id) orelse
            native_util.impossibleByInvariant("secret vault reserved handle resolves directly");
        slot.handle = .{
            .id = handle_id.value,
            .store_handle_id = store_handle.id,
            .secret_id = request.secret_id,
            .holder = request.holder,
            .task_id = request.task_id,
            .expires_at_ticks = request.expires_at_ticks,
            .hardware_backed = store_handle.hardware_backed,
            .raw_export_allowed = store_handle.export_allowed,
        };
        self.active_handle_count += 1;
        return &slot.handle;
    }

    pub fn exportRaw(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: ExportRequest,
        ledger: ?*event_ledger.Ledger,
        out: *secure_secret_store.Value,
    ) Error![]const u8 {
        std.crypto.secureZero(u8, out);
        errdefer std.crypto.secureZero(u8, out);
        const handle = (self.findHandleConst(request.handle_id) orelse {
            try recordExport(ledger, request, 0, false, false);
            return error.VaultHandleNotFound;
        }).*;
        _ = self.requireExportHandle(policies, subjects, request) catch |err| {
            try recordExportFromHandle(ledger, request, &handle, false);
            return err;
        };
        errdefer recordExportFromHandle(ledger, request, &handle, false) catch {};
        const raw = try self.store.exportRaw(handle.store_handle_id, .{
            .holder = request.holder,
            .task_id = request.task_id,
        }, out);
        // The provider may yield while opening sealed material. A revoked or
        // recycled lease and a new policy must withhold the recovered bytes.
        _ = try self.requireExportHandle(policies, subjects, request);
        try recordExportFromHandle(ledger, request, &handle, true);
        return raw;
    }

    fn requireExportHandle(self: *const Service, policies: *const policy_object.Directory, subjects: policy_object.SubjectSet, request: ExportRequest) Error!*const VaultHandle {
        const handle = try self.requireLiveHandle(.{ .holder = request.holder, .task_id = request.task_id, .handle_id = request.handle_id, .now_ticks = request.now_ticks });
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .export_raw,
            .hardware_backed = handle.hardware_backed,
            .raw_export = true,
            .lease_ticks = handle.expires_at_ticks - request.now_ticks,
        });
        if (!decision.allowed) return error.PolicyDenied;
        if (!handle.raw_export_allowed) return error.RawExportDenied;
        return handle;
    }

    pub fn signDigest(
        self: *Service,
        policies: *const policy_object.Directory,
        subjects: policy_object.SubjectSet,
        request: SignRequest,
        ledger: ?*event_ledger.Ledger,
    ) Error!manifest.Signature {
        return self.signMessage(policies, subjects, .{
            .holder = request.holder,
            .task_id = request.task_id,
            .handle_id = request.handle_id,
            .now_ticks = request.now_ticks,
        }, &request.digest, ledger);
    }

    fn requireLiveHandle(self: *const Service, request: SigningAuthority) Error!*const VaultHandle {
        const handle = self.findHandleConst(request.handle_id) orelse return error.VaultHandleNotFound;
        if (!handle.holder.eql(request.holder) or handle.task_id != request.task_id) return error.HandleHolderMismatch;
        if (handle.revoked) return error.HandleRevoked;
        if (handle.expired(request.now_ticks)) return error.HandleExpired;
        return handle;
    }

    pub fn requireSigningHandle(self: *const Service, policies: *const policy_object.Directory, subjects: policy_object.SubjectSet, request: SigningAuthority) Error!*const VaultHandle {
        const handle = try self.requireLiveHandle(request);
        const decision = policies.secretVaultDecision(subjects, .{
            .operation = .sign,
            .hardware_backed = handle.hardware_backed,
            .lease_ticks = handle.expires_at_ticks - request.now_ticks,
        });
        if (!decision.allowed) return error.PolicyDenied;
        return handle;
    }

    pub fn signMessage(self: *Service, policies: *const policy_object.Directory, subjects: policy_object.SubjectSet, request: SigningAuthority, message: []const u8, ledger: ?*event_ledger.Ledger) Error!manifest.Signature {
        const handle = (self.findHandleConst(request.handle_id) orelse {
            if (ledger) |log| try log.recordSecretVault(request.holder, request.task_id, 0, request.handle_id, false, false, false, false, false, request.now_ticks, "sign digest");
            return error.VaultHandleNotFound;
        }).*;
        errdefer if (ledger) |log| log.recordSecretVault(request.holder, request.task_id, handle.secret_id, handle.id, false, handle.hardware_backed, false, false, false, request.now_ticks, "sign digest") catch {};
        _ = try self.requireSigningHandle(policies, subjects, request);
        const signature = try self.store.signMessage(handle.store_handle_id, .{
            .holder = request.holder,
            .task_id = request.task_id,
        }, message);
        // Keep the audit identity by value across the provider wait. Reacquire
        // the full generational lease and current policy before success.
        _ = try self.requireSigningHandle(policies, subjects, request);
        if (ledger) |log| try log.recordSecretVault(request.holder, request.task_id, handle.secret_id, handle.id, true, handle.hardware_backed, false, false, false, request.now_ticks, "sign digest");
        return signature;
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

        errdefer recordRotate(ledger, request, 0, false) catch {};
        const slot_index = try self.store.nextSecretSlot();
        const previous_id = self.store.secrets[slot_index].id;
        const secret = try self.store.importSecret(
            request.owner,
            request.label,
            request.raw,
            request.hardware_backed,
            request.exportable,
        );
        errdefer self.discardUnpublishedSecret(slot_index, previous_id);
        try recordRotate(ledger, request, secret.id, true);
        _ = self.revokeSecretHandles(request.old_secret_id);
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
            try recordRevoke(ledger, request, handle.hardware_backed, true);
            _ = self.markRevoked(handle);
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
            const has_live_handle = for (self.handles.slots) |slot| {
                if (slot.in_use and !slot.handle.revoked and slot.handle.secret_id == request.secret_id) break true;
            } else false;
            try recordRevoke(ledger, request, secret.hardware_backed, has_live_handle);
            if (!has_live_handle) return error.VaultHandleNotFound;
            _ = self.revokeSecretHandles(request.secret_id);
            return;
        }
        try recordRevoke(ledger, request, false, false);
        return error.VaultHandleNotFound;
    }

    // The durable caller must first reject references that still require this
    // key. Retiring removes all live leases and reclaims its physical slot.
    pub fn retireSecret(self: *Service, policies: *const policy_object.Directory, subjects: policy_object.SubjectSet, request: RetireRequest, ledger: ?*event_ledger.Ledger) Error!void {
        const secret = self.store.describeSecret(request.secret_id) orelse return error.SecretNotFound;
        if (!secret.owner.eql(request.owner)) return error.SecretOwnerMismatch;
        const decision = policies.secretVaultDecision(subjects, .{ .operation = .retire, .hardware_backed = secret.hardware_backed });
        if (ledger) |log| try log.recordSecretVault(request.owner, request.task_id, request.secret_id, 0, decision.allowed, secret.hardware_backed, false, false, true, request.now_ticks, "retire secret");
        if (!decision.allowed) return error.PolicyDenied;
        try self.store.retireSecret(request.secret_id);
        for (&self.handles.slots) |*slot| {
            if (!slot.in_use or slot.handle.secret_id != request.secret_id) continue;
            const id = slot.handle.id;
            _ = self.markRevoked(&slot.handle);
            _ = self.handles.removeHandle(.{ .value = id });
        }
    }

    pub fn findHandle(self: *Service, handle_id: u64) ?*VaultHandle {
        const slot = self.handles.getByHandle(.{ .value = handle_id }) orelse return null;
        return &slot.handle;
    }

    pub fn findHandleConst(self: *const Service, handle_id: u64) ?*const VaultHandle {
        const slot = self.handles.getConstByHandle(.{ .value = handle_id }) orelse return null;
        return &slot.handle;
    }

    pub fn activeHandleCount(self: *const Service) usize {
        return self.active_handle_count;
    }

    pub fn activeHandleCountAt(self: *const Service, now_ticks: u64) usize {
        if (self.active_handle_count == 0) return 0;
        var count: usize = 0;
        for (&self.handles.slots) |*slot| {
            if (!slot.in_use or slot.handle.revoked) continue;
            if (!slot.handle.expired(now_ticks)) count += 1;
        }
        return count;
    }

    fn discardUnpublishedSecret(self: *Service, slot_index: usize, previous_id: u64) void {
        // No caller can observe this new record before the audit succeeds.
        // Erase its material, then restore the pristine slot or tombstone ID.
        std.debug.assert(!secure_secret_store.isLiveId(previous_id));
        self.store.retireSecret(self.store.secrets[slot_index].id) catch |err|
            native_util.impossibleByInvariantError("unpublished vault secret remains in its reserved slot", err);
        self.store.secrets[slot_index].id = previous_id;
    }

    fn revokeSecretHandles(self: *Service, secret_id: u64) usize {
        var revoked_count: usize = 0;
        for (&self.handles.slots) |*slot| {
            if (!slot.in_use or slot.handle.secret_id != secret_id) continue;
            if (self.markRevoked(&slot.handle)) revoked_count += 1;
        }
        return revoked_count;
    }

    fn markRevoked(self: *Service, handle: *VaultHandle) bool {
        if (handle.revoked) return false;
        handle.revoked = true;
        if (self.active_handle_count == 0) native_util.impossibleByInvariant("secret vault active handle count underflow");
        self.active_handle_count -= 1;
        return true;
    }

    fn terminalHandleSlot(self: *const Service, now_ticks: u64) ?usize {
        const start: usize = @intCast(self.next_reusable_handle);
        for (0..MAX_HANDLES) |offset| {
            const slot_index = (start + offset) % MAX_HANDLES;
            const slot = &self.handles.slots[slot_index];
            if (!slot.in_use) continue;
            if ((slot.handle.revoked or slot.handle.expired(now_ticks)) and
                self.handles.previewHandle(.{ .value = slot.handle.id }) != null and
                self.store.handles.previewHandle(.{ .value = slot.handle.store_handle_id }) != null) return slot_index;
        }
        return null;
    }

    fn reuseHandleSlot(self: *Service, retired_slot_index: usize) HandleId {
        const retired = &self.handles.slots[retired_slot_index].handle;
        if (!retired.revoked) {
            if (self.active_handle_count == 0) native_util.impossibleByInvariant("secret vault active handle count covers expired replacement");
            self.active_handle_count -= 1;
        }
        const handle_id = self.handles.replaceHandle(.{ .value = retired.id }) orelse
            native_util.impossibleByInvariant("secret vault replacement keeps its retired handle live");
        self.next_reusable_handle = @intCast((retired_slot_index + 1) % MAX_HANDLES);
        return handle_id;
    }
};

fn recordGeneration(ledger: ?*event_ledger.Ledger, request: GenerateSigningKeyRequest, secret_id: u64, allowed: bool) event_ledger.Error!void {
    if (ledger) |log| try log.recordSecretVault(request.owner, request.task_id, secret_id, 0, allowed, true, false, false, false, request.now_ticks, "generate signing key");
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
    hardware_backed: bool,
) event_ledger.Error!void {
    if (ledger) |active| {
        try active.recordSecretVault(
            request.owner,
            request.task_id,
            request.secret_id,
            handle_id,
            allowed,
            hardware_backed,
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

fn testHardwareProvider() secure_secret_store.HardwareSealProvider {
    return @import("../../tests/fixtures/secret_provider.zig").provider();
}

test "secret vault unload preserves stale lease rejection across repeated restores" {
    const Fixture = @import("../../tests/fixtures/document_signer.zig").Fixture;
    var fixture = Fixture{};
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 2 };
    const key = try fixture.init(owner, holder, 3, .{ .label = "unload", .seed = @splat(0x57) });
    const original = fixture.service.findHandleConst(key.key.handle_id).?.*;
    const record = fixture.service.store.describeSecret(original.secret_id).?.*;
    const context = secure_secret_store.ExportContext{ .holder = holder, .task_id = 3 };
    var previous = original;
    _ = try fixture.service.store.importSecret(owner, "resident value", &(@as(secure_secret_store.Value, @splat(0x98))), false, false);
    for (0..MAX_HANDLES * 3) |_| {
        fixture.service.unload();
        fixture.service.unload();
        try std.testing.expect(fixture.service.store.empty());
        try std.testing.expectEqual(@as(usize, 0), fixture.service.activeHandleCount());
        try std.testing.expect(fixture.service.store.hardware_provider.operations == null);
        for (fixture.service.store.secrets) |secret| {
            try std.testing.expectEqual(@as(u8, 0), secret.material.raw.len);
            try std.testing.expect(std.mem.allEqual(u8, &secret.material.raw.bytes, 0));
        }
        try std.testing.expectError(error.VaultHandleNotFound, key.key.validate(1));
        try std.testing.expectError(error.HandleNotFound, fixture.service.store.signMessage(original.store_handle_id, context, "stale"));
        fixture.service.attachHardwareProvider(testHardwareProvider());
        _ = try fixture.service.store.restoreSealedAt(record.id, owner, record.labelSlice(), record.sealedBlob().?, false);
        const fresh = (try fixture.service.lendHandle(&fixture.policies, fixture.authority.subjects, .{ .owner = owner, .holder = holder, .task_id = 3, .secret_id = record.id, .now_ticks = 1, .expires_at_ticks = 10 }, null)).*;
        try std.testing.expect(fresh.id != previous.id and fresh.store_handle_id != previous.store_handle_id);
        try std.testing.expect(fixture.service.findHandleConst(previous.id) == null);
        try std.testing.expectError(error.VaultHandleNotFound, key.key.validate(1));
        try std.testing.expectError(error.HandleNotFound, fixture.service.store.signMessage(original.store_handle_id, context, "stale"));
        const signature = try fixture.service.store.signMessage(fresh.store_handle_id, context, "fresh");
        try std.testing.expect(@import("../core/signing.zig").verify(signature, "fresh"));
        previous = fresh;
    }
}

test "secret vault stores active handle count in capacity-sized metadata" {
    try std.testing.expect(COMPACT_ACTIVE_HANDLE_COUNT_METADATA);
    try std.testing.expect(@FieldType(Service, "active_handle_count") == u8);
    try std.testing.expect(@sizeOf(Service) <= SERVICE_SIZE_CEILING_BYTES);
}

test "secret vault brokers sealed leased handles raw export policy rotation and revocation" {
    var secret_export_buffer: secure_secret_store.Value = undefined;
    defer std.crypto.secureZero(u8, &secret_export_buffer);
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
    try std.testing.expectEqual(@as(usize, 1), service.activeHandleCountAt(19));

    try std.testing.expectError(error.PolicyDenied, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 72,
        .handle_id = handle.id,
        .now_ticks = 5,
        .detail = "private api token raw export denied",
    }, &ledger, &secret_export_buffer));

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
    try std.testing.expectError(error.HandleRevoked, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 72,
        .handle_id = handle.id,
        .now_ticks = 7,
        .detail = "private api token old handle revoked",
    }, &ledger, &secret_export_buffer));

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
    }, &ledger, &secret_export_buffer));
    try std.testing.expectEqual(@as(usize, 0), service.activeHandleCount());

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
    try std.testing.expect(service.findHandle(first_secret_revoke_handle.id) != null);
    try std.testing.expect(service.findHandle(second_secret_revoke_handle.id) != null);
    try service.revoke(.{
        .subject = user,
        .task_id = 71,
        .secret_id = rotated.id,
        .now_ticks = 13,
        .detail = "private api token v2 secret revoked",
    }, &ledger);
    try std.testing.expectEqual(@as(usize, 0), service.activeHandleCount());
    try std.testing.expectError(error.HandleRevoked, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 72,
        .handle_id = first_secret_revoke_handle.id,
        .now_ticks = 14,
        .detail = "private api token v2 first raw export denied",
    }, &ledger, &secret_export_buffer));
    try std.testing.expectError(error.HandleRevoked, service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 73,
        .handle_id = second_secret_revoke_handle.id,
        .now_ticks = 14,
        .detail = "private api token v2 second raw export denied",
    }, &ledger, &secret_export_buffer));

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
    try std.testing.expectEqual(@as(usize, 1), expiry_service.activeHandleCountAt(19));
    try std.testing.expectEqual(@as(usize, 0), expiry_service.activeHandleCountAt(20));
    try std.testing.expectError(error.HandleExpired, expiry_service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 74,
        .handle_id = expiring_handle.id,
        .now_ticks = 20,
        .detail = "private expiring token at boundary",
    }, &expiry_ledger, &secret_export_buffer));

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
    }, &export_ledger, &secret_export_buffer));
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
    }, &export_ledger, &secret_export_buffer));
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

test "secret vault stages lending and reclaims terminal handles under pressure" {
    var secret_export_buffer: secure_secret_store.Value = undefined;
    defer std.crypto.secureZero(u8, &secret_export_buffer);
    const signing = @import("../core/signing.zig");

    var policies = policy_object.Directory.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 621 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 622 };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = user.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 3 },
        .label = "secret vault lending policy",
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = false,
        .deny_secret_raw_export = false,
        .max_secret_handle_lease_ticks = 100,
    }, signing.SignerIdentity{
        .label = "secret-vault-lending-policy",
        .seed = signing.seedFromByte(0xd9),
    });
    const subjects = policy_object.SubjectSet{ .user_id = user.serial };

    var full_service = Service.init();
    const full_secret = try full_service.store.importSecret(user, "full-token", "private full token", false, true);
    var first_full_handle_id: u64 = 0;
    var first_full_store_handle_id: u64 = 0;
    for (0..MAX_HANDLES) |index| {
        const filled = try full_service.lendHandle(&policies, subjects, .{
            .owner = user,
            .holder = app,
            .task_id = 90 + @as(u64, @intCast(index)),
            .secret_id = full_secret.id,
            .expires_at_ticks = 100,
            .now_ticks = 20,
            .allow_raw_export = true,

            .detail = "private full token capacity filler",
        }, null);
        if (index == 0) {
            first_full_handle_id = filled.id;
            first_full_store_handle_id = filled.store_handle_id;
        }
    }
    try std.testing.expectEqual(MAX_HANDLES, full_service.activeHandleCount());
    try std.testing.expectEqual(MAX_HANDLES, full_service.activeHandleCountAt(99));
    try std.testing.expectEqual(@as(usize, 0), full_service.activeHandleCountAt(100));
    try std.testing.expect(full_service.findHandle(0) == null);

    try std.testing.expectError(error.HandleTableFull, full_service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 91,
        .secret_id = full_secret.id,
        .expires_at_ticks = 30,
        .now_ticks = 20,
        .allow_raw_export = true,

        .detail = "private full token rejected before lower store handle",
    }, null));
    try std.testing.expectEqual(MAX_HANDLES, full_service.handles.countInUse());
    try std.testing.expectEqual(MAX_HANDLES, full_service.store.handles.countInUse());
    try full_service.revoke(.{
        .subject = user,
        .task_id = 90,
        .secret_id = full_secret.id,
        .now_ticks = 21,
        .detail = "private full token revoked through bounded scan",
    }, null);
    try std.testing.expectEqual(@as(usize, 0), full_service.activeHandleCount());
    try std.testing.expect(full_service.findHandle(first_full_handle_id).?.revoked);

    const replacement = try full_service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 123,
        .secret_id = full_secret.id,
        .expires_at_ticks = 40,
        .now_ticks = 22,
        .allow_raw_export = true,

        .detail = "private full token replacement after revocation",
    }, null);
    const first_id = HandleId{ .value = first_full_handle_id };
    const replacement_id = HandleId{ .value = replacement.id };
    const first_store_id = secure_secret_store.HandleId{ .value = first_full_store_handle_id };
    const replacement_store_id = secure_secret_store.HandleId{ .value = replacement.store_handle_id };
    try std.testing.expectEqual(first_id.slotIndex(), replacement_id.slotIndex());
    try std.testing.expect(!first_id.eql(replacement_id));
    try std.testing.expectEqual(first_store_id.slotIndex(), replacement_store_id.slotIndex());
    try std.testing.expect(!first_store_id.eql(replacement_store_id));
    try std.testing.expect(full_service.findHandle(first_full_handle_id) == null);
    try std.testing.expect(full_service.store.describeHandle(first_full_store_handle_id) == null);
    try std.testing.expectEqual(@as(usize, 1), full_service.activeHandleCount());
    try std.testing.expectEqual(MAX_HANDLES, full_service.handles.countInUse());
    try std.testing.expectEqual(MAX_HANDLES, full_service.store.handles.countInUse());
    try std.testing.expectEqualStrings("private full token", try full_service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 123,
        .handle_id = replacement.id,
        .now_ticks = 23,
        .detail = "private full token replacement export",
    }, null, &secret_export_buffer));

    var expiry_reuse_service = Service.init();
    const expiry_reuse_secret = try expiry_reuse_service.store.importSecret(user, "expiry-reuse", "private expiry reuse token", false, true);
    var first_expired_handle_id: u64 = 0;
    var first_expired_store_handle_id: u64 = 0;
    for (0..MAX_HANDLES) |index| {
        const filled = try expiry_reuse_service.lendHandle(&policies, subjects, .{
            .owner = user,
            .holder = app,
            .task_id = 200 + @as(u64, @intCast(index)),
            .secret_id = expiry_reuse_secret.id,
            .expires_at_ticks = 30,
            .now_ticks = 20,
            .allow_raw_export = true,

            .detail = "private expiry reuse capacity filler",
        }, null);
        if (index == 0) {
            first_expired_handle_id = filled.id;
            first_expired_store_handle_id = filled.store_handle_id;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), expiry_reuse_service.activeHandleCountAt(30));

    const expiry_replacement = try expiry_reuse_service.lendHandle(&policies, subjects, .{
        .owner = user,
        .holder = app,
        .task_id = 300,
        .secret_id = expiry_reuse_secret.id,
        .expires_at_ticks = 40,
        .now_ticks = 30,
        .allow_raw_export = true,

        .detail = "private expiry reuse replacement",
    }, null);
    try std.testing.expect(expiry_reuse_service.findHandle(first_expired_handle_id) == null);
    try std.testing.expect(expiry_reuse_service.store.describeHandle(first_expired_store_handle_id) == null);
    try std.testing.expectEqual(MAX_HANDLES, expiry_reuse_service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 1), expiry_reuse_service.activeHandleCountAt(30));
    try std.testing.expectEqualStrings("private expiry reuse token", try expiry_reuse_service.exportRaw(&policies, subjects, .{
        .holder = app,
        .task_id = 300,
        .handle_id = expiry_replacement.id,
        .now_ticks = 31,
        .detail = "private expiry reuse replacement export",
    }, null, &secret_export_buffer));
}

test "vault signing enforces holder lease revocation and current policy without raw export" {
    const signing = @import("../core/signing.zig");
    var service = Service.init();
    service.attachHardwareProvider(testHardwareProvider());
    var policies = policy_object.Directory.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 101 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 102 };
    const subjects = policy_object.SubjectSet{ .user_id = owner.serial };
    const seed: [32]u8 = @splat(0x91);
    const secret = try service.importSecret(&policies, subjects, .{
        .owner = owner,
        .task_id = 5,
        .label = "signer",
        .raw = &seed,
        .now_ticks = 1,
    }, null);
    const handle = try service.lendHandle(&policies, subjects, .{
        .owner = owner,
        .holder = app,
        .task_id = 6,
        .secret_id = secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 2,
    }, null);
    const request = SignRequest{ .holder = app, .task_id = 6, .handle_id = handle.id, .digest = @splat(0x23), .now_ticks = 3 };
    const signature = try service.signDigest(&policies, subjects, request, null);
    try std.testing.expect(signing.verify(signature, &request.digest));
    var wrong = request;
    wrong.holder = owner;
    try std.testing.expectError(error.HandleHolderMismatch, service.signDigest(&policies, subjects, wrong, null));
    wrong = request;
    wrong.task_id += 1;
    try std.testing.expectError(error.HandleHolderMismatch, service.signDigest(&policies, subjects, wrong, null));
    wrong = request;
    wrong.now_ticks = 10;
    try std.testing.expectError(error.HandleExpired, service.signDigest(&policies, subjects, wrong, null));
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = owner.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "lock vault",
        .secret_vault_allowed = false,
    }, .{ .label = "policy", .seed = @splat(0x74) });
    try std.testing.expectError(error.PolicyDenied, service.signDigest(&policies, subjects, request, null));
    try service.revoke(.{
        .subject = owner,
        .task_id = 5,
        .handle_id = handle.id,
        .secret_id = secret.id,
        .expected_holder = app,
        .expected_holder_task_id = 6,
        .now_ticks = 4,
    }, null);
    try std.testing.expectError(error.HandleRevoked, service.signDigest(&policies, subjects, request, null));
}

test "vault signing and export revalidate authority after a yielding provider" {
    const cooperative = @import("../task/cooperative_worker.zig");
    const sealing = @import("../platform/secret_sealing.zig");
    const provider_fixture = @import("../../tests/fixtures/secret_provider.zig");
    const signing = @import("../core/signing.zig");
    const Fixture = struct {
        service: Service = .init(),
        policies: policy_object.Directory = .init(),
        request: SigningAuthority = undefined,
        exporting: bool,
        out: secure_secret_store.Value = @splat(0xaa),
        signature: ?manifest.Signature = null,
        failure: ?anyerror = null,
        const owner = principal.PrincipalId{ .kind = .user, .serial = 101 };
        const holder = principal.PrincipalId{ .kind = .service, .serial = 102 };
        const subjects = policy_object.SubjectSet{ .user_id = owner.serial };
        const seed: [32]u8 = @splat(0x91);
        const message = "yielding vault operation";

        fn seal(_: ?*anyopaque, binding: *const sealing.Binding, raw: []const u8, out: *sealing.Blob) sealing.Error!void {
            try provider_fixture.provider().seal(binding, raw, out);
        }
        fn open(_: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
            const len = try provider_fixture.provider().open(binding, blob, out);
            cooperative.current().?.yield();
            return len;
        }
        fn run(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.exporting) {
                _ = self.service.exportRaw(&self.policies, subjects, .{
                    .holder = self.request.holder,
                    .task_id = self.request.task_id,
                    .handle_id = self.request.handle_id,
                    .now_ticks = self.request.now_ticks,
                }, null, &self.out) catch |err| {
                    self.failure = err;
                    return;
                };
            } else {
                self.signature = self.service.signMessage(&self.policies, subjects, self.request, message, null) catch |err| {
                    self.failure = err;
                    return;
                };
            }
        }
        fn addKey(self: *@This()) !VaultHandle {
            const secret = try self.service.importSecret(&self.policies, subjects, .{ .owner = owner, .task_id = 5, .label = "signer", .raw = &seed, .exportable = true, .now_ticks = 1 }, null);
            return (try self.service.lendHandle(&self.policies, subjects, .{ .owner = owner, .holder = holder, .task_id = 6, .secret_id = secret.id, .expires_at_ticks = 10, .now_ticks = 2, .allow_raw_export = true }, null)).*;
        }
    };
    for ([_]bool{ false, true }) |exporting| {
        for (0..5) |mode| {
            var fixture = Fixture{ .exporting = exporting };
            defer fixture.service.unload();
            fixture.service.attachHardwareProvider(.{ .operations = &.{ .seal = Fixture.seal, .open = Fixture.open } });
            _ = try fixture.policies.create(.{ .scope = .user, .subject_id = Fixture.owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "allow vault", .secret_vault_allowed = true, .deny_secret_raw_export = false }, .{ .label = "policy", .seed = @splat(0x74) });
            const handle = try fixture.addKey();
            fixture.request = .{ .holder = Fixture.holder, .task_id = 6, .handle_id = handle.id, .now_ticks = 3 };
            var stack: [32 * 1024]u8 align(16) = undefined;
            var worker = cooperative.Worker{ .stack = &stack };
            try worker.start(&fixture, Fixture.run);
            try worker.step();
            try std.testing.expect(worker.state == .suspended and fixture.signature == null and fixture.failure == null);
            switch (mode) {
                1 => try fixture.service.revoke(.{ .subject = Fixture.owner, .task_id = 5, .handle_id = handle.id, .secret_id = handle.secret_id, .expected_holder = Fixture.holder, .expected_holder_task_id = 6, .now_ticks = 4 }, null),
                2 => {
                    try fixture.service.retireSecret(&fixture.policies, Fixture.subjects, .{ .owner = Fixture.owner, .task_id = 5, .secret_id = handle.secret_id, .now_ticks = 4 }, null);
                    const replacement = try fixture.addKey();
                    try std.testing.expectEqual((HandleId{ .value = handle.id }).slotIndex(), (HandleId{ .value = replacement.id }).slotIndex());
                    try std.testing.expect(replacement.id != handle.id and replacement.secret_id != handle.secret_id);
                },
                3 => fixture.service.unload(),
                4 => {
                    _ = try fixture.policies.create(.{ .scope = .user, .subject_id = Fixture.owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 1 }, .label = "deny vault", .secret_vault_allowed = false }, .{ .label = "policy", .seed = @splat(0x74) });
                },
                else => {},
            }
            try worker.step();
            try std.testing.expect(worker.state == .complete and std.mem.allEqual(u8, &stack, 0));
            if (mode == 0) {
                try std.testing.expect(fixture.failure == null);
                if (exporting) try std.testing.expectEqualSlices(u8, &Fixture.seed, fixture.out[0..32]) else try std.testing.expect(signing.verify(fixture.signature.?, Fixture.message));
            } else {
                try std.testing.expectEqual(@as(?anyerror, switch (mode) {
                    1 => error.HandleRevoked,
                    2, 3 => error.VaultHandleNotFound,
                    4 => error.PolicyDenied,
                    else => unreachable,
                }), fixture.failure);
                try std.testing.expect(fixture.signature == null);
                if (exporting) try std.testing.expect(std.mem.allEqual(u8, &fixture.out, 0));
            }
        }
    }
}

test "vault hardware policy uses stored custody when lending a software secret" {
    var service = Service.init();
    var policies = policy_object.Directory.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 71 };
    const app = principal.PrincipalId{ .kind = .app, .serial = 72 };
    const subjects = policy_object.SubjectSet{ .user_id = owner.serial };
    const secret = try service.store.importSecret(owner, "software", "value", false, false);
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = owner.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 1 },
        .label = "hardware required",
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = true,
    }, .{ .label = "policy", .seed = @splat(0x75) });
    try std.testing.expectError(error.PolicyDenied, service.lendHandle(&policies, subjects, .{
        .owner = owner,
        .holder = app,
        .task_id = 5,
        .secret_id = secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 1,
    }, null));
    try std.testing.expectEqual(@as(usize, 0), service.activeHandleCount());
}

test "signing key generation checks policy before provider use audits and denies export" {
    const signing = @import("../core/signing.zig");
    var generator = @import("../../tests/fixtures/secret_provider.zig").KeyGenerator{};
    var service = Service.init();
    service.attachHardwareProvider(generator.provider());
    var ledger = event_ledger.Ledger.init();
    var policies = policy_object.Directory.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 930 };
    const subjects = policy_object.SubjectSet{ .user_id = owner.serial };
    const request = GenerateSigningKeyRequest{ .owner = owner, .task_id = 40, .label = "identity", .now_ticks = 2 };
    const policy_key = signing.SignerIdentity{ .label = "generation policy", .seed = @splat(0x53) };
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = owner.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 931 },
        .label = "generation policy",
        .secret_vault_allowed = false,
        .require_hardware_backed_secrets = true,
        .deny_secret_raw_export = true,
    }, policy_key);
    try std.testing.expect(!@hasField(GenerateSigningKeyRequest, "raw"));
    try std.testing.expect(!@hasField(GenerateSigningKeyRequest, "exportable"));
    try std.testing.expect(!@hasField(GenerateSigningKeyRequest, "hardware_backed"));
    try std.testing.expectError(error.PolicyDenied, service.generateSigningKey(&policies, subjects, request, &ledger));
    try std.testing.expectEqual(@as(u8, 0), generator.calls);
    try std.testing.expectEqual(@as(u8, 0), service.store.secret_count);
    try std.testing.expect(!ledger.latestKind(.secret_vault).?.allowed);
    policies = policy_object.Directory.init();
    _ = try policies.create(.{
        .scope = .user,
        .subject_id = owner.serial,
        .issuer = .{ .kind = .policy_authority, .serial = 931 },
        .label = "generation policy",
        .secret_vault_allowed = true,
        .require_hardware_backed_secrets = true,
        .deny_secret_raw_export = true,
    }, policy_key);
    const secret = try service.generateSigningKey(&policies, subjects, request, &ledger);
    const event = ledger.latestKind(.secret_vault).?;
    try std.testing.expect(event.allowed and event.subject.eql(owner));
    try std.testing.expectEqual(secret.id, event.related_id);
    try std.testing.expectEqual(request.task_id, event.task_id);
    try std.testing.expectEqual(@as(u32, 1), event.detail_code);
    const holder = principal.PrincipalId{ .kind = .service, .serial = 932 };
    const handle = try service.lendHandle(&policies, subjects, .{
        .owner = owner,
        .holder = holder,
        .task_id = 41,
        .secret_id = secret.id,
        .expires_at_ticks = 10,
        .now_ticks = 3,
    }, &ledger);
    const digest: [32]u8 = @splat(0x61);
    const signature = try service.signDigest(&policies, subjects, .{
        .holder = holder,
        .task_id = 41,
        .handle_id = handle.id,
        .digest = digest,
        .now_ticks = 4,
    }, &ledger);
    try std.testing.expect(signing.verify(signature, &digest));
    var out: secure_secret_store.Value = @splat(0xaa);
    // Empty policy still cannot grant export of a generated signing key.
    policies = policy_object.Directory.init();
    try std.testing.expectError(error.RawExportDenied, service.exportRaw(&policies, subjects, .{
        .holder = holder,
        .task_id = 41,
        .handle_id = handle.id,
        .now_ticks = 4,
    }, &ledger, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
    generator.result = .fail;
    const before = service;
    try std.testing.expectError(error.HardwareOperationFailed, service.generateSigningKey(&policies, subjects, request, &ledger));
    try std.testing.expectEqualDeep(before, service);
    try std.testing.expect(!ledger.latestKind(.secret_vault).?.allowed);
}

test "signing key generation rolls back unpublished state when the audit cannot persist" {
    const storage_service = @import("../storage/storage_service.zig");
    const owner = principal.PrincipalId{ .kind = .user, .serial = 933 };
    var checkpoint = storage_service.CheckpointStore{};
    var storage = storage_service.Service.initWithStore(934, 935, owner, &checkpoint);
    var ledger = event_ledger.Ledger.init();
    // A missing diagnostics workspace forces the real persistence path to fail.
    ledger.storage = &storage;
    ledger.workspace_id = 99;
    var generator = @import("../../tests/fixtures/secret_provider.zig").KeyGenerator{};
    var service = Service.init();
    service.attachHardwareProvider(generator.provider());
    const policies = policy_object.Directory.init();
    const request = GenerateSigningKeyRequest{ .owner = owner, .task_id = 40, .label = "identity", .now_ticks = 2 };
    const before = service;
    try std.testing.expectError(error.WorkspaceNotFound, service.generateSigningKey(&policies, .{}, request, &ledger));
    try std.testing.expectEqualDeep(before, service);
    try std.testing.expectEqual(@as(u8, 1), generator.calls);
    const secret = try service.generateSigningKey(&policies, .{}, request, null);
    try std.testing.expectEqual(@as(u64, 1), secret.id);
}

test "key retirement requires owner policy and audit before removing every lease" {
    const storage_service = @import("../storage/storage_service.zig");
    const owner = principal.PrincipalId{ .kind = .user, .serial = 940 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 941 };
    const subjects = policy_object.SubjectSet{ .user_id = owner.serial };
    var service = Service.init();
    var policies = policy_object.Directory.init();
    const first = (try service.store.importSecret(owner, "first", "private", false, true)).id;
    const sibling = (try service.store.importSecret(owner, "sibling", "kept", false, true)).id;
    const first_handle = (try service.lendHandle(&policies, subjects, .{ .owner = owner, .holder = holder, .task_id = 30, .secret_id = first, .expires_at_ticks = 100, .now_ticks = 1, .allow_raw_export = true }, null)).*;
    _ = try service.lendHandle(&policies, subjects, .{ .owner = owner, .holder = holder, .task_id = 31, .secret_id = first, .expires_at_ticks = 100, .now_ticks = 1 }, null);
    const sibling_handle = (try service.lendHandle(&policies, subjects, .{ .owner = owner, .holder = holder, .task_id = 30, .secret_id = sibling, .expires_at_ticks = 100, .now_ticks = 1, .allow_raw_export = true }, null)).*;
    const request = RetireRequest{ .owner = owner, .task_id = 30, .secret_id = first, .now_ticks = 2 };
    const before = service;
    var foreign = request;
    foreign.owner = holder;
    try std.testing.expectError(error.SecretOwnerMismatch, service.retireSecret(&policies, subjects, foreign, null));
    _ = try policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 942 }, .label = "deny retirement", .secret_vault_allowed = false }, .{ .label = "policy", .seed = @splat(0xa1) });
    try std.testing.expectError(error.PolicyDenied, service.retireSecret(&policies, subjects, request, null));
    policies = .init();
    var checkpoint = storage_service.CheckpointStore{};
    var storage = storage_service.Service.initWithStore(943, 944, owner, &checkpoint);
    var ledger = event_ledger.Ledger.init();
    ledger.storage = &storage;
    ledger.workspace_id = 99;
    try std.testing.expectError(error.WorkspaceNotFound, service.retireSecret(&policies, subjects, request, &ledger));
    try std.testing.expectEqualDeep(before, service);
    try service.retireSecret(&policies, subjects, request, null);
    try std.testing.expectEqual(@as(usize, 1), service.activeHandleCount());
    try std.testing.expectEqual(@as(usize, 1), service.handles.countInUse());
    try std.testing.expectEqual(@as(usize, 1), service.store.handles.countInUse());
    try std.testing.expect(service.findHandleConst(first_handle.id) == null);
    try std.testing.expect(service.store.describeHandle(first_handle.store_handle_id) == null);
    var out: secure_secret_store.Value = undefined;
    defer std.crypto.secureZero(u8, &out);
    try std.testing.expectEqualStrings("kept", try service.exportRaw(&policies, subjects, .{ .holder = holder, .task_id = 30, .handle_id = sibling_handle.id, .now_ticks = 3 }, null, &out));
    const replacement = try service.store.importSecret(owner, "replacement", "new", false, true);
    try std.testing.expectEqual(@as(u64, 17), replacement.id);
    _ = try service.lendHandle(&policies, subjects, .{ .owner = owner, .holder = holder, .task_id = 30, .secret_id = replacement.id, .expires_at_ticks = 100, .now_ticks = 3 }, null);
    try std.testing.expectError(error.VaultHandleNotFound, service.exportRaw(&policies, subjects, .{ .holder = holder, .task_id = 30, .handle_id = first_handle.id, .now_ticks = 3 }, null, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
}

test "secret vault failed imports preserve reusable identities and existing leases" {
    for ([_]bool{ false, true }) |hardware| for ([_]bool{ false, true }) |reuse| {
        var failure: FailedAudit = undefined;
        failure.init();
        var service = Service.init();
        service.attachHardwareProvider(testHardwareProvider());
        const policies = policy_object.Directory.init();
        const owner = principal.PrincipalId{ .kind = .user, .serial = 950 };
        const holder = principal.PrincipalId{ .kind = .service, .serial = 951 };
        const kept = (try service.store.importSecret(owner, "kept", "existing", false, true)).id;
        _ = try service.lendHandle(&policies, .{}, .{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = kept, .expires_at_ticks = 100, .now_ticks = 1 }, null);
        if (reuse) {
            const temporary = (try service.store.importSecret(owner, "temporary", "old", false, true)).id;
            try service.retireSecret(&policies, .{}, .{ .owner = owner, .task_id = 1, .secret_id = temporary, .now_ticks = 2 }, null);
        }
        const request = ImportRequest{ .owner = owner, .task_id = 1, .label = "replacement", .raw = "private replacement", .hardware_backed = hardware, .exportable = true, .now_ticks = 3 };
        const before = service;
        for (0..secure_secret_store.MAX_SECRETS + 1) |_| {
            try std.testing.expectError(error.WorkspaceNotFound, service.importSecret(&policies, .{}, request, &failure.ledger));
            try std.testing.expectEqualDeep(before, service);
        }
        const imported = try service.importSecret(&policies, .{}, request, null);
        try std.testing.expectEqual(@as(u64, if (reuse) 18 else 2), imported.id);
    };
}

test "secret vault failed rotation leaves old and unrelated authority unchanged" {
    for (0..6) |mode| {
        var failure: FailedAudit = undefined;
        failure.init();
        var service = Service.init();
        var policies = policy_object.Directory.init();
        const owner = principal.PrincipalId{ .kind = .user, .serial = 950 };
        const holder = principal.PrincipalId{ .kind = .service, .serial = 951 };
        const old = (try service.store.importSecret(owner, "old", "old private", false, true)).id;
        const sibling = (try service.store.importSecret(owner, "sibling", "sibling private", false, true)).id;
        var handles: [3]VaultHandle = undefined;
        for (&handles, 0..) |*handle, i| handle.* = (try service.lendHandle(&policies, .{}, .{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = if (i == 2) sibling else old, .expires_at_ticks = 100, .now_ticks = 1, .allow_raw_export = true }, null)).*;
        var request = RotateRequest{ .owner = owner, .task_id = 1, .old_secret_id = old, .label = "replacement", .raw = "new private", .hardware_backed = false, .exportable = true, .now_ticks = 2 };
        const oversized = @as([secure_secret_store.MAX_VALUE_BYTES + 1]u8, @splat(0x51));
        const long_label = @as([secure_secret_store.MAX_LABEL_BYTES + 1]u8, @splat('x'));
        switch (mode) {
            0 => {}, // Audit failure after preparing a valid replacement.
            1 => request.raw = &oversized,
            2 => request.label = &long_label,
            3 => request.hardware_backed = true, // No provider attached.
            4 => for (2..secure_secret_store.MAX_SECRETS) |_| {
                _ = try service.store.importSecret(owner, "filler", "private", false, true);
            },
            5 => {
                _ = try policies.create(.{ .scope = .user, .subject_id = owner.serial, .issuer = .{ .kind = .policy_authority, .serial = 3 }, .label = "deny vault", .secret_vault_allowed = false }, .{ .label = "policy", .seed = @splat(0x61) });
            },
            else => unreachable,
        }
        const before = service;
        const expected = [_]Error{ error.WorkspaceNotFound, error.SecretTooLarge, error.LabelTooLong, error.HardwareProviderUnavailable, error.SecretTableFull, error.PolicyDenied };
        try std.testing.expectError(expected[mode], service.rotateSecret(&policies, .{ .user_id = owner.serial }, request, if (mode == 0) &failure.ledger else null));
        try std.testing.expectEqualDeep(before, service);
        if (mode == 0) {
            const replacement = try service.rotateSecret(&policies, .{}, request, null);
            try std.testing.expectEqual(@as(u64, 3), replacement.id);
            for (handles[0..2]) |handle| try std.testing.expect(service.findHandleConst(handle.id).?.revoked);
            var out: secure_secret_store.Value = undefined;
            defer std.crypto.secureZero(u8, &out);
            try std.testing.expectEqualStrings("sibling private", try service.exportRaw(&policies, .{}, .{ .holder = holder, .task_id = 1, .handle_id = handles[2].id, .now_ticks = 3 }, null, &out));
        }
    }
}

test "secret vault failed lending preserves free recycled revoked and expired slots" {
    for (0..4) |mode| {
        var failure: FailedAudit = undefined;
        failure.init();
        var service = Service.init();
        const policies = policy_object.Directory.init();
        const owner = principal.PrincipalId{ .kind = .user, .serial = 950 };
        const holder = principal.PrincipalId{ .kind = .service, .serial = 951 };
        const secret = (try service.store.importSecret(owner, "private", "value", false, true)).id;
        const request = LendRequest{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = secret, .expires_at_ticks = 100, .now_ticks = 3, .allow_raw_export = true };
        var old: VaultHandle = undefined;
        if (mode == 1) {
            const temporary = (try service.store.importSecret(owner, "temporary", "old", false, true)).id;
            var temporary_request = request;
            temporary_request.secret_id = temporary;
            old = (try service.lendHandle(&policies, .{}, temporary_request, null)).*;
            try service.retireSecret(&policies, .{}, .{ .owner = owner, .task_id = 1, .secret_id = temporary, .now_ticks = 3 }, null);
        } else if (mode >= 2) {
            for (0..MAX_HANDLES) |i| {
                var fill = request;
                fill.now_ticks = 1;
                if (mode == 3 and i == 0) fill.expires_at_ticks = 2;
                const handle = try service.lendHandle(&policies, .{}, fill, null);
                if (i == 0) old = handle.*;
            }
            if (mode == 2) try service.revoke(.{ .subject = owner, .task_id = 1, .handle_id = old.id, .secret_id = secret, .expected_holder = holder, .expected_holder_task_id = 1, .now_ticks = 2 }, null);
        }
        const before = service;
        for (0..MAX_HANDLES + 1) |_| {
            try std.testing.expectError(error.WorkspaceNotFound, service.lendHandle(&policies, .{}, request, &failure.ledger));
            try std.testing.expectEqualDeep(before, service);
        }
        const handle = try service.lendHandle(&policies, .{}, request, null);
        try std.testing.expectEqual(@as(usize, if (mode >= 2) MAX_HANDLES else 1), service.activeHandleCount());
        if (mode != 0) {
            try std.testing.expect(handle.id != old.id and handle.store_handle_id != old.store_handle_id);
            try std.testing.expect(service.findHandleConst(old.id) == null);
            try std.testing.expect(service.store.describeHandle(old.store_handle_id) == null);
        }
    }
}

test "secret vault failed audit leaves single and whole secret revocation unapplied" {
    for ([_]bool{ false, true }) |whole| {
        var failure: FailedAudit = undefined;
        failure.init();
        var service = Service.init();
        const policies = policy_object.Directory.init();
        const owner = principal.PrincipalId{ .kind = .user, .serial = 950 };
        const holder = principal.PrincipalId{ .kind = .service, .serial = 951 };
        const secret = (try service.store.importSecret(owner, "private", "value", false, true)).id;
        var handles: [2]VaultHandle = undefined;
        for (&handles) |*handle| handle.* = (try service.lendHandle(&policies, .{}, .{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = secret, .expires_at_ticks = 100, .now_ticks = 1 }, null)).*;
        const request = RevokeRequest{ .subject = owner, .task_id = 1, .handle_id = if (whole) 0 else handles[0].id, .secret_id = secret, .expected_holder = holder, .expected_holder_task_id = 1, .now_ticks = 2 };
        const before = service;
        try std.testing.expectError(error.WorkspaceNotFound, service.revoke(request, &failure.ledger));
        try std.testing.expectEqualDeep(before, service);
        try service.revoke(request, null);
        try std.testing.expect(service.findHandleConst(handles[0].id).?.revoked);
        try std.testing.expectEqual(whole, service.findHandleConst(handles[1].id).?.revoked);
        try std.testing.expectEqual(@as(usize, if (whole) 0 else 1), service.activeHandleCount());
    }
}

test "secret vault failed generation restores a retired slot without consuming its identity" {
    var failure: FailedAudit = undefined;
    failure.init();
    var service = Service.init();
    var generator = @import("../../tests/fixtures/secret_provider.zig").KeyGenerator{};
    service.attachHardwareProvider(generator.provider());
    const policies = policy_object.Directory.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 950 };
    _ = try service.store.importSecret(owner, "kept", "existing", false, true);
    const retired = (try service.store.importSecret(owner, "retired", "old", false, true)).id;
    try service.store.retireSecret(retired);
    const request = GenerateSigningKeyRequest{ .owner = owner, .task_id = 1, .label = "signer", .now_ticks = 3 };
    const before = service;
    try std.testing.expectError(error.WorkspaceNotFound, service.generateSigningKey(&policies, .{}, request, &failure.ledger));
    try std.testing.expectEqualDeep(before, service);
    const key = try service.generateSigningKey(&policies, .{}, request, null);
    try std.testing.expectEqual(@as(u64, 18), key.id);
    try std.testing.expect(!key.exportable and key.hardware_provider_used and !key.resident_material);
}

test "secret vault lending preflights lower capacity before accepting an audit" {
    var ledger = event_ledger.Ledger.init();
    var service = Service.init();
    const policies = policy_object.Directory.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 950 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 951 };
    const secret = (try service.store.importSecret(owner, "private", "value", false, true)).id;
    for (0..MAX_HANDLES) |_| _ = try service.store.lendHandle(secret, holder, 1, true);
    const before = service;
    try std.testing.expectError(error.HandleTableFull, service.lendHandle(&policies, .{}, .{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = secret, .expires_at_ticks = 100, .now_ticks = 3 }, &ledger));
    try std.testing.expectEqualDeep(before, service);
    try std.testing.expect(!ledger.latestKind(.secret_vault).?.allowed);
}

test "secret vault audit failure withholds exported bytes and signatures" {
    var failure: FailedAudit = undefined;
    failure.init();
    var service = Service.init();
    service.attachHardwareProvider(testHardwareProvider());
    const policies = policy_object.Directory.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 950 };
    const holder = principal.PrincipalId{ .kind = .service, .serial = 951 };
    const seed = @as([32]u8, @splat(0x53));
    const exportable = (try service.store.importSecret(owner, "exportable", "private", true, true)).id;
    const signer = (try service.store.importSecret(owner, "signer", &seed, true, false)).id;
    const export_handle = (try service.lendHandle(&policies, .{}, .{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = exportable, .expires_at_ticks = 100, .now_ticks = 1, .allow_raw_export = true }, null)).*;
    const signing_handle = (try service.lendHandle(&policies, .{}, .{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = signer, .expires_at_ticks = 100, .now_ticks = 1 }, null)).*;
    const before = service;
    var out: secure_secret_store.Value = @splat(0x55);
    defer std.crypto.secureZero(u8, &out);
    try std.testing.expectError(error.WorkspaceNotFound, service.exportRaw(&policies, .{}, .{ .holder = holder, .task_id = 1, .handle_id = export_handle.id, .now_ticks = 3 }, &failure.ledger, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
    try std.testing.expectError(error.WorkspaceNotFound, service.signMessage(&policies, .{}, .{ .holder = holder, .task_id = 1, .handle_id = signing_handle.id, .now_ticks = 3 }, "message", &failure.ledger));
    try std.testing.expectEqualDeep(before, service);
    const signed = try service.signMessage(&policies, .{}, .{ .holder = holder, .task_id = 1, .handle_id = signing_handle.id, .now_ticks = 3 }, "message", null);
    try std.testing.expect(@import("../core/signing.zig").verify(signed, "message"));
}

test "secret vault exhaustion skips terminal leases that either arena cannot replace" {
    for ([_]bool{ false, true }) |lower| {
        var service = Service.init();
        const policies = policy_object.Directory.init();
        const owner = principal.PrincipalId{ .kind = .user, .serial = 970 };
        const holder = principal.PrincipalId{ .kind = .service, .serial = 971 };
        const secret = (try service.store.importSecret(owner, "private", "value", false, true)).id;
        if (lower) service.store.handles.slot_generations[0] = indexed_arena.MAX_HANDLE_GENERATION else service.handles.slot_generations[0] = indexed_arena.MAX_HANDLE_GENERATION;
        const request = LendRequest{ .owner = owner, .holder = holder, .task_id = 1, .secret_id = secret, .expires_at_ticks = 100, .now_ticks = 1 };
        const first = (try service.lendHandle(&policies, .{}, request, null)).*;
        for (1..MAX_HANDLES) |_| _ = try service.lendHandle(&policies, .{}, request, null);
        try service.revoke(.{ .subject = owner, .task_id = 1, .secret_id = secret, .now_ticks = 2 }, null);
        const next = try service.lendHandle(&policies, .{}, request, null);
        try std.testing.expectEqual(@as(usize, 1), (HandleId{ .value = next.id }).slotIndex());
        try std.testing.expect(service.findHandleConst(first.id).?.revoked);
        try service.retireSecret(&policies, .{}, .{ .owner = owner, .task_id = 1, .secret_id = secret, .now_ticks = 2 }, null);
        // A retired arena slot remains unavailable even when all leases are gone.
        @memset(&service.handles.slot_generations, indexed_arena.EXHAUSTED_HANDLE_GENERATION);
        const another = (try service.store.importSecret(owner, "another", "new", false, true)).id;
        var exhausted_request = request;
        exhausted_request.secret_id = another;
        const before = service;
        try std.testing.expectError(error.HandleTableFull, service.lendHandle(&policies, .{}, exhausted_request, null));
        try std.testing.expectEqualDeep(before, service);
    }
}

const FailedAudit = if (@import("builtin").is_test) struct {
    const storage_service = @import("../storage/storage_service.zig");
    checkpoint: storage_service.CheckpointStore,
    storage: storage_service.Service,
    ledger: event_ledger.Ledger,

    fn init(self: *@This()) void {
        self.checkpoint = .{};
        self.storage = storage_service.Service.initWithStore(952, 953, .{ .kind = .user, .serial = 950 }, &self.checkpoint);
        self.ledger = .init();
        self.ledger.storage = &self.storage;
        self.ledger.workspace_id = 99; // Missing workspace exercises audit persistence failure.
    }
} else void;
