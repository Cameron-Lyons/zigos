const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const sealing = @import("secret_sealing.zig");
const manifest = @import("../policy/manifest.zig");

pub const MAX_SECRETS: usize = 16;
pub const MAX_HANDLES: usize = 32;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_VALUE_BYTES: usize = sealing.MAX_VALUE_BYTES;
pub const Value = sealing.Value;
pub const SealedBlob = sealing.Blob;
pub const RawValue = struct { len: u8 = 0, bytes: Value = @splat(0) };
pub const DIRECT_SECRET_LOOKUP = true;
pub const DENSE_SECRET_TABLE = true;
pub const COMPACT_SECRET_METADATA = true;
pub const IMPORTS_INTO_PREZEROED_SECRET_SLOTS = true;
pub const DIRECT_HANDLE_LOOKUP = true;
pub const OVERWRITES_RESERVED_HANDLE_SLOTS = true;
pub const STORE_SIZE_CEILING_BYTES: usize = 14_800;

pub const SecretRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    hardware_backed: bool,
    hardware_provider_used: bool,
    exportable: bool,
    resident_material: bool,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    sealed_digest_present: bool,
    sealed_digest: crypto_hash.Digest,
    material: union(enum) {
        raw: RawValue,
        sealed: SealedBlob,
    },

    pub fn sealedBlob(self: *const SecretRecord) ?[]const u8 {
        return switch (self.material) {
            .sealed => |*blob| blob.slice(),
            .raw => null,
        };
    }

    pub fn labelSlice(self: *const SecretRecord) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }
};

pub const SecretHandle = struct {
    id: u64,
    secret_id: u64,
    holder: principal.PrincipalId,
    task_id: u64,
    hardware_backed: bool,
    export_allowed: bool,
};

pub const ExportContext = struct {
    holder: principal.PrincipalId,
    task_id: u64,
};

pub const HardwareSealProvider = sealing.Provider;

pub const Error = sealing.Error || error{
    HandleHolderMismatch,
    HandleNotFound,
    HandleTableFull,
    LabelTooLong,
    RawExportDenied,
    SecretNotFound,
    SecretTableFull,
    InvalidSigningKey,
};

const HandleSlot = struct {
    in_use: bool = false,
    handle: SecretHandle = .{
        .id = 0,
        .secret_id = 0,
        .holder = .{ .kind = .service, .serial = 0 },
        .task_id = 0,
        .hardware_backed = false,
        .export_allowed = false,
    },
};

pub const HandleId = indexed_arena.GenerationalHandle("SecureSecretStoreHandle");
const HandleArena = indexed_arena.GenerationalArena("SecureSecretStoreHandle", HandleSlot, MAX_HANDLES);

pub const Store = struct {
    hardware_provider: HardwareSealProvider = .{},
    secrets: [MAX_SECRETS]SecretRecord = [_]SecretRecord{zeroSecret()} ** MAX_SECRETS,
    secret_count: u8 = 0,
    handles: HandleArena = HandleArena.init(),

    comptime {
        if (MAX_SECRETS > std.math.maxInt(u8)) {
            @compileError("secret count no longer fits compact storage");
        }
        if (MAX_LABEL_BYTES > std.math.maxInt(u8) or MAX_VALUE_BYTES > std.math.maxInt(u8)) {
            @compileError("secret content no longer fits compact length metadata");
        }
        if (@sizeOf(@This()) > STORE_SIZE_CEILING_BYTES) {
            @compileError("secure secret store exceeds its fixed-state size ceiling");
        }
    }

    pub fn init() Store {
        return .{};
    }

    pub fn attachHardwareProvider(self: *Store, provider: HardwareSealProvider) void {
        self.hardware_provider = provider;
    }

    pub fn importSecret(
        self: *Store,
        owner: principal.PrincipalId,
        label: []const u8,
        raw: []const u8,
        hardware_backed: bool,
        exportable: bool,
    ) Error!*SecretRecord {
        if (raw.len > MAX_VALUE_BYTES) return error.SecretTooLarge;
        if (label.len > MAX_LABEL_BYTES) return error.LabelTooLong;
        const slot_index = self.countSecrets();
        if (slot_index >= MAX_SECRETS) return error.SecretTableFull;
        const secret_id: u64 = @intCast(slot_index + 1);
        var blob = SealedBlob{};
        if (hardware_backed) {
            const binding = materialBinding(owner, label, exportable);
            try self.hardware_provider.seal(&binding, raw, &blob);
        }
        const secret = &self.secrets[slot_index];
        if (secret.id != 0) native_util.impossibleByInvariant("dense secret imports append into pre-zeroed slots");
        secret.id = secret_id;
        secret.owner = owner;
        secret.hardware_backed = hardware_backed;
        secret.hardware_provider_used = hardware_backed;
        secret.exportable = exportable;
        secret.resident_material = !hardware_backed;
        secret.label_len = @intCast(native_util.copyTextExact(&secret.label, label) catch unreachable);
        if (hardware_backed) {
            secret.sealed_digest_present = true;
            std.crypto.hash.sha2.Sha256.hash(blob.slice(), &secret.sealed_digest, .{});
            secret.material = .{ .sealed = blob };
        } else {
            secret.material = .{ .raw = .{ .len = @intCast(raw.len) } };
            @memcpy(secret.material.raw.bytes[0..raw.len], raw);
        }

        self.secret_count += 1;
        return secret;
    }

    pub fn lendHandle(
        self: *Store,
        secret_id: u64,
        holder: principal.PrincipalId,
        task_id: u64,
        allow_raw_export: bool,
    ) Error!SecretHandle {
        const secret = self.findSecret(secret_id) orelse return error.SecretNotFound;
        if (self.handles.countInUse() >= MAX_HANDLES) return error.HandleTableFull;
        return self.installHandle(null, secret, holder, task_id, allow_raw_export);
    }

    pub fn replaceHandle(
        self: *Store,
        retired_handle_id: u64,
        secret_id: u64,
        holder: principal.PrincipalId,
        task_id: u64,
        allow_raw_export: bool,
    ) Error!SecretHandle {
        const secret = self.findSecret(secret_id) orelse return error.SecretNotFound;
        const retired_handle = HandleId{ .value = retired_handle_id };
        if (self.handles.getConstByHandle(retired_handle) == null) return error.HandleNotFound;
        return self.installHandle(retired_handle, secret, holder, task_id, allow_raw_export);
    }

    fn installHandle(
        self: *Store,
        retired_handle: ?HandleId,
        secret: *const SecretRecord,
        holder: principal.PrincipalId,
        task_id: u64,
        allow_raw_export: bool,
    ) Error!SecretHandle {
        const handle_id = if (retired_handle) |retired|
            self.handles.replaceHandle(retired) orelse
                native_util.impossibleByInvariant("secure store replacement keeps its retired handle live")
        else
            self.handles.reserveHandleForOverwrite() orelse return error.HandleTableFull;
        const handle = SecretHandle{
            .id = handle_id.value,
            .secret_id = secret.id,
            .holder = holder,
            .task_id = task_id,
            .hardware_backed = secret.hardware_backed,
            .export_allowed = allow_raw_export and secret.exportable,
        };
        const slot = self.handles.getByHandle(handle_id) orelse
            native_util.impossibleByInvariant("secure store reserved handle resolves directly");
        slot.* = .{
            .in_use = true,
            .handle = handle,
        };
        return handle;
    }

    pub fn describeHandle(self: *const Store, handle_id: u64) ?SecretHandle {
        const slot = self.handles.getConstByHandle(.{ .value = handle_id }) orelse return null;
        return slot.handle;
    }

    pub fn describeSecret(self: *const Store, secret_id: u64) ?*const SecretRecord {
        return self.findSecretConst(secret_id);
    }

    // Restore only after authenticating the encrypted record against its supplied
    // metadata. Restoring records never restores handles or their authority.
    pub fn restoreSealed(self: *Store, owner: principal.PrincipalId, label: []const u8, blob: []const u8, exportable: bool) Error!*SecretRecord {
        if (label.len > MAX_LABEL_BYTES) return error.LabelTooLong;
        if (self.countSecrets() >= MAX_SECRETS) return error.SecretTableFull;
        const binding = materialBinding(owner, label, exportable);
        var scratch: Value = undefined;
        defer std.crypto.secureZero(u8, &scratch);
        _ = try self.hardware_provider.open(&binding, blob, &scratch);
        const secret = &self.secrets[self.countSecrets()];
        secret.id = @intCast(self.countSecrets() + 1);
        secret.owner = owner;
        secret.hardware_backed = true;
        secret.hardware_provider_used = true;
        secret.exportable = exportable;
        secret.resident_material = false;
        secret.label_len = @intCast(native_util.copyTextExact(&secret.label, label) catch unreachable);
        secret.sealed_digest_present = true;
        std.crypto.hash.sha2.Sha256.hash(blob, &secret.sealed_digest, .{});
        secret.material = .{ .sealed = .{} };
        @memcpy(secret.material.sealed.bytes[0..blob.len], blob);
        secret.material.sealed.len = @intCast(blob.len);
        self.secret_count += 1;
        return secret;
    }

    pub fn exportRaw(self: *const Store, handle_id: u64, context: ExportContext, out: *Value) Error![]const u8 {
        std.crypto.secureZero(u8, out);
        errdefer std.crypto.secureZero(u8, out);
        const handle = self.describeHandle(handle_id) orelse return error.HandleNotFound;
        if (!handle.holder.eql(context.holder) or handle.task_id != context.task_id) return error.HandleHolderMismatch;
        if (!handle.export_allowed) return error.RawExportDenied;
        const secret = self.findSecretConst(handle.secret_id) orelse return error.SecretNotFound;
        const len = try self.openMaterial(secret, out);
        return out[0..len];
    }

    // Signing does not grant raw export. Only the fixed-size caller digest enters
    // Ed25519; the recovered seed and expanded key pair expire with this call.
    pub fn signDigest(self: *const Store, handle_id: u64, context: ExportContext, digest: *const sealing.Binding) Error!manifest.Signature {
        const handle = self.describeHandle(handle_id) orelse return error.HandleNotFound;
        if (!handle.holder.eql(context.holder) or handle.task_id != context.task_id) return error.HandleHolderMismatch;
        const secret = self.findSecretConst(handle.secret_id) orelse return error.SecretNotFound;
        var raw: Value = undefined;
        defer std.crypto.secureZero(u8, &raw);
        const len = try self.openMaterial(secret, &raw);
        if (len != 32) return error.InvalidSigningKey;
        const Ed25519 = std.crypto.sign.Ed25519;
        var pair = Ed25519.KeyPair.generateDeterministic(raw[0..32].*) catch return error.InvalidSigningKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        const signature = pair.sign(digest, null) catch return error.InvalidSigningKey;
        var result = manifest.Signature{ .signer = secret.labelSlice(), .public_key_len = 32, .value_len = 64 };
        result.public_key[0..32].* = pair.public_key.toBytes();
        result.value[0..64].* = signature.toBytes();
        return result;
    }

    fn openMaterial(self: *const Store, secret: *const SecretRecord, out: *Value) Error!usize {
        std.crypto.secureZero(u8, out);
        return switch (secret.material) {
            .raw => |*value| blk: {
                @memcpy(out[0..value.len], value.bytes[0..value.len]);
                break :blk value.len;
            },
            .sealed => |*blob| blk: {
                const binding = materialBinding(secret.owner, secret.labelSlice(), secret.exportable);
                break :blk try self.hardware_provider.open(&binding, blob.slice(), out);
            },
        };
    }

    fn findSecret(self: *Store, secret_id: u64) ?*SecretRecord {
        const slot_index = self.secretSlotIndex(secret_id) orelse return null;
        return &self.secrets[slot_index];
    }

    fn findSecretConst(self: *const Store, secret_id: u64) ?*const SecretRecord {
        const slot_index = self.secretSlotIndex(secret_id) orelse return null;
        return &self.secrets[slot_index];
    }

    fn countSecrets(self: *const Store) usize {
        return @intCast(self.secret_count);
    }

    fn secretSlotIndex(self: *const Store, secret_id: u64) ?usize {
        if (secret_id == 0 or secret_id > self.countSecrets()) return null;
        const slot_index: usize = @intCast(secret_id - 1);
        return if (self.secrets[slot_index].id == secret_id) slot_index else null;
    }
};

fn zeroSecret() SecretRecord {
    return .{
        .id = 0,
        .owner = .{ .kind = .service, .serial = 0 },
        .hardware_backed = false,
        .hardware_provider_used = false,
        .exportable = false,
        .resident_material = false,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .sealed_digest_present = false,
        .sealed_digest = crypto_hash.zero_digest,
        .material = .{ .raw = .{} },
    };
}

fn materialBinding(owner: principal.PrincipalId, label: []const u8, exportable: bool) sealing.Binding {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "zigos-sealed-secret-v1-owner", &owner.keyBytes());
    crypto_hash.updateBytes(&hasher, "label", label);
    crypto_hash.updateBool(&hasher, "exportable", exportable);
    return crypto_hash.finalize(&hasher);
}

test "secret imports preserve zeroed inactive storage" {
    var secret_export_buffer: Value = undefined;
    defer std.crypto.secureZero(u8, &secret_export_buffer);
    try std.testing.expect(IMPORTS_INTO_PREZEROED_SECRET_SLOTS);
    try std.testing.expect(OVERWRITES_RESERVED_HANDLE_SLOTS);

    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 9 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 10 };
    const secret = try store.importSecret(owner, "key", "value", false, true);

    try std.testing.expectEqual(@as(u64, 1), secret.id);
    try std.testing.expectEqualStrings("key", secret.labelSlice());
    try std.testing.expectEqualStrings("value", secret.material.raw.bytes[0..secret.material.raw.len]);
    for (secret.label[@as(usize, secret.label_len)..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (secret.material.raw.bytes[secret.material.raw.len..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    for (secret.sealed_digest) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    const handle = try store.lendHandle(secret.id, holder, 44, true);
    try std.testing.expectEqual(handle, store.describeHandle(handle.id).?);
    try std.testing.expectEqualStrings("value", try store.exportRaw(handle.id, .{
        .holder = holder,
        .task_id = 44,
    }, &secret_export_buffer));
}

test "secure secret store requires a hardware provider before hardware-backed imports" {
    var secret_export_buffer: Value = undefined;
    defer std.crypto.secureZero(u8, &secret_export_buffer);
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const app_holder = principal.PrincipalId{ .kind = .app, .serial = 44 };

    try std.testing.expectError(error.HardwareProviderUnavailable, store.importSecret(owner, "api-key", "super-secret-token", true, false));
    store.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());

    const api_key = try store.importSecret(owner, "api-key", "super-secret-token", true, false);
    const handle = try store.lendHandle(api_key.id, app_holder, 90, true);
    try std.testing.expect(handle.hardware_backed);
    try std.testing.expect(!handle.export_allowed);
    try std.testing.expect(!api_key.resident_material);
    try std.testing.expect(api_key.sealed_digest_present);
    try std.testing.expect(api_key.hardware_provider_used);
    try std.testing.expect(api_key.sealedBlob() != null);
    try std.testing.expectError(error.RawExportDenied, store.exportRaw(handle.id, .{
        .holder = app_holder,
        .task_id = 90,
    }, &secret_export_buffer));

    const exportable = try store.importSecret(owner, "backup-code", "abcd-efgh", false, true);
    const export_handle = try store.lendHandle(exportable.id, app_holder, 91, true);
    try std.testing.expectError(error.HandleHolderMismatch, store.exportRaw(export_handle.id, .{
        .holder = owner,
        .task_id = 91,
    }, &secret_export_buffer));
    try std.testing.expectError(error.HandleHolderMismatch, store.exportRaw(export_handle.id, .{
        .holder = app_holder,
        .task_id = 92,
    }, &secret_export_buffer));
    try std.testing.expectEqualStrings("abcd-efgh", try store.exportRaw(export_handle.id, .{
        .holder = app_holder,
        .task_id = 91,
    }, &secret_export_buffer));
}

test "secure secret store uses hardware seal provider for sealed and exportable hardware-backed imports" {
    var store = Store.init();
    store.attachHardwareProvider(@import("../../tests/fixtures/secret_provider.zig").provider());

    const owner = principal.PrincipalId{ .kind = .user, .serial = 3 };
    const sealed = try store.importSecret(owner, "device-key", "private-material", true, false);
    try std.testing.expect(sealed.hardware_backed);
    try std.testing.expect(sealed.hardware_provider_used);
    try std.testing.expect(sealed.sealed_digest_present);
    var expected: crypto_hash.Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(sealed.sealedBlob().?, &expected, .{});
    try std.testing.expectEqualSlices(u8, expected[0..], sealed.sealed_digest[0..]);
    try std.testing.expect(sealed.sealedBlob() != null);

    const exportable = try store.importSecret(owner, "portable-key", "exportable-material", true, true);
    try std.testing.expect(exportable.hardware_backed);
    try std.testing.expect(exportable.hardware_provider_used);
    try std.testing.expect(exportable.sealed_digest_present);
    try std.testing.expect(!exportable.resident_material);
    try std.testing.expect(exportable.sealedBlob() != null);
}

test "secure secret store reports missing handles and oversized secrets" {
    var secret_export_buffer: Value = undefined;
    defer std.crypto.secureZero(u8, &secret_export_buffer);
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 2 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 45 };
    const oversized = [_]u8{'x'} ** (MAX_VALUE_BYTES + 1);

    try std.testing.expectError(error.SecretTooLarge, store.importSecret(owner, "too-large", &oversized, true, false));
    try std.testing.expectError(error.SecretNotFound, store.lendHandle(999, holder, 1, false));
    try std.testing.expectError(error.HandleNotFound, store.exportRaw(999, .{
        .holder = holder,
        .task_id = 1,
    }, &secret_export_buffer));
}

test "secure secret store uses direct dense ids and bounds handle capacity" {
    const owner = principal.PrincipalId{ .kind = .user, .serial = 4 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 46 };

    var full_secrets = Store.init();
    var label_buffer: [MAX_LABEL_BYTES]u8 = undefined;
    for (0..MAX_SECRETS) |index| {
        const label = try std.fmt.bufPrint(&label_buffer, "full-secret-{d}", .{index});
        const secret = try full_secrets.importSecret(owner, label, "private full secret", false, true);
        try std.testing.expectEqual(@as(u64, @intCast(index + 1)), secret.id);
    }
    try std.testing.expect(full_secrets.describeSecret(0) == null);
    try std.testing.expect(full_secrets.describeSecret(MAX_SECRETS + 1) == null);
    try std.testing.expectError(error.SecretTableFull, full_secrets.importSecret(
        owner,
        "full-secret",
        "private full secret",
        true,
        false,
    ));
    try std.testing.expectEqual(MAX_SECRETS, full_secrets.countSecrets());

    var full_handles = Store.init();
    const full_handle_secret = try full_handles.importSecret(owner, "full-handle", "private full handle", false, true);
    for (0..MAX_HANDLES) |index| {
        const handle = try full_handles.lendHandle(full_handle_secret.id, holder, @intCast(100 + index), true);
        try std.testing.expectEqual(index, (HandleId{ .value = handle.id }).slotIndex());
        try std.testing.expectEqual(@as(u32, 1), (HandleId{ .value = handle.id }).generation());
    }
    try std.testing.expectError(error.HandleTableFull, full_handles.lendHandle(full_handle_secret.id, holder, 94, true));
    try std.testing.expect(full_handles.describeHandle(0) == null);
    try std.testing.expect(full_handles.describeHandle(HandleId.fromParts(MAX_HANDLES, 1).value) == null);
}

test "secure secret store replaces one handle with a direct generation" {
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 6 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 48 };
    const secret = try store.importSecret(owner, "replaceable", "replaceable material", false, true);
    store.handles.slot_generations[0] = std.math.maxInt(u32);
    const retired = try store.lendHandle(secret.id, holder, 95, true);
    const retired_id = HandleId{ .value = retired.id };
    try std.testing.expectEqual(@as(usize, 0), retired_id.slotIndex());
    try std.testing.expectEqual(std.math.maxInt(u32), retired_id.generation());

    try std.testing.expectError(error.HandleNotFound, store.replaceHandle(999, secret.id, holder, 96, true));
    try std.testing.expect(store.describeHandle(retired.id) != null);

    const replacement = try store.replaceHandle(retired.id, secret.id, holder, 96, true);
    const replacement_id = HandleId{ .value = replacement.id };
    try std.testing.expectEqual(retired_id.slotIndex(), replacement_id.slotIndex());
    try std.testing.expectEqual(@as(u32, 1), replacement_id.generation());
    try std.testing.expect(!retired_id.eql(replacement_id));
    try std.testing.expect(store.describeHandle(retired.id) == null);
    try std.testing.expectEqual(@as(u64, 96), store.describeHandle(replacement.id).?.task_id);
    try std.testing.expectEqual(@as(usize, 1), store.handles.countInUse());
}

test "secure secret store keeps secrets dense and handles direct through full tables" {
    var secret_export_buffer: Value = undefined;
    defer std.crypto.secureZero(u8, &secret_export_buffer);
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 4 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 46 };

    var first_secret_id: u64 = 0;
    var last_secret_id: u64 = 0;
    var index: usize = 0;
    while (index < MAX_SECRETS) : (index += 1) {
        const secret = try store.importSecret(owner, "indexed-secret", "portable material", false, true);
        if (index == 0) first_secret_id = secret.id;
        last_secret_id = secret.id;
    }
    try std.testing.expect(store.describeSecret(first_secret_id) != null);
    try std.testing.expect(store.describeSecret(last_secret_id) != null);
    try std.testing.expect(store.describeSecret(last_secret_id + 1) == null);
    try std.testing.expectError(error.SecretTableFull, store.importSecret(owner, "overflow-secret", "portable material", false, true));
    try std.testing.expect(@sizeOf(Store) <= STORE_SIZE_CEILING_BYTES);

    var first_handle_id: u64 = 0;
    var last_handle_id: u64 = 0;
    index = 0;
    while (index < MAX_HANDLES) : (index += 1) {
        const handle = try store.lendHandle(first_secret_id, holder, 200 + @as(u64, @intCast(index)), true);
        if (index == 0) first_handle_id = handle.id;
        last_handle_id = handle.id;
    }
    try std.testing.expect(store.describeHandle(first_handle_id) != null);
    try std.testing.expect(store.describeHandle(last_handle_id) != null);
    try std.testing.expectEqualStrings("portable material", try store.exportRaw(last_handle_id, .{
        .holder = holder,
        .task_id = 200 + @as(u64, @intCast(MAX_HANDLES - 1)),
    }, &secret_export_buffer));
    try std.testing.expectError(error.HandleTableFull, store.lendHandle(first_secret_id, holder, 999, true));
}

test "sealed secrets recover only under bound metadata and sign without raw export" {
    const fixture = @import("../../tests/fixtures/secret_provider.zig");
    const signing = @import("../core/signing.zig");
    const owner = principal.PrincipalId{ .kind = .user, .serial = 7 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 8 };
    const seed: [32]u8 = @splat(0x91);
    const digest: [32]u8 = @splat(0x19);
    var store = Store.init();
    store.attachHardwareProvider(fixture.provider());
    const secret = try store.importSecret(owner, "signing key", &seed, true, false);
    const blob = secret.material.sealed;
    try std.testing.expect(!secret.resident_material);
    try std.testing.expect(std.mem.indexOf(u8, blob.slice(), &seed) == null);
    const handle = try store.lendHandle(secret.id, holder, 11, true);
    var out: Value = @splat(0xaa);
    try std.testing.expectError(error.RawExportDenied, store.exportRaw(handle.id, .{ .holder = holder, .task_id = 11 }, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
    const signed = try store.signDigest(handle.id, .{ .holder = holder, .task_id = 11 }, &digest);
    try std.testing.expect(signing.verify(signed, &digest));
    try std.testing.expectEqualSlices(u8, &(try signing.publicKey(.{ .label = "key", .seed = seed })), signed.publicKeySlice());
    try std.testing.expectError(error.HandleHolderMismatch, store.signDigest(handle.id, .{ .holder = owner, .task_id = 11 }, &digest));
    try std.testing.expectError(error.HandleHolderMismatch, store.signDigest(handle.id, .{ .holder = holder, .task_id = 12 }, &digest));

    var restored = Store.init();
    restored.attachHardwareProvider(fixture.provider());
    try std.testing.expectError(error.InvalidSealedSecret, restored.restoreSealed(holder, "signing key", blob.slice(), false));
    try std.testing.expectError(error.InvalidSealedSecret, restored.restoreSealed(owner, "other key", blob.slice(), false));
    try std.testing.expectError(error.InvalidSealedSecret, restored.restoreSealed(owner, "signing key", blob.slice(), true));
    var damaged = blob;
    damaged.bytes[damaged.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidSealedSecret, restored.restoreSealed(owner, "signing key", damaged.slice(), false));
    try std.testing.expectEqual(@as(u8, 0), restored.secret_count);
    const recovered = try restored.restoreSealed(owner, "signing key", blob.slice(), false);
    try std.testing.expect(restored.describeHandle(handle.id) == null);
    const recovered_handle = try restored.lendHandle(recovered.id, holder, 12, false);
    const after = try restored.signDigest(recovered_handle.id, .{ .holder = holder, .task_id = 12 }, &digest);
    try std.testing.expectEqualSlices(u8, signed.valueSlice(), after.valueSlice());
    restored.attachHardwareProvider(.{});
    try std.testing.expectError(error.HardwareProviderUnavailable, restored.signDigest(recovered_handle.id, .{ .holder = holder, .task_id = 12 }, &digest));
}

test "failed providers leave no imported record and erase partial or oversized recovery output" {
    const BadProvider = struct {
        fn seal(_: ?*anyopaque, _: *const sealing.Binding, _: []const u8, out: *SealedBlob) sealing.Error!void {
            out.len = 12;
            @memset(out.bytes[0..12], 0xaa);
            return error.HardwareOperationFailed;
        }
        fn open(_: ?*anyopaque, _: *const sealing.Binding, _: []const u8, out: *Value) sealing.Error!usize {
            @memset(out, 0xaa);
            return error.HardwareOperationFailed;
        }
        fn oversized(_: ?*anyopaque, _: *const sealing.Binding, _: []const u8, out: *Value) sealing.Error!usize {
            @memset(out, 0xaa);
            return out.len + 1;
        }
    };
    var store = Store.init();
    store.attachHardwareProvider(.{ .sealFn = BadProvider.seal, .openFn = BadProvider.open });
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    try std.testing.expectError(error.HardwareOperationFailed, store.importSecret(owner, "key", "raw", true, false));
    try std.testing.expectEqual(@as(u8, 0), store.secret_count);
    try std.testing.expect(store.describeSecret(1) == null);
    var blob = SealedBlob{};
    const binding: sealing.Binding = @splat(0);
    try std.testing.expectError(error.HardwareOperationFailed, store.hardware_provider.seal(&binding, "raw", &blob));
    try std.testing.expectEqual(@as(u16, 0), blob.len);
    var out: Value = @splat(0xaa);
    try std.testing.expectError(error.HardwareOperationFailed, store.hardware_provider.open(&binding, "blob", &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
    store.hardware_provider.openFn = BadProvider.oversized;
    out = @splat(0xaa);
    try std.testing.expectError(error.InvalidSealedSecret, store.hardware_provider.open(&binding, "blob", &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0));
}
