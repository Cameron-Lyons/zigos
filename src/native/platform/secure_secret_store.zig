const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const indexed_arena = @import("../core/indexed_arena.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

pub const MAX_SECRETS: usize = 16;
pub const MAX_HANDLES: usize = 32;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_VALUE_BYTES: usize = 96;
pub const BOUNDED_SECRET_LOOKUP = true;
pub const DENSE_SECRET_TABLE = true;
pub const COMPACT_SECRET_METADATA = true;
pub const DIRECT_HANDLE_LOOKUP = true;
pub const SECRET_LOOKUP_COMPARISON_BOUND: usize = 5;
pub const STORE_SIZE_CEILING_BYTES: usize = 5_320;

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
    value_len: u8,
    value: [MAX_VALUE_BYTES]u8,

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

pub const HardwareSealProvider = struct {
    available: bool = false,
    sealFn: *const fn (label: []const u8, raw: []const u8) crypto_hash.Digest = defaultSeal,

    pub fn seal(self: HardwareSealProvider, label: []const u8, raw: []const u8) ?crypto_hash.Digest {
        if (!self.available) return null;
        return self.sealFn(label, raw);
    }
};

pub const Error = error{
    HandleHolderMismatch,
    HandleNotFound,
    HandleTableFull,
    HardwareProviderUnavailable,
    LabelTooLong,
    RawExportDenied,
    SecretIdExhausted,
    SecretNotFound,
    SecretTableFull,
    SecretTooLarge,
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
    next_secret_id: u64 = 1,
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
        if (self.countSecrets() >= MAX_SECRETS) return error.SecretTableFull;
        const secret_id = self.next_secret_id;
        if (secret_id == 0) return error.SecretIdExhausted;
        if (self.findSecretConst(secret_id) != null) return error.SecretIdExhausted;
        const hardware_sealed_digest = if (hardware_backed)
            self.hardware_provider.seal(label, raw) orelse return error.HardwareProviderUnavailable
        else
            crypto_hash.zero_digest;

        var secret = zeroSecret();
        secret.id = secret_id;
        secret.owner = owner;
        secret.hardware_backed = hardware_backed;
        secret.exportable = exportable;
        secret.resident_material = true;
        secret.label_len = @intCast(native_util.copyTextExact(&secret.label, label) catch return error.LabelTooLong);
        if (hardware_backed) {
            secret.hardware_provider_used = true;
            secret.sealed_digest_present = true;
            secret.sealed_digest = hardware_sealed_digest;
        }
        if (hardware_backed and !exportable) {
            secret.resident_material = false;
            secret.value_len = 0;
        } else {
            secret.value_len = @intCast(native_util.copyTextExact(&secret.value, raw) catch return error.SecretTooLarge);
        }

        const slot_index = self.countSecrets();
        const slot = &self.secrets[slot_index];
        slot.* = secret;
        self.secret_count += 1;
        self.next_secret_id +%= 1;
        return slot;
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
            self.handles.reserveHandle() orelse return error.HandleTableFull;
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
        slot.handle = handle;
        return handle;
    }

    pub fn describeHandle(self: *const Store, handle_id: u64) ?SecretHandle {
        const slot = self.handles.getConstByHandle(.{ .value = handle_id }) orelse return null;
        return slot.handle;
    }

    pub fn describeSecret(self: *const Store, secret_id: u64) ?*const SecretRecord {
        return self.findSecretConst(secret_id);
    }

    pub fn exportRaw(self: *const Store, handle_id: u64, context: ExportContext) Error![]const u8 {
        const handle = self.describeHandle(handle_id) orelse return error.HandleNotFound;
        if (!handle.holder.eql(context.holder) or handle.task_id != context.task_id) return error.HandleHolderMismatch;
        if (!handle.export_allowed) return error.RawExportDenied;
        const secret = self.findSecretConst(handle.secret_id) orelse return error.SecretNotFound;
        return secret.value[0..@as(usize, secret.value_len)];
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
        var low: usize = 0;
        var high = self.countSecrets();
        while (low < high) {
            const middle = low + (high - low) / 2;
            const candidate_id = self.secrets[middle].id;
            if (secret_id < candidate_id) {
                high = middle;
            } else if (secret_id > candidate_id) {
                low = middle + 1;
            } else {
                return middle;
            }
        }
        return null;
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
        .value_len = 0,
        .value = [_]u8{0} ** MAX_VALUE_BYTES,
    };
}

fn defaultSeal(label: []const u8, raw: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "hardware-seal-label", label);
    crypto_hash.updateBytes(&hasher, "hardware-seal-material", raw);
    return crypto_hash.finalize(&hasher);
}

test "secure secret store requires a hardware provider before hardware-backed imports" {
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const app_holder = principal.PrincipalId{ .kind = .app, .serial = 44 };

    try std.testing.expectError(error.HardwareProviderUnavailable, store.importSecret(owner, "api-key", "super-secret-token", true, false));
    store.attachHardwareProvider(.{ .available = true });

    const api_key = try store.importSecret(owner, "api-key", "super-secret-token", true, false);
    const handle = try store.lendHandle(api_key.id, app_holder, 90, true);
    try std.testing.expect(handle.hardware_backed);
    try std.testing.expect(!handle.export_allowed);
    try std.testing.expect(!api_key.resident_material);
    try std.testing.expect(api_key.sealed_digest_present);
    try std.testing.expect(api_key.hardware_provider_used);
    try std.testing.expectEqual(@as(usize, 0), api_key.value_len);
    try std.testing.expectError(error.RawExportDenied, store.exportRaw(handle.id, .{
        .holder = app_holder,
        .task_id = 90,
    }));

    const exportable = try store.importSecret(owner, "backup-code", "abcd-efgh", false, true);
    const export_handle = try store.lendHandle(exportable.id, app_holder, 91, true);
    try std.testing.expectError(error.HandleHolderMismatch, store.exportRaw(export_handle.id, .{
        .holder = owner,
        .task_id = 91,
    }));
    try std.testing.expectError(error.HandleHolderMismatch, store.exportRaw(export_handle.id, .{
        .holder = app_holder,
        .task_id = 92,
    }));
    try std.testing.expectEqualStrings("abcd-efgh", try store.exportRaw(export_handle.id, .{
        .holder = app_holder,
        .task_id = 91,
    }));
}

test "secure secret store uses hardware seal provider for sealed and exportable hardware-backed imports" {
    const Provider = struct {
        fn seal(label: []const u8, raw: []const u8) crypto_hash.Digest {
            var hasher = crypto_hash.init();
            crypto_hash.updateBytes(&hasher, "test-hardware", label);
            crypto_hash.updateBytes(&hasher, "sealed", raw);
            return crypto_hash.finalize(&hasher);
        }
    };

    var store = Store.init();
    store.attachHardwareProvider(.{
        .available = true,
        .sealFn = Provider.seal,
    });

    const owner = principal.PrincipalId{ .kind = .user, .serial = 3 };
    const sealed = try store.importSecret(owner, "device-key", "private-material", true, false);
    try std.testing.expect(sealed.hardware_backed);
    try std.testing.expect(sealed.hardware_provider_used);
    try std.testing.expect(sealed.sealed_digest_present);
    const expected = Provider.seal("device-key", "private-material");
    try std.testing.expectEqualSlices(u8, expected[0..], sealed.sealed_digest[0..]);
    try std.testing.expectEqual(@as(usize, 0), sealed.value_len);

    const exportable = try store.importSecret(owner, "portable-key", "exportable-material", true, true);
    try std.testing.expect(exportable.hardware_backed);
    try std.testing.expect(exportable.hardware_provider_used);
    try std.testing.expect(exportable.sealed_digest_present);
    try std.testing.expect(exportable.resident_material);
    try std.testing.expectEqualStrings("exportable-material", exportable.value[0..exportable.value_len]);
}

test "secure secret store reports missing handles and oversized secrets" {
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 2 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 45 };
    const oversized = [_]u8{'x'} ** (MAX_VALUE_BYTES + 1);

    try std.testing.expectError(error.SecretTooLarge, store.importSecret(owner, "too-large", &oversized, true, false));
    try std.testing.expectError(error.SecretNotFound, store.lendHandle(999, holder, 1, false));
    try std.testing.expectError(error.HandleNotFound, store.exportRaw(999, .{
        .holder = holder,
        .task_id = 1,
    }));
}

test "secure secret store stops secret allocation at id exhaustion and bounds handle capacity" {
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 4 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 46 };

    store.next_secret_id = std.math.maxInt(u64);
    const max_secret = try store.importSecret(owner, "max-secret", "private max secret", false, true);
    try std.testing.expectEqual(std.math.maxInt(u64), max_secret.id);
    try std.testing.expectEqual(@as(u64, 0), store.next_secret_id);
    try std.testing.expect(store.describeSecret(0) == null);
    try std.testing.expectError(error.SecretIdExhausted, store.importSecret(owner, "exhausted-secret", "private exhausted secret", false, true));
    try std.testing.expectEqual(@as(usize, 1), store.countSecrets());

    var full_secrets = Store.init();
    var label_buffer: [MAX_LABEL_BYTES]u8 = undefined;
    for (0..MAX_SECRETS) |index| {
        const label = try std.fmt.bufPrint(&label_buffer, "full-secret-{d}", .{index});
        _ = try full_secrets.importSecret(owner, label, "private full secret", false, true);
    }
    const secret_next_before = full_secrets.next_secret_id;
    try std.testing.expectError(error.SecretTableFull, full_secrets.importSecret(
        owner,
        "full-secret",
        "private full secret",
        true,
        false,
    ));
    try std.testing.expectEqual(secret_next_before, full_secrets.next_secret_id);
    try std.testing.expect(full_secrets.describeSecret(secret_next_before) == null);

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

test "secure secret store direct insertion rejects staged secret id collisions" {
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 5 };

    const original_secret = try store.importSecret(owner, "original", "original material", false, true);
    store.next_secret_id = original_secret.id;
    try std.testing.expectError(error.SecretIdExhausted, store.importSecret(owner, "replacement", "replacement material", false, true));
    try std.testing.expectEqual(@as(usize, 1), store.countSecrets());
    try std.testing.expectEqualStrings("original material", store.describeSecret(original_secret.id).?.value[0..original_secret.value_len]);

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
    }));
    try std.testing.expectError(error.HandleTableFull, store.lendHandle(first_secret_id, holder, 999, true));
}
