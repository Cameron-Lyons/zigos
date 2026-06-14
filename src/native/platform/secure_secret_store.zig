const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");

pub const MAX_SECRETS: usize = 16;
pub const MAX_HANDLES: usize = 32;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_VALUE_BYTES: usize = 96;

pub const SecretRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    hardware_backed: bool,
    hardware_provider_used: bool,
    exportable: bool,
    resident_material: bool,
    label_len: usize,
    label: [MAX_LABEL_BYTES]u8,
    sealed_digest_present: bool,
    sealed_digest: crypto_hash.Digest,
    value_len: usize,
    value: [MAX_VALUE_BYTES]u8,

    pub fn labelSlice(self: *const SecretRecord) []const u8 {
        return self.label[0..self.label_len];
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

pub const HardwareSealProvider = struct {
    available: bool = false,
    sealFn: *const fn (label: []const u8, raw: []const u8) crypto_hash.Digest = defaultSeal,

    pub fn seal(self: HardwareSealProvider, label: []const u8, raw: []const u8) ?crypto_hash.Digest {
        if (!self.available) return null;
        return self.sealFn(label, raw);
    }
};

pub const Error = error{
    HandleNotFound,
    HandleTableFull,
    LabelTooLong,
    RawExportDenied,
    SecretNotFound,
    SecretTableFull,
    SecretTooLarge,
};

const SecretSlot = struct {
    in_use: bool = false,
    secret: SecretRecord = zeroSecret(),
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

pub const Store = struct {
    next_secret_id: u64 = 1,
    next_handle_id: u64 = 1,
    hardware_provider: HardwareSealProvider = .{},
    secrets: [MAX_SECRETS]SecretSlot = [_]SecretSlot{SecretSlot{}} ** MAX_SECRETS,
    handles: [MAX_HANDLES]HandleSlot = [_]HandleSlot{HandleSlot{}} ** MAX_HANDLES,

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
        for (&self.secrets) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.secret = zeroSecret();
            slot.secret.id = self.next_secret_id;
            self.next_secret_id += 1;
            slot.secret.owner = owner;
            slot.secret.hardware_backed = hardware_backed;
            slot.secret.exportable = exportable;
            slot.secret.resident_material = true;
            slot.secret.label_len = native_util.copyTextExact(&slot.secret.label, label) catch return error.LabelTooLong;
            if (hardware_backed and !exportable) {
                slot.secret.resident_material = false;
                slot.secret.sealed_digest_present = true;
                if (self.hardware_provider.seal(label, raw)) |sealed_digest| {
                    slot.secret.hardware_provider_used = true;
                    slot.secret.sealed_digest = sealed_digest;
                } else {
                    slot.secret.sealed_digest = digestSecretMaterial(raw);
                }
                slot.secret.value_len = 0;
                @memset(&slot.secret.value, 0);
            } else {
                slot.secret.value_len = native_util.copyTextExact(&slot.secret.value, raw) catch unreachable;
            }
            return &slot.secret;
        }
        return error.SecretTableFull;
    }

    pub fn lendHandle(
        self: *Store,
        secret_id: u64,
        holder: principal.PrincipalId,
        task_id: u64,
        allow_raw_export: bool,
    ) Error!SecretHandle {
        const secret = self.findSecret(secret_id) orelse return error.SecretNotFound;
        for (&self.handles) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.handle = .{
                .id = self.next_handle_id,
                .secret_id = secret_id,
                .holder = holder,
                .task_id = task_id,
                .hardware_backed = secret.hardware_backed,
                .export_allowed = allow_raw_export and secret.exportable,
            };
            self.next_handle_id += 1;
            return slot.handle;
        }
        return error.HandleTableFull;
    }

    pub fn describeHandle(self: *const Store, handle_id: u64) ?SecretHandle {
        for (self.handles) |slot| {
            if (slot.in_use and slot.handle.id == handle_id) return slot.handle;
        }
        return null;
    }

    pub fn exportRaw(self: *const Store, handle_id: u64) Error![]const u8 {
        const handle = self.describeHandle(handle_id) orelse return error.HandleNotFound;
        if (!handle.export_allowed) return error.RawExportDenied;
        const secret = self.findSecretConst(handle.secret_id) orelse return error.SecretNotFound;
        return secret.value[0..secret.value_len];
    }

    fn findSecret(self: *Store, secret_id: u64) ?*SecretRecord {
        for (&self.secrets) |*slot| {
            if (slot.in_use and slot.secret.id == secret_id) return &slot.secret;
        }
        return null;
    }

    fn findSecretConst(self: *const Store, secret_id: u64) ?*const SecretRecord {
        for (&self.secrets) |*slot| {
            if (slot.in_use and slot.secret.id == secret_id) return &slot.secret;
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

fn digestSecretMaterial(raw: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "secret-material", raw);
    return crypto_hash.finalize(&hasher);
}

fn defaultSeal(label: []const u8, raw: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "hardware-seal-label", label);
    crypto_hash.updateBytes(&hasher, "hardware-seal-material", raw);
    return crypto_hash.finalize(&hasher);
}

test "secure secret store returns handles by default and only exports raw when allowed" {
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 1 };
    const app_holder = principal.PrincipalId{ .kind = .app, .serial = 44 };

    const api_key = try store.importSecret(owner, "api-key", "super-secret-token", true, false);
    const handle = try store.lendHandle(api_key.id, app_holder, 90, true);
    try std.testing.expect(handle.hardware_backed);
    try std.testing.expect(!handle.export_allowed);
    try std.testing.expect(!api_key.resident_material);
    try std.testing.expect(api_key.sealed_digest_present);
    try std.testing.expect(!api_key.hardware_provider_used);
    try std.testing.expectEqual(@as(usize, 0), api_key.value_len);
    try std.testing.expectError(error.RawExportDenied, store.exportRaw(handle.id));

    const exportable = try store.importSecret(owner, "backup-code", "abcd-efgh", false, true);
    const export_handle = try store.lendHandle(exportable.id, app_holder, 91, true);
    try std.testing.expectEqualStrings("abcd-efgh", try store.exportRaw(export_handle.id));
}

test "secure secret store uses hardware seal provider when available" {
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
}

test "secure secret store reports missing handles and oversized secrets" {
    var store = Store.init();
    const owner = principal.PrincipalId{ .kind = .user, .serial = 2 };
    const holder = principal.PrincipalId{ .kind = .app, .serial = 45 };
    const oversized = [_]u8{'x'} ** (MAX_VALUE_BYTES + 1);

    try std.testing.expectError(error.SecretTooLarge, store.importSecret(owner, "too-large", &oversized, true, false));
    try std.testing.expectError(error.SecretNotFound, store.lendHandle(999, holder, 1, false));
    try std.testing.expectError(error.HandleNotFound, store.exportRaw(999));
}
