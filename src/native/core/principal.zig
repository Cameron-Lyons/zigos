const std = @import("std");
const manifest = @import("../policy/manifest.zig");

pub const MAX_PRINCIPAL_KEYS = 32;
pub const MAX_PUBLISHER_BYTES = 64;

pub const PrincipalKind = enum(u8) {
    user,
    device,
    app,
    service,
    policy_authority,
    team,
};

pub const PrincipalId = struct {
    kind: PrincipalKind,
    serial: u64,

    pub fn eql(self: PrincipalId, other: PrincipalId) bool {
        return self.kind == other.kind and self.serial == other.serial;
    }
};

pub const PrincipalRecord = struct {
    id: PrincipalId,
    label_len: usize,
    label: [48]u8,

    pub fn init(id: PrincipalId, label: []const u8) PrincipalRecord {
        var record = PrincipalRecord{
            .id = id,
            .label_len = @min(label.len, 47),
            .label = [_]u8{0} ** 48,
        };
        @memcpy(record.label[0..record.label_len], label[0..record.label_len]);
        return record;
    }

    pub fn labelSlice(self: *const PrincipalRecord) []const u8 {
        return self.label[0..self.label_len];
    }
};

pub const PrincipalKeyRecord = struct {
    principal_id: PrincipalId,
    issuer: PrincipalId,
    public_key: [32]u8,
    publisher_len: usize = 0,
    publisher: [MAX_PUBLISHER_BYTES]u8 = [_]u8{0} ** MAX_PUBLISHER_BYTES,
    policy_authority_root: bool = false,
    revoked: bool = false,
    revocation_generation: u32 = 0,

    pub fn publisherSlice(self: *const PrincipalKeyRecord) []const u8 {
        return self.publisher[0..self.publisher_len];
    }

    pub fn fingerprint(self: *const PrincipalKeyRecord) u64 {
        return std.hash.Wyhash.hash(0x5A47_5052_494E_4349, &self.public_key);
    }
};

const PrincipalKeySlot = struct {
    in_use: bool = false,
    record: PrincipalKeyRecord = undefined,
};

pub const KeyringError = error{
    KeyringFull,
    PublisherTooLong,
    EmptyPublisher,
    PrincipalKeyNotFound,
};

pub const Keyring = struct {
    slots: [MAX_PRINCIPAL_KEYS]PrincipalKeySlot = [_]PrincipalKeySlot{.{}} ** MAX_PRINCIPAL_KEYS,

    pub fn init() Keyring {
        return .{};
    }

    pub fn bindPolicyAuthorityRoot(
        self: *Keyring,
        principal_id: PrincipalId,
        public_key: [32]u8,
    ) KeyringError!*PrincipalKeyRecord {
        return self.put(.{
            .principal_id = principal_id,
            .issuer = principal_id,
            .public_key = public_key,
            .policy_authority_root = true,
        });
    }

    pub fn bindPublisher(
        self: *Keyring,
        principal_id: PrincipalId,
        issuer: PrincipalId,
        publisher: []const u8,
        public_key: [32]u8,
    ) KeyringError!*PrincipalKeyRecord {
        if (publisher.len == 0) return error.EmptyPublisher;
        if (publisher.len > MAX_PUBLISHER_BYTES) return error.PublisherTooLong;
        var record = PrincipalKeyRecord{
            .principal_id = principal_id,
            .issuer = issuer,
            .public_key = public_key,
        };
        record.publisher_len = publisher.len;
        @memcpy(record.publisher[0..publisher.len], publisher);
        return self.put(record);
    }

    pub fn revokePrincipal(self: *Keyring, principal_id: PrincipalId) KeyringError!void {
        var found = false;
        for (&self.slots) |*slot| {
            if (!slot.in_use or !slot.record.principal_id.eql(principal_id)) continue;
            slot.record.revoked = true;
            slot.record.revocation_generation +|= 1;
            found = true;
        }
        if (!found) return error.PrincipalKeyNotFound;
    }

    pub fn isPolicyAuthorityRoot(self: *const Keyring, principal_id: PrincipalId) bool {
        for (&self.slots) |*slot| {
            if (slot.in_use and
                slot.record.policy_authority_root and
                !slot.record.revoked and
                slot.record.principal_id.eql(principal_id))
            {
                return true;
            }
        }
        return false;
    }

    pub fn isPolicyAuthorityRootKey(
        self: *const Keyring,
        principal_id: PrincipalId,
        public_key: [32]u8,
    ) bool {
        for (&self.slots) |*slot| {
            if (slot.in_use and
                slot.record.policy_authority_root and
                !slot.record.revoked and
                slot.record.principal_id.eql(principal_id) and
                std.mem.eql(u8, slot.record.public_key[0..], public_key[0..]))
            {
                return true;
            }
        }
        return false;
    }

    pub fn trustedPublisherSignature(self: *const Keyring, publisher: []const u8, signature: manifest.Signature) bool {
        if (!signature.isComplete()) return false;
        for (&self.slots) |*slot| {
            if (!slot.in_use or slot.record.revoked) continue;
            if (slot.record.publisher_len == 0) continue;
            if (!std.mem.eql(u8, slot.record.publisherSlice(), publisher)) continue;
            if (!std.mem.eql(u8, slot.record.public_key[0..], signature.ed25519PublicKeySlice())) continue;
            return true;
        }
        return false;
    }

    fn put(self: *Keyring, record: PrincipalKeyRecord) KeyringError!*PrincipalKeyRecord {
        for (&self.slots) |*slot| {
            if (slot.in_use and
                slot.record.principal_id.eql(record.principal_id) and
                std.mem.eql(u8, slot.record.public_key[0..], record.public_key[0..]))
            {
                slot.record = record;
                return &slot.record;
            }
        }
        for (&self.slots) |*slot| {
            if (slot.in_use) continue;
            slot.in_use = true;
            slot.record = record;
            return &slot.record;
        }
        return error.KeyringFull;
    }
};

pub fn kindName(kind: PrincipalKind) []const u8 {
    return switch (kind) {
        .user => "UserPrincipal",
        .team => "TeamPrincipal",
        .device => "DevicePrincipal",
        .app => "AppPrincipal",
        .service => "ServicePrincipal",
        .policy_authority => "PolicyAuthorityPrincipal",
    };
}

test "principal records preserve identity and labels" {
    const id = PrincipalId{ .kind = .service, .serial = 7 };
    const record = PrincipalRecord.init(id, "session-manager");

    try std.testing.expect(record.id.eql(id));
    try std.testing.expectEqualStrings("session-manager", record.labelSlice());
    try std.testing.expectEqualStrings("ServicePrincipal", kindName(record.id.kind));
    try std.testing.expectEqualStrings("TeamPrincipal", kindName(.team));
}

test "principal keyring binds publishers to trusted keys and supports revocation" {
    var keyring = Keyring.init();
    const root = PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const publisher = PrincipalId{ .kind = .app, .serial = 7 };
    const root_key = [_]u8{0xA1} ** 32;
    const publisher_key = [_]u8{0xB2} ** 32;

    _ = try keyring.bindPolicyAuthorityRoot(root, root_key);
    _ = try keyring.bindPublisher(publisher, root, "Example Software", publisher_key);
    try std.testing.expect(keyring.isPolicyAuthorityRoot(root));
    try std.testing.expect(keyring.isPolicyAuthorityRootKey(root, root_key));
    try std.testing.expect(!keyring.isPolicyAuthorityRootKey(root, publisher_key));

    var signature = manifest.Signature{
        .signer = "Example Software",
        .public_key_len = 32,
        .value_len = 64,
    };
    @memcpy(signature.public_key[0..publisher_key.len], publisher_key[0..]);
    @memset(signature.value[0..manifest.ED25519_SIGNATURE_BYTES], 0xC3);
    try std.testing.expect(keyring.trustedPublisherSignature("Example Software", signature));

    try keyring.revokePrincipal(publisher);
    try std.testing.expect(!keyring.trustedPublisherSignature("Example Software", signature));
}
