const std = @import("std");
const hash_seeds = @import("hash_seeds.zig");
const indexed_arena = @import("indexed_arena.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("util.zig");
const signing = @import("signing.zig");

pub const MAX_PRINCIPAL_KEYS = 32;
pub const MAX_PRINCIPAL_LABEL_BYTES = 48;
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

    pub const key_bytes: usize = @sizeOf(PrincipalKind) + @sizeOf(u64);

    pub fn eql(self: PrincipalId, other: PrincipalId) bool {
        return self.kind == other.kind and self.serial == other.serial;
    }

    pub fn keyBytes(self: PrincipalId) [key_bytes]u8 {
        const serial_offset = @sizeOf(PrincipalKind);
        var bytes: [key_bytes]u8 = undefined;
        bytes[0] = @intFromEnum(self.kind);
        std.mem.writeInt(u64, bytes[serial_offset..][0..@sizeOf(u64)], self.serial, .little);
        return bytes;
    }
};

pub const PrincipalRecord = struct {
    id: PrincipalId,
    label_len: usize,
    label: [MAX_PRINCIPAL_LABEL_BYTES]u8,

    pub fn init(id: PrincipalId, label: []const u8) PrincipalRecord {
        var record = PrincipalRecord{
            .id = id,
            .label_len = @min(label.len, MAX_PRINCIPAL_LABEL_BYTES - 1),
            .label = [_]u8{0} ** MAX_PRINCIPAL_LABEL_BYTES,
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
    public_key: signing.PublicKey,
    publisher_len: usize = 0,
    publisher: [MAX_PUBLISHER_BYTES]u8 = [_]u8{0} ** MAX_PUBLISHER_BYTES,
    policy_authority_root: bool = false,
    revoked: bool = false,
    revocation_generation: u32 = 0,

    pub fn publisherSlice(self: *const PrincipalKeyRecord) []const u8 {
        return self.publisher[0..self.publisher_len];
    }

    pub fn fingerprint(self: *const PrincipalKeyRecord) u64 {
        return std.hash.Wyhash.hash(hash_seeds.principal_key_fingerprint, &self.public_key);
    }
};

const PrincipalKeySlot = struct {
    in_use: bool = false,
    record: PrincipalKeyRecord = undefined,
};

fn principalIndexKey(principal_id: PrincipalId) u64 {
    const bytes = principal_id.keyBytes();
    return indexed_arena.nonZeroKey(native_util.fnv1a64(&bytes));
}

fn principalPublicKeyIndexKey(principal_id: PrincipalId, public_key: signing.PublicKey) u64 {
    const principal_bytes = principal_id.keyBytes();
    var hash = native_util.fnv1a64(&principal_bytes);
    hash = native_util.fnv1a64WithSeed(hash, public_key[0..]);
    return indexed_arena.nonZeroKey(hash);
}

fn principalKeySlotKey(slot: *const PrincipalKeySlot) u64 {
    return principalPublicKeyIndexKey(slot.record.principal_id, slot.record.public_key);
}

fn publisherIndexKey(publisher: []const u8) u64 {
    return indexed_arena.nonZeroKey(native_util.fnv1a64(publisher));
}

pub const KeyringError = error{
    KeyringFull,
    PublisherTooLong,
    EmptyPublisher,
    PrincipalKeyNotFound,
};

const PRINCIPAL_KEY_INDEX_CAPACITY = MAX_PRINCIPAL_KEYS * 2;
const PrincipalKeyArena = indexed_arena.IndexedArenaWithKey(u64, PrincipalKeySlot, MAX_PRINCIPAL_KEYS, PRINCIPAL_KEY_INDEX_CAPACITY, principalKeySlotKey);
const PrincipalKeyPrincipalIndex = indexed_arena.MultimapIndex(MAX_PRINCIPAL_KEYS, MAX_PRINCIPAL_KEYS, PRINCIPAL_KEY_INDEX_CAPACITY);
const PrincipalKeyPublisherIndex = indexed_arena.MultimapIndex(MAX_PRINCIPAL_KEYS, MAX_PRINCIPAL_KEYS, PRINCIPAL_KEY_INDEX_CAPACITY);

pub const Keyring = struct {
    slots: PrincipalKeyArena = PrincipalKeyArena.init(),
    principal_index: PrincipalKeyPrincipalIndex = PrincipalKeyPrincipalIndex.init(),
    publisher_index: PrincipalKeyPublisherIndex = PrincipalKeyPublisherIndex.init(),

    pub fn init() Keyring {
        return .{};
    }

    pub fn bindPolicyAuthorityRoot(
        self: *Keyring,
        principal_id: PrincipalId,
        public_key: signing.PublicKey,
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
        public_key: signing.PublicKey,
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
        var slot_index = self.principal_index.head(principalIndexKey(principal_id));
        while (slot_index != indexed_arena.no_index) : (slot_index = self.principal_index.next(slot_index)) {
            if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("principal key principal index points outside key slots");
            const slot = &self.slots.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("principal key principal index points at a free key slot");
            if (!slot.record.principal_id.eql(principal_id)) continue;
            slot.record.revoked = true;
            slot.record.revocation_generation +|= 1;
            self.slots.markDirty(principalKeySlotKey(slot));
            found = true;
        }
        if (!found) return error.PrincipalKeyNotFound;
    }

    pub fn isPolicyAuthorityRoot(self: *const Keyring, principal_id: PrincipalId) bool {
        var slot_index = self.principal_index.head(principalIndexKey(principal_id));
        while (slot_index != indexed_arena.no_index) : (slot_index = self.principal_index.next(slot_index)) {
            if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("principal key principal index points outside key slots");
            const slot = &self.slots.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("principal key principal index points at a free key slot");
            if (slot.record.policy_authority_root and
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
        public_key: signing.PublicKey,
    ) bool {
        const slot = self.slots.getConst(principalPublicKeyIndexKey(principal_id, public_key)) orelse return false;
        return slot.record.policy_authority_root and
            !slot.record.revoked and
            slot.record.principal_id.eql(principal_id) and
            std.mem.eql(u8, slot.record.public_key[0..], public_key[0..]);
    }

    pub fn trustedPublisherSignature(self: *const Keyring, publisher: []const u8, signature: manifest.Signature) bool {
        if (!signature.isComplete()) return false;
        return self.publisherSignatureMatches(publisher, signature.ed25519PublicKeySlice(), false);
    }

    pub fn revokedPublisherSignature(self: *const Keyring, publisher: []const u8, signature: manifest.Signature) bool {
        if (!signature.isComplete()) return false;
        return self.publisherSignatureMatches(publisher, signature.publicKeySlice(), true);
    }

    fn publisherSignatureMatches(
        self: *const Keyring,
        publisher: []const u8,
        public_key: []const u8,
        revoked: bool,
    ) bool {
        var slot_index = self.publisher_index.head(publisherIndexKey(publisher));
        while (slot_index != indexed_arena.no_index) : (slot_index = self.publisher_index.next(slot_index)) {
            if (slot_index >= self.slots.slots.len) native_util.impossibleByInvariant("principal key publisher index points outside key slots");
            const slot = &self.slots.slots[slot_index];
            if (!slot.in_use) native_util.impossibleByInvariant("principal key publisher index points at a free key slot");
            if (slot.record.revoked != revoked) continue;
            if (slot.record.publisher_len == 0) continue;
            if (!std.mem.eql(u8, slot.record.publisherSlice(), publisher)) continue;
            if (!std.mem.eql(u8, slot.record.public_key[0..], public_key)) continue;
            return true;
        }
        return false;
    }

    fn put(self: *Keyring, record: PrincipalKeyRecord) KeyringError!*PrincipalKeyRecord {
        const record_key = principalPublicKeyIndexKey(record.principal_id, record.public_key);
        if (self.slots.slotIndexOf(record_key)) |slot_index| {
            const slot = &self.slots.slots[slot_index];
            if (!slot.record.principal_id.eql(record.principal_id) or
                !std.mem.eql(u8, slot.record.public_key[0..], record.public_key[0..]))
            {
                native_util.impossibleByInvariant("principal key primary index points at the wrong key");
            }
            self.removePublisherSlot(slot_index, &slot.record);
            slot.record = record;
            if (!self.appendPublisherSlot(slot_index, &slot.record)) {
                native_util.impossibleByInvariant("principal key publisher index covers key slots");
            }
            self.slots.markDirty(record_key);
            return &slot.record;
        }

        const slot_index = self.slots.reserveIndex(record_key) orelse return error.KeyringFull;
        const slot = &self.slots.slots[slot_index];
        slot.record = record;

        if (!self.principal_index.append(principalIndexKey(record.principal_id), slot_index)) {
            _ = self.slots.removeIndex(slot_index);
            native_util.impossibleByInvariant("principal key principal index covers key slots");
        }
        if (!self.appendPublisherSlot(slot_index, &slot.record)) {
            _ = self.principal_index.remove(principalIndexKey(record.principal_id), slot_index);
            _ = self.slots.removeIndex(slot_index);
            native_util.impossibleByInvariant("principal key publisher index covers key slots");
        }
        return &slot.record;
    }

    fn appendPublisherSlot(self: *Keyring, slot_index: usize, record: *const PrincipalKeyRecord) bool {
        if (record.publisher_len == 0) return true;
        return self.publisher_index.append(publisherIndexKey(record.publisherSlice()), slot_index);
    }

    fn removePublisherSlot(self: *Keyring, slot_index: usize, record: *const PrincipalKeyRecord) void {
        if (record.publisher_len == 0) return;
        _ = self.publisher_index.remove(publisherIndexKey(record.publisherSlice()), slot_index);
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
    const root_key = signing.publicKeyFromByte(0xA1);
    const publisher_key = signing.publicKeyFromByte(0xB2);

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

test "principal keyring updates publisher indexes when bindings are replaced" {
    var keyring = Keyring.init();
    const root = PrincipalId{ .kind = .policy_authority, .serial = 1 };
    const publisher = PrincipalId{ .kind = .app, .serial = 7 };
    const publisher_key = signing.publicKeyFromByte(0xD4);

    _ = try keyring.bindPublisher(publisher, root, "Old Publisher", publisher_key);

    var signature = manifest.Signature{
        .signer = "Old Publisher",
        .public_key_len = 32,
        .value_len = 64,
    };
    @memcpy(signature.public_key[0..publisher_key.len], publisher_key[0..]);
    @memset(signature.value[0..manifest.ED25519_SIGNATURE_BYTES], 0xE5);
    try std.testing.expect(keyring.trustedPublisherSignature("Old Publisher", signature));

    _ = try keyring.bindPublisher(publisher, root, "New Publisher", publisher_key);
    try std.testing.expectEqual(@as(usize, 1), keyring.slots.countInUse());
    try std.testing.expect(!keyring.trustedPublisherSignature("Old Publisher", signature));

    signature.signer = "New Publisher";
    try std.testing.expect(keyring.trustedPublisherSignature("New Publisher", signature));

    try keyring.revokePrincipal(publisher);
    try std.testing.expect(!keyring.trustedPublisherSignature("New Publisher", signature));
}
