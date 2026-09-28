const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const device_graph = @import("../sync/device_graph.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const secure_secret_store = @import("secure_secret_store.zig");
const signing = @import("../core/signing.zig");
const vault_service = @import("../services/secret_vault_service.zig");
const policy_object = @import("../policy/policy_object.zig");
const event_ledger = @import("event_ledger.zig");
const binary_cursor = @import("binary_cursor");
pub const unlock_context = @import("unlock_context.zig");

pub const MAX_CREDENTIALS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_RP_ID_BYTES: usize = 64;
pub const MAX_ORIGIN_BYTES: usize = 96;
pub const MAX_CHALLENGE_BYTES: usize = 64;
pub const MAX_SNAPSHOT_BYTES: usize = 1 + MAX_CREDENTIALS * (139 + MAX_RP_ID_BYTES + MAX_LABEL_BYTES);
pub const SnapshotError = error{ InvalidIdentitySnapshot, IdentitySnapshotTooLarge, IdentityStoreNotEmpty };
const SnapshotWriter = binary_cursor.Writer(SnapshotError, error.IdentitySnapshotTooLarge);
const SnapshotReader = binary_cursor.Reader(SnapshotError, error.InvalidIdentitySnapshot);
pub const DIRECT_CREDENTIAL_LOOKUP = true;
pub const DENSE_CREDENTIAL_TABLE = true;
pub const COMPACT_CREDENTIAL_METADATA = true;
pub const COMPACT_IDENTITY_PROOF_METADATA = true;
pub const STORE_SIZE_CEILING_BYTES: usize = 5_000;
pub const LOCAL_UNLOCK_PROOF_SIZE_CEILING_BYTES: usize = 304;
pub const ASSERTION_SIZE_CEILING_BYTES: usize = 416;
pub const ASSERTION_REQUEST_SIZE_CEILING_BYTES: usize = 392;
pub const RECOVERY_APPROVAL_SIZE_CEILING_BYTES: usize = 320;
pub const RECOVERY_REQUEST_SIZE_CEILING_BYTES: usize = 368;

comptime {
    if (MAX_RP_ID_BYTES > std.math.maxInt(u8) or
        MAX_LABEL_BYTES > std.math.maxInt(u8) or
        MAX_ORIGIN_BYTES > std.math.maxInt(u8) or
        MAX_CHALLENGE_BYTES > std.math.maxInt(u8))
    {
        @compileError("OS identity text exceeds compact length metadata capacity");
    }
}

pub const CredentialScope = enum(u8) {
    device_bound,
    synced,
};

pub const CredentialStatus = enum(u8) {
    active,
    revoked,
};

pub const UnlockMethod = enum(u8) {
    biometric,
    device_pin,
    recovery_key,
};

// Holds the identity service's private vault lease and service task identity.
// These signing handles must never be lent to apps. Session policy subjects and
// time come from authenticated service state, not credential request fields.
// The caller serializes access to all borrowed stores during an operation.
pub const VaultAuthority = struct {
    vault: *vault_service.Service,
    policies: *const policy_object.Directory,
    subjects: policy_object.SubjectSet,
    holder: principal.PrincipalId,
    task_id: u64,
    now_ticks: u64,
    unlock_session: *const unlock_context.Session,
    ledger: ?*event_ledger.Ledger = null,
};

pub const RegisterCredentialRequest = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    label: []const u8,
    scope: CredentialScope = .synced,
    recovery_threshold: u8 = 1,
    key_handle_id: u64,
};

pub const LocalUnlockProof = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    method: UnlockMethod,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    context: unlock_context.Binding,
    relying_party_id_len: u8,
    relying_party_id: [MAX_RP_ID_BYTES]u8,
    challenge_len: u8,
    challenge: [MAX_CHALLENGE_BYTES]u8,
    // The verifier selects the device key from its trusted graph. Neither a
    // signer label nor a duplicate public key belongs in an unlock proof.
    signature: [signing.SIGNATURE_BYTES]u8 = @splat(0),

    pub fn relyingPartySlice(self: *const LocalUnlockProof) []const u8 {
        return self.relying_party_id[0..@as(usize, self.relying_party_id_len)];
    }

    pub fn challengeSlice(self: *const LocalUnlockProof) []const u8 {
        return self.challenge[0..@as(usize, self.challenge_len)];
    }
};

pub const AssertionRequest = struct {
    credential_id: u64,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    origin: []const u8,
    challenge: []const u8,
    local_unlock: ?LocalUnlockProof = null,
    key_handle_id: u64,
};

pub const RecoveryApproval = struct {
    device: principal.PrincipalId,
    local_unlock: LocalUnlockProof,
};

pub const RecoveryRequest = struct {
    credential_id: u64,
    recovery_device: principal.PrincipalId,
    relying_party_id: []const u8,
    local_unlock: LocalUnlockProof,
    approvals: []const RecoveryApproval = &.{},
    replacement_key_handle_id: u64,
};

pub const CredentialRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    primary_device: principal.PrincipalId,
    scope: CredentialScope,
    recovery_threshold: u8 = 1,
    status: CredentialStatus = .active,
    local_unlock_required: bool = true,
    phishing_resistant: bool = true,
    synced_to_device_graph: bool = false,
    hardware_backed_credential: bool = false,
    sealed_credential_secret: bool = false,
    relying_party_id_len: u8,
    relying_party_id: [MAX_RP_ID_BYTES]u8,
    label_len: u8,
    label: [MAX_LABEL_BYTES]u8,
    secret_id: u64,
    sealed_secret_digest: crypto_hash.Digest,
    credential_public_key: [signing.PUBLIC_KEY_BYTES]u8,
    credential_digest: crypto_hash.Digest,
    credential_generation: u32 = 1,
    assertion_count: u64 = 0,
    created_at_ticks: u64,
    last_asserted_at_ticks: u64 = 0,
    recovered_at_ticks: u64 = 0,
    revoked_at_ticks: u64 = 0,

    pub fn relyingPartySlice(self: *const CredentialRecord) []const u8 {
        return self.relying_party_id[0..@as(usize, self.relying_party_id_len)];
    }

    pub fn labelSlice(self: *const CredentialRecord) []const u8 {
        return self.label[0..@as(usize, self.label_len)];
    }

    pub fn isActive(self: *const CredentialRecord) bool {
        return self.status == .active;
    }

    pub fn isRecoverableThroughDeviceGraph(self: *const CredentialRecord) bool {
        return self.scope == .synced and self.synced_to_device_graph;
    }
};

pub const Assertion = struct {
    credential_id: u64,
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    credential_generation: u32,
    assertion_counter: u64,
    relying_party_id_len: u8,
    relying_party_id: [MAX_RP_ID_BYTES]u8,
    origin_len: u8,
    origin: [MAX_ORIGIN_BYTES]u8,
    challenge_len: u8,
    challenge: [MAX_CHALLENGE_BYTES]u8,
    signature: manifest.Signature,
    local_unlock_verified: bool,
    phishing_resistant: bool,
    hardware_backed_credential: bool,
    device_platform_backed: bool,
    primary_device_assertion: bool,
    device_trust_generation: u32,
    unlock_age_ticks: u64,

    pub fn relyingPartySlice(self: *const Assertion) []const u8 {
        return self.relying_party_id[0..@as(usize, self.relying_party_id_len)];
    }

    pub fn originSlice(self: *const Assertion) []const u8 {
        return self.origin[0..@as(usize, self.origin_len)];
    }

    pub fn challengeSlice(self: *const Assertion) []const u8 {
        return self.challenge[0..@as(usize, self.challenge_len)];
    }
};

comptime {
    if (@sizeOf(LocalUnlockProof) > LOCAL_UNLOCK_PROOF_SIZE_CEILING_BYTES or
        @sizeOf(Assertion) > ASSERTION_SIZE_CEILING_BYTES or
        @sizeOf(AssertionRequest) > ASSERTION_REQUEST_SIZE_CEILING_BYTES or
        @sizeOf(RecoveryApproval) > RECOVERY_APPROVAL_SIZE_CEILING_BYTES or
        @sizeOf(RecoveryRequest) > RECOVERY_REQUEST_SIZE_CEILING_BYTES)
    {
        @compileError("OS identity proof or request exceeds its size ceiling");
    }
}

pub const Error = error{
    ChallengeTooLong,
    CredentialNotFound,
    CredentialRevoked,
    CredentialTableFull,
    CredentialKeyBindingMismatch,
    CredentialKeyCustodyRequired,
    CredentialCounterExhausted,
    InvalidRecoveryThreshold,
    InvalidIdentityAuthority,
    InvalidRelyingParty,
    InvalidChallenge,
    DeviceBoundCredentialWrongDevice,
    DeviceBoundRecoveryDenied,
    DeviceNotTrusted,
    DeviceOwnerMismatch,
    InvalidCredentialSignature,
    InvalidLocalUnlock,
    LabelTooLong,
    LocalUnlockExpired,
    LocalUnlockRequired,
    OriginTooLong,
    PhishingOriginRejected,
    RecoveryApprovalDuplicate,
    RecoveryThresholdNotMet,
    RelyingPartyTooLong,
    TrustedUnlockRequired,
} || vault_service.Error || device_graph.Error || unlock_context.Error;

pub const Store = struct {
    credentials: [MAX_CREDENTIALS]CredentialRecord = [_]CredentialRecord{zeroCredential()} ** MAX_CREDENTIALS,
    credential_count: u8 = 0,

    comptime {
        if (MAX_CREDENTIALS > std.math.maxInt(u8)) {
            @compileError("credential count no longer fits compact storage");
        }
        if (@sizeOf(@This()) > STORE_SIZE_CEILING_BYTES) {
            @compileError("OS identity store exceeds its fixed-state size ceiling");
        }
    }

    pub fn init() Store {
        return .{};
    }

    // The enclosing vault catalog authenticates these bytes and commits them
    // with their sealed keys. No lease or unlock proof enters the snapshot.
    pub fn encodeSnapshot(self: *const Store, owner: principal.PrincipalId, secrets: *const secure_secret_store.Store, out: []u8) SnapshotError![]const u8 {
        if (self.credential_count > MAX_CREDENTIALS) return error.InvalidIdentitySnapshot;
        var writer = SnapshotWriter{ .buffer = out };
        try writer.writeByte(self.credential_count);
        for (self.credentials[0..self.credential_count], 0..) |*record, index| {
            if (record.id != index + 1) return error.InvalidIdentitySnapshot;
            try validateSnapshotRecord(record, owner);
            try validateSnapshotKey(record, secrets);
            const digest = snapshotCredentialDigest(record);
            if (!std.mem.eql(u8, &digest, &record.credential_digest)) return error.InvalidIdentitySnapshot;
            try writer.writeBytes(&record.owner.keyBytes());
            try writer.writeBytes(&record.primary_device.keyBytes());
            try writer.writeByte(@intFromEnum(record.scope));
            try writer.writeByte(record.recovery_threshold);
            try writer.writeByte(@intFromEnum(record.status));
            try writer.writeByte(record.relying_party_id_len);
            try writer.writeBytes(record.relyingPartySlice());
            try writer.writeByte(record.label_len);
            try writer.writeBytes(record.labelSlice());
            try writer.writeU64(record.secret_id);
            try writer.writeBytes(&record.sealed_secret_digest);
            try writer.writeBytes(&record.credential_public_key);
            try writer.writeU32(record.credential_generation);
            try writer.writeU64(record.assertion_count);
            try writer.writeU64(record.created_at_ticks);
            try writer.writeU64(record.last_asserted_at_ticks);
            try writer.writeU64(record.recovered_at_ticks);
            try writer.writeU64(record.revoked_at_ticks);
        }
        return out[0..writer.offset];
    }

    pub fn restoreSnapshot(self: *Store, owner: principal.PrincipalId, secrets: *const secure_secret_store.Store, bytes: []const u8) SnapshotError!void {
        if (self.credential_count != 0) return error.IdentityStoreNotEmpty;
        try validateSnapshot(owner, bytes);
        var reader = SnapshotReader{ .buffer = bytes };
        const count = try reader.readByte();
        errdefer {
            for (self.credentials[0..self.credential_count]) |*record| record.* = zeroCredential();
            self.credential_count = 0;
        }
        for (0..count) |index| {
            const record = try readSnapshotRecord(&reader, owner, index + 1);
            try validateSnapshotKey(&record, secrets);
            self.credentials[index] = record;
            self.credential_count += 1;
        }
    }

    pub fn registerCredential(
        self: *Store,
        graph: *const device_graph.Graph,
        authority: VaultAuthority,
        request: RegisterCredentialRequest,
    ) Error!*const CredentialRecord {
        _ = try requireTrustedDeviceForOwner(graph, request.owner, request.device);
        if (request.relying_party_id.len > MAX_RP_ID_BYTES) return error.RelyingPartyTooLong;
        if (!validDnsName(request.relying_party_id)) return error.InvalidRelyingParty;
        if (request.label.len > MAX_LABEL_BYTES) return error.LabelTooLong;
        if (request.recovery_threshold == 0 or request.recovery_threshold > device_graph.MAX_DEVICES) return error.InvalidRecoveryThreshold;
        if (self.countCredentials() >= MAX_CREDENTIALS) return error.CredentialTableFull;
        const secret = try signingSecret(authority, request.key_handle_id, request.owner);
        const slot_index = self.countCredentials();
        const credential_id: u64 = @intCast(slot_index + 1);

        var credential = zeroCredential();
        credential.id = credential_id;
        credential.owner = request.owner;
        credential.primary_device = request.device;
        credential.scope = request.scope;
        credential.recovery_threshold = request.recovery_threshold;
        credential.synced_to_device_graph = request.scope == .synced;
        credential.relying_party_id_len = @intCast(native_util.copyTextExact(&credential.relying_party_id, request.relying_party_id) catch return error.RelyingPartyTooLong);
        credential.label_len = @intCast(native_util.copyTextExact(&credential.label, request.label) catch return error.LabelTooLong);
        credential.created_at_ticks = authority.now_ticks;
        credential.secret_id = secret.id;
        credential.hardware_backed_credential = secret.hardware_backed;
        credential.sealed_credential_secret = secret.sealed_digest_present;
        credential.sealed_secret_digest = secret.sealed_digest;
        credential.credential_public_key = try credentialPublicKey(authority, request.key_handle_id, &credential);
        credential.credential_digest = credentialDigest(
            credential.owner,
            credential.primary_device,
            credential.scope,
            credential.relyingPartySlice(),
            &credential.credential_public_key,
            &credential.sealed_secret_digest,
            credential.credential_generation,
            credential.recovery_threshold,
        );

        const slot = &self.credentials[slot_index];
        slot.* = credential;
        self.credential_count += 1;
        return slot;
    }

    pub fn assertCredential(
        self: *Store,
        graph: *const device_graph.Graph,
        authority: VaultAuthority,
        request: AssertionRequest,
    ) Error!Assertion {
        if (request.origin.len > MAX_ORIGIN_BYTES) return error.OriginTooLong;
        if (request.challenge.len == 0) return error.InvalidChallenge;
        if (request.challenge.len > MAX_CHALLENGE_BYTES) return error.ChallengeTooLong;
        const credential = self.findCredential(request.credential_id) orelse return error.CredentialNotFound;
        try requireActiveCredential(credential);
        const device_record = try requireCredentialDevice(graph, credential, request.device);
        if (!std.mem.eql(u8, credential.relyingPartySlice(), request.relying_party_id)) return error.PhishingOriginRejected;
        if (!originMatchesRelyingParty(request.origin, credential.relyingPartySlice())) return error.PhishingOriginRejected;

        const unlock = request.local_unlock orelse return error.LocalUnlockRequired;
        try verifyLocalUnlock(graph, credential, request.device, unlock, request.challenge, authority.now_ticks, authority.unlock_session);
        const secret = try signingSecret(authority, request.key_handle_id, credential.owner);
        if (secret.id != credential.secret_id or !std.mem.eql(u8, &secret.sealed_digest, &credential.sealed_secret_digest)) return error.CredentialKeyBindingMismatch;
        const next_counter = std.math.add(u64, credential.assertion_count, 1) catch return error.CredentialCounterExhausted;
        const decision = authority.policies.credentialAssertionDecision(authority.subjects, .{
            .phishing_resistant = true,
            .hardware_backed = true,
            .local_unlock_verified = true,
            .unlock_age_ticks = authority.now_ticks - unlock.issued_at_ticks,
        });
        if (!decision.allowed) return error.PolicyDenied;

        var assertion = Assertion{
            .credential_id = credential.id,
            .owner = credential.owner,
            .device = request.device,
            .credential_generation = credential.credential_generation,
            .assertion_counter = next_counter,
            .relying_party_id_len = 0,
            .relying_party_id = [_]u8{0} ** MAX_RP_ID_BYTES,
            .origin_len = 0,
            .origin = [_]u8{0} ** MAX_ORIGIN_BYTES,
            .challenge_len = 0,
            .challenge = [_]u8{0} ** MAX_CHALLENGE_BYTES,
            .signature = .{},
            .local_unlock_verified = true,
            .phishing_resistant = true,
            .hardware_backed_credential = credential.hardware_backed_credential and credential.sealed_credential_secret,
            .device_platform_backed = device_record.usesPlatformBackedKey(),
            .primary_device_assertion = credential.primary_device.eql(request.device),
            .device_trust_generation = device_record.trust_generation,
            .unlock_age_ticks = authority.now_ticks - unlock.issued_at_ticks,
        };
        assertion.relying_party_id_len = @intCast(native_util.copyTextExact(&assertion.relying_party_id, credential.relyingPartySlice()) catch return error.RelyingPartyTooLong);
        assertion.origin_len = @intCast(native_util.copyTextExact(&assertion.origin, request.origin) catch return error.OriginTooLong);
        assertion.challenge_len = @intCast(native_util.copyTextExact(&assertion.challenge, request.challenge) catch return error.ChallengeTooLong);
        const digest = assertionDigest(&assertion);
        assertion.signature = try signThroughVault(authority, request.key_handle_id, &digest);
        if (!verifyAssertion(&assertion, &credential.credential_public_key)) return error.InvalidCredentialSignature;
        credential.assertion_count = next_counter;
        credential.last_asserted_at_ticks = authority.now_ticks;
        return assertion;
    }

    // Approvers sign this intent, including the current credential generation
    // and replacement ciphertext binding. An approval cannot select another key
    // or be replayed after a completed recovery.
    pub fn recoveryChallenge(
        self: *const Store,
        authority: VaultAuthority,
        credential_id: u64,
        recovery_device: principal.PrincipalId,
        replacement_key_handle_id: u64,
    ) Error!crypto_hash.Digest {
        const credential = self.findCredentialConst(credential_id) orelse return error.CredentialNotFound;
        try requireActiveCredential(credential);
        if (!credential.isRecoverableThroughDeviceGraph()) return error.DeviceBoundRecoveryDenied;
        const secret = try signingSecret(authority, replacement_key_handle_id, credential.owner);
        return recoveryIntentDigest(credential, recovery_device, secret);
    }

    pub fn recoverCredential(
        self: *Store,
        graph: *const device_graph.Graph,
        authority: VaultAuthority,
        request: RecoveryRequest,
    ) Error!*const CredentialRecord {
        const credential = self.findCredential(request.credential_id) orelse return error.CredentialNotFound;
        try requireActiveCredential(credential);
        if (!credential.isRecoverableThroughDeviceGraph()) return error.DeviceBoundRecoveryDenied;
        if (!std.mem.eql(u8, credential.relyingPartySlice(), request.relying_party_id)) return error.PhishingOriginRejected;
        const generation = std.math.add(u32, credential.credential_generation, 1) catch return error.CredentialCounterExhausted;
        const secret = try signingSecret(authority, request.replacement_key_handle_id, credential.owner);
        const challenge = recoveryIntentDigest(credential, request.recovery_device, secret);
        try verifyRecoveryThreshold(graph, credential, request, &challenge, authority.now_ticks, authority.unlock_session);
        var replacement = credential.*;
        replacement.primary_device = request.recovery_device;
        replacement.secret_id = secret.id;
        replacement.sealed_secret_digest = secret.sealed_digest;
        replacement.credential_generation = generation;
        replacement.recovered_at_ticks = authority.now_ticks;
        replacement.credential_public_key = try credentialPublicKey(authority, request.replacement_key_handle_id, &replacement);
        replacement.credential_digest = credentialDigest(
            replacement.owner,
            replacement.primary_device,
            replacement.scope,
            replacement.relyingPartySlice(),
            &replacement.credential_public_key,
            &replacement.sealed_secret_digest,
            replacement.credential_generation,
            replacement.recovery_threshold,
        );
        credential.* = replacement;
        return credential;
    }

    pub fn revokeCredential(self: *Store, credential_id: u64, tick: u64) Error!void {
        const credential = self.findCredential(credential_id) orelse return error.CredentialNotFound;
        try requireActiveCredential(credential);
        credential.status = .revoked;
        credential.revoked_at_ticks = tick;
    }

    fn findCredential(self: *Store, credential_id: u64) ?*CredentialRecord {
        const slot_index = self.credentialSlotIndex(credential_id) orelse return null;
        return &self.credentials[slot_index];
    }

    pub fn findCredentialConst(self: *const Store, credential_id: u64) ?*const CredentialRecord {
        const slot_index = self.credentialSlotIndex(credential_id) orelse return null;
        return &self.credentials[slot_index];
    }

    fn countCredentials(self: *const Store) usize {
        return @intCast(self.credential_count);
    }

    fn credentialSlotIndex(self: *const Store, credential_id: u64) ?usize {
        if (credential_id == 0 or credential_id > self.countCredentials()) return null;
        const slot_index: usize = @intCast(credential_id - 1);
        return if (self.credentials[slot_index].id == credential_id) slot_index else null;
    }
};

pub fn validateSnapshot(owner: principal.PrincipalId, bytes: []const u8) SnapshotError!void {
    var reader = SnapshotReader{ .buffer = bytes };
    const count = try reader.readByte();
    if (count > MAX_CREDENTIALS) return error.InvalidIdentitySnapshot;
    for (0..count) |index| _ = try readSnapshotRecord(&reader, owner, index + 1);
    if (!reader.eof()) return error.InvalidIdentitySnapshot;
}

fn readSnapshotRecord(reader: *SnapshotReader, owner: principal.PrincipalId, id: u64) SnapshotError!CredentialRecord {
    var record = zeroCredential();
    record.id = id;
    record.owner = try readSnapshotPrincipal(reader);
    record.primary_device = try readSnapshotPrincipal(reader);
    record.scope = std.enums.fromInt(CredentialScope, try reader.readByte()) orelse return error.InvalidIdentitySnapshot;
    record.recovery_threshold = try reader.readByte();
    record.status = std.enums.fromInt(CredentialStatus, try reader.readByte()) orelse return error.InvalidIdentitySnapshot;
    record.relying_party_id_len = try reader.readByte();
    if (record.relying_party_id_len > MAX_RP_ID_BYTES) return error.InvalidIdentitySnapshot;
    try reader.readBytes(record.relying_party_id[0..record.relying_party_id_len]);
    record.label_len = try reader.readByte();
    if (record.label_len > MAX_LABEL_BYTES) return error.InvalidIdentitySnapshot;
    try reader.readBytes(record.label[0..record.label_len]);
    record.secret_id = try reader.readU64();
    try reader.readBytes(&record.sealed_secret_digest);
    try reader.readBytes(&record.credential_public_key);
    record.credential_generation = try reader.readU32();
    record.assertion_count = try reader.readU64();
    record.created_at_ticks = try reader.readU64();
    record.last_asserted_at_ticks = try reader.readU64();
    record.recovered_at_ticks = try reader.readU64();
    record.revoked_at_ticks = try reader.readU64();
    record.synced_to_device_graph = record.scope == .synced;
    record.hardware_backed_credential = true;
    record.sealed_credential_secret = true;
    try validateSnapshotRecord(&record, owner);
    record.credential_digest = snapshotCredentialDigest(&record);
    return record;
}

fn readSnapshotPrincipal(reader: *SnapshotReader) SnapshotError!principal.PrincipalId {
    const kind = std.enums.fromInt(principal.PrincipalKind, try reader.readByte()) orelse return error.InvalidIdentitySnapshot;
    return .{ .kind = kind, .serial = try reader.readU64() };
}

fn snapshotCredentialDigest(record: *const CredentialRecord) crypto_hash.Digest {
    return credentialDigest(record.owner, record.primary_device, record.scope, record.relyingPartySlice(), &record.credential_public_key, &record.sealed_secret_digest, record.credential_generation, record.recovery_threshold);
}

fn validateSnapshotRecord(record: *const CredentialRecord, owner: principal.PrincipalId) SnapshotError!void {
    if (owner.serial == 0 or !record.owner.eql(owner) or record.primary_device.kind != .device or record.primary_device.serial == 0 or
        record.relying_party_id_len > MAX_RP_ID_BYTES or record.label_len > MAX_LABEL_BYTES or record.secret_id == 0 or
        record.credential_generation == 0 or record.recovery_threshold == 0 or record.recovery_threshold > device_graph.MAX_DEVICES or
        !record.local_unlock_required or !record.phishing_resistant or !record.hardware_backed_credential or !record.sealed_credential_secret or
        record.synced_to_device_graph != (record.scope == .synced)) return error.InvalidIdentitySnapshot;
    if (!validDnsName(record.relyingPartySlice())) return error.InvalidIdentitySnapshot;
}

fn validateSnapshotKey(record: *const CredentialRecord, secrets: *const secure_secret_store.Store) SnapshotError!void {
    const secret = secrets.describeSecret(record.secret_id) orelse return error.InvalidIdentitySnapshot;
    if (!secret.owner.eql(record.owner) or !secret.hardware_backed or !secret.hardware_provider_used or secret.exportable or
        secret.resident_material or !secret.sealed_digest_present or secret.sealedBlob() == null or
        !std.mem.eql(u8, &secret.sealed_digest, &record.sealed_secret_digest)) return error.InvalidIdentitySnapshot;
}

pub const UnlockRequest = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    challenge: []const u8,
    method: UnlockMethod,
    expires_at_ticks: u64,
    key_handle_id: u64,
};

// Called only by a trusted authenticator after local verification. The private
// device-key lease stays in that service; this API does not verify a PIN or a
// biometric and is not an app request boundary.
pub fn issueLocalUnlockProof(graph: *const device_graph.Graph, authority: VaultAuthority, request: UnlockRequest) Error!LocalUnlockProof {
    const device = try requireTrustedDeviceForOwner(graph, request.owner, request.device);
    _ = try signingSecret(authority, request.key_handle_id, request.owner);
    var proof = try makeLocalUnlockProof(try authority.unlock_session.binding(), request.owner, request.device, request.relying_party_id, request.challenge, request.method, authority.now_ticks, request.expires_at_ticks);
    const digest = localUnlockDigest(&proof);
    const signature = try signThroughVault(authority, request.key_handle_id, &digest);
    if (signature.value_len != signing.SIGNATURE_BYTES or !std.mem.eql(u8, signature.publicKeySlice(), device.device_signature.publicKeySlice())) return error.InvalidLocalUnlock;
    proof.signature = signature.value[0..signing.SIGNATURE_BYTES].*;
    try verifyUnlockSignature(device, &proof);
    return proof;
}

pub fn createLocalUnlockProofForVerification(
    context: unlock_context.Binding,
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    challenge: []const u8,
    method: UnlockMethod,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    device_identity: signing.SignerIdentity,
) Error!LocalUnlockProof {
    if (comptime @import("builtin").os.tag == .freestanding) {
        if (comptime !@import("../../kernel/config.zig").includesVerificationEvidence()) return error.TrustedUnlockRequired;
    }
    var proof = try makeLocalUnlockProof(context, owner, device, relying_party_id, challenge, method, issued_at_ticks, expires_at_ticks);
    const signature = signing.sign(device_identity, &localUnlockDigest(&proof)) catch return error.InvalidLocalUnlock;
    proof.signature = signature.value[0..signing.SIGNATURE_BYTES].*;
    return proof;
}

fn makeLocalUnlockProof(
    context: unlock_context.Binding,
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    challenge: []const u8,
    method: UnlockMethod,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
) Error!LocalUnlockProof {
    if (!context.valid()) return error.InvalidUnlockContext;
    if (expires_at_ticks <= issued_at_ticks) return error.LocalUnlockExpired;
    if (relying_party_id.len > MAX_RP_ID_BYTES) return error.RelyingPartyTooLong;
    if (!validDnsName(relying_party_id)) return error.InvalidRelyingParty;
    if (challenge.len == 0) return error.InvalidChallenge;
    var proof = LocalUnlockProof{
        .owner = owner,
        .device = device,
        .method = method,
        .issued_at_ticks = issued_at_ticks,
        .expires_at_ticks = expires_at_ticks,
        .context = context,
        .relying_party_id_len = 0,
        .relying_party_id = [_]u8{0} ** MAX_RP_ID_BYTES,
        .challenge_len = 0,
        .challenge = [_]u8{0} ** MAX_CHALLENGE_BYTES,
    };
    proof.relying_party_id_len = @intCast(native_util.copyTextExact(&proof.relying_party_id, relying_party_id) catch return error.RelyingPartyTooLong);
    proof.challenge_len = @intCast(native_util.copyTextExact(&proof.challenge, challenge) catch return error.ChallengeTooLong);
    return proof;
}

fn verifyLocalUnlock(
    graph: *const device_graph.Graph,
    credential: *const CredentialRecord,
    device: principal.PrincipalId,
    proof: LocalUnlockProof,
    challenge: []const u8,
    tick: u64,
    session: *const unlock_context.Session,
) Error!void {
    if (proof.relying_party_id_len > MAX_RP_ID_BYTES or proof.challenge_len > MAX_CHALLENGE_BYTES) return error.InvalidLocalUnlock;
    try session.require(proof.context);
    if (!proof.owner.eql(credential.owner) or !proof.device.eql(device)) return error.InvalidLocalUnlock;
    if (!std.mem.eql(u8, proof.relyingPartySlice(), credential.relyingPartySlice())) return error.InvalidLocalUnlock;
    if (!std.mem.eql(u8, proof.challengeSlice(), challenge)) return error.InvalidLocalUnlock;
    if (tick < proof.issued_at_ticks or tick >= proof.expires_at_ticks) return error.LocalUnlockExpired;

    const device_record = try requireTrustedDeviceForOwner(graph, credential.owner, device);
    try verifyUnlockSignature(device_record, &proof);
}

fn verifyUnlockSignature(device: *const device_graph.DeviceRecord, proof: *const LocalUnlockProof) Error!void {
    const key = device.device_signature.publicKeySlice();
    if (device.device_signature.format != .ed25519 or key.len != signing.PUBLIC_KEY_BYTES) return error.InvalidLocalUnlock;
    const signature = manifest.Signature{ .public_key = key[0..signing.PUBLIC_KEY_BYTES].*, .public_key_len = signing.PUBLIC_KEY_BYTES, .value = proof.signature, .value_len = signing.SIGNATURE_BYTES };
    if (!signing.verify(signature, &localUnlockDigest(proof))) return error.InvalidLocalUnlock;
}

fn requireCredentialDevice(
    graph: *const device_graph.Graph,
    credential: *const CredentialRecord,
    device: principal.PrincipalId,
) Error!*const device_graph.DeviceRecord {
    const device_record = try requireTrustedDeviceForOwner(graph, credential.owner, device);
    if (credential.scope == .device_bound and !credential.primary_device.eql(device)) {
        return error.DeviceBoundCredentialWrongDevice;
    }
    return device_record;
}

fn verifyRecoveryThreshold(
    graph: *const device_graph.Graph,
    credential: *const CredentialRecord,
    request: RecoveryRequest,
    challenge: []const u8,
    tick: u64,
    session: *const unlock_context.Session,
) Error!void {
    var trusted_devices: [device_graph.MAX_DEVICES]principal.PrincipalId = undefined;
    var trusted_device_count: usize = 0;

    try verifyRecoveryApproval(
        graph,
        credential,
        request.recovery_device,
        request.local_unlock,
        challenge,
        tick,
        session,
    );
    trusted_devices[trusted_device_count] = request.recovery_device;
    trusted_device_count += 1;

    for (request.approvals) |approval| {
        if (containsPrincipal(trusted_devices[0..trusted_device_count], approval.device)) return error.RecoveryApprovalDuplicate;
        try verifyRecoveryApproval(
            graph,
            credential,
            approval.device,
            approval.local_unlock,
            challenge,
            tick,
            session,
        );
        if (trusted_device_count >= trusted_devices.len) return error.RecoveryThresholdNotMet;
        trusted_devices[trusted_device_count] = approval.device;
        trusted_device_count += 1;
    }

    if (trusted_device_count < credential.recovery_threshold) return error.RecoveryThresholdNotMet;
}

fn verifyRecoveryApproval(
    graph: *const device_graph.Graph,
    credential: *const CredentialRecord,
    device: principal.PrincipalId,
    unlock: LocalUnlockProof,
    challenge: []const u8,
    tick: u64,
    session: *const unlock_context.Session,
) Error!void {
    _ = try requireTrustedDeviceForOwner(graph, credential.owner, device);
    try verifyLocalUnlock(graph, credential, device, unlock, challenge, tick, session);
}

fn containsPrincipal(haystack: []const principal.PrincipalId, needle: principal.PrincipalId) bool {
    for (haystack) |candidate| {
        if (candidate.eql(needle)) return true;
    }
    return false;
}

fn requireTrustedDeviceForOwner(
    graph: *const device_graph.Graph,
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
) Error!*const device_graph.DeviceRecord {
    const record = graph.findDeviceConst(device) orelse return error.DeviceNotTrusted;
    if (!record.owner.eql(owner)) return error.DeviceOwnerMismatch;
    if (!record.isTrusted()) return error.DeviceNotTrusted;
    return record;
}

fn requireActiveCredential(credential: *const CredentialRecord) Error!void {
    if (!credential.isActive()) return error.CredentialRevoked;
}

fn zeroCredential() CredentialRecord {
    return .{
        .id = 0,
        .owner = .{ .kind = .user, .serial = 0 },
        .primary_device = .{ .kind = .device, .serial = 0 },
        .scope = .synced,
        .status = .active,
        .local_unlock_required = true,
        .phishing_resistant = true,
        .synced_to_device_graph = false,
        .hardware_backed_credential = false,
        .sealed_credential_secret = false,
        .relying_party_id_len = 0,
        .relying_party_id = [_]u8{0} ** MAX_RP_ID_BYTES,
        .label_len = 0,
        .label = [_]u8{0} ** MAX_LABEL_BYTES,
        .secret_id = 0,
        .sealed_secret_digest = crypto_hash.zero_digest,
        .credential_public_key = [_]u8{0} ** signing.PUBLIC_KEY_BYTES,
        .credential_digest = crypto_hash.zero_digest,
        .credential_generation = 1,
        .assertion_count = 0,
        .created_at_ticks = 0,
        .last_asserted_at_ticks = 0,
        .recovered_at_ticks = 0,
        .revoked_at_ticks = 0,
    };
}

fn credentialDigest(
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    scope: CredentialScope,
    relying_party_id: []const u8,
    public_key: *const [signing.PUBLIC_KEY_BYTES]u8,
    sealed_secret_digest: *const crypto_hash.Digest,
    generation: u32,
    recovery_threshold: u8,
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "domain", "zigos.identity.credential.v1");
    crypto_hash.updateInt(&hasher, "recovery-threshold", recovery_threshold);
    crypto_hash.updateEnum(&hasher, "owner-kind", owner.kind);
    crypto_hash.updateInt(&hasher, "owner-serial", owner.serial);
    crypto_hash.updateEnum(&hasher, "device-kind", device.kind);
    crypto_hash.updateInt(&hasher, "device-serial", device.serial);
    crypto_hash.updateEnum(&hasher, "credential-scope", scope);
    crypto_hash.updateBytes(&hasher, "relying-party-id", relying_party_id);
    crypto_hash.updateBytes(&hasher, "credential-public-key", public_key);
    crypto_hash.updateBytes(&hasher, "sealed-secret-digest", sealed_secret_digest);
    crypto_hash.updateInt(&hasher, "credential-generation", generation);
    return crypto_hash.finalize(&hasher);
}

fn localUnlockDigest(proof: *const LocalUnlockProof) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "domain", "zigos.identity.local-unlock.v2");
    crypto_hash.updateBytes(&hasher, "boot-instance", &proof.context.boot_instance);
    crypto_hash.updateBytes(&hasher, "session-nonce", &proof.context.session_nonce);
    crypto_hash.updateEnum(&hasher, "owner-kind", proof.owner.kind);
    crypto_hash.updateInt(&hasher, "owner-serial", proof.owner.serial);
    crypto_hash.updateEnum(&hasher, "device-kind", proof.device.kind);
    crypto_hash.updateInt(&hasher, "device-serial", proof.device.serial);
    crypto_hash.updateBytes(&hasher, "relying-party-id", proof.relyingPartySlice());
    crypto_hash.updateBytes(&hasher, "challenge", proof.challengeSlice());
    crypto_hash.updateEnum(&hasher, "unlock-method", proof.method);
    crypto_hash.updateInt(&hasher, "issued-at", proof.issued_at_ticks);
    crypto_hash.updateInt(&hasher, "expires-at", proof.expires_at_ticks);
    return crypto_hash.finalize(&hasher);
}

fn signingSecret(authority: VaultAuthority, handle_id: u64, owner: principal.PrincipalId) Error!*const secure_secret_store.SecretRecord {
    if (authority.holder.kind != .service) return error.InvalidIdentityAuthority;
    const handle = authority.vault.findHandle(handle_id) orelse return error.VaultHandleNotFound;
    const secret = authority.vault.store.describeSecret(handle.secret_id) orelse return error.SecretNotFound;
    if (!secret.owner.eql(owner)) return error.SecretOwnerMismatch;
    if (!secret.hardware_backed or !secret.hardware_provider_used or !secret.sealed_digest_present or
        secret.exportable or secret.resident_material or secret.sealedBlob() == null) return error.CredentialKeyCustodyRequired;
    return secret;
}

fn signThroughVault(authority: VaultAuthority, handle_id: u64, digest: *const crypto_hash.Digest) Error!manifest.Signature {
    return authority.vault.signDigest(authority.policies, authority.subjects, .{
        .holder = authority.holder,
        .task_id = authority.task_id,
        .handle_id = handle_id,
        .digest = digest.*,
        .now_ticks = authority.now_ticks,
    }, authority.ledger);
}

fn recoveryIntentDigest(credential: *const CredentialRecord, recovery_device: principal.PrincipalId, secret: *const secure_secret_store.SecretRecord) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "domain", "zigos.identity.recovery-intent.v1");
    crypto_hash.updateInt(&hasher, "credential-id", credential.id);
    crypto_hash.updateBytes(&hasher, "credential-digest", &credential.credential_digest);
    crypto_hash.updateInt(&hasher, "generation", credential.credential_generation);
    crypto_hash.updateInt(&hasher, "threshold", credential.recovery_threshold);
    crypto_hash.updateEnum(&hasher, "recovery-device-kind", recovery_device.kind);
    crypto_hash.updateInt(&hasher, "recovery-device-serial", recovery_device.serial);
    crypto_hash.updateInt(&hasher, "replacement-secret-id", secret.id);
    crypto_hash.updateBytes(&hasher, "replacement-sealed-digest", &secret.sealed_digest);
    return crypto_hash.finalize(&hasher);
}

fn credentialPublicKey(authority: VaultAuthority, handle_id: u64, credential: *const CredentialRecord) Error!signing.PublicKey {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "domain", "zigos.identity.key-binding.v1");
    crypto_hash.updateInt(&hasher, "credential-id", credential.id);
    crypto_hash.updateEnum(&hasher, "owner-kind", credential.owner.kind);
    crypto_hash.updateInt(&hasher, "owner-serial", credential.owner.serial);
    crypto_hash.updateEnum(&hasher, "device-kind", credential.primary_device.kind);
    crypto_hash.updateInt(&hasher, "device-serial", credential.primary_device.serial);
    crypto_hash.updateEnum(&hasher, "scope", credential.scope);
    crypto_hash.updateBytes(&hasher, "relying-party-id", credential.relyingPartySlice());
    crypto_hash.updateBytes(&hasher, "sealed-secret-digest", &credential.sealed_secret_digest);
    crypto_hash.updateInt(&hasher, "generation", credential.credential_generation);
    crypto_hash.updateInt(&hasher, "recovery-threshold", credential.recovery_threshold);
    const digest = crypto_hash.finalize(&hasher);
    const signature = try signThroughVault(authority, handle_id, &digest);
    if (!signing.verify(signature, &digest) or signature.public_key_len != signing.PUBLIC_KEY_BYTES) return error.InvalidCredentialSignature;
    return signature.public_key[0..signing.PUBLIC_KEY_BYTES].*;
}

pub fn verifyAssertion(assertion: *const Assertion, expected_public_key: *const signing.PublicKey) bool {
    if (assertion.relying_party_id_len > MAX_RP_ID_BYTES or assertion.origin_len > MAX_ORIGIN_BYTES or
        assertion.challenge_len == 0 or assertion.challenge_len > MAX_CHALLENGE_BYTES) return false;
    if (assertion.signature.public_key_len != signing.PUBLIC_KEY_BYTES or
        !std.mem.eql(u8, assertion.signature.publicKeySlice(), expected_public_key)) return false;
    const digest = assertionDigest(assertion);
    return signing.verify(assertion.signature, &digest);
}

fn assertionDigest(assertion: *const Assertion) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "domain", "zigos.identity.assertion.v1");
    crypto_hash.updateInt(&hasher, "credential-id", assertion.credential_id);
    crypto_hash.updateEnum(&hasher, "owner-kind", assertion.owner.kind);
    crypto_hash.updateInt(&hasher, "owner-serial", assertion.owner.serial);
    crypto_hash.updateEnum(&hasher, "device-kind", assertion.device.kind);
    crypto_hash.updateInt(&hasher, "device-serial", assertion.device.serial);
    crypto_hash.updateInt(&hasher, "generation", assertion.credential_generation);
    crypto_hash.updateInt(&hasher, "assertion-counter", assertion.assertion_counter);
    crypto_hash.updateBytes(&hasher, "relying-party-id", assertion.relyingPartySlice());
    crypto_hash.updateBytes(&hasher, "origin", assertion.originSlice());
    crypto_hash.updateBytes(&hasher, "challenge", assertion.challengeSlice());
    crypto_hash.updateBool(&hasher, "local-unlock-verified", assertion.local_unlock_verified);
    crypto_hash.updateBool(&hasher, "phishing-resistant", assertion.phishing_resistant);
    crypto_hash.updateBool(&hasher, "hardware-backed-credential", assertion.hardware_backed_credential);
    crypto_hash.updateBool(&hasher, "device-platform-backed", assertion.device_platform_backed);
    crypto_hash.updateBool(&hasher, "primary-device-assertion", assertion.primary_device_assertion);
    crypto_hash.updateInt(&hasher, "device-trust-generation", assertion.device_trust_generation);
    crypto_hash.updateInt(&hasher, "unlock-age-ticks", assertion.unlock_age_ticks);
    return crypto_hash.finalize(&hasher);
}

// Credential callers supply canonical HTTPS origins and ASCII DNS names
// (including already encoded IDNA labels). Reject URL paths and user-info.
fn originMatchesRelyingParty(origin: []const u8, relying_party_id: []const u8) bool {
    const https = "https://";
    if (!std.mem.startsWith(u8, origin, https) or !validDnsName(relying_party_id)) return false;
    const authority = origin[https.len..];
    const end = std.mem.indexOfScalar(u8, authority, ':') orelse authority.len;
    const host = authority[0..end];
    if (!validDnsName(host)) return false;
    if (end < authority.len) {
        const port = authority[end + 1 ..];
        if (port.len == 0 or port.len > 5 or port[0] == '0') return false;
        for (port) |byte| if (byte < '0' or byte > '9') return false;
        _ = std.fmt.parseInt(u16, port, 10) catch return false;
    }
    if (std.mem.eql(u8, host, relying_party_id)) return true;
    return host.len > relying_party_id.len + 1 and
        std.mem.endsWith(u8, host, relying_party_id) and
        host[host.len - relying_party_id.len - 1] == '.';
}

fn validDnsName(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    var label_len: usize = 0;
    var previous: u8 = 0;
    for (name) |byte| {
        if (byte == '.') {
            if (label_len == 0 or previous == '-') return false;
            label_len = 0;
        } else {
            if (!(byte >= 'a' and byte <= 'z') and !(byte >= '0' and byte <= '9') and byte != '-') return false;
            if (label_len == 0 and byte == '-') return false;
            label_len += 1;
            if (label_len > 63) return false;
        }
        previous = byte;
    }
    return label_len != 0 and previous != '-';
}

const identity_keys = @import("../../tests/fixtures/identity_vault.zig");

fn testHardwareProvider() secure_secret_store.HardwareSealProvider {
    return @import("../../tests/fixtures/secret_provider.zig").provider();
}

test "os identity keeps proof and assertion metadata compact" {
    try std.testing.expectEqual(u8, @FieldType(LocalUnlockProof, "relying_party_id_len"));
    try std.testing.expectEqual(u8, @FieldType(LocalUnlockProof, "challenge_len"));
    try std.testing.expectEqual(u8, @FieldType(Assertion, "relying_party_id_len"));
    try std.testing.expectEqual(u8, @FieldType(Assertion, "origin_len"));
    try std.testing.expectEqual(u8, @FieldType(Assertion, "challenge_len"));
    try std.testing.expect(@sizeOf(LocalUnlockProof) <= LOCAL_UNLOCK_PROOF_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(Assertion) <= ASSERTION_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(AssertionRequest) <= ASSERTION_REQUEST_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(RecoveryApproval) <= RECOVERY_APPROVAL_SIZE_CEILING_BYTES);
    try std.testing.expect(@sizeOf(RecoveryRequest) <= RECOVERY_REQUEST_SIZE_CEILING_BYTES);
}

test "os identity creates passkey credentials and rejects phishing origins" {
    try std.testing.expect(std.meta.stringToEnum(UnlockMethod, "password") == null);

    var graph = device_graph.Graph.init();
    var secrets = vault_service.Service.init();
    const policies = policy_object.Directory.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 701 };
    const authority = identity_keys.context(&secrets, &policies, user);
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 711 };
    const user_identity = signing.SignerIdentity{
        .label = "passkey-user",
        .seed = signing.seedFromByte(0xA1),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "passkey-laptop",
        .seed = signing.seedFromByte(0xA2),
    };
    const credential_identity = signing.SignerIdentity{
        .label = "accounts.example-passkey",
        .seed = signing.seedFromByte(0xA3),
    };
    const handle_credential_identity = try identity_keys.provision(authority, user, credential_identity);

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);
    const credential = try identities.registerCredential(&graph, identity_keys.at(authority, 2), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .label = "accounts-passkey",
        .scope = .synced,
        .key_handle_id = handle_credential_identity,
    });
    try std.testing.expect(credential.local_unlock_required);
    try std.testing.expect(credential.phishing_resistant);
    try std.testing.expect(credential.isRecoverableThroughDeviceGraph());
    try std.testing.expect(!std.mem.allEqual(u8, &credential.sealed_secret_digest, 0));

    const unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, laptop, "accounts.example", "nonce-1", .biometric, 3, 8, laptop_identity);
    const assertion = try identities.assertCredential(&graph, identity_keys.at(authority, 4), .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://login.accounts.example",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .key_handle_id = handle_credential_identity,
    });
    try std.testing.expect(assertion.local_unlock_verified);
    try std.testing.expect(assertion.phishing_resistant);
    try std.testing.expect(assertion.hardware_backed_credential);
    try std.testing.expect(!assertion.device_platform_backed);
    try std.testing.expect(assertion.primary_device_assertion);
    try std.testing.expectEqual(@as(u32, 1), assertion.device_trust_generation);
    try std.testing.expectEqual(@as(u64, 1), assertion.unlock_age_ticks);
    try std.testing.expectEqual(@as(u64, 1), assertion.assertion_counter);
    try std.testing.expectEqualStrings("accounts.example", assertion.relyingPartySlice());

    try std.testing.expectError(error.PhishingOriginRejected, identities.assertCredential(&graph, identity_keys.at(authority, 5), .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example.evil.test",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .key_handle_id = handle_credential_identity,
    }));
    try std.testing.expectError(error.LocalUnlockRequired, identities.assertCredential(&graph, identity_keys.at(authority, 5), .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "nonce-1",
        .key_handle_id = handle_credential_identity,
    }));
}

test "os identity registration rejects overlong text without consuming credential ids" {
    var graph = device_graph.Graph.init();
    var secrets = vault_service.Service.init();
    const policies = policy_object.Directory.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 751 };
    const authority = identity_keys.context(&secrets, &policies, user);
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 761 };
    const user_identity = signing.SignerIdentity{
        .label = "oversized-user",
        .seed = signing.seedFromByte(0xD1),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "oversized-laptop",
        .seed = signing.seedFromByte(0xD2),
    };
    const credential_identity = signing.SignerIdentity{
        .label = "oversized-passkey",
        .seed = signing.seedFromByte(0xD3),
    };
    const oversized_relying_party = [_]u8{'r'} ** (MAX_RP_ID_BYTES + 1);
    const oversized_label = [_]u8{'l'} ** (MAX_LABEL_BYTES + 1);

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);

    try std.testing.expectError(error.RelyingPartyTooLong, identities.registerCredential(&graph, identity_keys.at(authority, 2), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = oversized_relying_party[0..],
        .label = "accounts-passkey",
        .scope = .synced,
        .key_handle_id = 0,
    }));
    try std.testing.expectError(error.LabelTooLong, identities.registerCredential(&graph, identity_keys.at(authority, 3), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .label = oversized_label[0..],
        .scope = .synced,
        .key_handle_id = 0,
    }));
    try std.testing.expect(identities.findCredential(1) == null);
    try std.testing.expect(secrets.store.describeSecret(1) == null);

    const handle_credential_identity = try identity_keys.provision(authority, user, credential_identity);
    const credential = try identities.registerCredential(&graph, identity_keys.at(authority, 4), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .label = "accounts-passkey",
        .scope = .synced,
        .key_handle_id = handle_credential_identity,
    });
    try std.testing.expectEqual(@as(u64, 1), credential.id);
    try std.testing.expectEqual(@as(u64, 1), credential.secret_id);
    try std.testing.expect(identities.findCredential(2) == null);
    try std.testing.expect(secrets.store.describeSecret(2) == null);
}

test "os identity full credential table does not consume secrets" {
    var graph = device_graph.Graph.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 771 };
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 781 };
    const user_identity = signing.SignerIdentity{
        .label = "wrap-user",
        .seed = signing.seedFromByte(0xE1),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "wrap-laptop",
        .seed = signing.seedFromByte(0xE2),
    };

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);

    var full_identities = Store.init();
    var full_secrets = vault_service.Service.init();
    const policies = policy_object.Directory.init();
    const authority = identity_keys.context(&full_secrets, &policies, user);
    for (0..MAX_CREDENTIALS) |index| {
        const credential_id: u64 = @intCast(index + 1);
        full_identities.credentials[index] = zeroCredential();
        full_identities.credentials[index].id = credential_id;
    }
    full_identities.credential_count = @intCast(MAX_CREDENTIALS);
    try std.testing.expect(full_identities.findCredential(0) == null);
    try std.testing.expect(full_identities.findCredential(MAX_CREDENTIALS + 1) == null);
    try std.testing.expect(full_secrets.store.describeSecret(1) == null);
    try std.testing.expectError(error.CredentialTableFull, full_identities.registerCredential(&graph, identity_keys.at(authority, 5), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "wrap.example",
        .label = "wrap-passkey-full",
        .scope = .synced,
        .key_handle_id = 0,
    }));
    try std.testing.expectEqual(MAX_CREDENTIALS, full_identities.countCredentials());
    try std.testing.expect(full_secrets.store.describeSecret(1) == null);
}

test "os identity recovers synced credentials through trusted device graph" {
    var graph = device_graph.Graph.init();
    var secrets = vault_service.Service.init();
    const policies = policy_object.Directory.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 801 };
    const authority = identity_keys.context(&secrets, &policies, user);
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 811 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 812 };
    const user_identity = signing.SignerIdentity{
        .label = "recover-user",
        .seed = signing.seedFromByte(0xB1),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "recover-laptop",
        .seed = signing.seedFromByte(0xB2),
    };
    const phone_identity = signing.SignerIdentity{
        .label = "recover-phone",
        .seed = signing.seedFromByte(0xB3),
    };
    const first_credential_identity = signing.SignerIdentity{
        .label = "recover-passkey-v1",
        .seed = signing.seedFromByte(0xB4),
    };
    const handle_first_credential_identity = try identity_keys.provision(authority, user, first_credential_identity);
    const replacement_credential_identity = signing.SignerIdentity{
        .label = "recover-passkey-v2",
        .seed = signing.seedFromByte(0xB5),
    };
    const handle_replacement_credential_identity = try identity_keys.provision(authority, user, replacement_credential_identity);

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);
    _ = try graph.enrollDevice(user, phone, "phone", user_identity, phone_identity, 2);
    const synced = try identities.registerCredential(&graph, identity_keys.at(authority, 3), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "zigos.dev",
        .label = "zigos-passkey",
        .scope = .synced,
        .recovery_threshold = 2,
        .key_handle_id = handle_first_credential_identity,
    });
    const first_digest = synced.credential_digest;
    const bound = try identities.registerCredential(&graph, identity_keys.at(authority, 4), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "admin.zigos.dev",
        .label = "admin-device-key",
        .scope = .device_bound,
        .key_handle_id = handle_first_credential_identity,
    });

    const recovery_challenge = try identities.recoveryChallenge(authority, synced.id, phone, handle_replacement_credential_identity);
    const recovery_unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "zigos.dev", &recovery_challenge, .recovery_key, 5, 10, phone_identity);
    try std.testing.expectError(error.RecoveryThresholdNotMet, identities.recoverCredential(&graph, identity_keys.at(authority, 6), .{
        .credential_id = synced.id,
        .recovery_device = phone,
        .relying_party_id = "zigos.dev",
        .local_unlock = recovery_unlock,
        .replacement_key_handle_id = handle_replacement_credential_identity,
    }));

    const laptop_recovery_unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, laptop, "zigos.dev", &recovery_challenge, .recovery_key, 5, 10, laptop_identity);
    const approvals = [_]RecoveryApproval{
        .{
            .device = laptop,
            .local_unlock = laptop_recovery_unlock,
        },
    };
    const recovered = try identities.recoverCredential(&graph, identity_keys.at(authority, 6), .{
        .credential_id = synced.id,
        .recovery_device = phone,
        .relying_party_id = "zigos.dev",
        .local_unlock = recovery_unlock,
        .approvals = &approvals,
        .replacement_key_handle_id = handle_replacement_credential_identity,
    });
    try std.testing.expectEqual(phone, recovered.primary_device);
    try std.testing.expectEqual(@as(u32, 2), recovered.credential_generation);
    try std.testing.expectEqual(@as(u64, 6), recovered.recovered_at_ticks);
    try std.testing.expect(!std.mem.eql(u8, first_digest[0..], recovered.credential_digest[0..]));

    const unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "zigos.dev", "nonce-2", .device_pin, 7, 11, phone_identity);
    const assertion = try identities.assertCredential(&graph, identity_keys.at(authority, 8), .{
        .credential_id = synced.id,
        .device = phone,
        .relying_party_id = "zigos.dev",
        .origin = "https://zigos.dev",
        .challenge = "nonce-2",
        .local_unlock = unlock,
        .key_handle_id = handle_replacement_credential_identity,
    });
    try std.testing.expectEqual(@as(u32, 2), assertion.credential_generation);
    try std.testing.expect(assertion.hardware_backed_credential);
    try std.testing.expect(assertion.primary_device_assertion);
    try std.testing.expectEqual(@as(u64, 1), assertion.unlock_age_ticks);

    const bound_recovery_unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "admin.zigos.dev", "recover-bound", .recovery_key, 9, 12, phone_identity);
    try std.testing.expectError(error.DeviceBoundRecoveryDenied, identities.recoverCredential(&graph, identity_keys.at(authority, 10), .{
        .credential_id = bound.id,
        .recovery_device = phone,
        .relying_party_id = "admin.zigos.dev",
        .local_unlock = bound_recovery_unlock,
        .replacement_key_handle_id = handle_replacement_credential_identity,
    }));
}

test "os identity keeps dense credentials searchable and rejects full tables before secret import" {
    var graph = device_graph.Graph.init();
    var secrets = vault_service.Service.init();
    const policies = policy_object.Directory.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 851 };
    const authority = identity_keys.context(&secrets, &policies, user);
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 861 };
    const user_identity = signing.SignerIdentity{
        .label = "full-user",
        .seed = signing.seedFromByte(0xD1),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "full-laptop",
        .seed = signing.seedFromByte(0xD2),
    };

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);

    var index: usize = 0;
    while (index < MAX_CREDENTIALS) : (index += 1) {
        const credential_identity = signing.SignerIdentity{
            .label = "full-passkey",
            .seed = signing.seedFromByte(@intCast(0x10 + index)),
        };
        const handle_credential_identity = try identity_keys.provision(authority, user, credential_identity);
        const credential = try identities.registerCredential(&graph, identity_keys.at(authority, 20 + @as(u64, @intCast(index))), .{
            .owner = user,
            .device = laptop,
            .relying_party_id = "full.example",
            .label = "full-passkey",
            .scope = .synced,
            .key_handle_id = handle_credential_identity,
        });
        try std.testing.expectEqual(credential.id, identities.findCredentialConst(credential.id).?.id);
    }

    try std.testing.expectEqual(@as(usize, MAX_CREDENTIALS), identities.countCredentials());
    try std.testing.expectEqual(@as(u64, 1), identities.findCredentialConst(1).?.id);
    try std.testing.expectEqual(@as(u64, MAX_CREDENTIALS), identities.findCredentialConst(MAX_CREDENTIALS).?.id);
    try std.testing.expect(identities.findCredentialConst(MAX_CREDENTIALS + 1) == null);
    try std.testing.expectError(error.CredentialTableFull, identities.registerCredential(&graph, identity_keys.at(authority, 99), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "full.example",
        .label = "overflow-passkey",
        .scope = .synced,
        .key_handle_id = 0,
    }));
    try std.testing.expectEqual(@as(usize, MAX_CREDENTIALS), identities.countCredentials());
    try std.testing.expect(@sizeOf(Store) <= STORE_SIZE_CEILING_BYTES);
}

test "os identity requires fresh local unlock and primary device for device-bound credentials" {
    var graph = device_graph.Graph.init();
    var secrets = vault_service.Service.init();
    const policies = policy_object.Directory.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 901 };
    const authority = identity_keys.context(&secrets, &policies, user);
    const laptop = principal.PrincipalId{ .kind = .device, .serial = 911 };
    const phone = principal.PrincipalId{ .kind = .device, .serial = 912 };
    const user_identity = signing.SignerIdentity{
        .label = "bound-user",
        .seed = signing.seedFromByte(0xC1),
    };
    const laptop_identity = signing.SignerIdentity{
        .label = "bound-laptop",
        .seed = signing.seedFromByte(0xC2),
    };
    const phone_identity = signing.SignerIdentity{
        .label = "bound-phone",
        .seed = signing.seedFromByte(0xC3),
    };
    const credential_identity = signing.SignerIdentity{
        .label = "bound-passkey",
        .seed = signing.seedFromByte(0xC4),
    };
    const handle_credential_identity = try identity_keys.provision(authority, user, credential_identity);

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);
    _ = try graph.enrollDevice(user, phone, "phone", user_identity, phone_identity, 2);
    const credential = try identities.registerCredential(&graph, identity_keys.at(authority, 3), .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "device.example",
        .label = "device-bound-passkey",
        .scope = .device_bound,
        .key_handle_id = handle_credential_identity,
    });
    const phone_unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, phone, "device.example", "nonce-3", .biometric, 4, 8, phone_identity);
    try std.testing.expectError(error.DeviceBoundCredentialWrongDevice, identities.assertCredential(&graph, identity_keys.at(authority, 5), .{
        .credential_id = credential.id,
        .device = phone,
        .relying_party_id = "device.example",
        .origin = "https://device.example",
        .challenge = "nonce-3",
        .local_unlock = phone_unlock,
        .key_handle_id = handle_credential_identity,
    }));

    const expired_unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, user, laptop, "device.example", "nonce-4", .biometric, 4, 5, laptop_identity);
    try std.testing.expectError(error.LocalUnlockExpired, identities.assertCredential(&graph, identity_keys.at(authority, 6), .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "device.example",
        .origin = "https://device.example",
        .challenge = "nonce-4",
        .local_unlock = expired_unlock,
        .key_handle_id = handle_credential_identity,
    }));
}

const VaultIdentityFixture = if (@import("builtin").is_test) struct {
    graph: device_graph.Graph = device_graph.Graph.init(),
    vault: vault_service.Service = vault_service.Service.init(),
    policies: policy_object.Directory = policy_object.Directory.init(),
    identities: Store = Store.init(),
    handle_id: u64 = 0,
    credential_id: u64 = 0,
    unlock_session: unlock_context.Session = identity_keys.unlock_session,

    const owner = principal.PrincipalId{ .kind = .user, .serial = 1201 };
    const device = principal.PrincipalId{ .kind = .device, .serial = 1202 };
    const owner_key = signing.SignerIdentity{ .label = "identity-test-owner", .seed = @splat(0x51) };
    const device_key = signing.SignerIdentity{ .label = "identity-test-device", .seed = @splat(0x52) };
    const credential_key = signing.SignerIdentity{ .label = "identity-test-credential", .seed = @splat(0x53) };

    fn init() !VaultIdentityFixture {
        var self = VaultIdentityFixture{};
        self.vault.attachHardwareProvider(testHardwareProvider());
        _ = try self.graph.ensureUserRoot(owner, "owner", owner_key);
        _ = try self.graph.enrollDevice(owner, device, "device", owner_key, device_key, 1);
        self.handle_id = try identity_keys.provision(self.authority(1), owner, credential_key);
        const record = try self.identities.registerCredential(&self.graph, self.authority(2), .{
            .owner = owner,
            .device = device,
            .relying_party_id = "accounts.example",
            .label = "account",
            .key_handle_id = self.handle_id,
        });
        self.credential_id = record.id;
        return self;
    }

    fn authority(self: *VaultIdentityFixture, tick: u64) VaultAuthority {
        var result = identity_keys.at(identity_keys.context(&self.vault, &self.policies, owner), tick);
        result.unlock_session = &self.unlock_session;
        return result;
    }

    fn request(self: *const VaultIdentityFixture) !AssertionRequest {
        return .{
            .credential_id = self.credential_id,
            .device = device,
            .relying_party_id = "accounts.example",
            .origin = "https://accounts.example",
            .challenge = "nonce",
            .local_unlock = try createLocalUnlockProofForVerification(try self.unlock_session.binding(), owner, device, "accounts.example", "nonce", .device_pin, 2, 2000, device_key),
            .key_handle_id = self.handle_id,
        };
    }
} else void;

test "os identity signs every assertion claim through the sealed vault key" {
    try std.testing.expect(!@hasField(AssertionRequest, "credential_identity"));
    try std.testing.expect(!@hasField(RegisterCredentialRequest, "credential_identity"));
    try std.testing.expect(!@hasField(RecoveryRequest, "replacement_credential_identity"));
    try std.testing.expect(!@hasField(RecoveryRequest, "threshold"));
    try std.testing.expect(!@hasField(AssertionRequest, "tick"));
    var fixture = try VaultIdentityFixture.init();
    const request = try fixture.request();
    const assertion = try fixture.identities.assertCredential(&fixture.graph, fixture.authority(3), request);
    const record = fixture.identities.findCredential(fixture.credential_id).?;
    try std.testing.expect(verifyAssertion(&assertion, &record.credential_public_key));
    try std.testing.expectEqual(@as(u64, 1), assertion.assertion_counter);
    var changed = assertion;
    changed.assertion_counter += 1;
    try std.testing.expect(!verifyAssertion(&changed, &record.credential_public_key));
    changed = assertion;
    changed.credential_generation += 1;
    try std.testing.expect(!verifyAssertion(&changed, &record.credential_public_key));
    changed = assertion;
    changed.device_trust_generation += 1;
    try std.testing.expect(!verifyAssertion(&changed, &record.credential_public_key));
    changed = assertion;
    changed.unlock_age_ticks += 1;
    try std.testing.expect(!verifyAssertion(&changed, &record.credential_public_key));
    inline for (.{ "local_unlock_verified", "phishing_resistant", "hardware_backed_credential", "device_platform_backed", "primary_device_assertion" }) |field| {
        changed = assertion;
        @field(changed, field) = !@field(changed, field);
        try std.testing.expect(!verifyAssertion(&changed, &record.credential_public_key));
    }
    inline for (.{ "relying_party_id", "origin", "challenge" }) |field| {
        changed = assertion;
        @field(changed, field)[0] ^= 1;
        try std.testing.expect(!verifyAssertion(&changed, &record.credential_public_key));
    }
    changed = assertion;
    changed.challenge_len = MAX_CHALLENGE_BYTES + 1;
    try std.testing.expect(!verifyAssertion(&changed, &record.credential_public_key));
    const wrong_key = [_]u8{0x91} ** signing.PUBLIC_KEY_BYTES;
    try std.testing.expect(!verifyAssertion(&assertion, &wrong_key));
}

test "os identity rejects an unlock proof captured before a verifier restart" {
    var before = try VaultIdentityFixture.init();
    const old_request = try before.request();
    _ = try before.identities.assertCredential(&before.graph, before.authority(3), old_request);
    var after = try VaultIdentityFixture.init();
    after.unlock_session.current.boot_instance[0] ^= 1;
    try std.testing.expectError(error.UnlockContextMismatch, after.identities.assertCredential(&after.graph, after.authority(3), old_request));
}

test "os identity binds unlock signatures to live sessions and rejects proof transplantation" {
    var fixture = try VaultIdentityFixture.init();
    const request = try fixture.request();
    const captured_authority = fixture.authority(3);
    fixture.unlock_session.lock();
    try std.testing.expectError(error.UnlockContextUnavailable, fixture.identities.assertCredential(&fixture.graph, captured_authority, request));
    fixture.unlock_session.current.session_nonce[0] ^= 1;
    fixture.unlock_session.active = true;
    try std.testing.expectError(error.UnlockContextMismatch, fixture.identities.assertCredential(&fixture.graph, captured_authority, request));
    var transplanted = request;
    transplanted.local_unlock.?.context = try fixture.unlock_session.binding();
    try std.testing.expectError(error.InvalidLocalUnlock, fixture.identities.assertCredential(&fixture.graph, captured_authority, transplanted));
    try std.testing.expectEqual(@as(u64, 0), fixture.identities.findCredentialConst(1).?.assertion_count);
    const accepted = try fixture.identities.assertCredential(&fixture.graph, captured_authority, try fixture.request());
    try std.testing.expectEqual(@as(u64, 1), accepted.assertion_counter);
}

test "os identity issues unlock proofs only through the enrolled device key lease" {
    var fixture = try VaultIdentityFixture.init();
    const device_handle = try identity_keys.provision(fixture.authority(3), VaultIdentityFixture.owner, VaultIdentityFixture.device_key);
    const request = UnlockRequest{ .owner = VaultIdentityFixture.owner, .device = VaultIdentityFixture.device, .relying_party_id = "accounts.example", .challenge = "nonce", .method = .device_pin, .expires_at_ticks = 20, .key_handle_id = device_handle };
    const proof = try issueLocalUnlockProof(&fixture.graph, fixture.authority(3), request);
    var assertion = try fixture.request();
    assertion.local_unlock = proof;
    _ = try fixture.identities.assertCredential(&fixture.graph, fixture.authority(4), assertion);
    var wrong_key = request;
    wrong_key.key_handle_id = fixture.handle_id;
    try std.testing.expectError(error.InvalidLocalUnlock, issueLocalUnlockProof(&fixture.graph, fixture.authority(3), wrong_key));
    fixture.vault.findHandle(device_handle).?.expires_at_ticks = 3;
    try std.testing.expectError(error.HandleExpired, issueLocalUnlockProof(&fixture.graph, fixture.authority(3), request));
    fixture.vault.findHandle(device_handle).?.expires_at_ticks = 100;
    fixture.vault.findHandle(device_handle).?.revoked = true;
    try std.testing.expectError(error.HandleRevoked, issueLocalUnlockProof(&fixture.graph, fixture.authority(3), request));
    fixture.unlock_session.lock();
    try std.testing.expectError(error.UnlockContextUnavailable, issueLocalUnlockProof(&fixture.graph, fixture.authority(3), request));
}

test "os identity recovery requires every approval to bind the current verifier session" {
    var fixture = try VaultIdentityFixture.init();
    const owner = VaultIdentityFixture.owner;
    const device = VaultIdentityFixture.device;
    const phone = principal.PrincipalId{ .kind = .device, .serial = 1203 };
    const phone_key = signing.SignerIdentity{ .label = "phone", .seed = @splat(0x65) };
    _ = try fixture.graph.enrollDevice(owner, phone, "phone", VaultIdentityFixture.owner_key, phone_key, 2);
    fixture.identities = .init();
    _ = try fixture.identities.registerCredential(&fixture.graph, fixture.authority(2), .{ .owner = owner, .device = device, .relying_party_id = "accounts.example", .label = "account", .recovery_threshold = 2, .key_handle_id = fixture.handle_id });
    const replacement = try identity_keys.provision(fixture.authority(2), owner, .{ .label = "replacement", .seed = @splat(0x71) });
    const challenge = try fixture.identities.recoveryChallenge(fixture.authority(3), 1, device, replacement);
    const old_phone = try createLocalUnlockProofForVerification(try fixture.unlock_session.binding(), owner, phone, "accounts.example", &challenge, .recovery_key, 2, 10, phone_key);
    fixture.unlock_session.current.session_nonce[0] ^= 1;
    var approvals = [_]RecoveryApproval{.{ .device = phone, .local_unlock = old_phone }};
    const request = RecoveryRequest{ .credential_id = 1, .recovery_device = device, .relying_party_id = "accounts.example", .replacement_key_handle_id = replacement, .approvals = &approvals, .local_unlock = try createLocalUnlockProofForVerification(try fixture.unlock_session.binding(), owner, device, "accounts.example", &challenge, .recovery_key, 2, 10, VaultIdentityFixture.device_key) };
    try std.testing.expectError(error.UnlockContextMismatch, fixture.identities.recoverCredential(&fixture.graph, fixture.authority(3), request));
    approvals[0].local_unlock.context = try fixture.unlock_session.binding();
    try std.testing.expectError(error.InvalidLocalUnlock, fixture.identities.recoverCredential(&fixture.graph, fixture.authority(3), request));
    try std.testing.expectEqual(@as(u32, 1), fixture.identities.findCredentialConst(1).?.credential_generation);
    approvals[0].local_unlock = try createLocalUnlockProofForVerification(try fixture.unlock_session.binding(), owner, phone, "accounts.example", &challenge, .recovery_key, 2, 10, phone_key);
    const recovered = try fixture.identities.recoverCredential(&fixture.graph, fixture.authority(3), request);
    try std.testing.expectEqual(@as(u32, 2), recovered.credential_generation);
}

test "os identity snapshot preserves counters revocations and complete table bounds" {
    var fixture = try VaultIdentityFixture.init();
    const base = fixture.identities.credentials[0];
    for (&fixture.identities.credentials, 0..) |*record, index| {
        record.* = base;
        record.id = index + 1;
        record.status = if (index % 2 == 0) .active else .revoked;
        record.assertion_count = std.math.maxInt(u64) - index;
        record.credential_generation = @intCast(index + 1);
        record.relying_party_id_len = MAX_RP_ID_BYTES;
        @memset(&record.relying_party_id, 'a');
        record.relying_party_id[MAX_RP_ID_BYTES - 2] = '.';
        record.label_len = MAX_LABEL_BYTES;
        @memset(&record.label, 'k');
        record.credential_digest = snapshotCredentialDigest(record);
    }
    fixture.identities.credential_count = MAX_CREDENTIALS;
    var buffer: [MAX_SNAPSHOT_BYTES]u8 = undefined;
    const bytes = try fixture.identities.encodeSnapshot(VaultIdentityFixture.owner, &fixture.vault.store, &buffer);
    try std.testing.expectEqual(MAX_SNAPSHOT_BYTES, bytes.len);
    var recovered = Store.init();
    try recovered.restoreSnapshot(VaultIdentityFixture.owner, &fixture.vault.store, bytes);
    try std.testing.expectEqualDeep(fixture.identities, recovered);
    try std.testing.expectError(error.IdentityStoreNotEmpty, recovered.restoreSnapshot(VaultIdentityFixture.owner, &fixture.vault.store, bytes));
}

test "os identity snapshot rejects truncated noncanonical and mismatched key state" {
    var fixture = try VaultIdentityFixture.init();
    var buffer: [MAX_SNAPSHOT_BYTES]u8 = undefined;
    const bytes = try fixture.identities.encodeSnapshot(VaultIdentityFixture.owner, &fixture.vault.store, &buffer);
    for (0..bytes.len) |len| try std.testing.expectError(error.InvalidIdentitySnapshot, validateSnapshot(VaultIdentityFixture.owner, bytes[0..len]));
    const mutations = [_]struct { offset: usize, value: u8 }{
        .{ .offset = 0, .value = MAX_CREDENTIALS + 1 },
        .{ .offset = 1, .value = 255 }, // Owner kind.
        .{ .offset = 10, .value = 255 }, // Device kind.
        .{ .offset = 19, .value = 255 }, // Scope.
        .{ .offset = 20, .value = 0 }, // Recovery threshold.
        .{ .offset = 21, .value = 255 }, // Status.
        .{ .offset = 22, .value = MAX_RP_ID_BYTES + 1 },
    };
    for (mutations) |mutation| {
        const original = buffer[mutation.offset];
        buffer[mutation.offset] = mutation.value;
        try std.testing.expectError(error.InvalidIdentitySnapshot, validateSnapshot(VaultIdentityFixture.owner, bytes));
        buffer[mutation.offset] = original;
    }
    buffer[bytes.len] = 0;
    try std.testing.expectError(error.InvalidIdentitySnapshot, validateSnapshot(VaultIdentityFixture.owner, buffer[0 .. bytes.len + 1]));
    fixture.vault.store.secrets[0].sealed_digest[0] ^= 1;
    var recovered = Store.init();
    try std.testing.expectError(error.InvalidIdentitySnapshot, recovered.restoreSnapshot(VaultIdentityFixture.owner, &fixture.vault.store, bytes));
    try std.testing.expectEqual(@as(u8, 0), recovered.credential_count);
    fixture.vault.store.secrets[0].sealed_digest[0] ^= 1;
    fixture.identities.credentials[1] = fixture.identities.credentials[0];
    fixture.identities.credentials[1].id = 2;
    fixture.identities.credential_count = 2;
    const pair = try fixture.identities.encodeSnapshot(VaultIdentityFixture.owner, &fixture.vault.store, &buffer);
    const last_digest = std.mem.lastIndexOf(u8, pair, &fixture.identities.credentials[1].sealed_secret_digest).?;
    buffer[last_digest] ^= 1;
    try std.testing.expectError(error.InvalidIdentitySnapshot, recovered.restoreSnapshot(VaultIdentityFixture.owner, &fixture.vault.store, pair));
    try std.testing.expectEqual(@as(u8, 0), recovered.credential_count);
    try std.testing.expectEqualDeep(zeroCredential(), recovered.credentials[0]);
}

test "os identity vault denials leave assertion counters and timestamps unchanged" {
    var fixture = try VaultIdentityFixture.init();
    const request = try fixture.request();
    const record = fixture.identities.findCredential(fixture.credential_id).?;
    const before = record.*;
    var authority = fixture.authority(3);
    authority.holder.serial += 1;
    try std.testing.expectError(error.HandleHolderMismatch, fixture.identities.assertCredential(&fixture.graph, authority, request));
    authority = fixture.authority(3);
    authority.holder.kind = .app;
    try std.testing.expectError(error.InvalidIdentityAuthority, fixture.identities.assertCredential(&fixture.graph, authority, request));
    try std.testing.expectError(error.HandleHolderMismatch, fixture.vault.signDigest(&fixture.policies, authority.subjects, .{
        .holder = authority.holder,
        .task_id = authority.task_id,
        .handle_id = fixture.handle_id,
        .digest = @splat(0x11),
        .now_ticks = 3,
    }, null));
    authority = fixture.authority(3);
    authority.task_id += 1;
    try std.testing.expectError(error.HandleHolderMismatch, fixture.identities.assertCredential(&fixture.graph, authority, request));
    try std.testing.expectError(error.HandleExpired, fixture.identities.assertCredential(&fixture.graph, fixture.authority(1001), request));
    fixture.vault.attachHardwareProvider(.{});
    try std.testing.expectError(error.HardwareProviderUnavailable, fixture.identities.assertCredential(&fixture.graph, fixture.authority(3), request));
    fixture.vault.attachHardwareProvider(testHardwareProvider());
    var other = request;
    // Even the same seed imported as another secret cannot substitute for the
    // credential's specific secret id and sealed binding.
    other.key_handle_id = try identity_keys.provision(fixture.authority(3), VaultIdentityFixture.owner, VaultIdentityFixture.credential_key);
    try std.testing.expectError(error.CredentialKeyBindingMismatch, fixture.identities.assertCredential(&fixture.graph, fixture.authority(4), other));
    try std.testing.expectEqualDeep(before, record.*);
    record.assertion_count = std.math.maxInt(u64);
    try std.testing.expectError(error.CredentialCounterExhausted, fixture.identities.assertCredential(&fixture.graph, fixture.authority(4), request));
    record.* = before;
    try fixture.vault.revoke(.{
        .subject = VaultIdentityFixture.owner,
        .task_id = 1,
        .handle_id = fixture.handle_id,
        .secret_id = record.secret_id,
        .expected_holder = fixture.authority(4).holder,
        .expected_holder_task_id = 1,
        .now_ticks = 4,
    }, null);
    try std.testing.expectError(error.HandleRevoked, fixture.identities.assertCredential(&fixture.graph, fixture.authority(5), request));
    try std.testing.expectEqualDeep(before, record.*);
}

test "os identity rechecks both credential and vault policy before returning assertions" {
    var fixture = try VaultIdentityFixture.init();
    const request = try fixture.request();
    const policy_key = signing.SignerIdentity{ .label = "identity-policy", .seed = @splat(0x61) };
    for (0..2) |variant| {
        fixture.policies = policy_object.Directory.init();
        _ = try fixture.policies.create(.{
            .scope = .user,
            .subject_id = VaultIdentityFixture.owner.serial,
            .issuer = .{ .kind = .policy_authority, .serial = 1200 },
            .label = "identity policy",
            .credential_assertions_allowed = variant == 1,
            .secret_vault_allowed = variant == 0,
        }, policy_key);
        try std.testing.expectError(error.PolicyDenied, fixture.identities.assertCredential(&fixture.graph, fixture.authority(3), request));
        try std.testing.expectEqual(@as(u64, 0), fixture.identities.findCredential(fixture.credential_id).?.assertion_count);
    }
}

test "os identity rejects malformed origins unlock lengths and expiry boundaries" {
    var fixture = try VaultIdentityFixture.init();
    const original = try fixture.request();
    const invalid_origins = [_][]const u8{
        "https://accounts.example:443@evil.example", "https://accounts.example/path",  "https://accounts.example?query",
        "https://accounts.example:65536",            "https://accounts.example:0",     "https://accounts.example:+443",
        "https://accounts.example:",                 "https://accounts.example:0443",  "https://accounts.example.",
        "https://.accounts.example",                 "https://evil..accounts.example", "https://-bad.accounts.example",
        "https://bad-.accounts.example",             "https://evilaccounts.example",   "https://accounts.example.evil",
        "http://accounts.example",                   "https://ACCOUNTS.EXAMPLE",
    };
    for (invalid_origins) |origin| {
        var request = original;
        request.origin = origin;
        try std.testing.expectError(error.PhishingOriginRejected, fixture.identities.assertCredential(&fixture.graph, fixture.authority(3), request));
    }
    var malformed = original;
    malformed.local_unlock.?.relying_party_id_len = MAX_RP_ID_BYTES + 1;
    try std.testing.expectError(error.InvalidLocalUnlock, fixture.identities.assertCredential(&fixture.graph, fixture.authority(3), malformed));
    malformed = original;
    malformed.local_unlock.?.challenge_len = MAX_CHALLENGE_BYTES + 1;
    try std.testing.expectError(error.InvalidLocalUnlock, fixture.identities.assertCredential(&fixture.graph, fixture.authority(3), malformed));
    try std.testing.expectError(error.LocalUnlockExpired, fixture.identities.assertCredential(&fixture.graph, fixture.authority(2000), original));
    try std.testing.expectEqual(@as(u64, 0), fixture.identities.findCredential(fixture.credential_id).?.assertion_count);
    for ([_][]const u8{ "https://accounts.example", "https://login.accounts.example", "https://accounts.example:443", "https://accounts.example:8443" }) |origin| {
        var request = original;
        request.origin = origin;
        const assertion = try fixture.identities.assertCredential(&fixture.graph, fixture.authority(3), request);
        try std.testing.expect(verifyAssertion(&assertion, &fixture.identities.findCredential(fixture.credential_id).?.credential_public_key));
    }
}

test "os identity registration rejects foreign exportable and software key custody" {
    var fixture = try VaultIdentityFixture.init();
    const before = fixture.identities.credential_count;
    const owner = VaultIdentityFixture.owner;
    for (0..3) |variant| {
        const secret_owner = if (variant == 0) principal.PrincipalId{ .kind = .user, .serial = owner.serial + 1 } else owner;
        const secret = try fixture.vault.importSecret(&fixture.policies, .{}, .{
            .owner = secret_owner,
            .task_id = 1,
            .label = "other credential",
            .raw = &VaultIdentityFixture.credential_key.seed,
            .hardware_backed = variant != 1,
            .exportable = variant == 2,
            .now_ticks = 2,
        }, null);
        const handle = try fixture.vault.lendHandle(&fixture.policies, .{}, .{
            .owner = secret_owner,
            .holder = fixture.authority(2).holder,
            .task_id = 1,
            .secret_id = secret.id,
            .expires_at_ticks = 20,
            .now_ticks = 2,
        }, null);
        const request = RegisterCredentialRequest{
            .owner = owner,
            .device = VaultIdentityFixture.device,
            .relying_party_id = "accounts.example",
            .label = "other",
            .key_handle_id = handle.id,
        };
        if (variant == 0) {
            try std.testing.expectError(error.SecretOwnerMismatch, fixture.identities.registerCredential(&fixture.graph, fixture.authority(3), request));
        } else {
            try std.testing.expectError(error.CredentialKeyCustodyRequired, fixture.identities.registerCredential(&fixture.graph, fixture.authority(3), request));
        }
        try std.testing.expectEqual(before, fixture.identities.credential_count);
    }
}

test "os identity recovery binds approval to the replacement key and generation atomically" {
    var fixture = try VaultIdentityFixture.init();
    const owner = VaultIdentityFixture.owner;
    const device = VaultIdentityFixture.device;
    const replacement = try identity_keys.provision(fixture.authority(2), owner, .{ .label = "replacement", .seed = @splat(0x71) });
    const other = try identity_keys.provision(fixture.authority(2), owner, .{ .label = "other", .seed = @splat(0x72) });
    const record = fixture.identities.findCredential(fixture.credential_id).?;
    const before = record.*;
    const challenge = try fixture.identities.recoveryChallenge(fixture.authority(2), record.id, device, replacement);
    var request = RecoveryRequest{
        .credential_id = record.id,
        .recovery_device = device,
        .relying_party_id = "accounts.example",
        .local_unlock = try createLocalUnlockProofForVerification(identity_keys.unlock_session.current, owner, device, "accounts.example", &challenge, .recovery_key, 2, 10, VaultIdentityFixture.device_key),
        .replacement_key_handle_id = other,
    };
    try std.testing.expectError(error.InvalidLocalUnlock, fixture.identities.recoverCredential(&fixture.graph, fixture.authority(3), request));
    request.replacement_key_handle_id = replacement;
    fixture.vault.attachHardwareProvider(.{});
    try std.testing.expectError(error.HardwareProviderUnavailable, fixture.identities.recoverCredential(&fixture.graph, fixture.authority(3), request));
    try std.testing.expectEqualDeep(before, record.*);
    fixture.vault.attachHardwareProvider(testHardwareProvider());
    const recovered = try fixture.identities.recoverCredential(&fixture.graph, fixture.authority(3), request);
    try std.testing.expectEqual(@as(u32, 2), recovered.credential_generation);
    try std.testing.expect(!std.mem.eql(u8, &before.credential_public_key, &recovered.credential_public_key));
    try std.testing.expectError(error.InvalidLocalUnlock, fixture.identities.recoverCredential(&fixture.graph, fixture.authority(4), request));
    var assertion_request = try fixture.request();
    try std.testing.expectError(error.CredentialKeyBindingMismatch, fixture.identities.assertCredential(&fixture.graph, fixture.authority(4), assertion_request));
    assertion_request.key_handle_id = replacement;
    const assertion = try fixture.identities.assertCredential(&fixture.graph, fixture.authority(4), assertion_request);
    try std.testing.expect(verifyAssertion(&assertion, &recovered.credential_public_key));
    try std.testing.expect(!verifyAssertion(&assertion, &before.credential_public_key));
}
