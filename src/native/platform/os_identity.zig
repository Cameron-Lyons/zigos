const std = @import("std");
const crypto_hash = @import("../core/crypto_hash.zig");
const device_graph = @import("../sync/device_graph.zig");
const manifest = @import("../policy/manifest.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const secure_secret_store = @import("secure_secret_store.zig");
const signing = @import("../core/signing.zig");

pub const MAX_CREDENTIALS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 48;
pub const MAX_RP_ID_BYTES: usize = 64;
pub const MAX_ORIGIN_BYTES: usize = 96;
pub const MAX_CHALLENGE_BYTES: usize = 64;

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

pub const RegisterCredentialRequest = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    label: []const u8,
    scope: CredentialScope = .synced,
    credential_identity: signing.SignerIdentity,
    tick: u64,
};

pub const LocalUnlockProof = struct {
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    method: UnlockMethod,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    relying_party_id_len: usize,
    relying_party_id: [MAX_RP_ID_BYTES]u8,
    challenge_len: usize,
    challenge: [MAX_CHALLENGE_BYTES]u8,
    signature: manifest.Signature = .{},

    pub fn relyingPartySlice(self: *const LocalUnlockProof) []const u8 {
        return self.relying_party_id[0..self.relying_party_id_len];
    }

    pub fn challengeSlice(self: *const LocalUnlockProof) []const u8 {
        return self.challenge[0..self.challenge_len];
    }
};

pub const AssertionRequest = struct {
    credential_id: u64,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    origin: []const u8,
    challenge: []const u8,
    local_unlock: ?LocalUnlockProof = null,
    credential_identity: signing.SignerIdentity,
    tick: u64,
};

pub const RecoveryApproval = struct {
    device: principal.PrincipalId,
    local_unlock: LocalUnlockProof,
};

pub const RecoveryRequest = struct {
    credential_id: u64,
    recovery_device: principal.PrincipalId,
    relying_party_id: []const u8,
    challenge: []const u8,
    local_unlock: LocalUnlockProof,
    threshold: usize = 1,
    approvals: []const RecoveryApproval = &.{},
    replacement_credential_identity: signing.SignerIdentity,
    tick: u64,
};

pub const CredentialRecord = struct {
    id: u64,
    owner: principal.PrincipalId,
    primary_device: principal.PrincipalId,
    scope: CredentialScope,
    status: CredentialStatus = .active,
    local_unlock_required: bool = true,
    phishing_resistant: bool = true,
    synced_to_device_graph: bool = false,
    hardware_backed_credential: bool = false,
    sealed_credential_secret: bool = false,
    relying_party_id_len: usize,
    relying_party_id: [MAX_RP_ID_BYTES]u8,
    label_len: usize,
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
        return self.relying_party_id[0..self.relying_party_id_len];
    }

    pub fn labelSlice(self: *const CredentialRecord) []const u8 {
        return self.label[0..self.label_len];
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
    relying_party_id_len: usize,
    relying_party_id: [MAX_RP_ID_BYTES]u8,
    origin_len: usize,
    origin: [MAX_ORIGIN_BYTES]u8,
    challenge_len: usize,
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
        return self.relying_party_id[0..self.relying_party_id_len];
    }

    pub fn originSlice(self: *const Assertion) []const u8 {
        return self.origin[0..self.origin_len];
    }

    pub fn challengeSlice(self: *const Assertion) []const u8 {
        return self.challenge[0..self.challenge_len];
    }
};

pub const Error = error{
    ChallengeTooLong,
    CredentialNotFound,
    CredentialRevoked,
    CredentialTableFull,
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
} || secure_secret_store.Error || device_graph.Error;

const CredentialSlot = struct {
    in_use: bool = false,
    credential: CredentialRecord = zeroCredential(),
};

pub const Store = struct {
    next_credential_id: u64 = 1,
    credentials: [MAX_CREDENTIALS]CredentialSlot = [_]CredentialSlot{CredentialSlot{}} ** MAX_CREDENTIALS,

    pub fn init() Store {
        return .{};
    }

    pub fn registerCredential(
        self: *Store,
        graph: *const device_graph.Graph,
        secrets: *secure_secret_store.Store,
        request: RegisterCredentialRequest,
    ) Error!*CredentialRecord {
        _ = try requireTrustedDeviceForOwner(graph, request.owner, request.device);

        const slot = self.allocateCredential() orelse return error.CredentialTableFull;
        var credential = zeroCredential();
        credential.id = self.next_credential_id;
        self.next_credential_id += 1;
        credential.owner = request.owner;
        credential.primary_device = request.device;
        credential.scope = request.scope;
        credential.synced_to_device_graph = request.scope == .synced;
        credential.relying_party_id_len = native_util.copyTextExact(&credential.relying_party_id, request.relying_party_id) catch return error.RelyingPartyTooLong;
        credential.label_len = native_util.copyTextExact(&credential.label, request.label) catch return error.LabelTooLong;
        credential.credential_public_key = signing.publicKey(request.credential_identity) catch return error.InvalidCredentialSignature;
        credential.created_at_ticks = request.tick;

        const secret = try secrets.importSecret(
            request.owner,
            request.label,
            request.credential_identity.seed[0..],
            true,
            false,
        );
        credential.secret_id = secret.id;
        credential.hardware_backed_credential = secret.hardware_backed;
        credential.sealed_credential_secret = secret.sealed_digest_present;
        credential.sealed_secret_digest = secret.sealed_digest;
        credential.credential_digest = credentialDigest(
            credential.owner,
            credential.primary_device,
            credential.scope,
            credential.relyingPartySlice(),
            &credential.credential_public_key,
            &credential.sealed_secret_digest,
            credential.credential_generation,
        );

        slot.in_use = true;
        slot.credential = credential;
        return &slot.credential;
    }

    pub fn assertCredential(
        self: *Store,
        graph: *const device_graph.Graph,
        request: AssertionRequest,
    ) Error!Assertion {
        if (request.origin.len > MAX_ORIGIN_BYTES) return error.OriginTooLong;
        if (request.challenge.len > MAX_CHALLENGE_BYTES) return error.ChallengeTooLong;
        const credential = self.findCredential(request.credential_id) orelse return error.CredentialNotFound;
        try requireActiveCredential(credential);
        const device_record = try requireCredentialDevice(graph, credential, request.device);
        if (!std.mem.eql(u8, credential.relyingPartySlice(), request.relying_party_id)) return error.PhishingOriginRejected;
        if (!originMatchesRelyingParty(request.origin, credential.relyingPartySlice())) return error.PhishingOriginRejected;

        const unlock = request.local_unlock orelse return error.LocalUnlockRequired;
        try verifyLocalUnlock(graph, credential, request.device, unlock, request.challenge, request.tick);

        const digest = assertionDigest(
            credential.id,
            credential.owner,
            request.device,
            credential.credential_generation,
            credential.relyingPartySlice(),
            request.origin,
            request.challenge,
        );
        const signature = signing.sign(request.credential_identity, &digest) catch return error.InvalidCredentialSignature;
        if (!std.mem.eql(u8, signature.publicKeySlice(), &credential.credential_public_key)) return error.InvalidCredentialSignature;
        if (!signing.verify(signature, &digest)) return error.InvalidCredentialSignature;

        credential.assertion_count += 1;
        credential.last_asserted_at_ticks = request.tick;

        var assertion = Assertion{
            .credential_id = credential.id,
            .owner = credential.owner,
            .device = request.device,
            .credential_generation = credential.credential_generation,
            .assertion_counter = credential.assertion_count,
            .relying_party_id_len = 0,
            .relying_party_id = [_]u8{0} ** MAX_RP_ID_BYTES,
            .origin_len = 0,
            .origin = [_]u8{0} ** MAX_ORIGIN_BYTES,
            .challenge_len = 0,
            .challenge = [_]u8{0} ** MAX_CHALLENGE_BYTES,
            .signature = signature,
            .local_unlock_verified = true,
            .phishing_resistant = true,
            .hardware_backed_credential = credential.hardware_backed_credential and credential.sealed_credential_secret,
            .device_platform_backed = device_record.usesPlatformBackedKey(),
            .primary_device_assertion = credential.primary_device.eql(request.device),
            .device_trust_generation = device_record.trust_generation,
            .unlock_age_ticks = request.tick - unlock.issued_at_ticks,
        };
        assertion.relying_party_id_len = native_util.copyTextExact(&assertion.relying_party_id, credential.relyingPartySlice()) catch unreachable;
        assertion.origin_len = native_util.copyTextExact(&assertion.origin, request.origin) catch return error.OriginTooLong;
        assertion.challenge_len = native_util.copyTextExact(&assertion.challenge, request.challenge) catch return error.ChallengeTooLong;
        return assertion;
    }

    pub fn recoverCredential(
        self: *Store,
        graph: *const device_graph.Graph,
        secrets: *secure_secret_store.Store,
        request: RecoveryRequest,
    ) Error!*CredentialRecord {
        const credential = self.findCredential(request.credential_id) orelse return error.CredentialNotFound;
        try requireActiveCredential(credential);
        if (!credential.isRecoverableThroughDeviceGraph()) return error.DeviceBoundRecoveryDenied;
        if (!std.mem.eql(u8, credential.relyingPartySlice(), request.relying_party_id)) return error.PhishingOriginRejected;
        try verifyRecoveryThreshold(graph, credential, request);

        const secret = try secrets.importSecret(
            credential.owner,
            credential.labelSlice(),
            request.replacement_credential_identity.seed[0..],
            true,
            false,
        );
        credential.primary_device = request.recovery_device;
        credential.secret_id = secret.id;
        credential.sealed_secret_digest = secret.sealed_digest;
        credential.credential_public_key = signing.publicKey(request.replacement_credential_identity) catch return error.InvalidCredentialSignature;
        credential.credential_generation += 1;
        credential.recovered_at_ticks = request.tick;
        credential.credential_digest = credentialDigest(
            credential.owner,
            credential.primary_device,
            credential.scope,
            credential.relyingPartySlice(),
            &credential.credential_public_key,
            &credential.sealed_secret_digest,
            credential.credential_generation,
        );
        return credential;
    }

    pub fn revokeCredential(self: *Store, credential_id: u64, tick: u64) Error!void {
        const credential = self.findCredential(credential_id) orelse return error.CredentialNotFound;
        try requireActiveCredential(credential);
        credential.status = .revoked;
        credential.revoked_at_ticks = tick;
    }

    pub fn findCredential(self: *Store, credential_id: u64) ?*CredentialRecord {
        for (&self.credentials) |*slot| {
            if (slot.in_use and slot.credential.id == credential_id) return &slot.credential;
        }
        return null;
    }

    pub fn findCredentialConst(self: *const Store, credential_id: u64) ?*const CredentialRecord {
        for (&self.credentials) |*slot| {
            if (slot.in_use and slot.credential.id == credential_id) return &slot.credential;
        }
        return null;
    }

    fn allocateCredential(self: *Store) ?*CredentialSlot {
        for (&self.credentials) |*slot| {
            if (!slot.in_use) return slot;
        }
        return null;
    }
};

pub fn createLocalUnlockProof(
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    challenge: []const u8,
    method: UnlockMethod,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
    device_identity: signing.SignerIdentity,
) Error!LocalUnlockProof {
    if (expires_at_ticks < issued_at_ticks) return error.LocalUnlockExpired;
    var proof = LocalUnlockProof{
        .owner = owner,
        .device = device,
        .method = method,
        .issued_at_ticks = issued_at_ticks,
        .expires_at_ticks = expires_at_ticks,
        .relying_party_id_len = 0,
        .relying_party_id = [_]u8{0} ** MAX_RP_ID_BYTES,
        .challenge_len = 0,
        .challenge = [_]u8{0} ** MAX_CHALLENGE_BYTES,
        .signature = .{},
    };
    proof.relying_party_id_len = native_util.copyTextExact(&proof.relying_party_id, relying_party_id) catch return error.RelyingPartyTooLong;
    proof.challenge_len = native_util.copyTextExact(&proof.challenge, challenge) catch return error.ChallengeTooLong;
    const digest = localUnlockDigest(
        proof.owner,
        proof.device,
        proof.relyingPartySlice(),
        proof.challengeSlice(),
        proof.method,
        proof.issued_at_ticks,
        proof.expires_at_ticks,
    );
    proof.signature = signing.sign(device_identity, &digest) catch return error.InvalidLocalUnlock;
    if (!signing.verify(proof.signature, &digest)) return error.InvalidLocalUnlock;
    return proof;
}

fn verifyLocalUnlock(
    graph: *const device_graph.Graph,
    credential: *const CredentialRecord,
    device: principal.PrincipalId,
    proof: LocalUnlockProof,
    challenge: []const u8,
    tick: u64,
) Error!void {
    if (!proof.owner.eql(credential.owner) or !proof.device.eql(device)) return error.InvalidLocalUnlock;
    if (!std.mem.eql(u8, proof.relyingPartySlice(), credential.relyingPartySlice())) return error.InvalidLocalUnlock;
    if (!std.mem.eql(u8, proof.challengeSlice(), challenge)) return error.InvalidLocalUnlock;
    if (tick < proof.issued_at_ticks or tick > proof.expires_at_ticks) return error.LocalUnlockExpired;

    const device_record = try requireTrustedDeviceForOwner(graph, credential.owner, device);
    const digest = localUnlockDigest(
        proof.owner,
        proof.device,
        proof.relyingPartySlice(),
        proof.challengeSlice(),
        proof.method,
        proof.issued_at_ticks,
        proof.expires_at_ticks,
    );
    if (!std.mem.eql(u8, proof.signature.publicKeySlice(), device_record.device_signature.publicKeySlice())) return error.InvalidLocalUnlock;
    if (!signing.verify(proof.signature, &digest)) return error.InvalidLocalUnlock;
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
) Error!void {
    if (request.threshold == 0) return error.RecoveryThresholdNotMet;

    var trusted_devices: [device_graph.MAX_DEVICES]principal.PrincipalId = undefined;
    var trusted_device_count: usize = 0;

    try verifyRecoveryApproval(
        graph,
        credential,
        request.recovery_device,
        request.local_unlock,
        request.challenge,
        request.tick,
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
            request.challenge,
            request.tick,
        );
        if (trusted_device_count >= trusted_devices.len) return error.RecoveryThresholdNotMet;
        trusted_devices[trusted_device_count] = approval.device;
        trusted_device_count += 1;
    }

    if (trusted_device_count < request.threshold) return error.RecoveryThresholdNotMet;
}

fn verifyRecoveryApproval(
    graph: *const device_graph.Graph,
    credential: *const CredentialRecord,
    device: principal.PrincipalId,
    unlock: LocalUnlockProof,
    challenge: []const u8,
    tick: u64,
) Error!void {
    _ = try requireTrustedDeviceForOwner(graph, credential.owner, device);
    try verifyLocalUnlock(graph, credential, device, unlock, challenge, tick);
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
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
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

fn localUnlockDigest(
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    relying_party_id: []const u8,
    challenge: []const u8,
    method: UnlockMethod,
    issued_at_ticks: u64,
    expires_at_ticks: u64,
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "owner-kind", owner.kind);
    crypto_hash.updateInt(&hasher, "owner-serial", owner.serial);
    crypto_hash.updateEnum(&hasher, "device-kind", device.kind);
    crypto_hash.updateInt(&hasher, "device-serial", device.serial);
    crypto_hash.updateBytes(&hasher, "relying-party-id", relying_party_id);
    crypto_hash.updateBytes(&hasher, "challenge", challenge);
    crypto_hash.updateEnum(&hasher, "unlock-method", method);
    crypto_hash.updateInt(&hasher, "issued-at", issued_at_ticks);
    crypto_hash.updateInt(&hasher, "expires-at", expires_at_ticks);
    return crypto_hash.finalize(&hasher);
}

fn assertionDigest(
    credential_id: u64,
    owner: principal.PrincipalId,
    device: principal.PrincipalId,
    generation: u32,
    relying_party_id: []const u8,
    origin: []const u8,
    challenge: []const u8,
) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateInt(&hasher, "credential-id", credential_id);
    crypto_hash.updateEnum(&hasher, "owner-kind", owner.kind);
    crypto_hash.updateInt(&hasher, "owner-serial", owner.serial);
    crypto_hash.updateEnum(&hasher, "device-kind", device.kind);
    crypto_hash.updateInt(&hasher, "device-serial", device.serial);
    crypto_hash.updateInt(&hasher, "generation", generation);
    crypto_hash.updateBytes(&hasher, "relying-party-id", relying_party_id);
    crypto_hash.updateBytes(&hasher, "origin", origin);
    crypto_hash.updateBytes(&hasher, "challenge", challenge);
    return crypto_hash.finalize(&hasher);
}

fn originMatchesRelyingParty(origin: []const u8, relying_party_id: []const u8) bool {
    const https = "https://";
    if (!std.mem.startsWith(u8, origin, https)) return false;
    const host_start = https.len;
    const host_end = hostEnd(origin[host_start..]) + host_start;
    const host = origin[host_start..host_end];
    if (std.mem.eql(u8, host, relying_party_id)) return true;
    if (host.len <= relying_party_id.len + 1) return false;
    if (!std.mem.endsWith(u8, host, relying_party_id)) return false;
    return host[host.len - relying_party_id.len - 1] == '.';
}

fn hostEnd(rest: []const u8) usize {
    var index: usize = 0;
    while (index < rest.len) : (index += 1) {
        switch (rest[index]) {
            '/', ':', '?', '#' => return index,
            else => {},
        }
    }
    return rest.len;
}

fn testHardwareSeal(label: []const u8, raw: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "identity-test-secret-provider", label);
    crypto_hash.updateBytes(&hasher, "identity-test-seal", raw);
    return crypto_hash.finalize(&hasher);
}

fn testHardwareProvider() secure_secret_store.HardwareSealProvider {
    return .{
        .available = true,
        .sealFn = testHardwareSeal,
    };
}

test "os identity creates passkey credentials and rejects phishing origins" {
    try std.testing.expect(std.meta.stringToEnum(UnlockMethod, "password") == null);

    var graph = device_graph.Graph.init();
    var secrets = secure_secret_store.Store.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 701 };
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

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);
    const credential = try identities.registerCredential(&graph, &secrets, .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .label = "accounts-passkey",
        .scope = .synced,
        .credential_identity = credential_identity,
        .tick = 2,
    });
    try std.testing.expect(credential.local_unlock_required);
    try std.testing.expect(credential.phishing_resistant);
    try std.testing.expect(credential.isRecoverableThroughDeviceGraph());
    try std.testing.expect(!std.mem.allEqual(u8, &credential.sealed_secret_digest, 0));

    const unlock = try createLocalUnlockProof(user, laptop, "accounts.example", "nonce-1", .biometric, 3, 8, laptop_identity);
    const assertion = try identities.assertCredential(&graph, .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://login.accounts.example",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .credential_identity = credential_identity,
        .tick = 4,
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

    try std.testing.expectError(error.PhishingOriginRejected, identities.assertCredential(&graph, .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example.evil.test",
        .challenge = "nonce-1",
        .local_unlock = unlock,
        .credential_identity = credential_identity,
        .tick = 5,
    }));
    try std.testing.expectError(error.LocalUnlockRequired, identities.assertCredential(&graph, .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "accounts.example",
        .origin = "https://accounts.example",
        .challenge = "nonce-1",
        .credential_identity = credential_identity,
        .tick = 5,
    }));
}

test "os identity recovers synced credentials through trusted device graph" {
    var graph = device_graph.Graph.init();
    var secrets = secure_secret_store.Store.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 801 };
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
    const replacement_credential_identity = signing.SignerIdentity{
        .label = "recover-passkey-v2",
        .seed = signing.seedFromByte(0xB5),
    };

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);
    _ = try graph.enrollDevice(user, phone, "phone", user_identity, phone_identity, 2);
    const synced = try identities.registerCredential(&graph, &secrets, .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "zigos.dev",
        .label = "zigos-passkey",
        .scope = .synced,
        .credential_identity = first_credential_identity,
        .tick = 3,
    });
    const first_digest = synced.credential_digest;
    const bound = try identities.registerCredential(&graph, &secrets, .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "admin.zigos.dev",
        .label = "admin-device-key",
        .scope = .device_bound,
        .credential_identity = first_credential_identity,
        .tick = 4,
    });

    const recovery_unlock = try createLocalUnlockProof(user, phone, "zigos.dev", "recover-1", .recovery_key, 5, 10, phone_identity);
    try std.testing.expectError(error.RecoveryThresholdNotMet, identities.recoverCredential(&graph, &secrets, .{
        .credential_id = synced.id,
        .recovery_device = phone,
        .relying_party_id = "zigos.dev",
        .challenge = "recover-1",
        .local_unlock = recovery_unlock,
        .threshold = 2,
        .replacement_credential_identity = replacement_credential_identity,
        .tick = 6,
    }));

    const laptop_recovery_unlock = try createLocalUnlockProof(user, laptop, "zigos.dev", "recover-1", .recovery_key, 5, 10, laptop_identity);
    const approvals = [_]RecoveryApproval{
        .{
            .device = laptop,
            .local_unlock = laptop_recovery_unlock,
        },
    };
    const recovered = try identities.recoverCredential(&graph, &secrets, .{
        .credential_id = synced.id,
        .recovery_device = phone,
        .relying_party_id = "zigos.dev",
        .challenge = "recover-1",
        .local_unlock = recovery_unlock,
        .threshold = 2,
        .approvals = &approvals,
        .replacement_credential_identity = replacement_credential_identity,
        .tick = 6,
    });
    try std.testing.expectEqual(phone, recovered.primary_device);
    try std.testing.expectEqual(@as(u32, 2), recovered.credential_generation);
    try std.testing.expectEqual(@as(u64, 6), recovered.recovered_at_ticks);
    try std.testing.expect(!std.mem.eql(u8, first_digest[0..], recovered.credential_digest[0..]));

    const unlock = try createLocalUnlockProof(user, phone, "zigos.dev", "nonce-2", .device_pin, 7, 11, phone_identity);
    const assertion = try identities.assertCredential(&graph, .{
        .credential_id = synced.id,
        .device = phone,
        .relying_party_id = "zigos.dev",
        .origin = "https://zigos.dev",
        .challenge = "nonce-2",
        .local_unlock = unlock,
        .credential_identity = replacement_credential_identity,
        .tick = 8,
    });
    try std.testing.expectEqual(@as(u32, 2), assertion.credential_generation);
    try std.testing.expect(assertion.hardware_backed_credential);
    try std.testing.expect(assertion.primary_device_assertion);
    try std.testing.expectEqual(@as(u64, 1), assertion.unlock_age_ticks);

    const bound_recovery_unlock = try createLocalUnlockProof(user, phone, "admin.zigos.dev", "recover-bound", .recovery_key, 9, 12, phone_identity);
    try std.testing.expectError(error.DeviceBoundRecoveryDenied, identities.recoverCredential(&graph, &secrets, .{
        .credential_id = bound.id,
        .recovery_device = phone,
        .relying_party_id = "admin.zigos.dev",
        .challenge = "recover-bound",
        .local_unlock = bound_recovery_unlock,
        .replacement_credential_identity = replacement_credential_identity,
        .tick = 10,
    }));
}

test "os identity requires fresh local unlock and primary device for device-bound credentials" {
    var graph = device_graph.Graph.init();
    var secrets = secure_secret_store.Store.init();
    secrets.attachHardwareProvider(testHardwareProvider());
    var identities = Store.init();
    const user = principal.PrincipalId{ .kind = .user, .serial = 901 };
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

    _ = try graph.ensureUserRoot(user, "owner", user_identity);
    _ = try graph.enrollDevice(user, laptop, "laptop", user_identity, laptop_identity, 1);
    _ = try graph.enrollDevice(user, phone, "phone", user_identity, phone_identity, 2);
    const credential = try identities.registerCredential(&graph, &secrets, .{
        .owner = user,
        .device = laptop,
        .relying_party_id = "device.example",
        .label = "device-bound-passkey",
        .scope = .device_bound,
        .credential_identity = credential_identity,
        .tick = 3,
    });
    const phone_unlock = try createLocalUnlockProof(user, phone, "device.example", "nonce-3", .biometric, 4, 8, phone_identity);
    try std.testing.expectError(error.DeviceBoundCredentialWrongDevice, identities.assertCredential(&graph, .{
        .credential_id = credential.id,
        .device = phone,
        .relying_party_id = "device.example",
        .origin = "https://device.example",
        .challenge = "nonce-3",
        .local_unlock = phone_unlock,
        .credential_identity = credential_identity,
        .tick = 5,
    }));

    const expired_unlock = try createLocalUnlockProof(user, laptop, "device.example", "nonce-4", .biometric, 4, 5, laptop_identity);
    try std.testing.expectError(error.LocalUnlockExpired, identities.assertCredential(&graph, .{
        .credential_id = credential.id,
        .device = laptop,
        .relying_party_id = "device.example",
        .origin = "https://device.example",
        .challenge = "nonce-4",
        .local_unlock = expired_unlock,
        .credential_identity = credential_identity,
        .tick = 6,
    }));
}
