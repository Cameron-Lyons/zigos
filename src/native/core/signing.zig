const std = @import("std");
const crypto_hash = @import("crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const SEED_BYTES = Ed25519.KeyPair.seed_length;
pub const PUBLIC_KEY_BYTES = Ed25519.PublicKey.encoded_length;
pub const SIGNATURE_BYTES = Ed25519.Signature.encoded_length;
pub const Seed = [SEED_BYTES]u8;
pub const PublicKey = [PUBLIC_KEY_BYTES]u8;
pub const SIGNATURE_FORMAT_ED25519 = manifest.SIGNATURE_FORMAT_ED25519;
pub const SIGNATURE_FORMAT_ML_DSA65 = manifest.SIGNATURE_FORMAT_ML_DSA65;
pub const ED25519_PUBLIC_KEY_BYTES = manifest.ED25519_PUBLIC_KEY_BYTES;
pub const ED25519_SIGNATURE_BYTES = manifest.ED25519_SIGNATURE_BYTES;
pub const MAX_SIGNATURE_PROVIDERS: usize = 6;

pub const SignatureProfile = enum {
    ed25519,
};

pub const SignatureProviderRole = enum {
    production,
    preview,
    test_only,
};

pub const SignatureKeyCustody = enum {
    software_seed,
    hardware_security_module,
    cloud_kms,
    tpm,
    secure_enclave,
};

pub const SignatureProviderBoundary = enum {
    local_software,
    offline_hsm,
    cloud_kms,
    platform_tpm,
    secure_enclave,
};

pub const SignatureVerifierProtocol = enum {
    local_manifest,
    dsse_in_toto_slsa,
};

pub const SignatureProviderDescriptor = struct {
    name: []const u8,
    profile: SignatureProfile,
    role: SignatureProviderRole,
    provider_boundary: SignatureProviderBoundary = .local_software,
    custody: SignatureKeyCustody = .software_seed,
    hardware_backed: bool = false,
    rotation_supported: bool = false,
    revocation_supported: bool = false,
    customer_verifiable: bool = false,
    verifier_protocol: SignatureVerifierProtocol = .local_manifest,

    pub fn format(self: SignatureProviderDescriptor) []const u8 {
        return formatForProfile(self.profile);
    }

    pub fn hasOperationalCustody(self: SignatureProviderDescriptor) bool {
        return self.hardware_backed and self.custody != .software_seed;
    }

    pub fn hasReleaseProviderBoundary(self: SignatureProviderDescriptor) bool {
        return switch (self.provider_boundary) {
            .offline_hsm, .cloud_kms, .platform_tpm, .secure_enclave => true,
            .local_software => false,
        };
    }

    pub fn hasLifecycleControls(self: SignatureProviderDescriptor) bool {
        return self.rotation_supported and self.revocation_supported;
    }

    pub fn releaseEligible(self: SignatureProviderDescriptor) bool {
        if (self.role != .production) return false;
        if (!self.hasReleaseProviderBoundary()) return false;
        if (!self.hasOperationalCustody()) return false;
        if (!self.hasLifecycleControls()) return false;
        if (!self.customer_verifiable) return false;
        return self.verifier_protocol == .dsse_in_toto_slsa;
    }
};

pub const ReleaseRootKeyHandle = struct {
    key_id: []const u8,
    label: []const u8,
    public_key: PublicKey,
    generation: u32,
    provider_boundary: SignatureProviderBoundary,
    custody: SignatureKeyCustody,
};

pub const ExternalReleaseProvider = struct {
    descriptor: SignatureProviderDescriptor,
    key: ReleaseRootKeyHandle,
    context: *anyopaque,
    sign_fn: *const fn (*anyopaque, ReleaseRootKeyHandle, []const u8) anyerror![SIGNATURE_BYTES]u8,

    pub fn init(
        descriptor: SignatureProviderDescriptor,
        key: ReleaseRootKeyHandle,
        context: *anyopaque,
        sign_fn: *const fn (*anyopaque, ReleaseRootKeyHandle, []const u8) anyerror![SIGNATURE_BYTES]u8,
    ) !ExternalReleaseProvider {
        if (!descriptor.releaseEligible()) return error.ReleaseProviderNotEligible;
        if (descriptor.profile != .ed25519) return error.ReleaseProviderUnsupportedProfile;
        if (key.generation == 0) return error.ReleaseKeyGenerationInvalid;
        if (key.key_id.len == 0 or key.label.len == 0) return error.ReleaseKeyIdentityMissing;
        if (key.provider_boundary != descriptor.provider_boundary) return error.ReleaseProviderBoundaryMismatch;
        if (key.custody != descriptor.custody) return error.ReleaseProviderCustodyMismatch;
        return .{
            .descriptor = descriptor,
            .key = key,
            .context = context,
            .sign_fn = sign_fn,
        };
    }

    pub fn provider(self: *ExternalReleaseProvider) SignatureProvider {
        return SignatureProvider.init(ExternalReleaseProvider, self, self.descriptor);
    }

    pub fn sign(self: *ExternalReleaseProvider, identity: SignerIdentity, message: []const u8) !manifest.Signature {
        if (!std.mem.eql(u8, identity.label, self.key.label)) return error.ReleaseKeyIdentityMismatch;
        const signature_bytes = try self.sign_fn(self.context, self.key, message);
        var result = manifest.Signature{
            .format = .ed25519,
            .signer = self.key.label,
            .public_key_len = PUBLIC_KEY_BYTES,
            .value_len = SIGNATURE_BYTES,
        };
        @memcpy(result.public_key[0..PUBLIC_KEY_BYTES], &self.key.public_key);
        @memcpy(result.value[0..SIGNATURE_BYTES], &signature_bytes);
        return result;
    }

    pub fn verify(self: *ExternalReleaseProvider, signature: manifest.Signature, message: []const u8) bool {
        if (signature.format != .ed25519) return false;
        if (!std.mem.eql(u8, signature.signer, self.key.label)) return false;
        if (!std.mem.eql(u8, signature.ed25519PublicKeySlice(), &self.key.public_key)) return false;
        return verifySignature(signature, message);
    }
};

pub const SignerIdentity = struct {
    label: []const u8,
    seed: Seed,
};

pub fn seedFromByte(byte: u8) Seed {
    return @as([SEED_BYTES]u8, @splat(byte));
}

pub fn publicKeyFromByte(byte: u8) PublicKey {
    return @as([PUBLIC_KEY_BYTES]u8, @splat(byte));
}

pub const PublicIdentity = struct {
    label: []const u8,
    public_key: PublicKey,
};

pub const SignatureProvider = struct {
    context: *anyopaque,
    descriptor: SignatureProviderDescriptor,
    sign_fn: *const fn (*anyopaque, SignerIdentity, []const u8) anyerror!manifest.Signature,
    verify_fn: *const fn (*anyopaque, manifest.Signature, []const u8) bool,

    pub fn init(
        comptime Provider: type,
        provider: *Provider,
        descriptor: SignatureProviderDescriptor,
    ) SignatureProvider {
        return .{
            .context = @ptrCast(provider),
            .descriptor = descriptor,
            .sign_fn = struct {
                fn sign(context: *anyopaque, identity: SignerIdentity, message: []const u8) anyerror!manifest.Signature {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.sign(identity, message);
                }
            }.sign,
            .verify_fn = struct {
                fn verify(context: *anyopaque, signature: manifest.Signature, message: []const u8) bool {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.verify(signature, message);
                }
            }.verify,
        };
    }

    pub fn sign(self: SignatureProvider, identity: SignerIdentity, message: []const u8) !manifest.Signature {
        const signature = try self.sign_fn(self.context, identity, message);
        if (!std.mem.eql(u8, signature.formatSlice(), self.descriptor.format())) return error.SignatureProviderProfileMismatch;
        if (!signature.isComplete()) return error.SignatureProviderIncompleteSignature;
        return signature;
    }

    pub fn verify(self: SignatureProvider, signature: manifest.Signature, message: []const u8) bool {
        if (!std.mem.eql(u8, signature.formatSlice(), self.descriptor.format())) return false;
        return self.verify_fn(self.context, signature, message);
    }

    pub fn releaseEligible(self: SignatureProvider) bool {
        return self.descriptor.releaseEligible();
    }
};

pub const SignatureProviderRegistry = struct {
    provider_count: usize = 0,
    providers: [MAX_SIGNATURE_PROVIDERS]SignatureProvider = undefined,

    pub fn init() SignatureProviderRegistry {
        return .{};
    }

    pub fn register(self: *SignatureProviderRegistry, provider: SignatureProvider) !void {
        if (self.provider_count >= self.providers.len) return error.SignatureProviderRegistryFull;
        self.providers[self.provider_count] = provider;
        self.provider_count += 1;
    }

    pub fn find(self: *const SignatureProviderRegistry, profile: SignatureProfile) ?SignatureProvider {
        var index: usize = 0;
        while (index < self.provider_count) : (index += 1) {
            const provider = self.providers[index];
            if (provider.descriptor.profile == profile) return provider;
        }
        return null;
    }

    pub fn findReleaseEligible(self: *const SignatureProviderRegistry, profile: SignatureProfile) ?SignatureProvider {
        var index: usize = 0;
        while (index < self.provider_count) : (index += 1) {
            const provider = self.providers[index];
            if (provider.descriptor.profile == profile and provider.releaseEligible()) return provider;
        }
        return null;
    }

    pub fn sign(
        self: *const SignatureProviderRegistry,
        profile: SignatureProfile,
        identity: SignerIdentity,
        message: []const u8,
    ) !manifest.Signature {
        const provider = self.find(profile) orelse return error.SignatureProviderUnavailable;
        return provider.sign(identity, message);
    }

    pub fn verify(self: *const SignatureProviderRegistry, signature: manifest.Signature, message: []const u8) bool {
        const profile = profileForFormat(signature.format) orelse return false;
        const provider = self.find(profile) orelse return false;
        return provider.verify(signature, message);
    }
};

pub const SoftwareEd25519Provider = struct {
    pub const descriptor = SignatureProviderDescriptor{
        .name = "software-ed25519",
        .profile = .ed25519,
        .role = .test_only,
        .custody = .software_seed,
    };

    pub fn provider(self: *SoftwareEd25519Provider) SignatureProvider {
        return SignatureProvider.init(SoftwareEd25519Provider, self, descriptor);
    }

    pub fn sign(self: *SoftwareEd25519Provider, identity: SignerIdentity, message: []const u8) !manifest.Signature {
        _ = self;
        return signWithProfile(identity, message, .ed25519);
    }

    pub fn verify(self: *SoftwareEd25519Provider, signature: manifest.Signature, message: []const u8) bool {
        _ = self;
        return signingProfileMatches(signature, .ed25519) and verifySignature(signature, message);
    }
};

pub fn publicKey(identity: SignerIdentity) !PublicKey {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(identity.seed);
    return key_pair.public_key.toBytes();
}

pub fn publicIdentity(identity: SignerIdentity) !PublicIdentity {
    return .{
        .label = identity.label,
        .public_key = try publicKey(identity),
    };
}

pub fn sign(identity: SignerIdentity, message: []const u8) !manifest.Signature {
    return signWithProfile(identity, message, .ed25519);
}

// Local software signing. Release-eligible signing goes through an
// ExternalReleaseProvider registered in a SignatureProviderRegistry.
pub fn signWithDefaultRegistry(
    profile: SignatureProfile,
    identity: SignerIdentity,
    message: []const u8,
) !manifest.Signature {
    return signWithProfile(identity, message, profile);
}

pub fn signWithProfile(identity: SignerIdentity, message: []const u8, profile: SignatureProfile) !manifest.Signature {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(identity.seed);
    const signature = try key_pair.sign(message, null);
    const public_key = key_pair.public_key.toBytes();
    const signature_bytes = signature.toBytes();

    var result = manifest.Signature{
        .format = signatureFormatForProfile(profile),
        .signer = identity.label,
        .public_key_len = Ed25519.PublicKey.encoded_length,
        .value_len = Ed25519.Signature.encoded_length,
    };
    @memcpy(result.public_key[0..PUBLIC_KEY_BYTES], public_key[0..]);
    @memcpy(result.value[0..SIGNATURE_BYTES], signature_bytes[0..]);
    return result;
}

pub fn verify(signature: manifest.Signature, message: []const u8) bool {
    return verifySignature(signature, message);
}

pub fn verifyWithDefaultRegistry(signature: manifest.Signature, message: []const u8) bool {
    return verifySignature(signature, message);
}

fn verifySignature(signature: manifest.Signature, message: []const u8) bool {
    if (!signature.isComplete()) return false;

    if (!verifyEd25519(signature.ed25519PublicKeySlice(), signature.ed25519SignatureSlice(), message)) return false;
    return signature.format == .ed25519;
}

fn verifyEd25519(public_key_bytes: []const u8, signature_bytes: []const u8, message: []const u8) bool {
    if (public_key_bytes.len != PUBLIC_KEY_BYTES or signature_bytes.len != SIGNATURE_BYTES) return false;
    const public_key_array: [PUBLIC_KEY_BYTES]u8 = public_key_bytes[0..PUBLIC_KEY_BYTES].*;
    const signature_array: [SIGNATURE_BYTES]u8 = signature_bytes[0..SIGNATURE_BYTES].*;
    const public_key = Ed25519.PublicKey.fromBytes(public_key_array) catch return false;
    const raw_signature = Ed25519.Signature.fromBytes(signature_array);
    raw_signature.verify(message, public_key) catch return false;
    return true;
}

pub fn verifyTrusted(
    signature: manifest.Signature,
    message: []const u8,
    expected_identity: SignerIdentity,
) bool {
    return verifyTrustedPublicKey(
        signature,
        message,
        publicIdentity(expected_identity) catch return false,
    );
}

pub fn verifyTrustedPublicKey(
    signature: manifest.Signature,
    message: []const u8,
    expected_identity: PublicIdentity,
) bool {
    if (!std.mem.eql(u8, signature.signer, expected_identity.label)) return false;
    const expected_public_key = expected_identity.public_key;
    if (!std.mem.eql(u8, signature.ed25519PublicKeySlice(), &expected_public_key)) return false;
    return verify(signature, message);
}

fn formatForProfile(profile: SignatureProfile) []const u8 {
    return switch (profile) {
        .ed25519 => manifest.SIGNATURE_FORMAT_ED25519,
    };
}

fn signatureFormatForProfile(profile: SignatureProfile) manifest.SignatureFormat {
    return switch (profile) {
        .ed25519 => .ed25519,
    };
}

fn profileForFormat(format: manifest.SignatureFormat) ?SignatureProfile {
    return switch (format) {
        .ed25519 => .ed25519,
        .ml_dsa65, .unknown => null,
    };
}

fn signingProfileMatches(signature: manifest.Signature, profile: SignatureProfile) bool {
    return signature.format == signatureFormatForProfile(profile);
}

test "ed25519 signing produces verifiable native signatures" {
    const identity = SignerIdentity{
        .label = "zigos.test",
        .seed = seedFromByte(0x11),
    };
    const signature = try sign(identity, "storage-state");
    try std.testing.expect(signature.isComplete());
    try std.testing.expectEqualSlices(u8, &try publicKey(identity), signature.publicKeySlice());
    try std.testing.expect(verify(signature, "storage-state"));
    try std.testing.expect(!verify(signature, "sync-state"));
    try std.testing.expect(verifyTrusted(signature, "storage-state", identity));
    try std.testing.expect(verifyTrustedPublicKey(signature, "storage-state", try publicIdentity(identity)));

    const wrong_identity = SignerIdentity{
        .label = "zigos.other",
        .seed = seedFromByte(0x12),
    };
    try std.testing.expect(!verifyTrusted(signature, "storage-state", wrong_identity));
}

test "signature providers expose release eligibility and reject mismatched profiles" {
    const identity = SignerIdentity{
        .label = "zigos.provider",
        .seed = seedFromByte(0x61),
    };
    var ed25519_provider_impl = SoftwareEd25519Provider{};
    const ed25519_provider = ed25519_provider_impl.provider();

    try std.testing.expect(!ed25519_provider.releaseEligible());
    try std.testing.expectEqual(SignatureProviderRole.test_only, ed25519_provider.descriptor.role);
    try std.testing.expectEqual(SignatureProviderBoundary.local_software, ed25519_provider.descriptor.provider_boundary);
    try std.testing.expectEqualStrings(manifest.SIGNATURE_FORMAT_ED25519, ed25519_provider.descriptor.format());
    try std.testing.expect(profileForFormat(.ml_dsa65) == null);

    const ed25519_signature = try ed25519_provider.sign(identity, "provider-message");
    try std.testing.expect(ed25519_provider.verify(ed25519_signature, "provider-message"));

    var wrong_format = ed25519_signature;
    wrong_format.format = .ml_dsa65;
    try std.testing.expect(!ed25519_provider.verify(wrong_format, "provider-message"));
}

test "release eligibility requires hardware custody lifecycle controls and verifier protocol" {
    const local_fixture = SignatureProviderDescriptor{
        .name = "local-fixture",
        .profile = .ed25519,
        .role = .production,
        .custody = .software_seed,
        .hardware_backed = false,
        .rotation_supported = true,
        .revocation_supported = true,
        .customer_verifiable = true,
        .verifier_protocol = .dsse_in_toto_slsa,
    };
    try std.testing.expect(!local_fixture.releaseEligible());

    const operational = SignatureProviderDescriptor{
        .name = "release-hsm-ed25519",
        .profile = .ed25519,
        .role = .production,
        .provider_boundary = .offline_hsm,
        .custody = .hardware_security_module,
        .hardware_backed = true,
        .rotation_supported = true,
        .revocation_supported = true,
        .customer_verifiable = true,
        .verifier_protocol = .dsse_in_toto_slsa,
    };
    try std.testing.expect(operational.releaseEligible());

    var tpm_operational = operational;
    tpm_operational.name = "release-tpm-ed25519";
    tpm_operational.provider_boundary = .platform_tpm;
    tpm_operational.custody = .tpm;
    try std.testing.expect(tpm_operational.releaseEligible());

    var enclave_operational = operational;
    enclave_operational.name = "release-secure-enclave-ed25519";
    enclave_operational.provider_boundary = .secure_enclave;
    enclave_operational.custody = .secure_enclave;
    try std.testing.expect(enclave_operational.releaseEligible());

    var no_provider_boundary = operational;
    no_provider_boundary.provider_boundary = .local_software;
    try std.testing.expect(!no_provider_boundary.releaseEligible());

    var no_rotation = operational;
    no_rotation.rotation_supported = false;
    try std.testing.expect(!no_rotation.releaseEligible());

    var local_protocol = operational;
    local_protocol.verifier_protocol = .local_manifest;
    try std.testing.expect(!local_protocol.releaseEligible());
}

test "external release provider uses key handles instead of software signer seeds" {
    const SigningBackend = struct {
        seed: Seed,

        fn sign(context: *anyopaque, key: ReleaseRootKeyHandle, message: []const u8) ![SIGNATURE_BYTES]u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            const key_pair = try Ed25519.KeyPair.generateDeterministic(self.seed);
            try std.testing.expectEqualSlices(u8, &key.public_key, &key_pair.public_key.toBytes());
            return (try key_pair.sign(message, null)).toBytes();
        }
    };

    const root_identity = SignerIdentity{
        .label = "zigos.release.root",
        .seed = seedFromByte(0x71),
    };
    var backend = SigningBackend{ .seed = root_identity.seed };
    var provider_impl = try ExternalReleaseProvider.init(
        .{
            .name = "release-kms-ed25519",
            .profile = .ed25519,
            .role = .production,
            .provider_boundary = .cloud_kms,
            .custody = .cloud_kms,
            .hardware_backed = true,
            .rotation_supported = true,
            .revocation_supported = true,
            .customer_verifiable = true,
            .verifier_protocol = .dsse_in_toto_slsa,
        },
        .{
            .key_id = "kms://zigos/release/root/1",
            .label = root_identity.label,
            .public_key = try publicKey(root_identity),
            .generation = 1,
            .provider_boundary = .cloud_kms,
            .custody = .cloud_kms,
        },
        &backend,
        SigningBackend.sign,
    );
    const provider = provider_impl.provider();
    try std.testing.expect(provider.releaseEligible());

    const software_fixture_identity = SignerIdentity{
        .label = root_identity.label,
        .seed = seedFromByte(0x72),
    };
    const signature = try provider.sign(software_fixture_identity, "release-dsse-pae");
    try std.testing.expect(provider.verify(signature, "release-dsse-pae"));
    try std.testing.expect(!provider.verify(signature, "tampered-release-dsse-pae"));

    var tampered_public_key = signature;
    tampered_public_key.public_key[0] ^= 0x80;
    try std.testing.expect(!provider.verify(tampered_public_key, "release-dsse-pae"));
}

test "signature provider fails closed when implementation returns the wrong profile" {
    const BadProvider = struct {
        fn provider(self: *@This()) SignatureProvider {
            return SignatureProvider.init(@This(), self, .{
                .name = "bad-provider",
                .profile = .ed25519,
                .role = .test_only,
            });
        }

        fn sign(self: *@This(), identity: SignerIdentity, message: []const u8) !manifest.Signature {
            _ = self;
            var signature = try signWithProfile(identity, message, .ed25519);
            signature.format = .ml_dsa65;
            return signature;
        }

        fn verify(self: *@This(), signature: manifest.Signature, message: []const u8) bool {
            _ = self;
            return verifySignature(signature, message);
        }
    };

    var bad_provider_impl = BadProvider{};
    const bad_provider = bad_provider_impl.provider();
    const identity = SignerIdentity{
        .label = "zigos.bad-provider",
        .seed = seedFromByte(0x62),
    };

    try std.testing.expectError(
        error.SignatureProviderProfileMismatch,
        bad_provider.sign(identity, "provider-message"),
    );
}

test "signature provider registry selects providers by profile and release eligibility" {
    const identity = SignerIdentity{
        .label = "zigos.registry",
        .seed = seedFromByte(0x63),
    };
    var ed25519_provider_impl = SoftwareEd25519Provider{};
    var registry = SignatureProviderRegistry.init();
    try registry.register(ed25519_provider_impl.provider());

    try std.testing.expect(registry.find(.ed25519) != null);
    try std.testing.expect(registry.findReleaseEligible(.ed25519) == null);
    try std.testing.expectError(error.SignatureProviderUnavailable, SignatureProviderRegistry.init().sign(.ed25519, identity, "registry-message"));

    const ed25519_signature = try registry.sign(.ed25519, identity, "registry-message");
    try std.testing.expect(registry.verify(ed25519_signature, "registry-message"));

    var unsupported = ed25519_signature;
    unsupported.format = .unknown;
    try std.testing.expect(!registry.verify(unsupported, "registry-message"));
}
