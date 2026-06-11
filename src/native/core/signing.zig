const std = @import("std");
const manifest = @import("../policy/manifest.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const SEED_BYTES = Ed25519.KeyPair.seed_length;
pub const PUBLIC_KEY_BYTES = Ed25519.PublicKey.encoded_length;
pub const SIGNATURE_BYTES = Ed25519.Signature.encoded_length;
pub const SIGNATURE_FORMAT_ED25519 = manifest.SIGNATURE_FORMAT_ED25519;
pub const SIGNATURE_FORMAT_ED25519_ML_DSA65 = manifest.SIGNATURE_FORMAT_ED25519_ML_DSA65;
pub const SIGNATURE_FORMAT_ML_DSA65 = manifest.SIGNATURE_FORMAT_ML_DSA65;
pub const ED25519_PUBLIC_KEY_BYTES = manifest.ED25519_PUBLIC_KEY_BYTES;
pub const ED25519_SIGNATURE_BYTES = manifest.ED25519_SIGNATURE_BYTES;
pub const ML_DSA65_PUBLIC_KEY_BYTES = manifest.ML_DSA65_PUBLIC_KEY_BYTES;
pub const ML_DSA65_SIGNATURE_BYTES = manifest.ML_DSA65_SIGNATURE_BYTES;
pub const MAX_SIGNATURE_PROVIDERS: usize = 6;

pub const SignatureProfile = enum {
    ed25519,
    ed25519_ml_dsa65_hybrid_preview,
    ml_dsa65_fips204,
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

pub const FipsStandard = enum {
    not_applicable,
    fips_203,
    fips_204,
    fips_205,
};

pub const PostQuantumAlgorithm = enum {
    not_applicable,
    ml_kem_768,
    ml_dsa_65,
    slh_dsa_sha2_128s,
};

pub const Fips204Implementation = enum {
    not_applicable,
    preview_commitment,
    validated_provider,
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
    fips_standard: FipsStandard = .not_applicable,
    post_quantum_algorithm: PostQuantumAlgorithm = .not_applicable,
    fips_204: Fips204Implementation = .not_applicable,
    fips_validated: bool = false,
    fips_140_validated_module: bool = false,
    validation_certificate: []const u8 = "",

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
        if (self.verifier_protocol != .dsse_in_toto_slsa) return false;
        return switch (self.profile) {
            .ed25519 => self.fips_204 != .preview_commitment and
                self.post_quantum_algorithm == .not_applicable,
            .ed25519_ml_dsa65_hybrid_preview => false,
            .ml_dsa65_fips204 => self.fips_standard == .fips_204 and
                self.post_quantum_algorithm == .ml_dsa_65 and
                self.fips_204 == .validated_provider and
                self.fips_validated and
                self.fips_140_validated_module and
                self.validation_certificate.len != 0,
        };
    }
};

pub const ReleaseRootKeyHandle = struct {
    key_id: []const u8,
    label: []const u8,
    public_key: [PUBLIC_KEY_BYTES]u8,
    generation: u32,
    provider_boundary: SignatureProviderBoundary,
    custody: SignatureKeyCustody,
};

pub const MlDsaReleaseRootKeyHandle = struct {
    key_id: []const u8,
    label: []const u8,
    public_key: [ML_DSA65_PUBLIC_KEY_BYTES]u8,
    generation: u32,
    provider_boundary: SignatureProviderBoundary,
    custody: SignatureKeyCustody,
    validation_certificate: []const u8,
};

pub const MlDsaSignatureEnvelope = struct {
    format: []const u8 = manifest.SIGNATURE_FORMAT_ML_DSA65,
    signer: []const u8,
    public_key: [ML_DSA65_PUBLIC_KEY_BYTES]u8,
    value: [ML_DSA65_SIGNATURE_BYTES]u8,

    pub fn isComplete(self: MlDsaSignatureEnvelope) bool {
        return std.mem.eql(u8, self.format, manifest.SIGNATURE_FORMAT_ML_DSA65) and
            self.signer.len != 0;
    }
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
            .format = manifest.SIGNATURE_FORMAT_ED25519,
            .signer = self.key.label,
            .public_key_len = PUBLIC_KEY_BYTES,
            .value_len = SIGNATURE_BYTES,
        };
        @memcpy(result.public_key[0..PUBLIC_KEY_BYTES], &self.key.public_key);
        @memcpy(result.value[0..SIGNATURE_BYTES], &signature_bytes);
        return result;
    }

    pub fn verify(self: *ExternalReleaseProvider, signature: manifest.Signature, message: []const u8) bool {
        if (!std.mem.eql(u8, signature.format, manifest.SIGNATURE_FORMAT_ED25519)) return false;
        if (!std.mem.eql(u8, signature.signer, self.key.label)) return false;
        if (!std.mem.eql(u8, signature.ed25519PublicKeySlice(), &self.key.public_key)) return false;
        return verifySignature(signature, message);
    }
};

pub const ExternalMlDsaReleaseProvider = struct {
    descriptor: SignatureProviderDescriptor,
    key: MlDsaReleaseRootKeyHandle,
    context: *anyopaque,
    sign_fn: *const fn (*anyopaque, MlDsaReleaseRootKeyHandle, []const u8) anyerror![ML_DSA65_SIGNATURE_BYTES]u8,
    verify_fn: *const fn (*anyopaque, MlDsaReleaseRootKeyHandle, []const u8, [ML_DSA65_SIGNATURE_BYTES]u8) bool,

    pub fn init(
        descriptor: SignatureProviderDescriptor,
        key: MlDsaReleaseRootKeyHandle,
        context: *anyopaque,
        sign_fn: *const fn (*anyopaque, MlDsaReleaseRootKeyHandle, []const u8) anyerror![ML_DSA65_SIGNATURE_BYTES]u8,
        verify_fn: *const fn (*anyopaque, MlDsaReleaseRootKeyHandle, []const u8, [ML_DSA65_SIGNATURE_BYTES]u8) bool,
    ) !ExternalMlDsaReleaseProvider {
        if (!descriptor.releaseEligible()) return error.ReleaseProviderNotEligible;
        if (descriptor.profile != .ml_dsa65_fips204) return error.ReleaseProviderUnsupportedProfile;
        if (key.generation == 0) return error.ReleaseKeyGenerationInvalid;
        if (key.key_id.len == 0 or key.label.len == 0) return error.ReleaseKeyIdentityMissing;
        if (key.provider_boundary != descriptor.provider_boundary) return error.ReleaseProviderBoundaryMismatch;
        if (key.custody != descriptor.custody) return error.ReleaseProviderCustodyMismatch;
        if (!std.mem.eql(u8, key.validation_certificate, descriptor.validation_certificate)) {
            return error.ReleaseProviderValidationMismatch;
        }
        return .{
            .descriptor = descriptor,
            .key = key,
            .context = context,
            .sign_fn = sign_fn,
            .verify_fn = verify_fn,
        };
    }

    pub fn releaseEligible(self: ExternalMlDsaReleaseProvider) bool {
        return self.descriptor.releaseEligible();
    }

    pub fn sign(self: *ExternalMlDsaReleaseProvider, identity: SignerIdentity, message: []const u8) !MlDsaSignatureEnvelope {
        if (!std.mem.eql(u8, identity.label, self.key.label)) return error.ReleaseKeyIdentityMismatch;
        const signature_bytes = try self.sign_fn(self.context, self.key, message);
        return .{
            .format = manifest.SIGNATURE_FORMAT_ML_DSA65,
            .signer = self.key.label,
            .public_key = self.key.public_key,
            .value = signature_bytes,
        };
    }

    pub fn verify(self: *ExternalMlDsaReleaseProvider, signature: MlDsaSignatureEnvelope, message: []const u8) bool {
        if (!std.mem.eql(u8, signature.format, manifest.SIGNATURE_FORMAT_ML_DSA65)) return false;
        if (!std.mem.eql(u8, signature.signer, self.key.label)) return false;
        if (!std.mem.eql(u8, &signature.public_key, &self.key.public_key)) return false;
        return self.verify_fn(self.context, self.key, message, signature.value);
    }
};

pub const SignerIdentity = struct {
    label: []const u8,
    seed: [SEED_BYTES]u8,
};

pub const PublicIdentity = struct {
    label: []const u8,
    public_key: [PUBLIC_KEY_BYTES]u8,
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
        if (!std.mem.eql(u8, signature.format, self.descriptor.format())) return error.SignatureProviderProfileMismatch;
        if (!signature.isComplete()) return error.SignatureProviderIncompleteSignature;
        return signature;
    }

    pub fn verify(self: SignatureProvider, signature: manifest.Signature, message: []const u8) bool {
        if (!std.mem.eql(u8, signature.format, self.descriptor.format())) return false;
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

pub const HybridPreviewProvider = struct {
    pub const descriptor = SignatureProviderDescriptor{
        .name = "software-ed25519-ml-dsa65-preview",
        .profile = .ed25519_ml_dsa65_hybrid_preview,
        .role = .preview,
        .custody = .software_seed,
        .fips_204 = .preview_commitment,
    };

    pub fn provider(self: *HybridPreviewProvider) SignatureProvider {
        return SignatureProvider.init(HybridPreviewProvider, self, descriptor);
    }

    pub fn sign(self: *HybridPreviewProvider, identity: SignerIdentity, message: []const u8) !manifest.Signature {
        _ = self;
        return signWithProfile(identity, message, .ed25519_ml_dsa65_hybrid_preview);
    }

    pub fn verify(self: *HybridPreviewProvider, signature: manifest.Signature, message: []const u8) bool {
        _ = self;
        return signingProfileMatches(signature, .ed25519_ml_dsa65_hybrid_preview) and verifySignature(signature, message);
    }
};

pub fn publicKey(identity: SignerIdentity) ![PUBLIC_KEY_BYTES]u8 {
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
    return signWithDefaultRegistry(.ed25519, identity, message);
}

pub fn signWithDefaultRegistry(
    profile: SignatureProfile,
    identity: SignerIdentity,
    message: []const u8,
) !manifest.Signature {
    var ed25519_provider_impl = SoftwareEd25519Provider{};
    var hybrid_provider_impl = HybridPreviewProvider{};
    var registry = try defaultSoftwareRegistry(&ed25519_provider_impl, &hybrid_provider_impl);
    return registry.sign(profile, identity, message);
}

pub fn signWithProfile(identity: SignerIdentity, message: []const u8, profile: SignatureProfile) !manifest.Signature {
    if (profile == .ml_dsa65_fips204) return error.SignatureProviderUnavailable;

    const key_pair = try Ed25519.KeyPair.generateDeterministic(identity.seed);
    const signature = try key_pair.sign(message, null);
    const public_key = key_pair.public_key.toBytes();
    const signature_bytes = signature.toBytes();

    var result = manifest.Signature{
        .format = formatForProfile(profile),
        .signer = identity.label,
        .public_key_len = Ed25519.PublicKey.encoded_length,
        .value_len = Ed25519.Signature.encoded_length,
    };
    @memcpy(result.public_key[0..PUBLIC_KEY_BYTES], public_key[0..]);
    @memcpy(result.value[0..SIGNATURE_BYTES], signature_bytes[0..]);

    if (profile == .ed25519_ml_dsa65_hybrid_preview) {
        const pq_public_commitment = hybridPublicCommitment(public_key[0..], identity.label);
        const pq_signature_binding = hybridSignatureBinding(&pq_public_commitment, signature_bytes[0..], message);
        @memcpy(result.public_key[PUBLIC_KEY_BYTES..manifest.HYBRID_PUBLIC_KEY_BYTES], pq_public_commitment[0..]);
        @memcpy(result.value[SIGNATURE_BYTES..manifest.HYBRID_SIGNATURE_BYTES], pq_signature_binding[0..]);
        result.public_key_len = manifest.HYBRID_PUBLIC_KEY_BYTES;
        result.value_len = manifest.HYBRID_SIGNATURE_BYTES;
    }

    return result;
}

pub fn verify(signature: manifest.Signature, message: []const u8) bool {
    return verifyWithDefaultRegistry(signature, message);
}

pub fn verifyWithDefaultRegistry(signature: manifest.Signature, message: []const u8) bool {
    var ed25519_provider_impl = SoftwareEd25519Provider{};
    var hybrid_provider_impl = HybridPreviewProvider{};
    var registry = defaultSoftwareRegistry(&ed25519_provider_impl, &hybrid_provider_impl) catch return false;
    return registry.verify(signature, message);
}

fn verifySignature(signature: manifest.Signature, message: []const u8) bool {
    if (!signature.isComplete()) return false;

    if (!verifyEd25519(signature.ed25519PublicKeySlice(), signature.ed25519SignatureSlice(), message)) return false;
    if (std.mem.eql(u8, signature.format, manifest.SIGNATURE_FORMAT_ED25519)) return true;
    if (std.mem.eql(u8, signature.format, manifest.SIGNATURE_FORMAT_ED25519_ML_DSA65)) {
        const expected_public_commitment = hybridPublicCommitment(signature.ed25519PublicKeySlice(), signature.signer);
        if (!std.mem.eql(u8, signature.hybridPostQuantumCommitmentSlice(), &expected_public_commitment)) return false;
        const expected_signature_binding = hybridSignatureBinding(
            &expected_public_commitment,
            signature.ed25519SignatureSlice(),
            message,
        );
        return std.mem.eql(u8, signature.hybridPostQuantumBindingSlice(), &expected_signature_binding);
    }
    if (std.mem.eql(u8, signature.format, manifest.SIGNATURE_FORMAT_ML_DSA65)) return false;
    return false;
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
        .ed25519_ml_dsa65_hybrid_preview => manifest.SIGNATURE_FORMAT_ED25519_ML_DSA65,
        .ml_dsa65_fips204 => manifest.SIGNATURE_FORMAT_ML_DSA65,
    };
}

pub fn profileForFormat(format: []const u8) ?SignatureProfile {
    if (std.mem.eql(u8, format, manifest.SIGNATURE_FORMAT_ED25519)) return .ed25519;
    if (std.mem.eql(u8, format, manifest.SIGNATURE_FORMAT_ED25519_ML_DSA65)) return .ed25519_ml_dsa65_hybrid_preview;
    if (std.mem.eql(u8, format, manifest.SIGNATURE_FORMAT_ML_DSA65)) return .ml_dsa65_fips204;
    return null;
}

pub fn defaultSoftwareRegistry(
    ed25519_provider_impl: *SoftwareEd25519Provider,
    hybrid_provider_impl: *HybridPreviewProvider,
) !SignatureProviderRegistry {
    var registry = SignatureProviderRegistry.init();
    try registry.register(ed25519_provider_impl.provider());
    try registry.register(hybrid_provider_impl.provider());
    return registry;
}

fn signingProfileMatches(signature: manifest.Signature, profile: SignatureProfile) bool {
    return std.mem.eql(u8, signature.format, formatForProfile(profile));
}

fn hybridPublicCommitment(ed25519_public_key: []const u8, signer: []const u8) [manifest.ML_DSA65_PREVIEW_PUBLIC_COMMITMENT_BYTES]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("zigos.ml-dsa65-preview.public.v1");
    hasher.update(ed25519_public_key);
    hasher.update(signer);
    var digest: [manifest.ML_DSA65_PREVIEW_PUBLIC_COMMITMENT_BYTES]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn hybridSignatureBinding(
    pq_public_commitment: *const [manifest.ML_DSA65_PREVIEW_PUBLIC_COMMITMENT_BYTES]u8,
    ed25519_signature: []const u8,
    message: []const u8,
) [manifest.ML_DSA65_PREVIEW_SIGNATURE_BINDING_BYTES]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("zigos.ml-dsa65-preview.signature.v1");
    hasher.update(pq_public_commitment);
    hasher.update(ed25519_signature);
    hasher.update(message);
    var digest: [manifest.ML_DSA65_PREVIEW_SIGNATURE_BINDING_BYTES]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

test "ed25519 signing produces verifiable native signatures" {
    const identity = SignerIdentity{
        .label = "zigos.test",
        .seed = [_]u8{0x11} ** Ed25519.KeyPair.seed_length,
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
        .seed = [_]u8{0x12} ** Ed25519.KeyPair.seed_length,
    };
    try std.testing.expect(!verifyTrusted(signature, "storage-state", wrong_identity));
}

test "hybrid post-quantum preview signatures bind ed25519 signatures to a second verification slot" {
    const identity = SignerIdentity{
        .label = "zigos.hybrid",
        .seed = [_]u8{0x51} ** Ed25519.KeyPair.seed_length,
    };
    var signature = try signWithProfile(identity, "release-artifact", .ed25519_ml_dsa65_hybrid_preview);

    try std.testing.expect(signature.isComplete());
    try std.testing.expect(signature.usesHybridPostQuantumProfile());
    try std.testing.expectEqual(@as(usize, manifest.HYBRID_PUBLIC_KEY_BYTES), signature.publicKeySlice().len);
    try std.testing.expectEqual(@as(usize, manifest.HYBRID_SIGNATURE_BYTES), signature.valueSlice().len);
    try std.testing.expect(verify(signature, "release-artifact"));
    try std.testing.expect(verifyTrusted(signature, "release-artifact", identity));

    signature.value[manifest.ED25519_SIGNATURE_BYTES] ^= 0x80;
    try std.testing.expect(!verify(signature, "release-artifact"));

    signature = try signWithProfile(identity, "release-artifact", .ed25519_ml_dsa65_hybrid_preview);
    signature.public_key[manifest.ED25519_PUBLIC_KEY_BYTES] ^= 0x40;
    try std.testing.expect(!verify(signature, "release-artifact"));
}

test "signature providers expose release eligibility and reject mismatched profiles" {
    const identity = SignerIdentity{
        .label = "zigos.provider",
        .seed = [_]u8{0x61} ** Ed25519.KeyPair.seed_length,
    };
    var ed25519_provider_impl = SoftwareEd25519Provider{};
    const ed25519_provider = ed25519_provider_impl.provider();
    var hybrid_provider_impl = HybridPreviewProvider{};
    const hybrid_provider = hybrid_provider_impl.provider();

    try std.testing.expect(!ed25519_provider.releaseEligible());
    try std.testing.expect(!hybrid_provider.releaseEligible());
    try std.testing.expectEqual(SignatureProviderRole.test_only, ed25519_provider.descriptor.role);
    try std.testing.expectEqual(SignatureProviderRole.preview, hybrid_provider.descriptor.role);
    try std.testing.expectEqual(SignatureProviderBoundary.local_software, ed25519_provider.descriptor.provider_boundary);
    try std.testing.expectEqual(SignatureProviderBoundary.local_software, hybrid_provider.descriptor.provider_boundary);
    try std.testing.expectEqual(Fips204Implementation.preview_commitment, hybrid_provider.descriptor.fips_204);
    try std.testing.expectEqualStrings(manifest.SIGNATURE_FORMAT_ED25519, ed25519_provider.descriptor.format());
    try std.testing.expectEqualStrings(manifest.SIGNATURE_FORMAT_ED25519_ML_DSA65, hybrid_provider.descriptor.format());
    try std.testing.expectEqual(SignatureProfile.ml_dsa65_fips204, profileForFormat(manifest.SIGNATURE_FORMAT_ML_DSA65).?);

    const ed25519_signature = try ed25519_provider.sign(identity, "provider-message");
    const hybrid_signature = try hybrid_provider.sign(identity, "provider-message");

    try std.testing.expect(ed25519_provider.verify(ed25519_signature, "provider-message"));
    try std.testing.expect(hybrid_provider.verify(hybrid_signature, "provider-message"));
    try std.testing.expect(!ed25519_provider.verify(hybrid_signature, "provider-message"));
    try std.testing.expect(!hybrid_provider.verify(ed25519_signature, "provider-message"));
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

    var preview_hybrid = operational;
    preview_hybrid.profile = .ed25519_ml_dsa65_hybrid_preview;
    preview_hybrid.fips_204 = .preview_commitment;
    preview_hybrid.fips_validated = true;
    try std.testing.expect(!preview_hybrid.releaseEligible());

    var pqc_without_validation = operational;
    pqc_without_validation.name = "release-hsm-ml-dsa65-unvalidated";
    pqc_without_validation.profile = .ml_dsa65_fips204;
    pqc_without_validation.fips_standard = .fips_204;
    pqc_without_validation.post_quantum_algorithm = .ml_dsa_65;
    pqc_without_validation.fips_204 = .validated_provider;
    pqc_without_validation.fips_validated = true;
    pqc_without_validation.fips_140_validated_module = false;
    pqc_without_validation.validation_certificate = "CMVP-TBD";
    try std.testing.expect(!pqc_without_validation.releaseEligible());

    var validated_pqc = pqc_without_validation;
    validated_pqc.name = "release-hsm-ml-dsa65";
    validated_pqc.fips_140_validated_module = true;
    validated_pqc.validation_certificate = "CMVP-ML-DSA65-0001";
    try std.testing.expect(validated_pqc.releaseEligible());
}

test "external release provider uses key handles instead of software signer seeds" {
    const SigningBackend = struct {
        seed: [SEED_BYTES]u8,

        fn sign(context: *anyopaque, key: ReleaseRootKeyHandle, message: []const u8) ![SIGNATURE_BYTES]u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            const key_pair = try Ed25519.KeyPair.generateDeterministic(self.seed);
            try std.testing.expectEqualSlices(u8, &key.public_key, &key_pair.public_key.toBytes());
            return (try key_pair.sign(message, null)).toBytes();
        }
    };

    const root_identity = SignerIdentity{
        .label = "zigos.release.root",
        .seed = [_]u8{0x71} ** Ed25519.KeyPair.seed_length,
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
        .seed = [_]u8{0x72} ** Ed25519.KeyPair.seed_length,
    };
    const signature = try provider.sign(software_fixture_identity, "release-dsse-pae");
    try std.testing.expect(provider.verify(signature, "release-dsse-pae"));
    try std.testing.expect(!provider.verify(signature, "tampered-release-dsse-pae"));

    var tampered_public_key = signature;
    tampered_public_key.public_key[0] ^= 0x80;
    try std.testing.expect(!provider.verify(tampered_public_key, "release-dsse-pae"));
}

test "external ML-DSA release provider requires a validated FIPS 204 boundary" {
    const PqcBackend = struct {
        fn signatureFor(key: MlDsaReleaseRootKeyHandle, message: []const u8) [ML_DSA65_SIGNATURE_BYTES]u8 {
            var digest: [32]u8 = undefined;
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update("zigos.external-ml-dsa-provider-test");
            hasher.update(key.key_id);
            hasher.update(key.validation_certificate);
            hasher.update(key.public_key[0..]);
            hasher.update(message);
            hasher.final(&digest);

            var output: [ML_DSA65_SIGNATURE_BYTES]u8 = undefined;
            for (&output, 0..) |*byte, index| {
                byte.* = digest[index % digest.len] ^ @as(u8, @intCast(index & 0xff));
            }
            return output;
        }

        fn sign(context: *anyopaque, key: MlDsaReleaseRootKeyHandle, message: []const u8) ![ML_DSA65_SIGNATURE_BYTES]u8 {
            _ = context;
            return signatureFor(key, message);
        }

        fn verify(
            context: *anyopaque,
            key: MlDsaReleaseRootKeyHandle,
            message: []const u8,
            signature: [ML_DSA65_SIGNATURE_BYTES]u8,
        ) bool {
            _ = context;
            const expected = signatureFor(key, message);
            return std.mem.eql(u8, &signature, &expected);
        }
    };

    const descriptor = SignatureProviderDescriptor{
        .name = "release-hsm-ml-dsa65",
        .profile = .ml_dsa65_fips204,
        .role = .production,
        .provider_boundary = .offline_hsm,
        .custody = .hardware_security_module,
        .hardware_backed = true,
        .rotation_supported = true,
        .revocation_supported = true,
        .customer_verifiable = true,
        .verifier_protocol = .dsse_in_toto_slsa,
        .fips_standard = .fips_204,
        .post_quantum_algorithm = .ml_dsa_65,
        .fips_204 = .validated_provider,
        .fips_validated = true,
        .fips_140_validated_module = true,
        .validation_certificate = "CMVP-ML-DSA65-0001",
    };
    var backend = PqcBackend{};
    var provider_impl = try ExternalMlDsaReleaseProvider.init(
        descriptor,
        .{
            .key_id = "hsm://zigos/release/ml-dsa65/1",
            .label = "zigos.release.ml-dsa65",
            .public_key = [_]u8{0xa5} ** ML_DSA65_PUBLIC_KEY_BYTES,
            .generation = 1,
            .provider_boundary = .offline_hsm,
            .custody = .hardware_security_module,
            .validation_certificate = descriptor.validation_certificate,
        },
        &backend,
        PqcBackend.sign,
        PqcBackend.verify,
    );
    try std.testing.expect(provider_impl.releaseEligible());

    const identity = SignerIdentity{
        .label = "zigos.release.ml-dsa65",
        .seed = [_]u8{0x7a} ** Ed25519.KeyPair.seed_length,
    };
    const signature = try provider_impl.sign(identity, "release-dsse-pae");
    try std.testing.expect(signature.isComplete());
    try std.testing.expectEqual(@as(usize, ML_DSA65_PUBLIC_KEY_BYTES), signature.public_key.len);
    try std.testing.expectEqual(@as(usize, ML_DSA65_SIGNATURE_BYTES), signature.value.len);
    try std.testing.expect(provider_impl.verify(signature, "release-dsse-pae"));
    try std.testing.expect(!provider_impl.verify(signature, "tampered-release-dsse-pae"));

    var tampered = signature;
    tampered.value[0] ^= 0x01;
    try std.testing.expect(!provider_impl.verify(tampered, "release-dsse-pae"));
}

test "signature provider fails closed when implementation returns the wrong profile" {
    const BadProvider = struct {
        fn provider(self: *@This()) SignatureProvider {
            return SignatureProvider.init(@This(), self, .{
                .name = "bad-provider",
                .profile = .ed25519_ml_dsa65_hybrid_preview,
                .role = .test_only,
            });
        }

        fn sign(self: *@This(), identity: SignerIdentity, message: []const u8) !manifest.Signature {
            _ = self;
            return signWithProfile(identity, message, .ed25519);
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
        .seed = [_]u8{0x62} ** Ed25519.KeyPair.seed_length,
    };

    try std.testing.expectError(
        error.SignatureProviderProfileMismatch,
        bad_provider.sign(identity, "provider-message"),
    );
}

test "signature provider registry selects providers by profile and release eligibility" {
    const identity = SignerIdentity{
        .label = "zigos.registry",
        .seed = [_]u8{0x63} ** Ed25519.KeyPair.seed_length,
    };
    var ed25519_provider_impl = SoftwareEd25519Provider{};
    var hybrid_provider_impl = HybridPreviewProvider{};
    var registry = SignatureProviderRegistry.init();
    try registry.register(ed25519_provider_impl.provider());
    try registry.register(hybrid_provider_impl.provider());

    try std.testing.expect(registry.find(.ed25519) != null);
    try std.testing.expect(registry.find(.ed25519_ml_dsa65_hybrid_preview) != null);
    try std.testing.expect(registry.find(.ml_dsa65_fips204) == null);
    try std.testing.expect(registry.findReleaseEligible(.ed25519) == null);
    try std.testing.expect(registry.findReleaseEligible(.ed25519_ml_dsa65_hybrid_preview) == null);
    try std.testing.expect(registry.findReleaseEligible(.ml_dsa65_fips204) == null);
    try std.testing.expectError(error.SignatureProviderUnavailable, registry.sign(.ml_dsa65_fips204, identity, "registry-message"));

    const ed25519_signature = try registry.sign(.ed25519, identity, "registry-message");
    const hybrid_signature = try registry.sign(.ed25519_ml_dsa65_hybrid_preview, identity, "registry-message");
    try std.testing.expect(registry.verify(ed25519_signature, "registry-message"));
    try std.testing.expect(registry.verify(hybrid_signature, "registry-message"));

    var unsupported = ed25519_signature;
    unsupported.format = "unknown";
    try std.testing.expect(!registry.verify(unsupported, "registry-message"));
}
