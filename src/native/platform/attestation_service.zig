const std = @import("std");
const builtin = @import("builtin");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("measured_boot.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

const addMeasuredArtifact = measured_boot.addMeasuredArtifact;

pub const MAX_REMOTE_PARTY_BYTES: usize = 64;
pub const MAX_NONCE_BYTES: usize = 32;
pub const MAX_POLICY_LABEL_BYTES: usize = 64;
pub const MAX_ROOT_LABEL_BYTES: usize = 48;
pub const MAX_ROOT_KEY_ID_BYTES: usize = 64;
pub const MAX_REVOKED_ROOT_GENERATIONS: usize = 8;
pub const MIN_REMOTE_NONCE_BYTES: usize = 16;
pub const MAX_REMOTE_NONCE_HISTORY: usize = 8;

pub const KeyOrigin = enum(u8) {
    software,
    secure_enclave,
    tpm,
    hsm,
    cloud_kms,
};

pub const RootProviderRole = enum(u8) {
    production,
    test_only,
};

pub const RootProviderDescriptor = struct {
    name: []const u8,
    role: RootProviderRole,
    origin: KeyOrigin,
    key_id: []const u8,
    key_generation: u64,
    provider_boundary: signing.SignatureProviderBoundary = .local_software,
    custody: signing.SignatureKeyCustody = .software_seed,
    hardware_backed: bool = true,
    rotation_supported: bool = true,
    revocation_supported: bool = true,
    customer_verifiable: bool = false,

    pub fn hasOperationalCustody(self: RootProviderDescriptor) bool {
        return self.hardware_backed and self.custody != .software_seed;
    }

    pub fn hasProviderBoundary(self: RootProviderDescriptor) bool {
        return switch (self.provider_boundary) {
            .offline_hsm, .cloud_kms, .platform_tpm, .secure_enclave => true,
            .local_software => false,
        };
    }

    pub fn hasLifecycleControls(self: RootProviderDescriptor) bool {
        return self.rotation_supported and self.revocation_supported;
    }

    pub fn productionEligible(self: RootProviderDescriptor) bool {
        return self.role == .production and
            isBackedRootOrigin(self.origin) and
            self.hasProviderBoundary() and
            self.hasOperationalCustody() and
            self.hasLifecycleControls() and
            !self.hasProductionUnsafeName() and
            self.customer_verifiable and
            self.key_id.len != 0 and
            self.key_generation != 0;
    }

    pub fn hasProductionUnsafeName(self: RootProviderDescriptor) bool {
        return hasTestOnlyOperationalName(self.name) or
            hasTestOnlyOperationalName(self.key_id);
    }
};

const TEST_ONLY_OPERATIONAL_NAME_MARKERS = [_][]const u8{
    "fake",
    "mock",
    "fixture",
    "smoke",
    "local-software",
    "software-fixture",
    "synthetic",
    "simulated",
};

fn hasTestOnlyOperationalName(value: []const u8) bool {
    if (containsNameTokenIgnoreCase(value, "test")) return true;
    for (TEST_ONLY_OPERATIONAL_NAME_MARKERS) |marker| {
        if (containsAsciiIgnoreCase(value, marker)) return true;
    }
    return false;
}

fn containsNameTokenIgnoreCase(value: []const u8, token: []const u8) bool {
    if (token.len == 0 or token.len > value.len) return false;
    var index: usize = 0;
    while (index + token.len <= value.len) : (index += 1) {
        if (!std.ascii.eqlIgnoreCase(value[index..][0..token.len], token)) continue;
        const starts_on_boundary = index == 0 or isOperationalNameSeparator(value[index - 1]);
        const after_index = index + token.len;
        const ends_on_boundary = after_index == value.len or isOperationalNameSeparator(value[after_index]);
        if (starts_on_boundary and ends_on_boundary) return true;
    }
    return false;
}

fn isOperationalNameSeparator(byte: u8) bool {
    return switch (byte) {
        '-', '_', '.', ':', '/', ' ' => true,
        else => false,
    };
}

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index..][0..needle.len], needle)) return true;
    }
    return false;
}

pub const RootProvider = struct {
    context: *anyopaque,
    descriptor: RootProviderDescriptor,
    label_fn: *const fn (*anyopaque) []const u8,
    sign_fn: *const fn (*anyopaque, []const u8) anyerror!manifest.Signature,
    verifier_metadata_digest_fn: ?*const fn (*anyopaque) ?crypto_hash.Digest = null,

    pub fn init(
        comptime Provider: type,
        provider: *Provider,
        descriptor: RootProviderDescriptor,
    ) RootProvider {
        return .{
            .context = @ptrCast(provider),
            .descriptor = descriptor,
            .label_fn = struct {
                fn label(context: *anyopaque) []const u8 {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.label();
                }
            }.label,
            .sign_fn = struct {
                fn sign(context: *anyopaque, digest: []const u8) anyerror!manifest.Signature {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.sign(digest);
                }
            }.sign,
            .verifier_metadata_digest_fn = if (@hasDecl(Provider, "verifierMetadataDigest")) struct {
                fn digest(context: *anyopaque) ?crypto_hash.Digest {
                    const typed_provider: *Provider = @ptrCast(@alignCast(context));
                    return typed_provider.verifierMetadataDigest();
                }
            }.digest else null,
        };
    }

    pub fn label(self: RootProvider) []const u8 {
        return self.label_fn(self.context);
    }

    pub fn origin(self: RootProvider) KeyOrigin {
        return self.descriptor.origin;
    }

    pub fn keyId(self: RootProvider) []const u8 {
        return self.descriptor.key_id;
    }

    pub fn keyGeneration(self: RootProvider) u64 {
        return self.descriptor.key_generation;
    }

    pub fn sign(self: RootProvider, digest: []const u8) anyerror!manifest.Signature {
        return self.sign_fn(self.context, digest);
    }

    pub fn verifierMetadataDigest(self: RootProvider) ?crypto_hash.Digest {
        const digest_fn = self.verifier_metadata_digest_fn orelse return null;
        return digest_fn(self.context);
    }

    pub fn testOnly(self: RootProvider) bool {
        return self.descriptor.role == .test_only;
    }
};

pub const AttestationRootKeyHandle = struct {
    key_id: []const u8,
    label: []const u8,
    public_identity: signing.PublicIdentity,
    generation: u64,
    origin: KeyOrigin,
    provider_boundary: signing.SignatureProviderBoundary,
    custody: signing.SignatureKeyCustody,
};

pub const AttestationVerifierMetadata = struct {
    provider_name: []const u8,
    key_id: []const u8,
    label: []const u8,
    public_key: signing.PublicKey,
    generation: u64,
    origin: KeyOrigin,
    provider_boundary: signing.SignatureProviderBoundary,
    custody: signing.SignatureKeyCustody,
    hardware_backed: bool,
    rotation_supported: bool,
    revocation_supported: bool,
    customer_verifiable: bool,

    pub fn fromProvider(
        descriptor: RootProviderDescriptor,
        key: AttestationRootKeyHandle,
    ) Error!AttestationVerifierMetadata {
        if (!descriptor.productionEligible()) return error.UnbackedAttestationRoot;
        if (!std.mem.eql(u8, descriptor.key_id, key.key_id)) return error.RootIdentityMismatch;
        if (!std.mem.eql(u8, key.label, key.public_identity.label)) return error.RootIdentityMismatch;
        if (hasTestOnlyOperationalName(key.label)) return error.UnbackedAttestationRoot;
        if (descriptor.key_generation != key.generation) return error.RootProviderGenerationMismatch;
        if (descriptor.origin != key.origin) return error.UnbackedAttestationRoot;
        if (descriptor.provider_boundary != key.provider_boundary) return error.RootProviderBoundaryMismatch;
        if (descriptor.custody != key.custody) return error.RootProviderCustodyMismatch;
        return metadataFromDescriptor(descriptor, key);
    }

    pub fn productionEligible(self: AttestationVerifierMetadata) bool {
        if (self.provider_name.len == 0 or self.key_id.len == 0 or self.label.len == 0) return false;
        if (hasTestOnlyOperationalName(self.label)) return false;
        if (self.generation == 0) return false;
        const descriptor = RootProviderDescriptor{
            .name = self.provider_name,
            .role = .production,
            .origin = self.origin,
            .key_id = self.key_id,
            .key_generation = self.generation,
            .provider_boundary = self.provider_boundary,
            .custody = self.custody,
            .hardware_backed = self.hardware_backed,
            .rotation_supported = self.rotation_supported,
            .revocation_supported = self.revocation_supported,
            .customer_verifiable = self.customer_verifiable,
        };
        return descriptor.productionEligible();
    }

    pub fn matchesProvider(
        self: AttestationVerifierMetadata,
        descriptor: RootProviderDescriptor,
        key: AttestationRootKeyHandle,
    ) bool {
        const expected = fromProvider(descriptor, key) catch return false;
        return self.matches(expected);
    }

    pub fn digest(self: AttestationVerifierMetadata) crypto_hash.Digest {
        var hasher = crypto_hash.init();
        crypto_hash.updateBytes(&hasher, "schema", "zigos.attestation-verifier-metadata.v1");
        crypto_hash.updateBytes(&hasher, "provider-name", self.provider_name);
        crypto_hash.updateBytes(&hasher, "key-id", self.key_id);
        crypto_hash.updateBytes(&hasher, "label", self.label);
        crypto_hash.updateBytes(&hasher, "public-key", &self.public_key);
        crypto_hash.updateInt(&hasher, "generation", self.generation);
        crypto_hash.updateEnum(&hasher, "origin", self.origin);
        crypto_hash.updateEnum(&hasher, "provider-boundary", self.provider_boundary);
        crypto_hash.updateEnum(&hasher, "custody", self.custody);
        crypto_hash.updateBool(&hasher, "hardware-backed", self.hardware_backed);
        crypto_hash.updateBool(&hasher, "rotation-supported", self.rotation_supported);
        crypto_hash.updateBool(&hasher, "revocation-supported", self.revocation_supported);
        crypto_hash.updateBool(&hasher, "customer-verifiable", self.customer_verifiable);
        return crypto_hash.finalize(&hasher);
    }

    fn matches(self: AttestationVerifierMetadata, expected: AttestationVerifierMetadata) bool {
        return std.mem.eql(u8, self.provider_name, expected.provider_name) and
            std.mem.eql(u8, self.key_id, expected.key_id) and
            std.mem.eql(u8, self.label, expected.label) and
            std.mem.eql(u8, &self.public_key, &expected.public_key) and
            self.generation == expected.generation and
            self.origin == expected.origin and
            self.provider_boundary == expected.provider_boundary and
            self.custody == expected.custody and
            self.hardware_backed == expected.hardware_backed and
            self.rotation_supported == expected.rotation_supported and
            self.revocation_supported == expected.revocation_supported and
            self.customer_verifiable == expected.customer_verifiable;
    }

    fn metadataFromDescriptor(
        descriptor: RootProviderDescriptor,
        key: AttestationRootKeyHandle,
    ) AttestationVerifierMetadata {
        return .{
            .provider_name = descriptor.name,
            .key_id = key.key_id,
            .label = key.label,
            .public_key = key.public_identity.public_key,
            .generation = key.generation,
            .origin = descriptor.origin,
            .provider_boundary = descriptor.provider_boundary,
            .custody = descriptor.custody,
            .hardware_backed = descriptor.hardware_backed,
            .rotation_supported = descriptor.rotation_supported,
            .revocation_supported = descriptor.revocation_supported,
            .customer_verifiable = descriptor.customer_verifiable,
        };
    }
};

pub const ExternalAttestationRootProvider = struct {
    descriptor: RootProviderDescriptor,
    key: AttestationRootKeyHandle,
    context: *anyopaque,
    sign_fn: *const fn (*anyopaque, AttestationRootKeyHandle, []const u8) anyerror!manifest.Signature,
    sign_count: usize = 0,

    pub fn init(
        descriptor: RootProviderDescriptor,
        key: AttestationRootKeyHandle,
        context: *anyopaque,
        sign_fn: *const fn (*anyopaque, AttestationRootKeyHandle, []const u8) anyerror!manifest.Signature,
    ) Error!ExternalAttestationRootProvider {
        if (!descriptor.productionEligible()) return error.UnbackedAttestationRoot;
        if (!std.mem.eql(u8, descriptor.key_id, key.key_id)) return error.RootIdentityMismatch;
        if (!std.mem.eql(u8, key.label, key.public_identity.label)) return error.RootIdentityMismatch;
        if (hasTestOnlyOperationalName(key.label)) return error.UnbackedAttestationRoot;
        if (descriptor.key_generation != key.generation) return error.RootProviderGenerationMismatch;
        if (descriptor.origin != key.origin) return error.UnbackedAttestationRoot;
        if (descriptor.provider_boundary != key.provider_boundary) return error.RootProviderBoundaryMismatch;
        if (descriptor.custody != key.custody) return error.RootProviderCustodyMismatch;
        return .{
            .descriptor = descriptor,
            .key = key,
            .context = context,
            .sign_fn = sign_fn,
        };
    }

    pub fn provider(self: *ExternalAttestationRootProvider) RootProvider {
        return RootProvider.init(ExternalAttestationRootProvider, self, self.descriptor);
    }

    pub fn publicIdentity(self: *const ExternalAttestationRootProvider) signing.PublicIdentity {
        return self.key.public_identity;
    }

    pub fn verifierMetadata(self: *const ExternalAttestationRootProvider) AttestationVerifierMetadata {
        return AttestationVerifierMetadata.metadataFromDescriptor(self.descriptor, self.key);
    }

    pub fn verifierMetadataDigest(self: *const ExternalAttestationRootProvider) crypto_hash.Digest {
        return self.verifierMetadata().digest();
    }

    pub fn label(self: *const ExternalAttestationRootProvider) []const u8 {
        return self.key.label;
    }

    pub fn sign(self: *ExternalAttestationRootProvider, digest: []const u8) !manifest.Signature {
        self.sign_count += 1;
        const signature = try self.sign_fn(self.context, self.key, digest);
        if (!signing.verifyTrustedPublicKey(signature, digest, self.key.public_identity)) {
            return error.RootIdentityMismatch;
        }
        return signature;
    }
};

pub const FakeTpmRootProvider = struct {
    signer: signing.SignerIdentity,
    key_generation: u64 = 1,
    sign_count: usize = 0,

    pub fn init(signer: signing.SignerIdentity) FakeTpmRootProvider {
        return .{ .signer = signer };
    }

    pub fn initGeneration(signer: signing.SignerIdentity, key_generation: u64) FakeTpmRootProvider {
        return .{ .signer = signer, .key_generation = key_generation };
    }

    pub fn provider(self: *FakeTpmRootProvider) RootProvider {
        return RootProvider.init(FakeTpmRootProvider, self, .{
            .name = "fake-tpm-root-provider",
            .role = .test_only,
            .origin = .tpm,
            .key_id = self.signer.label,
            .key_generation = self.key_generation,
        });
    }

    pub fn label(self: *const FakeTpmRootProvider) []const u8 {
        return self.signer.label;
    }

    pub fn sign(self: *FakeTpmRootProvider, digest: []const u8) !manifest.Signature {
        self.sign_count += 1;
        return signing.signWithDefaultRegistry(.ed25519, self.signer, digest);
    }

    pub fn publicIdentity(self: *const FakeTpmRootProvider) !signing.PublicIdentity {
        return signing.publicIdentity(self.signer);
    }
};

pub const FakeSecureEnclaveRootProvider = struct {
    signer: signing.SignerIdentity,
    key_generation: u64 = 1,
    sign_count: usize = 0,

    pub fn init(signer: signing.SignerIdentity) FakeSecureEnclaveRootProvider {
        return .{ .signer = signer };
    }

    pub fn initGeneration(signer: signing.SignerIdentity, key_generation: u64) FakeSecureEnclaveRootProvider {
        return .{ .signer = signer, .key_generation = key_generation };
    }

    pub fn provider(self: *FakeSecureEnclaveRootProvider) RootProvider {
        return RootProvider.init(FakeSecureEnclaveRootProvider, self, .{
            .name = "fake-secure-enclave-root-provider",
            .role = .test_only,
            .origin = .secure_enclave,
            .key_id = self.signer.label,
            .key_generation = self.key_generation,
        });
    }

    pub fn label(self: *const FakeSecureEnclaveRootProvider) []const u8 {
        return self.signer.label;
    }

    pub fn sign(self: *FakeSecureEnclaveRootProvider, digest: []const u8) !manifest.Signature {
        self.sign_count += 1;
        return signing.signWithDefaultRegistry(.ed25519, self.signer, digest);
    }

    pub fn publicIdentity(self: *const FakeSecureEnclaveRootProvider) !signing.PublicIdentity {
        return signing.publicIdentity(self.signer);
    }
};

pub const TestSoftwareRootProvider = struct {
    signer: signing.SignerIdentity,

    pub fn init(signer: signing.SignerIdentity) TestSoftwareRootProvider {
        return .{ .signer = signer };
    }

    pub fn provider(self: *TestSoftwareRootProvider) RootProvider {
        return RootProvider.init(TestSoftwareRootProvider, self, .{
            .name = "test-software-root-provider",
            .role = .test_only,
            .origin = .software,
            .key_id = self.signer.label,
            .key_generation = 1,
            .hardware_backed = false,
        });
    }

    pub fn label(self: *const TestSoftwareRootProvider) []const u8 {
        return self.signer.label;
    }

    pub fn sign(self: *TestSoftwareRootProvider, digest: []const u8) !manifest.Signature {
        return signing.signWithDefaultRegistry(.ed25519, self.signer, digest);
    }
};

pub const Statement = struct {
    device: principal.PrincipalId,
    generation: u64,
    record_count: usize,
    critical_service_count: usize,
    policy_count: usize,
    driver_count: usize,
    user_visible: bool,
    remote_party_len: usize,
    remote_party: [MAX_REMOTE_PARTY_BYTES]u8,
    nonce_len: usize,
    nonce: [MAX_NONCE_BYTES]u8,
    key_origin: KeyOrigin,
    root_label_len: usize,
    root_label: [MAX_ROOT_LABEL_BYTES]u8,
    root_key_id_len: usize,
    root_key_id: [MAX_ROOT_KEY_ID_BYTES]u8,
    root_key_generation: u64,
    root_digest: crypto_hash.Digest,
    root_provenance: measured_boot.RootProvenance,
    manifest_verified: bool,
    signature: manifest.Signature,

    pub fn remotePartySlice(self: *const Statement) []const u8 {
        return self.remote_party[0..self.remote_party_len];
    }

    pub fn nonceSlice(self: *const Statement) []const u8 {
        return self.nonce[0..self.nonce_len];
    }

    pub fn rootLabelSlice(self: *const Statement) []const u8 {
        return self.root_label[0..self.root_label_len];
    }

    pub fn rootKeyIdSlice(self: *const Statement) []const u8 {
        return self.root_key_id[0..self.root_key_id_len];
    }
};

pub const VerificationExpectation = struct {
    boot: *const measured_boot.BootRecord,
    remote_party: []const u8,
    nonce: []const u8,
    user_visible: bool,
    key_origin: ?KeyOrigin = null,
    root_key_id: []const u8 = "",
    minimum_root_generation: u64 = 0,
    revoked_root_generations: []const u64 = &.{},
    attestation_root: ?signing.PublicIdentity = null,
};

pub const RemoteAttestationRequestInit = struct {
    remote_party: []const u8,
    nonce: []const u8,
    policy_label: []const u8,
    user_visible: bool = true,
    expected_key_origin: ?KeyOrigin = null,
    root_key_id: []const u8 = "",
    minimum_root_generation: u64 = 0,
    revoked_root_generations: []const u64 = &.{},
    attestation_verifier_metadata_digest_required: bool = false,
    attestation_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,
};

pub const RemoteAttestationRequest = struct {
    remote_party_len: usize = 0,
    remote_party: [MAX_REMOTE_PARTY_BYTES]u8 = [_]u8{0} ** MAX_REMOTE_PARTY_BYTES,
    nonce_len: usize = 0,
    nonce: [MAX_NONCE_BYTES]u8 = [_]u8{0} ** MAX_NONCE_BYTES,
    policy_label_len: usize = 0,
    policy_label: [MAX_POLICY_LABEL_BYTES]u8 = [_]u8{0} ** MAX_POLICY_LABEL_BYTES,
    user_visible: bool = true,
    expected_key_origin: ?KeyOrigin = null,
    root_key_id_len: usize = 0,
    root_key_id: [MAX_ROOT_KEY_ID_BYTES]u8 = [_]u8{0} ** MAX_ROOT_KEY_ID_BYTES,
    minimum_root_generation: u64 = 0,
    revoked_root_generation_count: usize = 0,
    revoked_root_generations: [MAX_REVOKED_ROOT_GENERATIONS]u64 = [_]u64{0} ** MAX_REVOKED_ROOT_GENERATIONS,
    attestation_verifier_metadata_digest_required: bool = false,
    attestation_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,

    pub fn init(args: RemoteAttestationRequestInit) Error!RemoteAttestationRequest {
        if (args.revoked_root_generations.len > MAX_REVOKED_ROOT_GENERATIONS) return error.RevocationListFull;
        if (args.attestation_verifier_metadata_digest_required and
            std.mem.allEqual(u8, &args.attestation_verifier_metadata_digest, 0))
        {
            return error.AttestationVerifierMetadataMissing;
        }
        var request = RemoteAttestationRequest{
            .user_visible = args.user_visible,
            .expected_key_origin = args.expected_key_origin,
            .minimum_root_generation = args.minimum_root_generation,
            .revoked_root_generation_count = args.revoked_root_generations.len,
            .attestation_verifier_metadata_digest_required = args.attestation_verifier_metadata_digest_required,
            .attestation_verifier_metadata_digest = args.attestation_verifier_metadata_digest,
        };
        request.remote_party_len = native_util.copyTextExact(&request.remote_party, args.remote_party) catch return error.RemotePartyTooLong;
        request.nonce_len = native_util.copyTextExact(&request.nonce, args.nonce) catch return error.NonceTooLong;
        request.policy_label_len = native_util.copyTextExact(&request.policy_label, args.policy_label) catch return error.PolicyLabelTooLong;
        request.root_key_id_len = native_util.copyTextExact(&request.root_key_id, args.root_key_id) catch return error.RootKeyIdTooLong;
        for (args.revoked_root_generations, 0..) |generation, index| {
            request.revoked_root_generations[index] = generation;
        }
        return request;
    }

    pub fn remotePartySlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.remote_party[0..self.remote_party_len];
    }

    pub fn nonceSlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.nonce[0..self.nonce_len];
    }

    pub fn policyLabelSlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.policy_label[0..self.policy_label_len];
    }

    pub fn rootKeyIdSlice(self: *const RemoteAttestationRequest) []const u8 {
        return self.root_key_id[0..self.root_key_id_len];
    }

    pub fn revokedRootGenerationsSlice(self: *const RemoteAttestationRequest) []const u64 {
        return self.revoked_root_generations[0..self.revoked_root_generation_count];
    }

    pub fn digest(self: *const RemoteAttestationRequest) crypto_hash.Digest {
        var hasher = crypto_hash.init();
        crypto_hash.updateBytes(&hasher, "remote-party", self.remotePartySlice());
        crypto_hash.updateBytes(&hasher, "nonce", self.nonceSlice());
        crypto_hash.updateBytes(&hasher, "policy-label", self.policyLabelSlice());
        crypto_hash.updateBool(&hasher, "user-visible", self.user_visible);
        crypto_hash.updateBool(&hasher, "expected-origin-present", self.expected_key_origin != null);
        if (self.expected_key_origin) |origin| {
            crypto_hash.updateEnum(&hasher, "expected-origin", origin);
        }
        crypto_hash.updateBytes(&hasher, "root-key-id", self.rootKeyIdSlice());
        crypto_hash.updateInt(&hasher, "minimum-root-generation", self.minimum_root_generation);
        crypto_hash.updateInt(&hasher, "revoked-root-generation-count", self.revoked_root_generation_count);
        for (self.revokedRootGenerationsSlice()) |generation| {
            crypto_hash.updateInt(&hasher, "revoked-root-generation", generation);
        }
        crypto_hash.updateBool(&hasher, "attestation-verifier-metadata-digest-required", self.attestation_verifier_metadata_digest_required);
        if (self.attestation_verifier_metadata_digest_required) {
            crypto_hash.updateBytes(&hasher, "attestation-verifier-metadata-digest", &self.attestation_verifier_metadata_digest);
        }
        return crypto_hash.finalize(&hasher);
    }
};

pub const RemoteAttestationResponse = struct {
    request_digest: crypto_hash.Digest,
    policy_label_len: usize = 0,
    policy_label: [MAX_POLICY_LABEL_BYTES]u8 = [_]u8{0} ** MAX_POLICY_LABEL_BYTES,
    minimum_root_generation: u64 = 0,
    revoked_root_generation_count: usize = 0,
    revoked_root_generations: [MAX_REVOKED_ROOT_GENERATIONS]u64 = [_]u64{0} ** MAX_REVOKED_ROOT_GENERATIONS,
    attestation_verifier_metadata_digest_present: bool = false,
    attestation_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    statement: Statement,

    pub fn policyLabelSlice(self: *const RemoteAttestationResponse) []const u8 {
        return self.policy_label[0..self.policy_label_len];
    }

    pub fn revokedRootGenerationsSlice(self: *const RemoteAttestationResponse) []const u64 {
        return self.revoked_root_generations[0..self.revoked_root_generation_count];
    }
};

pub const Error = error{
    NonceTooLong,
    RemotePartyTooLong,
    PolicyLabelTooLong,
    RootNotProvisioned,
    RootIdentityMissing,
    RootIdentityMismatch,
    RootLabelTooLong,
    RootKeyIdTooLong,
    RootProviderBoundaryMismatch,
    RootProviderCustodyMismatch,
    RootProviderGenerationMismatch,
    TestRootProviderRejected,
    UnbackedAttestationRoot,
    RootLifecycleUnsupported,
    InvalidRootGeneration,
    StaleRootGeneration,
    RootGenerationRevoked,
    RevocationListFull,
    AttestationVerifierMetadataMissing,
    AttestationVerifierMetadataMismatch,
    UserVisibilityRequired,
    UnverifiedMeasuredRoot,
    RemoteNonceMissing,
    RemoteNonceTooShort,
    RemoteNonceReplay,
};

pub const Service = struct {
    device: principal.PrincipalId,
    visible_request_count: usize = 0,
    last_remote_party_len: usize = 0,
    last_remote_party: [MAX_REMOTE_PARTY_BYTES]u8 = [_]u8{0} ** MAX_REMOTE_PARTY_BYTES,
    last_remote_nonce_len: usize = 0,
    last_remote_nonce: [MAX_NONCE_BYTES]u8 = [_]u8{0} ** MAX_NONCE_BYTES,
    remote_nonce_history_count: usize = 0,
    remote_nonce_history: [MAX_REMOTE_NONCE_HISTORY]crypto_hash.Digest = [_]crypto_hash.Digest{crypto_hash.zero_digest} ** MAX_REMOTE_NONCE_HISTORY,
    has_provisioned_root: bool = false,
    root_origin: KeyOrigin = .software,
    root_label_len: usize = 0,
    root_label: [MAX_ROOT_LABEL_BYTES]u8 = [_]u8{0} ** MAX_ROOT_LABEL_BYTES,
    root_key_id_len: usize = 0,
    root_key_id: [MAX_ROOT_KEY_ID_BYTES]u8 = [_]u8{0} ** MAX_ROOT_KEY_ID_BYTES,
    root_key_generation: u64 = 0,
    revoked_root_generation_count: usize = 0,
    revoked_root_generations: [MAX_REVOKED_ROOT_GENERATIONS]u64 = [_]u64{0} ** MAX_REVOKED_ROOT_GENERATIONS,
    root_verifier_metadata_digest_present: bool = false,
    root_verifier_metadata_digest: crypto_hash.Digest = crypto_hash.zero_digest,
    root_provider: ?RootProvider = null,
    allow_test_root_providers: bool = builtin.is_test,

    pub fn init(device: principal.PrincipalId) Service {
        return .{ .device = device };
    }

    pub fn provisionRootProvider(self: *Service, provider: RootProvider) Error!void {
        if (!isBackedRootOrigin(provider.origin()) or !provider.descriptor.hardware_backed) return error.UnbackedAttestationRoot;
        if (provider.descriptor.role == .production and !provider.descriptor.productionEligible()) return error.UnbackedAttestationRoot;
        if (provider.descriptor.role == .production and hasTestOnlyOperationalName(provider.label())) return error.UnbackedAttestationRoot;
        if (!provider.descriptor.rotation_supported or !provider.descriptor.revocation_supported) return error.RootLifecycleUnsupported;
        if (provider.keyGeneration() == 0) return error.InvalidRootGeneration;
        if (provider.label().len == 0 or provider.keyId().len == 0) return error.RootIdentityMissing;
        if (provider.testOnly() and !self.allow_test_root_providers) return error.TestRootProviderRejected;
        if (self.isRootGenerationRevoked(provider.keyGeneration())) return error.RootGenerationRevoked;
        const verifier_metadata_digest = provider.verifierMetadataDigest();
        if (provider.descriptor.role == .production and verifier_metadata_digest == null) {
            return error.AttestationVerifierMetadataMissing;
        }
        self.has_provisioned_root = true;
        self.root_origin = provider.origin();
        self.root_label_len = native_util.copyTextExact(&self.root_label, provider.label()) catch return error.RootLabelTooLong;
        self.root_key_id_len = native_util.copyTextExact(&self.root_key_id, provider.keyId()) catch return error.RootLabelTooLong;
        self.root_key_generation = provider.keyGeneration();
        self.root_verifier_metadata_digest_present = verifier_metadata_digest != null;
        self.root_verifier_metadata_digest = verifier_metadata_digest orelse crypto_hash.zero_digest;
        self.root_provider = provider;
    }

    pub fn rotateRootProvider(self: *Service, provider: RootProvider) Error!void {
        if (self.has_provisioned_root and provider.keyGeneration() <= self.root_key_generation) {
            return error.StaleRootGeneration;
        }
        try self.provisionRootProvider(provider);
    }

    pub fn revokeRootGeneration(self: *Service, generation: u64) Error!void {
        if (self.isRootGenerationRevoked(generation)) return;
        if (self.revoked_root_generation_count >= self.revoked_root_generations.len) return error.RevocationListFull;
        self.revoked_root_generations[self.revoked_root_generation_count] = generation;
        self.revoked_root_generation_count += 1;
    }

    pub fn isRootGenerationRevoked(self: *const Service, generation: u64) bool {
        var index: usize = 0;
        while (index < self.revoked_root_generation_count) : (index += 1) {
            if (self.revoked_root_generations[index] == generation) return true;
        }
        return false;
    }

    pub fn attest(
        self: *Service,
        boot: measured_boot.BootRecord,
        remote_party: []const u8,
        nonce: []const u8,
        signer: signing.SignerIdentity,
        user_visible: bool,
    ) !Statement {
        if (remote_party.len != 0 and !user_visible) return error.UserVisibilityRequired;
        if (remote_party.len != 0) return error.RootNotProvisioned;
        return self.attestInternal(boot, remote_party, nonce, signer, user_visible, .software);
    }

    pub fn attestWithProvisionedRoot(
        self: *Service,
        boot: measured_boot.BootRecord,
        remote_party: []const u8,
        nonce: []const u8,
        user_visible: bool,
    ) (Error || anyerror)!Statement {
        if (!self.has_provisioned_root) return error.RootNotProvisioned;
        const provider = self.root_provider orelse return error.RootNotProvisioned;
        if (!isBackedRootOrigin(provider.origin())) return error.UnbackedAttestationRoot;
        if (provider.origin() != self.root_origin) return error.UnbackedAttestationRoot;
        if (self.isRootGenerationRevoked(provider.keyGeneration())) return error.RootGenerationRevoked;
        try self.validateRemoteChallenge(remote_party, nonce, user_visible);
        if (!boot.isRemoteAttestable()) return error.UnverifiedMeasuredRoot;
        if (!boot.isInternallyConsistent()) return error.UnverifiedMeasuredRoot;

        return self.attestWithProviderInternal(boot, remote_party, nonce, provider, user_visible);
    }

    pub fn respondToRemoteAttestationRequest(
        self: *Service,
        boot: measured_boot.BootRecord,
        request: RemoteAttestationRequest,
    ) (Error || anyerror)!RemoteAttestationResponse {
        const provider = self.root_provider orelse return error.RootNotProvisioned;
        if (request.expected_key_origin) |expected_origin| {
            if (provider.origin() != expected_origin) return error.UnbackedAttestationRoot;
        }
        if (request.root_key_id_len != 0 and !std.mem.eql(u8, provider.keyId(), request.rootKeyIdSlice())) return error.RootIdentityMismatch;
        if (request.minimum_root_generation != 0 and provider.keyGeneration() < request.minimum_root_generation) return error.StaleRootGeneration;
        for (request.revokedRootGenerationsSlice()) |revoked_generation| {
            if (provider.keyGeneration() == revoked_generation) return error.RootGenerationRevoked;
        }
        if (request.attestation_verifier_metadata_digest_required) {
            if (!self.root_verifier_metadata_digest_present) return error.AttestationVerifierMetadataMissing;
            if (!std.mem.eql(u8, &self.root_verifier_metadata_digest, &request.attestation_verifier_metadata_digest)) {
                return error.AttestationVerifierMetadataMismatch;
            }
        }
        const statement = try self.attestWithProvisionedRoot(
            boot,
            request.remotePartySlice(),
            request.nonceSlice(),
            request.user_visible,
        );
        var response = RemoteAttestationResponse{
            .request_digest = request.digest(),
            .minimum_root_generation = request.minimum_root_generation,
            .revoked_root_generation_count = request.revoked_root_generation_count,
            .statement = statement,
        };
        if (self.root_verifier_metadata_digest_present) {
            response.attestation_verifier_metadata_digest_present = true;
            response.attestation_verifier_metadata_digest = self.root_verifier_metadata_digest;
        }
        response.policy_label_len = native_util.copyTextExact(&response.policy_label, request.policyLabelSlice()) catch return error.PolicyLabelTooLong;
        for (request.revokedRootGenerationsSlice(), 0..) |generation, index| {
            response.revoked_root_generations[index] = generation;
        }
        return response;
    }

    pub fn verifyRemoteAttestationResponse(
        response: RemoteAttestationResponse,
        request: RemoteAttestationRequest,
        boot: *const measured_boot.BootRecord,
        trusted_root: signing.PublicIdentity,
    ) bool {
        const request_digest = request.digest();
        if (!std.mem.eql(u8, &response.request_digest, &request_digest)) return false;
        if (!std.mem.eql(u8, response.policyLabelSlice(), request.policyLabelSlice())) return false;
        if (response.minimum_root_generation != request.minimum_root_generation) return false;
        if (!std.mem.eql(u64, response.revokedRootGenerationsSlice(), request.revokedRootGenerationsSlice())) return false;
        if (request.attestation_verifier_metadata_digest_required) {
            if (!response.attestation_verifier_metadata_digest_present) return false;
            if (!std.mem.eql(u8, &response.attestation_verifier_metadata_digest, &request.attestation_verifier_metadata_digest)) return false;
        }

        return Service.verifyForBoot(response.statement, .{
            .boot = boot,
            .remote_party = request.remotePartySlice(),
            .nonce = request.nonceSlice(),
            .user_visible = request.user_visible,
            .key_origin = request.expected_key_origin,
            .root_key_id = request.rootKeyIdSlice(),
            .minimum_root_generation = request.minimum_root_generation,
            .revoked_root_generations = request.revokedRootGenerationsSlice(),
            .attestation_root = trusted_root,
        });
    }

    fn validateRemoteChallenge(
        self: *const Service,
        remote_party: []const u8,
        nonce: []const u8,
        user_visible: bool,
    ) Error!void {
        if (remote_party.len == 0) return;
        if (!user_visible) return error.UserVisibilityRequired;
        if (nonce.len == 0) return error.RemoteNonceMissing;
        if (nonce.len < MIN_REMOTE_NONCE_BYTES) return error.RemoteNonceTooShort;
        const digest = remoteChallengeDigest(remote_party, nonce);
        var index: usize = 0;
        while (index < self.remote_nonce_history_count) : (index += 1) {
            if (std.mem.eql(u8, &self.remote_nonce_history[index], &digest)) return error.RemoteNonceReplay;
        }
    }

    fn attestInternal(
        self: *Service,
        boot: measured_boot.BootRecord,
        remote_party: []const u8,
        nonce: []const u8,
        signer: signing.SignerIdentity,
        user_visible: bool,
        origin: KeyOrigin,
    ) !Statement {
        var statement = try self.buildStatement(boot, remote_party, nonce, signer.label, signer.label, 0, user_visible, origin);
        const digest = statementDigest(statement);
        statement.signature = try signing.signWithDefaultRegistry(.ed25519, signer, &digest);
        return statement;
    }

    fn attestWithProviderInternal(
        self: *Service,
        boot: measured_boot.BootRecord,
        remote_party: []const u8,
        nonce: []const u8,
        provider: RootProvider,
        user_visible: bool,
    ) !Statement {
        var statement = try self.buildStatement(
            boot,
            remote_party,
            nonce,
            self.rootLabelSlice(),
            self.rootKeyIdSlice(),
            provider.keyGeneration(),
            user_visible,
            provider.origin(),
        );
        const digest = statementDigest(statement);
        statement.signature = try provider.sign(&digest);
        return statement;
    }

    fn buildStatement(
        self: *Service,
        boot: measured_boot.BootRecord,
        remote_party: []const u8,
        nonce: []const u8,
        root_label: []const u8,
        root_key_id: []const u8,
        root_key_generation: u64,
        user_visible: bool,
        origin: KeyOrigin,
    ) !Statement {
        var statement = Statement{
            .device = self.device,
            .generation = boot.generation,
            .record_count = boot.record_count,
            .critical_service_count = boot.countKind(.critical_service),
            .policy_count = boot.countKind(.policy),
            .driver_count = boot.countKind(.driver_set),
            .user_visible = user_visible,
            .remote_party_len = 0,
            .remote_party = [_]u8{0} ** MAX_REMOTE_PARTY_BYTES,
            .nonce_len = 0,
            .nonce = [_]u8{0} ** MAX_NONCE_BYTES,
            .key_origin = origin,
            .root_label_len = 0,
            .root_label = [_]u8{0} ** MAX_ROOT_LABEL_BYTES,
            .root_key_id_len = 0,
            .root_key_id = [_]u8{0} ** MAX_ROOT_KEY_ID_BYTES,
            .root_key_generation = root_key_generation,
            .root_digest = boot.root_digest,
            .root_provenance = boot.root_provenance,
            .manifest_verified = boot.artifact_manifest_verified,
            .signature = .{},
        };
        statement.remote_party_len = native_util.copyTextExact(&statement.remote_party, remote_party) catch return error.RemotePartyTooLong;
        statement.nonce_len = native_util.copyTextExact(&statement.nonce, nonce) catch return error.NonceTooLong;
        statement.root_label_len = native_util.copyTextExact(&statement.root_label, root_label) catch return error.RootLabelTooLong;
        statement.root_key_id_len = native_util.copyTextExact(&statement.root_key_id, root_key_id) catch return error.RootLabelTooLong;

        if (user_visible) {
            self.visible_request_count += 1;
            self.last_remote_party_len = native_util.copyTextExact(&self.last_remote_party, remote_party) catch return error.RemotePartyTooLong;
            if (remote_party.len != 0) {
                self.last_remote_nonce_len = native_util.copyTextExact(&self.last_remote_nonce, nonce) catch return error.NonceTooLong;
                self.rememberRemoteChallenge(remote_party, nonce);
            }
        }

        return statement;
    }

    fn rememberRemoteChallenge(self: *Service, remote_party: []const u8, nonce: []const u8) void {
        const digest = remoteChallengeDigest(remote_party, nonce);
        if (self.remote_nonce_history_count < self.remote_nonce_history.len) {
            self.remote_nonce_history[self.remote_nonce_history_count] = digest;
            self.remote_nonce_history_count += 1;
            return;
        }
        std.mem.copyForwards(crypto_hash.Digest, self.remote_nonce_history[0 .. self.remote_nonce_history.len - 1], self.remote_nonce_history[1..]);
        self.remote_nonce_history[self.remote_nonce_history.len - 1] = digest;
    }

    pub fn verify(statement: Statement) bool {
        const digest = statementDigest(statement);
        return signing.verifyWithDefaultRegistry(statement.signature, &digest);
    }

    pub fn verifyForBoot(statement: Statement, expectation: VerificationExpectation) bool {
        const digest = statementDigest(statement);
        if (!signing.verifyWithDefaultRegistry(statement.signature, &digest)) return false;
        if (!expectation.boot.isRemoteAttestable()) return false;
        if (!expectation.boot.isInternallyConsistent()) return false;
        if (!isBackedRootOrigin(statement.key_origin)) return false;
        if (statement.generation != expectation.boot.generation) return false;
        if (statement.record_count != expectation.boot.record_count) return false;
        if (statement.critical_service_count != expectation.boot.countKind(.critical_service)) return false;
        if (statement.policy_count != expectation.boot.countKind(.policy)) return false;
        if (statement.driver_count != expectation.boot.countKind(.driver_set)) return false;
        if (!std.mem.eql(u8, &statement.root_digest, &expectation.boot.root_digest)) return false;
        if (statement.root_provenance != expectation.boot.root_provenance) return false;
        if (statement.manifest_verified != expectation.boot.artifact_manifest_verified) return false;
        if (!std.mem.eql(u8, statement.remotePartySlice(), expectation.remote_party)) return false;
        if (!std.mem.eql(u8, statement.nonceSlice(), expectation.nonce)) return false;
        if (statement.user_visible != expectation.user_visible) return false;
        if (expectation.key_origin) |expected_origin| {
            if (statement.key_origin != expected_origin) return false;
        }
        if (expectation.root_key_id.len != 0 and !std.mem.eql(u8, statement.rootKeyIdSlice(), expectation.root_key_id)) return false;
        if (expectation.minimum_root_generation != 0 and statement.root_key_generation < expectation.minimum_root_generation) return false;
        for (expectation.revoked_root_generations) |revoked_generation| {
            if (statement.root_key_generation == revoked_generation) return false;
        }
        if (expectation.attestation_root) |expected_root| {
            if (!std.mem.eql(u8, statement.rootLabelSlice(), expected_root.label)) return false;
            if (!signing.verifyTrustedPublicKey(statement.signature, &digest, expected_root)) return false;
        }
        return true;
    }

    fn rootLabelSlice(self: *const Service) []const u8 {
        return self.root_label[0..self.root_label_len];
    }

    fn rootKeyIdSlice(self: *const Service) []const u8 {
        return self.root_key_id[0..self.root_key_id_len];
    }
};

fn isBackedRootOrigin(origin: KeyOrigin) bool {
    return origin != .software;
}

fn statementDigest(statement: Statement) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateEnum(&hasher, "device-kind", statement.device.kind);
    crypto_hash.updateInt(&hasher, "device-serial", statement.device.serial);
    crypto_hash.updateInt(&hasher, "generation", statement.generation);
    crypto_hash.updateInt(&hasher, "record-count", statement.record_count);
    crypto_hash.updateInt(&hasher, "critical-service-count", statement.critical_service_count);
    crypto_hash.updateInt(&hasher, "policy-count", statement.policy_count);
    crypto_hash.updateInt(&hasher, "driver-count", statement.driver_count);
    crypto_hash.updateBool(&hasher, "user-visible", statement.user_visible);
    crypto_hash.updateBytes(&hasher, "remote-party", statement.remotePartySlice());
    crypto_hash.updateBytes(&hasher, "nonce", statement.nonceSlice());
    crypto_hash.updateEnum(&hasher, "key-origin", statement.key_origin);
    crypto_hash.updateBytes(&hasher, "root-label", statement.rootLabelSlice());
    crypto_hash.updateBytes(&hasher, "root-key-id", statement.rootKeyIdSlice());
    crypto_hash.updateInt(&hasher, "root-key-generation", statement.root_key_generation);
    crypto_hash.updateBytes(&hasher, "root-digest", &statement.root_digest);
    crypto_hash.updateEnum(&hasher, "root-provenance", statement.root_provenance);
    crypto_hash.updateBool(&hasher, "manifest-verified", statement.manifest_verified);
    return crypto_hash.finalize(&hasher);
}

fn remoteChallengeDigest(remote_party: []const u8, nonce: []const u8) crypto_hash.Digest {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "remote-party", remote_party);
    crypto_hash.updateBytes(&hasher, "nonce", nonce);
    return crypto_hash.finalize(&hasher);
}

fn verifiedTestBoot(generation: u64, root_provenance: measured_boot.RootProvenance) !measured_boot.BootRecord {
    var recorder = measured_boot.Recorder.init();
    var artifact_manifest = measured_boot.ArtifactManifest.init(generation);
    recorder.begin(generation);
    try addMeasuredArtifact(&recorder, &artifact_manifest, .kernel, "kernel-zigos", "kernel=v5");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .base_image, "stable-d", "image=v5");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "policy", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "storage", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "compositor", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .critical_service, "network", "healthy");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .policy, "org-defaults", "strict");
    try addMeasuredArtifact(&recorder, &artifact_manifest, .driver_set, "signed-drivers", "gpu+npu+net");
    var boot = recorder.finalize();
    try measured_boot.verifyBootRecordAgainstManifest(&boot, &artifact_manifest, root_provenance);
    return boot;
}

test "attestation service signs measured state and records user visible requests" {
    var recorder = measured_boot.Recorder.init();
    recorder.begin(12);
    try recorder.add(.kernel, "kernel-zigos", "kernel=v3");
    try recorder.add(.base_image, "stable-b", "image=v3");
    try recorder.add(.critical_service, "storage", "healthy");
    try recorder.add(.policy, "org-defaults", "strict");
    try recorder.add(.driver_set, "signed-drivers", "gpu+npu+net");
    const boot = recorder.finalize();

    var service = Service.init(.{ .kind = .device, .serial = 33 });
    try std.testing.expectError(error.RootNotProvisioned, service.attest(boot, "attest.example", "nonce-1", .{
        .label = "device-attest",
        .seed = signing.seedFromByte(0x51),
    }, true));

    const statement = try service.attest(boot, "", "nonce-1", .{
        .label = "device-attest",
        .seed = signing.seedFromByte(0x51),
    }, true);

    try std.testing.expectEqual(@as(u64, 12), statement.generation);
    try std.testing.expectEqual(@as(usize, 1), statement.critical_service_count);
    try std.testing.expectEqual(@as(usize, 1), statement.policy_count);
    try std.testing.expectEqual(@as(usize, 1), statement.driver_count);
    try std.testing.expectEqualStrings("", statement.remotePartySlice());
    try std.testing.expect(statement.user_visible);
    try std.testing.expect(Service.verify(statement));
    try std.testing.expectEqual(@as(usize, 1), service.visible_request_count);
    try std.testing.expectEqualStrings("", service.last_remote_party[0..service.last_remote_party_len]);
    try std.testing.expectEqual(KeyOrigin.software, statement.key_origin);
}

test "attestation service does not count hidden requests and detects tampering" {
    var recorder = measured_boot.Recorder.init();
    recorder.begin(13);
    try recorder.add(.kernel, "kernel-zigos", "kernel=v4");
    try recorder.add(.base_image, "stable-c", "image=v4");
    const boot = recorder.finalize();

    var service = Service.init(.{ .kind = .device, .serial = 34 });
    try std.testing.expectError(error.UserVisibilityRequired, service.attest(boot, "audit.example", "nonce-2", .{
        .label = "device-attest",
        .seed = signing.seedFromByte(0x54),
    }, false));

    const statement = try service.attest(boot, "", "nonce-2", .{
        .label = "device-attest",
        .seed = signing.seedFromByte(0x54),
    }, false);

    try std.testing.expect(!statement.user_visible);
    try std.testing.expectEqual(@as(usize, 0), service.visible_request_count);
    try std.testing.expect(Service.verify(statement));

    var tampered = statement;
    tampered.root_digest[0] ^=
        0xFF;
    try std.testing.expect(!Service.verify(tampered));
}

test "attestation service can use a provisioned hardware-backed root for visible remote requests" {
    const boot = try verifiedTestBoot(14, .bootloader_provided);
    const root_signer = signing.SignerIdentity{
        .label = "device-se",
        .seed = signing.seedFromByte(0x55),
    };
    var root_provider = FakeSecureEnclaveRootProvider.init(root_signer);
    const provider = root_provider.provider();
    const root_identity = try root_provider.publicIdentity();

    var service = Service.init(.{ .kind = .device, .serial = 35 });
    try std.testing.expect(!@hasField(Service, "root_seed"));
    try std.testing.expect(provider.testOnly());
    try std.testing.expectEqual(KeyOrigin.secure_enclave, provider.origin());
    try service.provisionRootProvider(provider);

    try std.testing.expectError(error.UserVisibilityRequired, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "nonce-3",
        false,
    ));

    const statement = try service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0003",
        true,
    );
    try std.testing.expect(Service.verify(statement));
    try std.testing.expect(Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0003",
        .user_visible = true,
        .key_origin = .secure_enclave,
        .root_key_id = "device-se",
        .minimum_root_generation = 1,
        .attestation_root = root_identity,
    }));
    try std.testing.expectError(error.RemoteNonceReplay, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0003",
        true,
    ));
    _ = try service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0004",
        true,
    );
    try std.testing.expectError(error.RemoteNonceReplay, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0003",
        true,
    ));
    try std.testing.expectError(error.RemoteNonceTooShort, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "nonce-3",
        true,
    ));
    try std.testing.expectEqual(@as(usize, 2), root_provider.sign_count);
    try std.testing.expectEqual(KeyOrigin.secure_enclave, statement.key_origin);
    try std.testing.expectEqualStrings("device-se", statement.rootLabelSlice());
    try std.testing.expectEqualStrings("device-se", statement.rootKeyIdSlice());
    try std.testing.expectEqual(@as(u64, 1), statement.root_key_generation);
    try std.testing.expectEqual(measured_boot.RootProvenance.bootloader_provided, statement.root_provenance);
    try std.testing.expect(statement.manifest_verified);

    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "wrong-nonce",
        .user_visible = true,
        .key_origin = .secure_enclave,
        .attestation_root = root_identity,
    }));
    var wrong_provenance_boot = boot;
    wrong_provenance_boot.root_provenance = .emulator_provided;
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &wrong_provenance_boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0003",
        .user_visible = true,
        .key_origin = .secure_enclave,
        .root_key_id = "device-se",
        .minimum_root_generation = 1,
        .attestation_root = root_identity,
    }));
}

test "attestation verifier rejects revoked root generations after rotation" {
    const boot = try verifiedTestBoot(18, .bootloader_provided);
    var v1_provider = FakeTpmRootProvider.initGeneration(.{
        .label = "device-tpm-v1",
        .seed = signing.seedFromByte(0x5C),
    }, 1);
    var v2_provider = FakeTpmRootProvider.initGeneration(.{
        .label = "device-tpm-v2",
        .seed = signing.seedFromByte(0x5D),
    }, 2);
    const v1_identity = try v1_provider.publicIdentity();
    const v2_identity = try v2_provider.publicIdentity();

    var service = Service.init(.{ .kind = .device, .serial = 42 });
    try service.provisionRootProvider(v1_provider.provider());
    const v1_statement = try service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0007",
        true,
    );
    try std.testing.expect(Service.verifyForBoot(v1_statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0007",
        .user_visible = true,
        .key_origin = .tpm,
        .root_key_id = "device-tpm-v1",
        .minimum_root_generation = 1,
        .attestation_root = v1_identity,
    }));

    try std.testing.expectError(error.StaleRootGeneration, service.rotateRootProvider(v1_provider.provider()));
    try service.rotateRootProvider(v2_provider.provider());
    try service.revokeRootGeneration(1);

    try std.testing.expect(!Service.verifyForBoot(v1_statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0007",
        .user_visible = true,
        .key_origin = .tpm,
        .root_key_id = "device-tpm-v1",
        .minimum_root_generation = 1,
        .revoked_root_generations = &.{1},
        .attestation_root = v1_identity,
    }));

    const v2_statement = try service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0008",
        true,
    );
    try std.testing.expect(Service.verifyForBoot(v2_statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0008",
        .user_visible = true,
        .key_origin = .tpm,
        .root_key_id = "device-tpm-v2",
        .minimum_root_generation = 2,
        .revoked_root_generations = &.{1},
        .attestation_root = v2_identity,
    }));

    try service.revokeRootGeneration(2);
    try std.testing.expectError(error.RootGenerationRevoked, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0009",
        true,
    ));
}

test "attestation request response records bind verifier policy rotation and revocation" {
    const boot = try verifiedTestBoot(19, .bootloader_provided);
    var v1_provider = FakeTpmRootProvider.initGeneration(.{
        .label = "device-tpm-v1",
        .seed = signing.seedFromByte(0x60),
    }, 1);
    var v2_provider = FakeTpmRootProvider.initGeneration(.{
        .label = "device-tpm-v2",
        .seed = signing.seedFromByte(0x61),
    }, 2);
    const v1_identity = try v1_provider.publicIdentity();
    const v2_identity = try v2_provider.publicIdentity();

    var service = Service.init(.{ .kind = .device, .serial = 45 });
    try service.provisionRootProvider(v1_provider.provider());
    const v1_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0010",
        .policy_label = "sync-overlay-policy",
        .expected_key_origin = .tpm,
        .root_key_id = "device-tpm-v1",
        .minimum_root_generation = 1,
    });
    const v1_response = try service.respondToRemoteAttestationRequest(boot, v1_request);
    const v1_request_digest = v1_request.digest();
    try std.testing.expect(std.mem.eql(u8, &v1_response.request_digest, &v1_request_digest));
    try std.testing.expectEqualStrings("sync-overlay-policy", v1_response.policyLabelSlice());
    try std.testing.expect(Service.verifyRemoteAttestationResponse(v1_response, v1_request, &boot, v1_identity));
    try std.testing.expectEqual(@as(usize, 1), service.visible_request_count);

    const wrong_policy_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0010",
        .policy_label = "other-policy",
        .expected_key_origin = .tpm,
        .root_key_id = "device-tpm-v1",
        .minimum_root_generation = 1,
    });
    try std.testing.expect(!Service.verifyRemoteAttestationResponse(v1_response, wrong_policy_request, &boot, v1_identity));

    var tampered_policy_response = v1_response;
    tampered_policy_response.policy_label[0] = 'x';
    try std.testing.expect(!Service.verifyRemoteAttestationResponse(tampered_policy_response, v1_request, &boot, v1_identity));

    const stale_generation_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0010",
        .policy_label = "sync-overlay-policy",
        .expected_key_origin = .tpm,
        .root_key_id = "device-tpm-v1",
        .minimum_root_generation = 2,
    });
    try std.testing.expectError(error.StaleRootGeneration, service.respondToRemoteAttestationRequest(boot, stale_generation_request));

    const wrong_root_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0010",
        .policy_label = "sync-overlay-policy",
        .expected_key_origin = .tpm,
        .root_key_id = "device-tpm-other",
        .minimum_root_generation = 1,
    });
    try std.testing.expectError(error.RootIdentityMismatch, service.respondToRemoteAttestationRequest(boot, wrong_root_request));

    try service.rotateRootProvider(v2_provider.provider());
    try service.revokeRootGeneration(1);
    const v2_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0011",
        .policy_label = "sync-overlay-policy",
        .expected_key_origin = .tpm,
        .root_key_id = "device-tpm-v2",
        .minimum_root_generation = 2,
        .revoked_root_generations = &.{1},
    });
    const v2_response = try service.respondToRemoteAttestationRequest(boot, v2_request);
    try std.testing.expect(Service.verifyRemoteAttestationResponse(v2_response, v2_request, &boot, v2_identity));
    try std.testing.expectEqual(@as(u64, 2), v2_response.statement.root_key_generation);
    try std.testing.expectEqualSlices(u64, &.{1}, v2_response.revokedRootGenerationsSlice());

    var missing_revocation_response = v2_response;
    missing_revocation_response.revoked_root_generation_count = 0;
    try std.testing.expect(!Service.verifyRemoteAttestationResponse(missing_revocation_response, v2_request, &boot, v2_identity));

    const current_revoked_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0012",
        .policy_label = "sync-overlay-policy",
        .expected_key_origin = .tpm,
        .root_key_id = "device-tpm-v2",
        .minimum_root_generation = 2,
        .revoked_root_generations = &.{2},
    });
    try std.testing.expectError(error.RootGenerationRevoked, service.respondToRemoteAttestationRequest(boot, current_revoked_request));

    const hidden_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0013",
        .policy_label = "hidden-policy",
        .user_visible = false,
        .expected_key_origin = .tpm,
        .root_key_id = "device-tpm-v2",
        .minimum_root_generation = 2,
    });
    try std.testing.expectError(error.UserVisibilityRequired, service.respondToRemoteAttestationRequest(boot, hidden_request));
}

test "external attestation root provider signs through operational key handles" {
    const boot = try verifiedTestBoot(20, .bootloader_provided);
    const external_signer = signing.SignerIdentity{
        .label = "device-hsm-root",
        .seed = signing.seedFromByte(0x62),
    };
    const public_identity = try signing.publicIdentity(external_signer);
    const key = AttestationRootKeyHandle{
        .key_id = "hsm-root-key-4",
        .label = "device-hsm-root",
        .public_identity = public_identity,
        .generation = 4,
        .origin = .hsm,
        .provider_boundary = .offline_hsm,
        .custody = .hardware_security_module,
    };
    const descriptor = RootProviderDescriptor{
        .name = "external-hsm-attestation-root",
        .role = .production,
        .origin = .hsm,
        .key_id = "hsm-root-key-4",
        .key_generation = 4,
        .provider_boundary = .offline_hsm,
        .custody = .hardware_security_module,
        .customer_verifiable = true,
    };
    try std.testing.expect(descriptor.productionEligible());
    try std.testing.expect(!@hasField(ExternalAttestationRootProvider, "signer"));

    const ExternalSignerFixture = struct {
        signer: signing.SignerIdentity,
        invocation_count: usize = 0,

        fn sign(context: *anyopaque, handle: AttestationRootKeyHandle, digest: []const u8) !manifest.Signature {
            const fixture: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, fixture.signer.label, handle.label)) return error.RootIdentityMismatch;
            fixture.invocation_count += 1;
            return signing.signWithDefaultRegistry(.ed25519, fixture.signer, digest);
        }
    };
    var fixture = ExternalSignerFixture{ .signer = external_signer };
    var provider_impl = try ExternalAttestationRootProvider.init(
        descriptor,
        key,
        &fixture,
        ExternalSignerFixture.sign,
    );
    const provider = provider_impl.provider();
    try std.testing.expect(!provider.testOnly());
    try std.testing.expectEqual(KeyOrigin.hsm, provider.origin());
    const verifier_metadata = provider_impl.verifierMetadata();
    try std.testing.expect(verifier_metadata.productionEligible());
    try std.testing.expect(verifier_metadata.matchesProvider(descriptor, key));
    const verifier_digest = verifier_metadata.digest();
    try std.testing.expect(!std.mem.eql(u8, &verifier_digest, &crypto_hash.zero_digest));

    var stale_metadata = verifier_metadata;
    stale_metadata.generation += 1;
    try std.testing.expect(!stale_metadata.matchesProvider(descriptor, key));
    var local_metadata = verifier_metadata;
    local_metadata.provider_boundary = .local_software;
    try std.testing.expect(!local_metadata.productionEligible());
    var tampered_key = key;
    tampered_key.public_identity.public_key[0] ^= 0x80;
    try std.testing.expect(!verifier_metadata.matchesProvider(descriptor, tampered_key));
    const stale_digest = stale_metadata.digest();
    try std.testing.expect(!std.mem.eql(u8, &verifier_digest, &stale_digest));

    var service = Service.init(.{ .kind = .device, .serial = 46 });
    service.allow_test_root_providers = false;
    try service.provisionRootProvider(provider);
    const request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0014",
        .policy_label = "hardware-root-policy",
        .expected_key_origin = .hsm,
        .root_key_id = "hsm-root-key-4",
        .minimum_root_generation = 4,
        .attestation_verifier_metadata_digest_required = true,
        .attestation_verifier_metadata_digest = verifier_digest,
    });
    const response = try service.respondToRemoteAttestationRequest(boot, request);
    try std.testing.expect(response.attestation_verifier_metadata_digest_present);
    try std.testing.expect(std.mem.eql(u8, &response.attestation_verifier_metadata_digest, &verifier_digest));
    try std.testing.expect(Service.verifyRemoteAttestationResponse(response, request, &boot, public_identity));
    try std.testing.expectEqual(@as(usize, 1), fixture.invocation_count);
    try std.testing.expectEqual(@as(usize, 1), provider_impl.sign_count);
    try std.testing.expectEqual(KeyOrigin.hsm, response.statement.key_origin);
    try std.testing.expectEqualStrings("device-hsm-root", response.statement.rootLabelSlice());
    try std.testing.expectEqualStrings("hsm-root-key-4", response.statement.rootKeyIdSlice());

    var mismatched_verifier_digest = verifier_digest;
    mismatched_verifier_digest[0] ^= 0x01;
    const mismatched_metadata_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0015",
        .policy_label = "hardware-root-policy",
        .expected_key_origin = .hsm,
        .root_key_id = "hsm-root-key-4",
        .minimum_root_generation = 4,
        .attestation_verifier_metadata_digest_required = true,
        .attestation_verifier_metadata_digest = mismatched_verifier_digest,
    });
    try std.testing.expectError(error.AttestationVerifierMetadataMismatch, service.respondToRemoteAttestationRequest(boot, mismatched_metadata_request));

    var tampered_metadata_response = response;
    tampered_metadata_response.attestation_verifier_metadata_digest[0] ^= 0x01;
    try std.testing.expect(!Service.verifyRemoteAttestationResponse(tampered_metadata_response, request, &boot, public_identity));

    var missing_metadata_response = response;
    missing_metadata_response.attestation_verifier_metadata_digest_present = false;
    try std.testing.expect(!Service.verifyRemoteAttestationResponse(missing_metadata_response, request, &boot, public_identity));

    var fake_provider = FakeTpmRootProvider.init(.{
        .label = "metadata-less-tpm",
        .seed = signing.seedFromByte(0x67),
    });
    var fake_service = Service.init(.{ .kind = .device, .serial = 47 });
    try fake_service.provisionRootProvider(fake_provider.provider());
    const metadata_required_request = try RemoteAttestationRequest.init(.{
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0016",
        .policy_label = "hardware-root-policy",
        .expected_key_origin = .tpm,
        .root_key_id = "metadata-less-tpm",
        .minimum_root_generation = 1,
        .attestation_verifier_metadata_digest_required = true,
        .attestation_verifier_metadata_digest = verifier_digest,
    });
    try std.testing.expectError(error.AttestationVerifierMetadataMissing, fake_service.respondToRemoteAttestationRequest(boot, metadata_required_request));
}

test "external attestation root provider rejects local software custody" {
    const signer_identity = signing.SignerIdentity{
        .label = "device-hsm-root",
        .seed = signing.seedFromByte(0x63),
    };
    const key = AttestationRootKeyHandle{
        .key_id = "hsm-root-key-5",
        .label = "device-hsm-root",
        .public_identity = try signing.publicIdentity(signer_identity),
        .generation = 5,
        .origin = .hsm,
        .provider_boundary = .offline_hsm,
        .custody = .hardware_security_module,
    };
    const SignFixture = struct {
        fn sign(_: *anyopaque, _: AttestationRootKeyHandle, _: []const u8) !manifest.Signature {
            return error.UnbackedAttestationRoot;
        }
    };
    var context: u8 = 0;

    var local_software_descriptor = RootProviderDescriptor{
        .name = "bad-local-attestation-root",
        .role = .production,
        .origin = .hsm,
        .key_id = "hsm-root-key-5",
        .key_generation = 5,
        .customer_verifiable = true,
    };
    try std.testing.expect(!local_software_descriptor.productionEligible());
    try std.testing.expectError(error.UnbackedAttestationRoot, ExternalAttestationRootProvider.init(
        local_software_descriptor,
        key,
        &context,
        SignFixture.sign,
    ));

    var boundary_mismatch_descriptor = local_software_descriptor;
    boundary_mismatch_descriptor.provider_boundary = .cloud_kms;
    boundary_mismatch_descriptor.custody = .cloud_kms;
    try std.testing.expect(boundary_mismatch_descriptor.productionEligible());
    try std.testing.expectError(error.RootProviderBoundaryMismatch, ExternalAttestationRootProvider.init(
        boundary_mismatch_descriptor,
        key,
        &context,
        SignFixture.sign,
    ));

    var custody_mismatch_descriptor = local_software_descriptor;
    custody_mismatch_descriptor.provider_boundary = .offline_hsm;
    custody_mismatch_descriptor.custody = .cloud_kms;
    try std.testing.expect(custody_mismatch_descriptor.productionEligible());
    try std.testing.expectError(error.RootProviderCustodyMismatch, ExternalAttestationRootProvider.init(
        custody_mismatch_descriptor,
        key,
        &context,
        SignFixture.sign,
    ));
}

test "production attestation descriptors reject test-only operational names" {
    const signer_identity = signing.SignerIdentity{
        .label = "device-hsm-root-6",
        .seed = signing.seedFromByte(0x68),
    };
    const key = AttestationRootKeyHandle{
        .key_id = "hsm-root-key-6",
        .label = "device-hsm-root-6",
        .public_identity = try signing.publicIdentity(signer_identity),
        .generation = 6,
        .origin = .hsm,
        .provider_boundary = .offline_hsm,
        .custody = .hardware_security_module,
    };
    const descriptor = RootProviderDescriptor{
        .name = "external-hsm-attestation-root",
        .role = .production,
        .origin = .hsm,
        .key_id = "hsm-root-key-6",
        .key_generation = 6,
        .provider_boundary = .offline_hsm,
        .custody = .hardware_security_module,
        .customer_verifiable = true,
    };
    try std.testing.expect(descriptor.productionEligible());

    const SignFixture = struct {
        fn sign(_: *anyopaque, _: AttestationRootKeyHandle, _: []const u8) !manifest.Signature {
            return error.UnbackedAttestationRoot;
        }
    };
    var context: u8 = 0;

    var fake_named_descriptor = descriptor;
    fake_named_descriptor.name = "fake-production-root";
    try std.testing.expect(fake_named_descriptor.hasProductionUnsafeName());
    try std.testing.expect(!fake_named_descriptor.productionEligible());
    try std.testing.expectError(error.UnbackedAttestationRoot, AttestationVerifierMetadata.fromProvider(fake_named_descriptor, key));
    try std.testing.expectError(error.UnbackedAttestationRoot, ExternalAttestationRootProvider.init(
        fake_named_descriptor,
        key,
        &context,
        SignFixture.sign,
    ));

    var test_key_descriptor = descriptor;
    test_key_descriptor.key_id = "hsm-root-key-test";
    try std.testing.expect(test_key_descriptor.hasProductionUnsafeName());
    try std.testing.expect(!test_key_descriptor.productionEligible());
    try std.testing.expectError(error.UnbackedAttestationRoot, AttestationVerifierMetadata.fromProvider(test_key_descriptor, key));

    const test_label_identity = signing.SignerIdentity{
        .label = "test-only-hsm-root",
        .seed = signing.seedFromByte(0x69),
    };
    var test_label_key = key;
    test_label_key.label = "test-only-hsm-root";
    test_label_key.public_identity = try signing.publicIdentity(test_label_identity);
    try std.testing.expect(descriptor.productionEligible());
    try std.testing.expectError(error.UnbackedAttestationRoot, AttestationVerifierMetadata.fromProvider(descriptor, test_label_key));
    try std.testing.expectError(error.UnbackedAttestationRoot, ExternalAttestationRootProvider.init(
        descriptor,
        test_label_key,
        &context,
        SignFixture.sign,
    ));
}

test "attestation service rejects emulator measured roots for remote attestations" {
    const boot = try verifiedTestBoot(17, .emulator_provided);
    try std.testing.expect(boot.hasVerifiedRoot());
    try std.testing.expect(!boot.isRemoteAttestable());

    var service = Service.init(.{ .kind = .device, .serial = 40 });
    var root_provider = FakeTpmRootProvider.init(.{
        .label = "device-tpm",
        .seed = signing.seedFromByte(0x5A),
    });
    try service.provisionRootProvider(root_provider.provider());

    try std.testing.expectError(error.UnverifiedMeasuredRoot, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0006",
        true,
    ));
}

test "attestation service rejects provisioned remote attestations without a verified measured root" {
    var recorder = measured_boot.Recorder.init();
    recorder.begin(15);
    try recorder.add(.kernel, "kernel-zigos", "kernel=v6");
    try recorder.add(.base_image, "stable-e", "image=v6");
    const boot = recorder.finalize();

    var service = Service.init(.{ .kind = .device, .serial = 36 });
    var root_provider = FakeSecureEnclaveRootProvider.init(.{
        .label = "device-se",
        .seed = signing.seedFromByte(0x56),
    });
    try service.provisionRootProvider(root_provider.provider());

    try std.testing.expectError(error.UnverifiedMeasuredRoot, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0004",
        true,
    ));
}

test "attestation service rejects software provisioned remote roots" {
    var service = Service.init(.{ .kind = .device, .serial = 37 });
    var software_provider = TestSoftwareRootProvider.init(.{
        .label = "software-root",
        .seed = signing.seedFromByte(0x57),
    });
    const provider = software_provider.provider();
    try std.testing.expect(provider.testOnly());
    try std.testing.expectError(error.UnbackedAttestationRoot, service.provisionRootProvider(provider));
}

test "attestation service gates fake hardware root providers to tests" {
    var service = Service.init(.{ .kind = .device, .serial = 41 });
    service.allow_test_root_providers = false;
    var root_provider = FakeTpmRootProvider.init(.{
        .label = "fake-tpm",
        .seed = signing.seedFromByte(0x5B),
    });
    const provider = root_provider.provider();

    try std.testing.expect(provider.testOnly());
    try std.testing.expectError(error.TestRootProviderRejected, service.provisionRootProvider(provider));
}

test "attestation service rejects generation zero root providers" {
    var service = Service.init(.{ .kind = .device, .serial = 43 });
    var root_provider = FakeTpmRootProvider.initGeneration(.{
        .label = "device-tpm-zero",
        .seed = signing.seedFromByte(0x5E),
    }, 0);

    try std.testing.expectError(error.InvalidRootGeneration, service.provisionRootProvider(root_provider.provider()));
}

test "attestation service rejects anonymous root providers" {
    var service = Service.init(.{ .kind = .device, .serial = 44 });
    var root_provider = FakeTpmRootProvider.initGeneration(.{
        .label = "",
        .seed = signing.seedFromByte(0x5F),
    }, 1);

    try std.testing.expectError(error.RootIdentityMissing, service.provisionRootProvider(root_provider.provider()));
}

test "attestation verification rejects measured state and statement tampering" {
    const boot = try verifiedTestBoot(16, .bootloader_provided);
    const root_signer = signing.SignerIdentity{
        .label = "device-tpm",
        .seed = signing.seedFromByte(0x58),
    };
    var root_provider = FakeTpmRootProvider.init(root_signer);
    const root_identity = try root_provider.publicIdentity();

    var service = Service.init(.{ .kind = .device, .serial = 38 });
    try service.provisionRootProvider(root_provider.provider());
    const statement = try service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0005",
        true,
    );
    const expectation = VerificationExpectation{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0005",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    };
    try std.testing.expect(Service.verifyForBoot(statement, expectation));

    const measured_artifact_indexes = [_]usize{ 0, 1, 2, 6, 7 };
    for (measured_artifact_indexes) |index| {
        var tampered_boot = boot;
        tampered_boot.records[index].digest[0] ^= 0xFF;
        try std.testing.expect(!Service.verifyForBoot(statement, .{
            .boot = &tampered_boot,
            .remote_party = "attest.example",
            .nonce = "remote-nonce-0005",
            .user_visible = true,
            .key_origin = .tpm,
            .attestation_root = root_identity,
        }));
    }

    var tampered_root = boot;
    tampered_root.root_digest[0] ^= 0xFF;
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &tampered_root,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0005",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));

    var tampered_manifest_state = boot;
    tampered_manifest_state.artifact_manifest_verified = false;
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &tampered_manifest_state,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0005",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));

    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "other.example",
        .nonce = "remote-nonce-0005",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "wrong-nonce",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0005",
        .user_visible = false,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "remote-nonce-0005",
        .user_visible = true,
        .key_origin = .secure_enclave,
        .attestation_root = root_identity,
    }));

    var wrong_key_service = Service.init(.{ .kind = .device, .serial = 39 });
    var wrong_key_provider = FakeTpmRootProvider.init(.{
        .label = "device-tpm",
        .seed = signing.seedFromByte(0x59),
    });
    try wrong_key_service.provisionRootProvider(wrong_key_provider.provider());
    const wrong_key_statement = try wrong_key_service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "remote-nonce-0005",
        true,
    );
    try std.testing.expect(!Service.verifyForBoot(wrong_key_statement, expectation));

    var tampered_statement = statement;
    tampered_statement.signature.value[0] ^= 0xFF;
    try std.testing.expect(!Service.verifyForBoot(tampered_statement, expectation));
}
