const std = @import("std");
const builtin = @import("builtin");
const crypto_hash = @import("../core/crypto_hash.zig");
const manifest = @import("../policy/manifest.zig");
const measured_boot = @import("measured_boot.zig");
const native_util = @import("../core/util.zig");
const principal = @import("../core/principal.zig");
const signing = @import("../core/signing.zig");

pub const MAX_REMOTE_PARTY_BYTES: usize = 64;
pub const MAX_NONCE_BYTES: usize = 32;
pub const MAX_ROOT_LABEL_BYTES: usize = 48;

pub const KeyOrigin = enum(u8) {
    software,
    secure_enclave,
    tpm,
};

pub const RootProviderRole = enum(u8) {
    production,
    test_only,
};

pub const RootProviderDescriptor = struct {
    name: []const u8,
    role: RootProviderRole,
    origin: KeyOrigin,
};

pub const RootProvider = struct {
    context: *anyopaque,
    descriptor: RootProviderDescriptor,
    label_fn: *const fn (*anyopaque) []const u8,
    sign_fn: *const fn (*anyopaque, []const u8) anyerror!manifest.Signature,

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
        };
    }

    pub fn label(self: RootProvider) []const u8 {
        return self.label_fn(self.context);
    }

    pub fn origin(self: RootProvider) KeyOrigin {
        return self.descriptor.origin;
    }

    pub fn sign(self: RootProvider, digest: []const u8) anyerror!manifest.Signature {
        return self.sign_fn(self.context, digest);
    }

    pub fn testOnly(self: RootProvider) bool {
        return self.descriptor.role == .test_only;
    }
};

pub const FakeTpmRootProvider = struct {
    signer: signing.SignerIdentity,
    sign_count: usize = 0,

    pub fn init(signer: signing.SignerIdentity) FakeTpmRootProvider {
        return .{ .signer = signer };
    }

    pub fn provider(self: *FakeTpmRootProvider) RootProvider {
        return RootProvider.init(FakeTpmRootProvider, self, .{
            .name = "fake-tpm-root-provider",
            .role = .test_only,
            .origin = .tpm,
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
    sign_count: usize = 0,

    pub fn init(signer: signing.SignerIdentity) FakeSecureEnclaveRootProvider {
        return .{ .signer = signer };
    }

    pub fn provider(self: *FakeSecureEnclaveRootProvider) RootProvider {
        return RootProvider.init(FakeSecureEnclaveRootProvider, self, .{
            .name = "fake-secure-enclave-root-provider",
            .role = .test_only,
            .origin = .secure_enclave,
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
    root_digest: [32]u8,
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
};

pub const VerificationExpectation = struct {
    boot: *const measured_boot.BootRecord,
    remote_party: []const u8,
    nonce: []const u8,
    user_visible: bool,
    key_origin: ?KeyOrigin = null,
    attestation_root: ?signing.PublicIdentity = null,
};

pub const Error = error{
    NonceTooLong,
    RemotePartyTooLong,
    RootNotProvisioned,
    RootLabelTooLong,
    TestRootProviderRejected,
    UnbackedAttestationRoot,
    UserVisibilityRequired,
    UnverifiedMeasuredRoot,
};

pub const Service = struct {
    device: principal.PrincipalId,
    visible_request_count: usize = 0,
    last_remote_party_len: usize = 0,
    last_remote_party: [MAX_REMOTE_PARTY_BYTES]u8 = [_]u8{0} ** MAX_REMOTE_PARTY_BYTES,
    has_provisioned_root: bool = false,
    root_origin: KeyOrigin = .software,
    root_label_len: usize = 0,
    root_label: [MAX_ROOT_LABEL_BYTES]u8 = [_]u8{0} ** MAX_ROOT_LABEL_BYTES,
    root_provider: ?RootProvider = null,
    allow_test_root_providers: bool = builtin.is_test,

    pub fn init(device: principal.PrincipalId) Service {
        return .{ .device = device };
    }

    pub fn provisionRootProvider(self: *Service, provider: RootProvider) Error!void {
        if (!isBackedRootOrigin(provider.origin())) return error.UnbackedAttestationRoot;
        if (provider.testOnly() and !self.allow_test_root_providers) return error.TestRootProviderRejected;
        self.has_provisioned_root = true;
        self.root_origin = provider.origin();
        self.root_label_len = native_util.copyTextExact(&self.root_label, provider.label()) catch return error.RootLabelTooLong;
        self.root_provider = provider;
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
        if (remote_party.len != 0 and !user_visible) return error.UserVisibilityRequired;
        if (!boot.isRemoteAttestable()) return error.UnverifiedMeasuredRoot;
        if (!boot.isInternallyConsistent()) return error.UnverifiedMeasuredRoot;

        return self.attestWithProviderInternal(boot, remote_party, nonce, provider, user_visible);
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
        var statement = try self.buildStatement(boot, remote_party, nonce, signer.label, user_visible, origin);
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
        var statement = try self.buildStatement(boot, remote_party, nonce, self.rootLabelSlice(), user_visible, provider.origin());
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
            .root_digest = boot.root_digest,
            .root_provenance = boot.root_provenance,
            .manifest_verified = boot.artifact_manifest_verified,
            .signature = .{},
        };
        statement.remote_party_len = native_util.copyTextExact(&statement.remote_party, remote_party) catch return error.RemotePartyTooLong;
        statement.nonce_len = native_util.copyTextExact(&statement.nonce, nonce) catch return error.NonceTooLong;
        statement.root_label_len = native_util.copyTextExact(&statement.root_label, root_label) catch return error.RootLabelTooLong;

        if (user_visible) {
            self.visible_request_count += 1;
            self.last_remote_party_len = native_util.copyTextExact(&self.last_remote_party, remote_party) catch return error.RemotePartyTooLong;
        }

        return statement;
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
        if (expectation.attestation_root) |expected_root| {
            if (!std.mem.eql(u8, statement.rootLabelSlice(), expected_root.label)) return false;
            if (!signing.verifyTrustedPublicKey(statement.signature, &digest, expected_root)) return false;
        }
        return true;
    }

    fn rootLabelSlice(self: *const Service) []const u8 {
        return self.root_label[0..self.root_label_len];
    }
};

fn isBackedRootOrigin(origin: KeyOrigin) bool {
    return origin != .software;
}

fn statementDigest(statement: Statement) [32]u8 {
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
    crypto_hash.updateBytes(&hasher, "root-digest", &statement.root_digest);
    crypto_hash.updateEnum(&hasher, "root-provenance", statement.root_provenance);
    crypto_hash.updateBool(&hasher, "manifest-verified", statement.manifest_verified);
    return crypto_hash.finalize(&hasher);
}

fn addMeasuredArtifact(
    recorder: *measured_boot.Recorder,
    artifact_manifest: *measured_boot.ArtifactManifest,
    kind: measured_boot.MeasurementKind,
    label: []const u8,
    payload: []const u8,
) !void {
    try recorder.add(kind, label, payload);
    try artifact_manifest.add(kind, label, payload);
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
        .seed = [_]u8{0x51} ** 32,
    }, true));

    const statement = try service.attest(boot, "", "nonce-1", .{
        .label = "device-attest",
        .seed = [_]u8{0x51} ** 32,
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
        .seed = [_]u8{0x54} ** 32,
    }, false));

    const statement = try service.attest(boot, "", "nonce-2", .{
        .label = "device-attest",
        .seed = [_]u8{0x54} ** 32,
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
        .seed = [_]u8{0x55} ** 32,
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
        "nonce-3",
        true,
    );
    try std.testing.expect(Service.verify(statement));
    try std.testing.expect(Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "nonce-3",
        .user_visible = true,
        .key_origin = .secure_enclave,
        .attestation_root = root_identity,
    }));
    try std.testing.expectEqual(@as(usize, 1), root_provider.sign_count);
    try std.testing.expectEqual(KeyOrigin.secure_enclave, statement.key_origin);
    try std.testing.expectEqualStrings("device-se", statement.rootLabelSlice());
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
        .nonce = "nonce-3",
        .user_visible = true,
        .key_origin = .secure_enclave,
        .attestation_root = root_identity,
    }));
}

test "attestation service rejects emulator measured roots for remote attestations" {
    const boot = try verifiedTestBoot(17, .emulator_provided);
    try std.testing.expect(boot.hasVerifiedRoot());
    try std.testing.expect(!boot.isRemoteAttestable());

    var service = Service.init(.{ .kind = .device, .serial = 40 });
    var root_provider = FakeTpmRootProvider.init(.{
        .label = "device-tpm",
        .seed = [_]u8{0x5A} ** 32,
    });
    try service.provisionRootProvider(root_provider.provider());

    try std.testing.expectError(error.UnverifiedMeasuredRoot, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "nonce-6",
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
        .seed = [_]u8{0x56} ** 32,
    });
    try service.provisionRootProvider(root_provider.provider());

    try std.testing.expectError(error.UnverifiedMeasuredRoot, service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "nonce-4",
        true,
    ));
}

test "attestation service rejects software provisioned remote roots" {
    var service = Service.init(.{ .kind = .device, .serial = 37 });
    var software_provider = TestSoftwareRootProvider.init(.{
        .label = "software-root",
        .seed = [_]u8{0x57} ** 32,
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
        .seed = [_]u8{0x5B} ** 32,
    });
    const provider = root_provider.provider();

    try std.testing.expect(provider.testOnly());
    try std.testing.expectError(error.TestRootProviderRejected, service.provisionRootProvider(provider));
}

test "attestation verification rejects measured state and statement tampering" {
    const boot = try verifiedTestBoot(16, .bootloader_provided);
    const root_signer = signing.SignerIdentity{
        .label = "device-tpm",
        .seed = [_]u8{0x58} ** 32,
    };
    var root_provider = FakeTpmRootProvider.init(root_signer);
    const root_identity = try root_provider.publicIdentity();

    var service = Service.init(.{ .kind = .device, .serial = 38 });
    try service.provisionRootProvider(root_provider.provider());
    const statement = try service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "nonce-5",
        true,
    );
    const expectation = VerificationExpectation{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "nonce-5",
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
            .nonce = "nonce-5",
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
        .nonce = "nonce-5",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));

    var tampered_manifest_state = boot;
    tampered_manifest_state.artifact_manifest_verified = false;
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &tampered_manifest_state,
        .remote_party = "attest.example",
        .nonce = "nonce-5",
        .user_visible = true,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));

    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "other.example",
        .nonce = "nonce-5",
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
        .nonce = "nonce-5",
        .user_visible = false,
        .key_origin = .tpm,
        .attestation_root = root_identity,
    }));
    try std.testing.expect(!Service.verifyForBoot(statement, .{
        .boot = &boot,
        .remote_party = "attest.example",
        .nonce = "nonce-5",
        .user_visible = true,
        .key_origin = .secure_enclave,
        .attestation_root = root_identity,
    }));

    var wrong_key_service = Service.init(.{ .kind = .device, .serial = 39 });
    var wrong_key_provider = FakeTpmRootProvider.init(.{
        .label = "device-tpm",
        .seed = [_]u8{0x59} ** 32,
    });
    try wrong_key_service.provisionRootProvider(wrong_key_provider.provider());
    const wrong_key_statement = try wrong_key_service.attestWithProvisionedRoot(
        boot,
        "attest.example",
        "nonce-5",
        true,
    );
    try std.testing.expect(!Service.verifyForBoot(wrong_key_statement, expectation));

    var tampered_statement = statement;
    tampered_statement.signature.value[0] ^= 0xFF;
    try std.testing.expect(!Service.verifyForBoot(tampered_statement, expectation));
}
