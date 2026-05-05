const std = @import("std");
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

pub const Error = error{
    NonceTooLong,
    RemotePartyTooLong,
    RootNotProvisioned,
    RootLabelTooLong,
    UserVisibilityRequired,
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
    root_seed: [32]u8 = [_]u8{0} ** 32,

    pub fn init(device: principal.PrincipalId) Service {
        return .{ .device = device };
    }

    pub fn provisionRoot(self: *Service, signer: signing.SignerIdentity, origin: KeyOrigin) Error!void {
        self.has_provisioned_root = true;
        self.root_origin = origin;
        self.root_label_len = native_util.copyTextExact(&self.root_label, signer.label) catch return error.RootLabelTooLong;
        self.root_seed = signer.seed;
    }

    pub fn attest(
        self: *Service,
        boot: measured_boot.BootRecord,
        remote_party: []const u8,
        nonce: []const u8,
        signer: signing.SignerIdentity,
        user_visible: bool,
    ) !Statement {
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
        if (remote_party.len != 0 and !user_visible) return error.UserVisibilityRequired;

        return self.attestInternal(boot, remote_party, nonce, .{
            .label = self.rootLabelSlice(),
            .seed = self.root_seed,
        }, user_visible, self.root_origin);
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
            .signature = .{},
        };
        statement.remote_party_len = native_util.copyTextExact(&statement.remote_party, remote_party) catch return error.RemotePartyTooLong;
        statement.nonce_len = native_util.copyTextExact(&statement.nonce, nonce) catch return error.NonceTooLong;
        statement.root_label_len = native_util.copyTextExact(&statement.root_label, signer.label) catch return error.RootLabelTooLong;

        if (user_visible) {
            self.visible_request_count += 1;
            self.last_remote_party_len = native_util.copyTextExact(&self.last_remote_party, remote_party) catch return error.RemotePartyTooLong;
        }

        const digest = statementDigest(statement);
        statement.signature = try signing.sign(signer, &digest);
        return statement;
    }

    pub fn verify(statement: Statement) bool {
        const digest = statementDigest(statement);
        return signing.verify(statement.signature, &digest);
    }

    fn rootLabelSlice(self: *const Service) []const u8 {
        return self.root_label[0..self.root_label_len];
    }
};

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
    return crypto_hash.finalize(&hasher);
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
    const statement = try service.attest(boot, "attest.example", "nonce-1", .{
        .label = "device-attest",
        .seed = [_]u8{0x51} ** 32,
    }, true);

    try std.testing.expectEqual(@as(u64, 12), statement.generation);
    try std.testing.expectEqual(@as(usize, 1), statement.critical_service_count);
    try std.testing.expectEqual(@as(usize, 1), statement.policy_count);
    try std.testing.expectEqual(@as(usize, 1), statement.driver_count);
    try std.testing.expectEqualStrings("attest.example", statement.remotePartySlice());
    try std.testing.expect(statement.user_visible);
    try std.testing.expect(Service.verify(statement));
    try std.testing.expectEqual(@as(usize, 1), service.visible_request_count);
    try std.testing.expectEqualStrings("attest.example", service.last_remote_party[0..service.last_remote_party_len]);
    try std.testing.expectEqual(KeyOrigin.software, statement.key_origin);
}

test "attestation service does not count hidden requests and detects tampering" {
    var recorder = measured_boot.Recorder.init();
    recorder.begin(13);
    try recorder.add(.kernel, "kernel-zigos", "kernel=v4");
    try recorder.add(.base_image, "stable-c", "image=v4");
    const boot = recorder.finalize();

    var service = Service.init(.{ .kind = .device, .serial = 34 });
    const statement = try service.attest(boot, "audit.example", "nonce-2", .{
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
    var recorder = measured_boot.Recorder.init();
    recorder.begin(14);
    try recorder.add(.kernel, "kernel-zigos", "kernel=v5");
    try recorder.add(.base_image, "stable-d", "image=v5");
    const boot = recorder.finalize();

    var service = Service.init(.{ .kind = .device, .serial = 35 });
    try service.provisionRoot(.{
        .label = "device-se",
        .seed = [_]u8{0x55} ** 32,
    }, .secure_enclave);

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
    try std.testing.expectEqual(KeyOrigin.secure_enclave, statement.key_origin);
    try std.testing.expectEqualStrings("device-se", statement.rootLabelSlice());
}
