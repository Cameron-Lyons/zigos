const std = @import("std");
const manifest = @import("manifest.zig");
const measured_boot = @import("measured_boot.zig");
const principal = @import("principal.zig");
const signing = @import("signing.zig");

pub const MAX_REMOTE_PARTY_BYTES: usize = 64;
pub const MAX_NONCE_BYTES: usize = 32;

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
    root_digest: [32]u8,
    signature: manifest.Signature,

    pub fn remotePartySlice(self: *const Statement) []const u8 {
        return self.remote_party[0..self.remote_party_len];
    }

    pub fn nonceSlice(self: *const Statement) []const u8 {
        return self.nonce[0..self.nonce_len];
    }
};

pub const Service = struct {
    device: principal.PrincipalId,
    visible_request_count: usize = 0,
    last_remote_party_len: usize = 0,
    last_remote_party: [MAX_REMOTE_PARTY_BYTES]u8 = [_]u8{0} ** MAX_REMOTE_PARTY_BYTES,

    pub fn init(device: principal.PrincipalId) Service {
        return .{ .device = device };
    }

    pub fn attest(
        self: *Service,
        boot: measured_boot.BootRecord,
        remote_party: []const u8,
        nonce: []const u8,
        signer: signing.SignerIdentity,
        user_visible: bool,
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
            .root_digest = boot.root_digest,
            .signature = .{},
        };
        statement.remote_party_len = copyText(&statement.remote_party, remote_party);
        statement.nonce_len = copyText(&statement.nonce, nonce);

        if (user_visible) {
            self.visible_request_count += 1;
            self.last_remote_party_len = copyText(&self.last_remote_party, remote_party);
        }

        const digest = statementDigest(statement);
        statement.signature = try signing.sign(signer, &digest);
        return statement;
    }

    pub fn verify(statement: Statement) bool {
        const digest = statementDigest(statement);
        return signing.verify(statement.signature, &digest);
    }
};

fn statementDigest(statement: Statement) [32]u8 {
    var digest = [_]u8{0} ** 32;
    const seeds = [_]u64{
        0xCBF29CE484222325,
        0x9E3779B185EBCA87,
        0xD6E8FEB86659FD93,
        0x94D049BB133111EB,
    };
    for (seeds, 0..) |seed, index| {
        var hash = seed;
        hash = hashByte(hash, @intFromEnum(statement.device.kind));
        hash = hashU64(hash, statement.device.serial);
        hash = hashU64(hash, statement.generation);
        hash = hashU64(hash, statement.record_count);
        hash = hashU64(hash, statement.critical_service_count);
        hash = hashU64(hash, statement.policy_count);
        hash = hashU64(hash, statement.driver_count);
        hash = hashByte(hash, if (statement.user_visible) 1 else 0);
        hash = hashBytes(hash, statement.remotePartySlice());
        hash = hashBytes(hash, statement.nonceSlice());
        hash = hashBytes(hash, &statement.root_digest);
        std.mem.writeInt(u64, digest[index * 8 ..][0..8], hash, .little);
    }
    return digest;
}

fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

fn hashBytes(start: u64, bytes: []const u8) u64 {
    var hash = start;
    for (bytes) |byte| {
        hash ^= byte;
        hash *%= 1099511628211;
    }
    return hash;
}

fn hashByte(start: u64, byte: u8) u64 {
    return hashBytes(start, &.{byte});
}

fn hashU64(start: u64, value: anytype) u64 {
    var buffer: [8]u8 = [_]u8{0} ** 8;
    std.mem.writeInt(u64, &buffer, @intCast(value), .little);
    return hashBytes(start, &buffer);
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
