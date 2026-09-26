const std = @import("std");
const sealing = @import("secret_sealing.zig");
const tpm = @import("tpm2_sealing.zig");

// This adapter borrows an initialized client, its serialized transport, and a
// nonzero authorization supplied by the unlock lifecycle. Detach before any of
// these objects move or expire. It never installs a default authorization.
pub fn Backend(comptime Io: type) type {
    return struct {
        const Self = @This();
        client: *tpm.Client,
        io: *Io,
        authorization: *const tpm.Key,

        pub fn provider(self: *Self) sealing.Provider {
            return .{ .context = self, .operations = &operations };
        }

        const operations = sealing.Provider.Operations{ .seal = seal, .open = open, .generateSigningKey = generateSigningKey };

        fn generateSigningKey(context: ?*anyopaque, binding: *const sealing.Binding, out: *sealing.Blob) sealing.Error!void {
            const self: *Self = @ptrCast(@alignCast(context orelse return error.HardwareProviderUnavailable));
            var seed: [std.crypto.sign.Ed25519.KeyPair.seed_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            self.io.random(&seed) catch return error.HardwareOperationFailed;
            try seal(context, binding, &seed, out);
        }

        fn seal(context: ?*anyopaque, binding: *const sealing.Binding, raw: []const u8, out: *sealing.Blob) sealing.Error!void {
            const self: *Self = @ptrCast(@alignCast(context orelse return error.HardwareProviderUnavailable));
            var key: tpm.Key = undefined;
            defer std.crypto.secureZero(u8, &key);
            self.io.random(&key) catch return error.HardwareOperationFailed;
            var nonce: [24]u8 = undefined;
            self.io.random(&nonce) catch return error.HardwareOperationFailed;
            var wrapped = tpm.Blob{};
            self.client.seal(self.io, &key, self.authorization, &wrapped) catch |err| return mapError(err);
            try sealing.encrypt(raw, &key, nonce, binding, wrapped.slice(), out);
        }

        fn open(context: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
            const self: *Self = @ptrCast(@alignCast(context orelse return error.HardwareProviderUnavailable));
            const envelope = try sealing.Envelope.parse(blob);
            var key: tpm.Key = undefined;
            defer std.crypto.secureZero(u8, &key);
            self.client.unseal(self.io, envelope.wrapped_key, self.authorization, &key) catch |err| return mapError(err);
            return envelope.open(&key, binding, out);
        }
    };
}

fn mapError(err: anyerror) sealing.Error {
    return switch (err) {
        error.NotInitialized, error.Failed, error.Unavailable => error.HardwareProviderUnavailable,
        error.InvalidAuthorization => error.InvalidAuthorization,
        error.InvalidBlob, error.WrongDevice, error.IntegrityFailure => error.InvalidSealedSecret,
        else => error.HardwareOperationFailed,
    };
}

test "signing key generation stops on each entropy failure before contacting TPM" {
    const FailingIo = struct {
        random_calls: u8 = 0,
        fail_at: u8,
        execute_calls: u8 = 0,
        pub fn random(self: *@This(), out: []u8) !void {
            self.random_calls += 1;
            @memset(out, 0xbb);
            if (self.random_calls == self.fail_at) return error.NoEntropy;
        }
        pub fn execute(self: *@This(), _: []const u8, _: []u8, _: u32) ![]u8 {
            self.execute_calls += 1;
            return error.UnexpectedTpmCommand;
        }
    };
    var client = tpm.Client{};
    const authorization: tpm.Key = @splat(0x73);
    const binding: sealing.Binding = @splat(0x71);
    for (1..4) |fail_at| {
        var io = FailingIo{ .fail_at = @intCast(fail_at) };
        var backend = Backend(FailingIo){ .client = &client, .io = &io, .authorization = &authorization };
        var blob = sealing.Blob{ .bytes = @splat(0xaa), .len = 40 };
        try std.testing.expectError(error.HardwareOperationFailed, backend.provider().generateSigningKey(&binding, &blob));
        try std.testing.expectEqual(@as(u8, @intCast(fail_at)), io.random_calls);
        try std.testing.expectEqual(@as(u8, 0), io.execute_calls);
        try std.testing.expectEqualDeep(sealing.Blob{}, blob);
    }
}
