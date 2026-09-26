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
            return .{ .context = self, .sealFn = seal, .openFn = open };
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
