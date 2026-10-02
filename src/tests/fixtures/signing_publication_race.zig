//! Insert a competing storage version at the hardware-signing boundary.
const sealing = @import("../../native/platform/secret_sealing.zig");
const storage_mod = @import("../../native/storage/storage_service.zig");
const objects = @import("../../native/storage/object_store.zig");
const software = @import("secret_provider.zig");

pub const Fixture = struct {
    storage: *storage_mod.Service,
    object_id: u64,
    version_id: u64 = 0,

    pub fn provider(self: *@This()) sealing.Provider {
        return .{ .context = self, .operations = &.{ .seal = seal, .open = open } };
    }

    fn seal(_: ?*anyopaque, binding: *const sealing.Binding, raw: []const u8, out: *sealing.Blob) sealing.Error!void {
        try software.provider().seal(binding, raw, out);
    }

    fn open(context: ?*anyopaque, binding: *const sealing.Binding, blob: []const u8, out: *sealing.Value) sealing.Error!usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        if (self.version_id == 0) {
            const payload = "concurrent publisher";
            const metadata = objects.signMetadata(@import("../../native/storage/document_save_test.zig").signer, "Competing object", "application/octet-stream", .secret, payload, 1) catch return error.HardwareOperationFailed;
            const stored = self.storage.putVersion(.{ .preferred_object_id = objects.ids.object(self.object_id), .object_type = .secret, .payload = payload, .metadata = metadata }) catch return error.HardwareOperationFailed;
            self.version_id = stored.version_id.raw();
        }
        return software.provider().open(binding, blob, out);
    }
};
