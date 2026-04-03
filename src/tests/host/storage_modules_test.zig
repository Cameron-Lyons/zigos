const std = @import("std");
const file_bridge = @import("../../native/storage/file_bridge.zig");
const object_store = @import("../../native/storage/object_store.zig");
const signing = @import("../../native/core/signing.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const storage_volume = @import("../../native/storage/storage_volume.zig");
const storage_volume_backend = @import("../../native/storage/storage_volume_backend.zig");
const workspace = @import("../../native/storage/workspace.zig");

test "storage storage modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(file_bridge);
    std.testing.refAllDecls(object_store);
    std.testing.refAllDecls(signing);
    std.testing.refAllDecls(storage_service);
    std.testing.refAllDecls(storage_volume);
    std.testing.refAllDecls(storage_volume_backend);
    std.testing.refAllDecls(workspace);
}
