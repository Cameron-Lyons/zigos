const std = @import("std");

const file_bridge = @import("../../native/storage/file_bridge.zig");
const object_store = @import("../../native/storage/object_store.zig");
const storage_service = @import("../../native/storage/storage_service.zig");
const storage_service_ipc = @import("../../native/storage/storage_service_ipc.zig");
const storage_volume = @import("../../native/storage/storage_volume.zig");
const storage_volume_test = @import("../../native/storage/storage_volume_test.zig");
const workspace = @import("../../native/storage/workspace.zig");
const workspace_test = @import("../../native/storage/workspace_test.zig");

test "storage host tests import native storage modules" {
    std.testing.refAllDecls(file_bridge);
    std.testing.refAllDecls(object_store);
    std.testing.refAllDecls(storage_service);
    std.testing.refAllDecls(storage_service_ipc);
    std.testing.refAllDecls(storage_volume);
    std.testing.refAllDecls(storage_volume_test);
    std.testing.refAllDecls(workspace);
    std.testing.refAllDecls(workspace_test);
}
