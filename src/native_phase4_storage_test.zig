const std = @import("std");
const file_bridge = @import("kernel/process/native/file_bridge.zig");
const object_store = @import("kernel/process/native/object_store.zig");
const signing = @import("kernel/process/native/signing.zig");
const storage_service = @import("kernel/process/native/storage_service.zig");
const storage_volume = @import("kernel/process/native/storage_volume.zig");
const storage_volume_backend = @import("kernel/process/native/storage_volume_backend.zig");
const workspace = @import("kernel/process/native/workspace.zig");

test "phase4 native storage modules compile and expose their tests from the src root" {
    std.testing.refAllDecls(file_bridge);
    std.testing.refAllDecls(object_store);
    std.testing.refAllDecls(signing);
    std.testing.refAllDecls(storage_service);
    std.testing.refAllDecls(storage_volume);
    std.testing.refAllDecls(storage_volume_backend);
    std.testing.refAllDecls(workspace);
}
