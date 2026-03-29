const std = @import("std");
const object_store = @import("object_store.zig");
const storage_volume = @import("storage_volume.zig");
const workspace = @import("workspace.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const dir = try std.fs.openDirAbsolute("/home/cameronl/zigos", .{});
    defer dir.close();
    const image = try dir.readFileAlloc(allocator, "build/native-store-smoke.img", 16 * 1024 * 1024);
    defer allocator.free(image);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const generation = try storage_volume.loadFromImage(image, &store, &workspaces);

    try std.io.getStdOut().writer().print(
        "generation={d} objects={d} versions={d} next_workspace={d} next_snapshot={d}\n",
        .{ generation, store.objectCount(), store.versionCount(), workspaces.next_workspace_id, workspaces.next_snapshot_id },
    );

    for (store.objects) |slot| {
        if (!slot.in_use) continue;
        try std.io.getStdOut().writer().print(
            "object id={d} latest={d} count={d}\n",
            .{ slot.object.id, slot.object.latest_version_id, slot.object.version_count },
        );
    }

    for (store.versions) |slot| {
        if (!slot.in_use) continue;
        try std.io.getStdOut().writer().print(
            "version id={d} object={d} prev={d} label={s} content_type={s} payload_len={d}\n",
            .{
                slot.version.id,
                slot.version.object_id,
                slot.version.previous_version_id,
                slot.version.metadata.labelSlice(),
                slot.version.metadata.contentTypeSlice(),
                slot.version.payload_len,
            },
        );
    }

    for (workspaces.workspaces) |slot| {
        if (!slot.in_use) continue;
        try std.io.getStdOut().writer().print(
            "workspace id={d} label={s} generation={d} entries={d}\n",
            .{ slot.workspace.id, slot.workspace.labelSlice(), slot.workspace.generation, slot.workspace.entry_count },
        );
    }

    for (workspaces.snapshots) |slot| {
        if (!slot.in_use) continue;
        try std.io.getStdOut().writer().print(
            "snapshot id={d} workspace={d} label={s} entries={d}\n",
            .{ slot.snapshot.id, slot.snapshot.workspace_id, slot.snapshot.labelSlice(), slot.snapshot.entry_count },
        );
    }
}
