const std = @import("std");
const object_store = @import("../native/storage/object_store.zig");
const storage_volume = @import("../native/storage/storage_volume.zig");
const workspace = @import("../native/storage/workspace.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const io = init.io;

    const image_path = if (args.len > 1) args[1] else "build/native-store-smoke.img";
    const image = try std.Io.Dir.cwd().readFileAlloc(io, image_path, allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(image);
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);

    var store = object_store.Store.init();
    var workspaces = workspace.Directory.init();
    const generation = try storage_volume.loadFromImage(image, &store, &workspaces);

    try stdout_writer.interface.print(
        "generation={d} objects={d} versions={d} next_workspace={d} next_snapshot={d}\n",
        .{ generation, store.objectCount(), store.versionCount(), workspaces.next_workspace_id, workspaces.next_snapshot_id },
    );

    for (store.objects.slots) |slot| {
        if (!slot.in_use) continue;
        try stdout_writer.interface.print(
            "object id={d} latest={d} count={d}\n",
            .{ slot.object.id, slot.object.latest_version_id, slot.object.version_count },
        );
    }

    for (store.versions.slots) |slot| {
        if (!slot.in_use) continue;
        try stdout_writer.interface.print(
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

    for (workspaces.workspaces.slots) |slot| {
        if (!slot.in_use) continue;
        try stdout_writer.interface.print(
            "workspace id={d} label={s} generation={d} entries={d}\n",
            .{ slot.workspace.id, slot.workspace.labelSlice(), slot.workspace.generation, slot.workspace.entry_count },
        );
    }

    for (workspaces.snapshots.slots) |slot| {
        if (!slot.in_use) continue;
        try stdout_writer.interface.print(
            "snapshot id={d} workspace={d} label={s} entries={d}\n",
            .{ slot.snapshot.id, slot.snapshot.workspace_id, slot.snapshot.labelSlice(), slot.snapshot.entry_count },
        );
    }

    try stdout_writer.interface.flush();
}
